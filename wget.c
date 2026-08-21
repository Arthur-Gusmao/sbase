/* See LICENSE file for copyright and license details. */
/*
 * TLS support is built on BearSSL <https://www.bearssl.org/>.
 * The trust anchor loading code is derived from BearSSL's tools,
 * Copyright (c) Thomas Pornin, MIT licence.
 */
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bearssl/bearssl.h>

#include "arg.h"
#include "util.h"

static char *cacert = "/etc/ssl/cert.pem";

static br_x509_trust_anchor *tas;
static size_t nta;
static size_t tacap;

struct url {
	char *host;
	char *port;
	char *path;
	int tls;
};

struct buf {
	unsigned char *data;
	size_t len;
	size_t cap;
};

/* buffered input over a raw socket or an ssl session */
struct rstream {
	int fd;
	br_sslio_context *ioc;
	unsigned char buf[65536];
	size_t pos;
	size_t len;
};

static void
usage(void)
{
	eprintf("usage: %s [-C cacert] [-O file] url\n", argv0);
}

static void *
blobdup(const void *b, size_t n)
{
	void *d;

	d = emalloc(n);
	memcpy(d, b, n);
	return d;
}

static void
bufappend(void *ctx, const void *data, size_t len)
{
	struct buf *b = ctx;

	if (b->len + len > b->cap) {
		b->cap = b->cap ? b->cap : 1024;
		while (b->len + len > b->cap)
			b->cap *= 2;
		b->data = erealloc(b->data, b->cap);
	}
	memcpy(b->data + b->len, data, len);
	b->len += len;
}

static void
parseurl(char *u, struct url *url)
{
	char *o = u;

	url->tls = 0;
	url->port = "80";
	if (!strncmp(u, "http://", 7)) {
		u += 7;
	} else if (!strncmp(u, "https://", 8)) {
		url->tls = 1;
		url->port = "443";
		u += 8;
	} else {
		eprintf("%s: unsupported url\n", o);
	}
	url->path = strchr(u, '/');
	if (url->path) {
		url->path = estrdup(url->path);
		*strchr(u, '/') = '\0';
	} else {
		url->path = "/";
	}
	url->host = estrdup(u);
	u = strchr(url->host, ':');
	if (u) {
		*u = '\0';
		url->port = u + 1;
	}
	if (!url->host[0])
		eprintf("%s: no host\n", o);
}

static int
dial(const char *host, const char *port)
{
	struct addrinfo hints, *res, *r;
	int fd, ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(host, port, &hints, &res);
	if (ret)
		eprintf("getaddrinfo: %s\n", gai_strerror(ret));
	fd = -1;
	for (r = res; r; r = r->ai_next) {
		fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
		if (fd < 0)
			continue;
		if (connect(fd, r->ai_addr, r->ai_addrlen) == 0)
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd < 0)
		eprintf("cannot connect to %s:%s\n", host, port);
	return fd;
}

static int
sock_read(void *ctx, unsigned char *buf, size_t len)
{
	ssize_t n;

	for (;;) {
		n = read(*(int *)ctx, buf, len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return -1;
		return n;
	}
}

static int
sock_write(void *ctx, const unsigned char *buf, size_t len)
{
	ssize_t n;

	for (;;) {
		n = write(*(int *)ctx, buf, len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return -1;
		return n;
	}
}

static int
cert_to_ta(br_x509_trust_anchor *ta, unsigned char *data, size_t len)
{
	struct buf dn = { 0 };
	br_x509_decoder_context dc;
	br_x509_pkey *pk;

	br_x509_decoder_init(&dc, bufappend, &dn);
	br_x509_decoder_push(&dc, data, len);
	pk = br_x509_decoder_get_pkey(&dc);
	if (pk == NULL || br_x509_decoder_last_error(&dc) != 0) {
		weprintf("certificate decoding failed\n");
		free(dn.data);
		return -1;
	}
	ta->dn.data = dn.data;
	ta->dn.len = dn.len;
	ta->flags = br_x509_decoder_isCA(&dc) ? BR_X509_TA_CA : 0;
	switch (pk->key_type) {
	case BR_KEYTYPE_RSA:
		ta->pkey.key_type = BR_KEYTYPE_RSA;
		ta->pkey.key.rsa.n = blobdup(pk->key.rsa.n, pk->key.rsa.nlen);
		ta->pkey.key.rsa.nlen = pk->key.rsa.nlen;
		ta->pkey.key.rsa.e = blobdup(pk->key.rsa.e, pk->key.rsa.elen);
		ta->pkey.key.rsa.elen = pk->key.rsa.elen;
		break;
	case BR_KEYTYPE_EC:
		ta->pkey.key_type = BR_KEYTYPE_EC;
		ta->pkey.key.ec.curve = pk->key.ec.curve;
		ta->pkey.key.ec.q = blobdup(pk->key.ec.q, pk->key.ec.qlen);
		ta->pkey.key.ec.qlen = pk->key.ec.qlen;
		break;
	default:
		weprintf("unsupported public key type\n");
		free(ta->dn.data);
		return -1;
	}
	return 0;
}

static void
add_ta(unsigned char *data, size_t len)
{
	if (nta == tacap) {
		tacap = tacap ? tacap * 2 : 64;
		tas = erealloc(tas, tacap * sizeof(*tas));
	}
	if (cert_to_ta(&tas[nta], data, len) == 0)
		nta++;
}

static void
load_anchors(const char *fname)
{
	unsigned char filebuf[8192];
	br_pem_decoder_context pc;
	struct buf der = { 0 };
	FILE *f;
	size_t n;
	int inobj = 0;

	f = fopen(fname, "r");
	if (!f)
		eprintf("fopen %s:", fname);
	br_pem_decoder_init(&pc);
	while ((n = fread(filebuf, 1, sizeof(filebuf), f)) > 0) {
		unsigned char *p = filebuf;
		size_t left = n;

		while (left > 0) {
			size_t t;

			t = br_pem_decoder_push(&pc, p, left);
			p += t;
			left -= t;
			for (;;) {
				switch (br_pem_decoder_event(&pc)) {
				case BR_PEM_BEGIN_OBJ:
					der.len = 0;
					br_pem_decoder_setdest(&pc,
					                       bufappend,
					                       &der);
					inobj = 1;
					break;
				case BR_PEM_END_OBJ:
					if (inobj &&
					    !strcmp(br_pem_decoder_name(&pc),
					            "CERTIFICATE"))
						add_ta(der.data, der.len);
					inobj = 0;
					break;
				case BR_PEM_ERROR:
					eprintf("%s: invalid PEM\n", fname);
				default:
					goto chunk;
				}
			}
		}
chunk:		;
	}
	fclose(f);
	free(der.data);
	if (nta == 0)
		eprintf("%s: no trust anchors found\n", fname);
}

static ssize_t
rs_fill(struct rstream *rs)
{
	ssize_t n;

	if (rs->ioc)
		n = br_sslio_read(rs->ioc, rs->buf, sizeof(rs->buf));
	else
		n = read(rs->fd, rs->buf, sizeof(rs->buf));
	if (n <= 0)
		return -1;
	rs->pos = 0;
	rs->len = n;
	return n;
}

static int
rs_getchar(struct rstream *rs)
{
	if (rs->pos >= rs->len && rs_fill(rs) < 0)
		return -1;
	return rs->buf[rs->pos++];
}

static int
rs_getline(struct rstream *rs, char *line, size_t size)
{
	size_t i = 0;
	int c = -1;

	while ((c = rs_getchar(rs)) >= 0) {
		if (c == '\n')
			break;
		if (i + 1 < size && c != '\r')
			line[i++] = c;
	}
	line[i] = '\0';
	return (c < 0 && i == 0) ? -1 : 0;
}

static int
rs_copy(struct rstream *rs, FILE *out)
{
	do {
		if (rs->pos < rs->len) {
			fwrite(rs->buf + rs->pos, 1, rs->len - rs->pos, out);
			rs->pos = rs->len;
		}
	} while (rs_fill(rs) >= 0);
	return ferror(out) ? -1 : 0;
}

static void
write_all(int fd, const void *buf, size_t len)
{
	const unsigned char *p = buf;
	ssize_t n;

	while (len > 0) {
		n = write(fd, p, len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			eprintf("write:");
		p += n;
		len -= n;
	}
}

static void
sendreq(int fd, br_sslio_context *ioc, struct url *url)
{
	char req[2048];
	int n;

	n = snprintf(req, sizeof(req),
	             "GET %s HTTP/1.0\r\n"
	             "Host: %s\r\n"
	             "User-Agent: sbase-wget\r\n"
	             "\r\n",
	             url->path, url->host);
	if (n < 0 || (size_t)n >= sizeof(req))
		eprintf("request too long\n");
	if (ioc) {
		br_sslio_write_all(ioc, req, n);
		br_sslio_flush(ioc);
	} else {
		write_all(fd, req, n);
	}
}

int
main(int argc, char *argv[])
{
	br_ssl_client_context sc;
	br_x509_minimal_context xc;
	br_sslio_context ioc;
	unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
	struct rstream rs;
	struct url url;
	const char *outname = NULL;
	char line[8192];
	FILE *out = stdout;
	int fd, status, ret;

	ARGBEGIN {
	case 'C':
		cacert = EARGF(usage());
		break;
	case 'O':
		outname = EARGF(usage());
		break;
	default:
		usage();
	} ARGEND

	if (argc != 1)
		usage();

	parseurl(argv[0], &url);
	signal(SIGPIPE, SIG_IGN);

	fd = dial(url.host, url.port);

	memset(&rs, 0, sizeof(rs));
	rs.fd = fd;

	if (url.tls) {
		load_anchors(cacert);
		br_ssl_client_init_full(&sc, &xc, tas, nta);
		br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof(iobuf), 1);
		br_ssl_client_reset(&sc, url.host, 0);
		br_sslio_init(&ioc, &sc.eng, sock_read, &fd, sock_write, &fd);
		rs.ioc = &ioc;
	}

	sendreq(fd, rs.ioc, &url);

	if (rs_getline(&rs, line, sizeof(line)) < 0)
		eprintf("%s: no response\n", url.host);
	if (strncmp(line, "HTTP/", 5) || strlen(line) < 12)
		eprintf("%s: bad response: %s\n", url.host, line);
	status = atoi(line + 9);
	while (rs_getline(&rs, line, sizeof(line)) == 0 && line[0])
		;

	if (outname) {
		out = fopen(outname, "wb");
		if (!out)
			eprintf("fopen %s:", outname);
	}

	if (rs_copy(&rs, out) < 0)
		weprintf("write error\n");

	if (outname && fclose(out))
		eprintf("%s: write error\n", outname);

	if (url.tls &&
	    br_ssl_engine_current_state(&sc.eng) == BR_SSL_CLOSED &&
	    br_ssl_engine_last_error(&sc.eng) != 0)
		eprintf("tls error %d\n",
		        br_ssl_engine_last_error(&sc.eng));

	close(fd);

	ret = (status >= 200 && status < 300) ? 0 : 1;
	if (fshut(stdout, "<stdout>"))
		ret = 1;
	return ret;
}
