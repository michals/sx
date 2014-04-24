/*
 *  Copyright (C) 2014 Skylable Ltd. <info-copyright@skylable.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */
#include "sx.h"
#include "curlevents.h"
#include "cert.h"
#include "vcrypto.h"
#include "vcryptocurl.h"
#include "sxreport.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#ifdef HMAC_UPDATE_RETURNS_INT
#define hmac_init_ex HMAC_Init_ex
#define hmac_update HMAC_Update
#define hmac_final HMAC_Final
#else
#define hmac_init_ex(a, b, c, d, e) (HMAC_Init_ex((a), (b), (c), (d), (e)), 1)
#define hmac_update(a, b, c) (HMAC_Update((a), (b), (c)), 1)
#define hmac_final(a, b, c) (HMAC_Final((a), (b), (c)), 1)
#endif

static int ssl_verify_hostname(X509_STORE_CTX *ctx, void *arg)
{
    STACK_OF(X509) *sk;
    X509 *x;
    curlev_t *ev = arg;
    sxi_conns_t *conns = sxi_curlev_get_conns(ev);
    sxc_client_t *sx = sxi_conns_get_client(conns);
    const char *name;

    (void)X509_verify_cert(ctx);
    sk = X509_STORE_CTX_get_chain(ctx);
    X509_STORE_CTX_set_error(ctx,X509_V_OK);
    if (!sk) {
        sxi_seterr(sx, SXE_ECOMM, "No certificate chain?");
        return 0;
    }
    x = sk_X509_value(sk, 0);
    name = sxi_conns_get_sslname(conns) ? sxi_conns_get_sslname(conns) : sxi_conns_get_dnsname(conns);
    if (sxi_verifyhost(sx, name, x) != CURLE_OK) {
#if 0
        if (!e->cafile) {
            sxi_notice(sx, "Ignoring %s!", sxc_geterrmsg(sx));
            ev->ssl_verified = 2;
            return 1;
        }
#endif
        sxi_seterr(sx, SXE_ECOMM, "Hostname mismatch in certificate, expected: \"%s\"", name);
        X509_STORE_CTX_set_error(ctx,X509_V_ERR_APPLICATION_VERIFICATION);
        return 0;
    }
    sxi_curlev_set_verified(ev, 1);
    return 1;
}

static CURLcode sslctxfun_hostname(CURL *curl, void *sslctx, void *parm)
{
    SSL_CTX *ctx = (SSL_CTX*)sslctx;
    SSL_CTX_set_default_verify_paths(ctx);
    SSL_CTX_set_cert_verify_callback(ctx, ssl_verify_hostname, parm);
    return CURLE_OK;
}

sxi_sslctxfun_t sxi_sslctxfun = sslctxfun_hostname;

struct sxi_hmac_ctx {
    sxc_client_t *sx;
    HMAC_CTX ctx;
};

sxi_hmac_ctx *sxi_hmac_init(sxc_client_t *sx)
{
    sxi_hmac_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        sxi_seterr(sx, SXE_EMEM,"cannot allocate hmac ctx");
        return NULL;
    }
    ctx->sx = sx;
    HMAC_CTX_init(&ctx->ctx);
    return ctx;
}

void sxi_hmac_cleanup(sxi_hmac_ctx **ctxptr)
{
    if (!ctxptr || !*ctxptr)
        return;
    HMAC_CTX_cleanup(&(*ctxptr)->ctx);
    free(*ctxptr);
    *ctxptr = NULL;
}

int sxi_hmac_init_ex(sxi_hmac_ctx *ctx,
                     const void *key, int key_len)
{
    if (!ctx)
        return 0;
    sxc_client_t *sx = ctx->sx;
    if (!hmac_init_ex(&ctx->ctx, key, key_len, EVP_sha1(), NULL)) {
        SXDEBUG("failed to init hmac context");
        sxi_seterr(sx, SXE_ECRYPT, "HMAC calculation failed");
        return 0;
    }
    return 1;
}

int sxi_hmac_update(sxi_hmac_ctx *ctx, const void *d, int len)
{
    if (!ctx)
        return 0;
    sxc_client_t *sx = ctx->sx;
    int r = hmac_update(&ctx->ctx, d, len);
    if(!r) {
	sxi_seterr(sx, SXE_ECRYPT, "HMAC calculation failed");
    }
    return r;
}

int sxi_hmac_update_str(sxi_hmac_ctx *ctx, const char *str) {
    if (!ctx)
        return 0;
    sxc_client_t *sx = ctx->sx;
    int r = hmac_update(&ctx->ctx, (unsigned char *)str, strlen(str));
    if(r)
	r = hmac_update(&ctx->ctx, (unsigned char *)"\n", 1);
    if(!r) {
	SXDEBUG("hmac_update failed for '%s'", str);
	sxi_seterr(sx, SXE_ECRYPT, "HMAC calculation failed");
    }
    return r;
}

int sxi_hmac_final(sxi_hmac_ctx *ctx, unsigned char *out, unsigned int *len)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    if (!ctx)
        return 0;
    sxc_client_t *sx = ctx->sx;
    if (!hmac_final(&ctx->ctx, md, len)) {
        SXDEBUG("failed to finalize hmac calculation");
        sxi_seterr(sx, SXE_ECRYPT, "HMAC finalization failed");
        return 0;
    }
    if (len && *len != HASH_BIN_LEN) {
        sxi_seterr(sx, SXE_ECRYPT, "Wrong hash size");
        return 0;
    }
    memcpy(out, md, HASH_BIN_LEN);
    return 1;
}

int sxi_crypto_check_ver(struct sxi_logger *l)
{
    uint32_t runtime_ver = SSLeay();
    uint32_t compile_ver = SSLEAY_VERSION_NUMBER;
    if((runtime_ver & 0xff0000000) != (compile_ver & 0xff0000000)) {
        sxi_log_msg(l, "crypto_check_ver", SX_LOG_CRIT,
                    "OpenSSL library version mismatch: compiled: %x, runtime: %d", compile_ver, runtime_ver);
        return -1;
    }
    return 0;
}

void sxi_report_crypto(sxc_client_t *sx)
{
    sxi_report_library_int(sx, "OpenSSL", SSLEAY_VERSION_NUMBER, SSLeay(), 0x10000000, 0x100000, 0x1000);
    sxi_info(sx, "OpenSSL CFLAGS: %s", SSLeay_version(SSLEAY_CFLAGS));
}

void sxi_sha256(const unsigned char *d, size_t n,unsigned char *md)
{
    SHA256(d, n, md);
}

struct sxi_md_ctx {
    sxc_client_t *sx;
    EVP_MD_CTX ctx;
};

sxi_md_ctx *sxi_md_init(sxc_client_t *sx)
{
    sxi_md_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        sxi_setsyserr(sx, SXE_EMEM, "Failed to allocate MD");
        return NULL;
    }
    ctx->sx = sx;
    EVP_MD_CTX_init(&ctx->ctx);
    return ctx;
}

void sxi_md_cleanup(sxi_md_ctx **ctxptr)
{
    if (!ctxptr)
        return;
    EVP_MD_CTX_cleanup(&(*ctxptr)->ctx);
    free(*ctxptr);
    *ctxptr = NULL;
}

int sxi_digest_init(sxi_md_ctx *ctx)
{
    sxc_client_t *sx = ctx->sx;
    if (!ctx)
        return 0;
    if(!EVP_DigestInit(&ctx->ctx, EVP_sha1())) {
	SXDEBUG("failed to init digest");
	sxi_seterr(sx, SXE_ECRYPT, "Cannot compute hash: unable to initialize digest");
	return 0;
    }
    return 1;
}

int sxi_digest_update(sxi_md_ctx *ctx, const void *d, size_t len)
{
    sxc_client_t *sx = ctx->sx;
    if (!ctx)
        return 0;
    if(!EVP_DigestUpdate(&ctx->ctx, d, len)) {
	SXDEBUG("failed to init digest");
	sxi_seterr(sx, SXE_ECRYPT, "Cannot compute hash: unable to update digest");
	return 0;
    }
    return 1;
}

int sxi_digest_final(sxi_md_ctx *ctx, unsigned char *out, unsigned int *len)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    sxc_client_t *sx = ctx->sx;
    if (!ctx)
        return 0;
    if(!EVP_DigestFinal(&ctx->ctx, md, len)) {
	SXDEBUG("failed to init digest");
	sxi_seterr(sx, SXE_ECRYPT, "Cannot compute hash: unable to finalize digest");
	return 0;
    }
    if (len && *len != HASH_BIN_LEN) {
	sxi_seterr(sx, SXE_ECRYPT, "Cannot compute hash: bad hash size");
        return 0;
    }
    memcpy(out, md, HASH_BIN_LEN);
    return 1;
}

int sxi_rand_bytes(unsigned char *d, int len)
{
    char namebuf[1024];
    const char *rndfile = RAND_file_name(namebuf, sizeof(namebuf));
    if(rndfile)
        RAND_load_file(rndfile, -1);
    if(RAND_status() == 1 && RAND_bytes(d, len) == 1) {
        RAND_write_file(rndfile);
        return 1;
    }
    return 0;
}

int sxi_rand_pseudo_bytes(unsigned char *d, int len)
{
    return RAND_pseudo_bytes(d, len);
}

void sxi_rand_cleanup(void)
{
    RAND_cleanup();
}
