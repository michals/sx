/*
 *  Copyright (C) 2012-2014 Skylable Ltd. <info-copyright@skylable.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *  Special exception for linking this software with OpenSSL:
 *
 *  In addition, as a special exception, Skylable Ltd. gives permission to
 *  link the code of this program with the OpenSSL library and distribute
 *  linked combinations including the two. You must obey the GNU General
 *  Public License in all respects for all of the code used other than
 *  OpenSSL. You may extend this exception to your version of the program,
 *  but you are not obligated to do so. If you do not wish to do so, delete
 *  this exception statement from your version.
 */

#include "config.h"
#include "default.h"

#include <string.h>
#include <strings.h>
#include <stdlib.h>

/* TODO: use vcrypto.h */
#include <openssl/evp.h>
#include <openssl/hmac.h>
#define sxi_hmac_init_ex HMAC_Init_ex
#define sxi_hmac_update HMAC_Update
#define sxi_hmac_final HMAC_Final

#include "fcgi-utils.h"
#include "fcgi-actions.h"
#include "utils.h"
#include "hashfs.h"
#include "../libsx/src/misc.h"

#define MAX_CLOCK_DRIFT 10

uint8_t hashbuf[UPLOAD_CHUNK_SIZE];
time_t last_flush;
void send_server_info(void) {
    last_flush = time(NULL);
    CGI_PRINTF("Server: Skylable SX\r\nSX-Cluster: %s (%s)\r\nVary: Accept-Encoding\r\n", src_version(), sx_hashfs_uuid(hashfs)->string);
}

static const char *http_err_str(int http_status) {
    int h = http_status / 100;

    switch(h) {
    case 1:
	WARN("called with informational response %d", http_status);
	return "No error";
    case 2:
	WARN("called with positive response %d", http_status);
	return "OK";
    case 3:
	WARN("called with redirect response %d", http_status);
	return "Redirection";
    case 4:
	switch(http_status) {
	case 401:
	    return "Unauthorized";
	case 403:
	    return "Forbidden";
	case 404:
	    return "Not Found";
	case 405:
	    return "Method Not Allowed";
	case 408:
	    return "Request Timeout";
	case 409:
	    return "Conflict";
	case 413:
	    return "Request Entity Too Large";
	case 414:
	    return "Request-URI Too Long";
        case 429:
            return "Too many requests";
	default:
	    WARN("unhandled status: %d", http_status);
	case 400:
	    return "Bad Request";
	}
    case 5:
	switch(http_status) {
	case 501:
	    return "Not Implemented";
	case 503:
	    return "Service Unavailable";
	case 507:
	    return "Insufficient Storage";
	default:
	    WARN("unhandled status: %d", http_status);
	case 500:
	    return "Internal Server Error";
	}
    }

    WARN("called with invalid response %d", http_status);
    return "Unknown error";
}

#define LOGO1 "data:image/png;base64,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"
#define LOGO2 "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"
static void print_html(int status, const char *title, int errnum, const char *errmsg)
{
    if (status)
	CGI_PRINTF("Status: %d\r\n", status);
    CGI_PRINTF("Content-Type: text/html\r\n\r\n\
<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n\
<html>\
    <head><title>%s</title></head>", title);
    CGI_PUTS("<body style='background-color:#9fcdea'>\
        <div style='position:absolute; top:50%; height:20em; margin-top: -10em; text-align:center; width: 90%;'>\
            <img src=\"");
    CGI_PUTS(LOGO1);/* too large to put into printf */
    CGI_PUTS(LOGO2);
    CGI_PUTS("\"/>");
    if (errmsg)
        CGI_PRINTF("<h2>Error %d</h2><pre>%s</pre>", errnum, errmsg);
    CGI_PUTS("\
            <h2>\
                This is an <a href=\"http://www.skylable.com/products/sx\">"SERVER_NAME" node</a>\
            </h2>\
        </div>\
        <div style=\"position: absolute; bottom:1em; right: 1em; border: #ddd 1px solid; font: 10px normal; color: #07c;\">");

    unsigned int version;
    const sx_uuid_t *cluster_uuid = sx_hashfs_uuid(hashfs);
    const sx_uuid_t *dist_uuid = sx_hashfs_distinfo(hashfs, &version, NULL);
    sx_uuid_t node_uuid;
    CGI_PRINTF("Cluster UUID: %s<br>Node UUID: %s<br>Distribution: ", cluster_uuid->string, sx_hashfs_self_uuid(hashfs, &node_uuid) == OK ? node_uuid.string : "&lt;not assigned yet&gt;");
    if(dist_uuid)
	CGI_PRINTF("%s(%u)", dist_uuid->string, version);
    else
	CGI_PUTS("&lt;not defined yet&gt;");
    CGI_PUTS("\
        </div>\
    </body>\
</html>");
}

static void send_error_helper(const char sep, int errnum, const char *message) {
    CGI_PRINTF("%c\"ErrorMessage\":", sep);
    json_send_qstring(message);
    if (errnum == 500 || errnum == 400) {
        if (message)
            WARN("HTTP %d: %s", errnum, message);
        CGI_PUTS(",\"ErrorDetails\":");
        json_send_qstring(msg_log_end());
    }
    CGI_PUTS(",\"NodeId\":");
    const sx_node_t *me = sx_hashfs_self(hashfs);
    json_send_qstring(me ? sx_node_uuid(me)->string : "<UNKNOWN>");
    CGI_PUTS(",\"ErrorId\":");
    json_send_qstring(msg_get_id());
    CGI_PUTC('}');
}

void send_partial_error(const char *message, rc_ty rc) {
    msg_set_reason("%s: %s", message, rc2str(rc));
    send_error_helper(',', 500, rc2str(rc));
}

void send_error(int errnum, const char *message) {
    if(!message || !*message)
	message = http_err_str(errnum);

    if(!is_sky()) {
        print_html(errnum, "Error", errnum, message);
    } else {
	CGI_PRINTF("Status: %d\r\nContent-Type: application/json\r\n", errnum);
        if (verb == VERB_HEAD) {
            /* workaround for old curl: it would close (instead of reusing)
             * the connection if a HEAD doesn't have Content-Length/chunked
             * encoding. And then we run out of ports due to too many
             * TIME_WAIT connections */
            CGI_PUTS("Content-Length: 0\r\n\r\n");
        } else {
            CGI_PUTS("\r\n");
            send_error_helper('{',errnum,message);
        }
    }
}

void send_home(void) {
    print_html(0, SERVER_NAME, 0, NULL);
}

int is_http_10(void) {
    const char *proto = FCGX_GetParam("SERVER_PROTOCOL", envp);
    return strcmp(proto, "HTTP/1.0") == 0;
}

static int hmac_update_str(HMAC_CTX *ctx, const char *str) {
    int r = sxi_hmac_update(ctx, (unsigned char *)str, strlen(str));
    if(r)
	r = sxi_hmac_update(ctx, (unsigned char *)"\n", 1);
    if(!r)
	WARN("hmac_update failed for '%s'", str);
    return r;
}

uint8_t user[AUTH_UID_LEN], rhmac[20];
sx_uid_t uid;
static sx_priv_t role;

static enum authed_t { AUTH_NOTAUTH, AUTH_BODYCHECK, AUTH_BODYCHECKING, AUTH_OK } authed;
static HMAC_CTX hmac_ctx;
static EVP_MD_CTX body_ctx;

static void auth_begin(void) {
    const char *param = FCGX_GetParam("HTTP_AUTHORIZATION", envp);
    uint8_t buf[AUTHTOK_BIN_LEN], key[AUTH_KEY_LEN];
    unsigned int blen = sizeof(buf);
    time_t reqdate, now;

    if(!param || strlen(param) != lenof("SKY ") + AUTHTOK_ASCII_LEN || strncmp(param, "SKY ", 4))
	return;

    if(sxi_b64_dec_core(param+4, buf, &blen) || blen != sizeof(buf))
	return;
    memcpy(user, buf, sizeof(user));
    memcpy(rhmac, buf+20, sizeof(rhmac));

    if(sx_hashfs_get_user_info(hashfs, user, &uid, key, &role) != OK) /* no such user */ {
        WARN("No such user: %s", param+4);
       return;
    }
    DEBUG("Request from uid %lld", (long long)uid);

    if(!sxi_hmac_init_ex(&hmac_ctx, key, sizeof(key), EVP_sha1(), NULL)) {
        WARN("hmac_init failed");
        quit_errmsg(500, "Failed to initialize crypto engine");
    }

    param = FCGX_GetParam("REQUEST_METHOD", envp);
    if(!param)
	return;
    if(!hmac_update_str(&hmac_ctx, param))
        quit_errmsg(500, "Failed to initialize crypto engine");

    param = FCGX_GetParam("REQUEST_URI", envp);
    if(!param)
	return;
    if(!hmac_update_str(&hmac_ctx, param+1))
        quit_errmsg(500, "Failed to initialize crypto engine");

    param = FCGX_GetParam("HTTP_DATE", envp);
    if(!param)
        quit_errmsg(400, "Missing Date: header");
    if(httpdate_to_time_t(param, &reqdate))
        quit_errmsg(400, "Date header in wrong format");
    now = time(NULL);
    if(reqdate < now - MAX_CLOCK_DRIFT * 60 || reqdate > now + MAX_CLOCK_DRIFT * 60)
        quit_errmsg(400, "Client clock drifted more than "STRIFY(MAX_CLOCK_DRIFT)" minutes");
    if(!hmac_update_str(&hmac_ctx, param))
        quit_errmsg(500, "Failed to initialize crypto engine");

    if(!content_len()) {
	uint8_t chmac[20];
	unsigned int chmac_len = 20;
	if(!hmac_update_str(&hmac_ctx, "da39a3ee5e6b4b0d3255bfef95601890afd80709"))
            quit_errmsg(500, "Failed to initialize crypto engine");
	if(!sxi_hmac_final(&hmac_ctx, chmac, &chmac_len))
            quit_errmsg(500, "Failed to initialize crypto engine");
	if(!hmac_compare(chmac, rhmac, sizeof(rhmac))) {
	    authed = AUTH_OK;
	} else {
	    /* WARN("auth mismatch"); */
	}
	return;
    } else
	authed = AUTH_BODYCHECK;
}

int get_body_chunk(char *buf, int buflen) {
    int r = FCGX_GetStr(buf, buflen, fcgi_in);
    if(r>=0) {
	if(authed == AUTH_BODYCHECK)
	    authed = AUTH_BODYCHECKING;
	if(authed == AUTH_BODYCHECKING && !EVP_DigestUpdate(&body_ctx, buf, r)) {
            WARN("EVP_DigestUpdate failed");
	    authed = AUTH_NOTAUTH;
	    return -1;
	}
    } else
	authed = AUTH_NOTAUTH;
    return r;
}

void auth_complete(void) {
    char content_hash[41];
    unsigned char d[20];
    unsigned int dlen = 20;

    if(authed == AUTH_OK)
	return;

    if(authed != AUTH_BODYCHECK && authed != AUTH_BODYCHECKING)
	goto auth_complete_fail;
    
    if(!EVP_DigestFinal(&body_ctx, d, NULL))
        quit_errmsg(500, "Failed to initialize crypto engine");

    bin2hex(d, sizeof(d), content_hash, sizeof(content_hash));
    content_hash[sizeof(content_hash)-1] = '\0';
    
    if(!hmac_update_str(&hmac_ctx, content_hash))
        quit_errmsg(500, "Failed to initialize crypto engine");

    if(!sxi_hmac_final(&hmac_ctx, d, &dlen))
        quit_errmsg(500, "Failed to initialize crypto engine");

    if(!hmac_compare(d, rhmac, sizeof(rhmac))) {
	authed = AUTH_OK;
	return;
    }

 auth_complete_fail:
    authed = AUTH_NOTAUTH;
}

int is_authed(void) {
    return (authed == AUTH_BODYCHECK || authed == AUTH_OK);
}

int is_sky(void) {
    const char *param = FCGX_GetParam("HTTP_AUTHORIZATION", envp);
    return (param && strlen(param) == 4 + 56 && !strncmp(param, "SKY ", 4));
}

void send_authreq(void) {
    CGI_PUTS("WWW-Authenticate: SKY realm=\""SERVER_NAME"\"\r\n");
    quit_errmsg(401, "Invalid credentials");
}

static char *inplace_urldecode(char *s, char forbid, char dedup, int *has_forbidden) {
    enum { COPY, PCT } mode = COPY;
    char *src = s, *dst = s, c;
    int v;

    if(!s)
	return NULL;
    if (has_forbidden)
        *has_forbidden = 0;
    while(1) {
	c = *src;
	src++;
	switch(mode) {
	case COPY:
	    if(!c) {
		*dst = '\0';
		return s;
	    }
	    if(c == '%') {
		mode = PCT;
		break;
	    }
	    if(dst != src - 1)
		*dst = c;
	    dst++;
	    if(dedup && c == dedup) {
		while(*src == c)
		    src++;
	    }
	    break;
	case PCT:
	    v = hexcharval(c);
	    if(c<0)
		return NULL;
	    *dst = v<<4;
	    c = *src;
	    src++;
	    v = hexcharval(c);
	    *dst |= v;
	    if(!*dst || *dst == forbid) {
                if (has_forbidden)
                    *has_forbidden = 1;
		return NULL;
            }
	    dst++;
	    mode = COPY;
	    break;
	}
    }
}


#define MAX_ARGS 256
char *volume, *path, *args[MAX_ARGS];
unsigned int nargs;
verb_t verb;

int arg_num(const char *arg) {
    unsigned int i, len = strlen(arg);
    for(i=0; i<nargs; i++) {
	if(strncmp(args[i], arg, len))
	    continue;
	if(args[i][len] == '\0' || args[i][len] == '=')
	    return i;
    }
    return -1;
}

const char *get_arg(const char *arg) {
    const char *ret;
    int i = arg_num(arg);
    if(i<0)
	return NULL;
    ret = strchr(args[i], '=');
    if(ret) {
	ret++;
	if(!*ret)
	    ret = NULL;
    }
    return ret;
}

int arg_is(const char *arg, const char *ref) {
    const char *val = get_arg(arg);
    if(!val) return 0;
    return strcmp(val, ref) == 0;
}

/*
 * Nginx supports a Request line of at most 8192 bytes:
 * 8192 = max(VERB URI HTTP/1.1\n) =>
 * 8192 = max(VERB) + 1 + max(URI) + 10
 * max(VERB) = strlen(OPTIONS) = 7
 * max(URI) = 8174 
 */
static char reqbuf[8174];
void handle_request(void) {
    const char *param;
    char *argp;
    unsigned int plen;

    msg_new_id();
    verb = VERB_UNSUP;
    param = FCGX_GetParam("REQUEST_METHOD", envp);
    if(param) {
	plen = strlen(param);
	switch(plen) {
	case 3:
	    if(!memcmp(param, "GET", 4))
		verb = VERB_GET;
	    else if(!memcmp(param, "PUT", 4))
		verb = VERB_PUT;
	    break;
	case 4:
	    if(!memcmp(param, "HEAD", 5))
		verb = VERB_HEAD;
	    else if(!memcmp(param, "POST", 5))
		verb = VERB_POST;
	    break;
	case 6:
	    if(!memcmp(param, "DELETE", 7))
		verb = VERB_DELETE;
	    break;
	case 7:
	    if(!memcmp(param, "OPTIONS", 8)) {
		CGI_PUTS("Allow: GET,HEAD,OPTIONS,PUT,DELETE\r\nContent-Length: 0\r\n\r\n");
		return;
	    }
	    break;
	}
    }
    if(verb == VERB_UNSUP)
	quit_errmsg(405, "Method Not Allowed");

    if(content_len()<0 || (verb != VERB_PUT && content_len()))
	quit_errmsg(400, "Invalid Content-Length: must be positive and method must be PUT");

    param = FCGX_GetParam("REQUEST_URI", envp);
    if(!param)
	quit_errmsg(400, "No URI provided");
    plen = strlen(param);
    if(*param != '/')
	quit_errmsg(400, "URI must start with /");
    if(plen > sizeof(reqbuf) - 1)
	quit_errmsg(414, "URL too long: request line must be <8k");

    do {
	param++;
	plen--;
    } while(*param == '/');

    memcpy(reqbuf, param, plen+1);
    argp = memchr(reqbuf, '?', plen);
    nargs = 0;
    if(argp) {
	unsigned int argslen = plen - (argp - reqbuf);
	plen = argp - reqbuf;
	do {
	    *argp = '\0';
	    argp++;
	    argslen--;
	} while(*argp == '?');
	if(!argslen)
	    argp = NULL;
	else {
	    do {
		char *nextarg;
		if(nargs >= MAX_ARGS)
		    quit_errmsg(414, "Too many parameters");
		nextarg = memchr(argp, '&', argslen);
		if(nextarg) {
		    do {
			*nextarg = '\0';
			nextarg++;
		    } while(*nextarg == '&');
		}
		if(*argp) {
		    if(!(args[nargs] = inplace_urldecode(argp, 0, 0, NULL)))
			quit_errmsg(400, "Invalid URL encoding");
		    if(utf8_validate_len(args[nargs]) < 0)
			quit_errmsg(400, "Parameters with invalid utf-8 encoding");
		    nargs++;
		}
		argslen -= nextarg - argp;
		argp = nextarg;
	    } while (argp);
	}
    }

    while(plen && reqbuf[plen-1] == '/') {
	plen--;
	reqbuf[plen] = '\0';
    }

    path = memchr(reqbuf, '/', plen);
    if(path) {
	do {
	    *path = '\0';
	    path ++;
	} while(*path == '/');
	if(!*path)
	    path = NULL;
    }
    volume = *reqbuf ? reqbuf : NULL;

    int forbidden = 0;
    if((volume && !inplace_urldecode(volume, '/', 0, &forbidden)) || (path && !inplace_urldecode(path, '/', '/', &forbidden))) {
        if (forbidden)
            quit_errmsg(400, "Volume or path with forbidden %2f or %00");
        else
            quit_errmsg(400, "Invalid URL encoding");
    }

    int vlen = volume ? utf8_validate_len(volume) : 0;
    int flen = path ? utf8_validate_len(path) : 0;

    if (vlen < 0 || flen < 0)
       quit_errmsg(400, "URL with invalid utf-8 encoding");

    if (is_reserved()) {
        /* No UTF8 used on reserved volumes, allow higher limit.
         * Otherwise we hit the 512 limit with batch requests already */
        if (path && strlen(path) > SXLIMIT_MAX_FILENAME_LEN * 12) {
            msg_set_reason("Path too long: filename must be <%d characters (%ld)",
                           SXLIMIT_MAX_FILENAME_LEN*12+ 1, strlen(path));
            quit_errmsg(414, msg_get_reason());
        }
    } else {
        if (flen > SXLIMIT_MAX_FILENAME_LEN) {
            msg_set_reason("Path too long: filename must be <%d UTF8 characters (%d)",
                           SXLIMIT_MAX_FILENAME_LEN + 1, flen);
            quit_errmsg(414, msg_get_reason());
        }
    }

    if (volume && strlen(volume) > SXLIMIT_MAX_VOLNAME_LEN) {
        msg_set_reason("Volume name too long: must be <= %d bytes", SXLIMIT_MAX_VOLNAME_LEN);
        quit_errmsg(414, msg_get_reason());
    }

    if(!EVP_DigestInit(&body_ctx, EVP_sha1()))
	quit_errmsg(500, "Failed to initialize crypto engine");
    HMAC_CTX_init(&hmac_ctx);

    authed = AUTH_NOTAUTH;
    role = PRIV_NONE;
    auth_begin();

    if(has_priv(PRIV_CLUSTER) && sx_hashfs_uses_secure_proto(hashfs) != is_https() &&
       !sx_storage_is_bare(hashfs)) {
        /* programmed nodes: must obey cluster SSL mode
         * unprogrammed nodes: can use SSL instead of non-SSL,
         *  it is the cluster's responsibility to initiate programming via SSL,
         *  as the unprogrammed node would accept both         *
         * */
        WARN("hashfs use-ssl: %d, https: %d, is_bare: %d",
              sx_hashfs_uses_secure_proto(hashfs), is_https(),
              sx_storage_is_bare(hashfs));
	quit_errmsg(403, sx_hashfs_uses_secure_proto(hashfs) ? "Cluster operations require SECURE mode" : "Cluster operations require INSECURE mode");
    }

    int dc = sx_hashfs_distcheck(hashfs);
    if(dc < 0) {
	CRIT("Failed to reload distribution");
	/* MODHDIST: should die here */
    }

    if(!volume)
	cluster_ops();
    else if(!path)
	volume_ops();
    else
	file_ops();

    if(authed == AUTH_BODYCHECKING)
	WARN("FIXME: Security fail");

    HMAC_CTX_cleanup(&hmac_ctx);
    EVP_MD_CTX_cleanup(&body_ctx);
}

int64_t content_len(void) {
    const char *clen = FCGX_GetParam("CONTENT_LENGTH", envp);
    if(!clen)
	return 0;

    return atoll(clen);
}

int get_priv(int volume_priv) {
    sx_priv_t mypriv;
    if(role < PRIV_ADMIN && volume_priv) {
	/* Volume specific check, requires lookup */
	if(sx_hashfs_get_access(hashfs, uid, volume, &mypriv) != OK) {
	    WARN("Unable to lookup volume access for uid %llu", (long long int )uid);
	    return 0;
	}
    } else {
	/* Non volume check, use the base role */
        mypriv = 0;
        if (role >= PRIV_ADMIN)
            mypriv |= PRIV_READ | PRIV_WRITE | PRIV_OWNER | PRIV_ADMIN;/* admin has all below */
        if (role >= PRIV_CLUSTER)
            mypriv |= PRIV_CLUSTER;
    }
    return mypriv;
}

int has_priv(sx_priv_t reqpriv) {
    return get_priv(!(reqpriv & ~(PRIV_READ | PRIV_WRITE | PRIV_OWNER))) & reqpriv;
}

int is_reserved(void) {
    return (volume && *volume == '.');
}

int volume_exists(void) {
    const sx_hashfs_volume_t *vol;
    return (sx_hashfs_volume_by_name(hashfs, volume, &vol) == OK);
}

/* FIXME: this does not handle UTF8! we must convert utf8 to utf32 for printing
 * with \u, and we must replace invalid utf8 characters with the unicode
 * replacement char. */
void json_send_qstring(const char *s) {
    const char *hex_digits = "0123456789abcdef", *begin = s;
    unsigned int len = 0;
    char escaped[6] = { '\\', 'u', '0', '0', 'x', 'x' };

    CGI_PUTC('"');
    while(1) {
	unsigned char c = begin[len];
	/* flush on end of string and escape quotation mark, reverse solidus,
	 * and the control characters (U+0000 through U+001F) */
	if(c < ' ' || c == '"' || c== '\\') {
	    if(len) /* flush */
		CGI_PUTD(begin, len);
	    begin = &begin[len+1];
	    len = 0;
	    if(!c) {
		CGI_PUTC('"');
		return;
	    }
	    escaped[4] = hex_digits[c >> 4];
	    escaped[5] = hex_digits[c & 0xf];
	    CGI_PUTD(escaped, 6);
	} else
	    len++;
    }
}

void send_httpdate(time_t t) {
    const char *month[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    const char *wkday[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    char buf[32];

    struct tm *ts = gmtime(&t);
    if(!ts)
	return;

    sprintf(buf, "%s, %02u %s %04u %02u:%02u:%02u GMT", wkday[ts->tm_wday], ts->tm_mday, month[ts->tm_mon], ts->tm_year + 1900, ts->tm_hour, ts->tm_min, ts->tm_sec);
    CGI_PUTS(buf);
}


void send_qstring_hash(const sx_hash_t *h) {
    char buf[sizeof(sx_hash_t) * 2 + 1];

    bin2hex(h->b, sizeof(h->b), buf, sizeof(buf));
    CGI_PUTC('"');
    CGI_PUTD(buf, sizeof(buf) - 1);
    CGI_PUTC('"');
}


int httpdate_to_time_t(const char *d, time_t *t) {
    if(!t || !d)
	return -1;

    d = strptimegm(d, "%a, %d %b %Y %H:%M:%S GMT", t);
    if(!d || *d)
	return -1;

    return 0;
}

void send_keepalive(void) {
    time_t now = time(NULL);
    if(now - last_flush > MAX_KEEPALIVE_INTERVAL) {
	last_flush = now;
	CGI_PUTC(' ');
	FCGX_FFlush(fcgi_out);
    }
}

void send_nodes(const sx_nodelist_t *nodes) {
    unsigned int i, comma = 0, nnodes;
    CGI_PUTC('[');
    for(i=0, nnodes = sx_nodelist_count(nodes); i<nnodes; i++) {
	const sx_node_t *node = sx_nodelist_get(nodes, i);

	if(comma)
	    CGI_PUTC(',');
	else
	    comma |= 1;

	if(has_priv(PRIV_CLUSTER))
	    json_send_qstring(sx_node_internal_addr(node));
	else
	    json_send_qstring(sx_node_addr(node));
    }
    CGI_PUTC(']');
}

void send_nodes_randomised(const sx_nodelist_t *nodes) {
    unsigned int nodeno, pos, comma = 0, nnodes;
    unsigned int list[256];

    CGI_PUTC('[');

    nnodes = sx_nodelist_count(nodes);
    for(nodeno=0, pos=0; nodeno<nnodes; nodeno++) {
	unsigned int i, j, t;

	list[pos++] = nodeno;
	if(pos != sizeof(list)/sizeof(list[0]) && nodeno != nnodes - 1)
	    continue;

	for(i=pos-1; i>=1; i--) {
	    j = rand() % (i+1);
	    if(i == j)
		continue;
	    t = list[i];
	    list[i] = list[j];
	    list[j] = t;
	}

	for(i=0; i<pos; i++) {
	    const sx_node_t *node = sx_nodelist_get(nodes, list[i]);

	    if(comma)
		CGI_PUTC(',');
	    else
		comma |= 1;

	    if(has_priv(PRIV_CLUSTER))
		json_send_qstring(sx_node_internal_addr(node));
	    else
		json_send_qstring(sx_node_addr(node));
	}

	pos = 0;
    }
    CGI_PUTC(']');
}

void send_job_info(job_t job) {
    /* FIXME:
     * For now we just output the job id integer as a string.
     * The client will treat it as an opaque type and simply
     * replay it back as is when polling
     * Therefore the format can be changed server side at any
     * time if we see the need for that */

    CGI_PUTS("Content-Type: application/json\r\n\r\n{\"requestId\":\"");
    CGI_PUTLL(job);
    CGI_PUTS("\",\"minPollInterval\":100,\"maxPollInterval\":6000}");
}

int is_https(void) {
    const char *proto = FCGX_GetParam("HTTPS", envp);
    return (proto && !strcasecmp(proto, "on"));
}
