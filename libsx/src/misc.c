/*
 *  Copyright (C) 2012-2014 Skylable Ltd. <info-copyright@skylable.com>
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

#include "default.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#if HAVE_FTW
#include <ftw.h>
#else
#include "ftw.h"
#endif

#include "libsx-int.h"
#include "misc.h"

int sxc_fgetline(sxc_client_t *sx, FILE *f, char **ret) {
    char buf[2048], *cur;
    int curlen = 0, len, eol = 0;

    *ret = cur = NULL;
    sxc_clearerr(sx);
    while(1) {
	if(!fgets(buf, sizeof(buf), f)) {
	    if(ferror(f)) {
		SXDEBUG("Failed to read line");
		sxi_setsyserr(sx, SXE_EREAD, "Failed to read line from stream");
		free(cur);
		return 1;
	    }
	    break;
	}
	len = strlen(buf);
	while(len) {
	    char l = buf[len-1];
	    if(l == '\n' || l == '\r') {
		eol = 1;
		len--;
	    } else
		break;
	}

	if(len) {
	    cur = sxi_realloc(sx, cur, curlen+len+1);
	    if(!cur)
		return 1;
	    memcpy(cur + curlen, buf, len);
	    curlen += len;
	    cur[curlen] = '\0';
	}
	if(eol)
	    break;
    }
    *ret = cur;
    return 0;
}

void *sxi_realloc(sxc_client_t *sx, void *ptr, unsigned int newlen) {
    void *oldptr = ptr;
    ptr = realloc(ptr, newlen);
    if(!ptr) {
	SXDEBUG("Failed to realloc to %u bytes", newlen);
	sxi_seterr(sx, SXE_EMEM, "Cannot increase allocated size: out of memory");
	free(oldptr);
    }
    return ptr;
}

int sxi_is_valid_authtoken(sxc_client_t *sx, const char *token) {
    char buf[AUTHTOK_BIN_LEN];
    unsigned int buflen = AUTHTOK_BIN_LEN;

    if(!token || strlen(token) != AUTHTOK_ASCII_LEN || sxi_b64_dec(sx, token, buf, &buflen)) {
	SXDEBUG("Failed to verify token '%s':", token ? token : "(null)");
	return 0;
    }

    return 1;
}

char *sxi_b64_enc_core(const void *data, unsigned int data_size) {
    const char *b64tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const unsigned char *udata = (const unsigned char *)data;
    char *ret = malloc(((data_size / 3) + 1) * 4 + 1);
    unsigned int i;

    if (!ret)
	return NULL;

    for(i=0; data_size > 2; i+=4, data_size-=3, udata+=3) {
	ret[i+0] = b64tab[udata[0] >> 2];
	ret[i+1] = b64tab[((udata[0]&3) << 4) | (udata[1] >> 4)];
	ret[i+2] = b64tab[((udata[1]&15) << 2) | (udata[2] >> 6)];
	ret[i+3] = b64tab[udata[2]&63];
    }

    if(data_size--) {
	ret[i++] = b64tab[udata[0] >> 2];
	if(data_size) {
	    ret[i++] = b64tab[((udata[0]&3) << 4) | (udata[1] >> 4)];
	    ret[i++] = b64tab[((udata[1]&15) << 2)];
	} else {
	    ret[i++] = b64tab[((udata[0]&3) << 4)];
	    ret[i++] = '=';
	}
	ret[i++] = '=';
    }
    ret[i] = '\0';
    return ret;
}

char *sxi_b64_enc(sxc_client_t *sx, const void *data, unsigned int data_size) {
    char *ret = sxi_b64_enc_core(data, data_size);
    if(!ret) {
	SXDEBUG("OOM on %u bytes long input", data_size);
	sxi_seterr(sx, SXE_EMEM, "Cannot encode data in base64: our of memory");
	return NULL;
    }
    return ret;
}

int sxi_b64_dec_core(const char *string, void *buf, unsigned int *buf_size) {
    unsigned int i, j, asciilen, binlen;
    const unsigned char *ustring = (const unsigned char *)string;
    unsigned char *ubuf = (unsigned char *)buf;
    const int b64tab[256] = {
	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, 62,  -1, -1, -1, 63,
	52, 53, 54, 55,  56, 57, 58, 59,    60, 61, -1, -1,  -1, -1, -1, -1,
	-1,  0,  1,  2,   3,  4,  5,  6,     7,  8,  9, 10,  11, 12, 13, 14,
	15, 16, 17, 18,  19, 20, 21, 22,    23, 24, 25, -1,  -1, -1, -1, -1,
	-1, 26, 27, 28,  29, 30, 31, 32,    33, 34, 35, 36,  37, 38, 39, 40,
	41, 42, 43, 44,  45, 46, 47, 48,    49, 50, 51, -1,  -1, -1, -1, -1,

	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
	-1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    };

    if(!string || !buf || !buf_size) {
	return 1;
    }

    asciilen = strlen(string);
    if(!asciilen) {
	*buf_size = 0;
	return 0;
    }

    if(asciilen % 4)
	return 1;
    binlen = asciilen / 4 * 3;
    if(string[asciilen-1] == '=')
	binlen--;
    if(string[asciilen-2] == '=')
	binlen--;
    if(binlen > *buf_size)
	return 1;
    *buf_size = binlen;

    for(i=0, j=0; i<asciilen; i+=4) {
	int v1 = b64tab[ustring[i+0]],
	    v2 = b64tab[ustring[i+1]],
	    v3 = b64tab[ustring[i+2]],
	    v4 = b64tab[ustring[i+3]];

	if((v1 |v2) < 0) return 1;
	ubuf[j++] = (v1<<2) | (v2>>4);

	if(j>=binlen) break;
	if(v3 < 0) return 1;
	ubuf[j++] = (v2<<4) | (v3>>2);

	if(j>=binlen) break;
	if(v4 < 0) return 1;
	ubuf[j++] = (v3 << 6) | (v4);
    }
    return 0;
}

int sxi_b64_dec(sxc_client_t *sx, const char *string, void *buf, unsigned int *buf_size) {
    if (!string || !buf || !buf_size) {
	SXDEBUG("called with NULL argument");
	sxi_seterr(sx, SXE_EARG, "Cannot decode base64 string: invalid argument");
	return 1;
    }
    if (sxi_b64_dec_core(string, buf, buf_size)) {
	sxi_seterr(sx, SXE_EARG, "Cannot decode base64 string");
	return 1;
    }
    return 0;
}

char *sxi_urlencode(sxc_client_t *sx, const char *string, int encode_slash) {
    const unsigned int urlenctab[256] = {
	1, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 3, 3, 3,
	3, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 3, 3, 3,
	3, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 1, 1, 3,
	1, 1, 1, 1,  1, 1, 1, 1,    1, 1, 3, 3,  3, 3, 3, 3,
	3, 1, 1, 1,  1, 1, 1, 1,    1, 1, 1, 1,  1, 1, 1, 1,
	1, 1, 1, 1,  1, 1, 1, 1,    1, 1, 1, 3,  3, 3, 3, 1,
	3, 1, 1, 1,  1, 1, 1, 1,    1, 1, 1, 1,  1, 1, 1, 1,
	1, 1, 1, 1,  1, 1, 1, 1,    1, 1, 1, 3,  3, 3, 1, 3,

	3, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 3, 3, 3,
	3, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 3, 3, 3,
	3, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 3, 3, 3,
	3, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 3, 3, 3,
	3, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 3, 3, 3,
	3, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 3, 3, 3,
	3, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 3, 3, 3,
	3, 3, 3, 3,  3, 3, 3, 3,    3, 3, 3, 3,  3, 3, 3, 3,
    };
    unsigned int len = 0;
    const uint8_t *s;
    char *ret, *r;

    if(!string) {
	SXDEBUG("called with NULL argument");
	sxi_seterr(sx, SXE_EARG, "Cannot encode URL: invalid argument");
	return NULL;
    }

    for(s=(const uint8_t *)string; *s; s++)
	len += urlenctab[*s];

    len++;
    if(!(ret = malloc(len))) {
	SXDEBUG("OOM allocating output buffer (%u bytes)", len);
	sxi_seterr(sx, SXE_EARG, "Cannot encode URL: out of memory");
	return NULL;
    }

    r = ret;
    s = (const uint8_t *)string;
    while(1) {
	unsigned int c = *s;
	s++;

	if(urlenctab[c] == 1 || (!encode_slash && c == 0x2f)) {
	    *r = c;
	    r++;
	    if(!c)
		break;
	} else {
	    sprintf(r, "%%%02x", c);
	    r += 3;
	}
    }

    return ret;
}


static void downcase(char *s) {
    for(;*s;s++) {
	char c = *s;
	if(c >='A' && c <= 'Z')
	    *s = c + ('a' - 'A');
    }
}

#define SXPROTO "sx://"
int sxi_uri_is_sx(sxc_client_t *sx, const char *uri) {
    return strncmp(uri, SXPROTO, strlen(SXPROTO)) == 0;
}

sxc_uri_t *sxc_parse_uri(sxc_client_t *sx, const char *uri) {
    unsigned int len = strlen(uri);
    sxc_uri_t *u;
    char *p;

    sxc_clearerr(sx);
    if(len <= lenof(SXPROTO) || strncmp(SXPROTO, uri, lenof(SXPROTO))) {
	SXDEBUG("URI '%s' is too short", uri);
	sxi_seterr(sx, SXE_EARG, "Cannot parse URL '%s': invalid argument", uri);
	return NULL;
    }
    uri += lenof(SXPROTO);
    len -= lenof(SXPROTO);

    u = malloc(sizeof(*u) + len + 1);
    if(!u) {
	SXDEBUG("OOM allocating result struct for '%s'", uri);
	sxi_seterr(sx, SXE_EMEM, "Cannot parse URL '%s': out of memory", uri);
	return NULL;
    }

    p = ((char *)u) + sizeof(*u);
    memcpy(p, uri, len+1);
    u->volume = memchr(p, '/', len);
    if(u->volume) {
	int hostlen = u->volume - p;
	do {
	    *u->volume = '\0';
	    u->volume++;
	} while(*u->volume == '/');
	if(!*u->volume)
	    u->volume=NULL;
	else {
	    int inlen = len - (u->volume - p);
	    u->path = memchr(u->volume, '/', inlen);
	    if(u->path) {
		do {
		    *u->path = '\0';
		    u->path++;
		} while(*u->path == '/');
		if(!*u->path)
		    u->path = NULL;
	    }
	}
	len = hostlen;
    }
    if(!u->volume)
	u->path = NULL;
    u->host = memchr(p, '@', len);
    if(u->host) {
	do {
	    *u->host = '\0';
	    u->host++;
	} while (*u->host == '@');
	if(!*u->host)
	    u->host = u->profile = NULL;
	else
	    u->profile = p;
    } else {
	u->host = p;
	u->profile = NULL;
    }

    if(!u->host || !*u->host) {
	SXDEBUG("URI has a NULL or empty host");
	sxi_seterr(sx, SXE_EARG, "Cannot parse URL '%s': invalid host", uri);
	free(u);
	return NULL;
    }

    downcase(u->host);
    return u;
}

void sxc_free_uri(sxc_uri_t *uri) {
    free(uri);
}

static const char hexchar[16] = "0123456789abcdef";
void sxi_bin2hex(const void *bin, unsigned int len, char *hex) {
    uint8_t *s = (uint8_t *)bin;
    while(len--) {
        uint8_t c = *s;
	s++;
        hex[0] = hexchar[c >> 4];
        hex[1] = hexchar[c & 0xf];
        hex += 2;
    }
    *hex = '\0';
}

static const int hexchars[256] = {
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
     0,  1,  2,  3,   4,  5,  6,  7,     8,  9, -1, -1,  -1, -1, -1, -1,
    -1, 10, 11, 12,  13, 14, 15, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, 10, 11, 12,  13, 14, 15, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,

    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
    -1, -1, -1, -1,  -1, -1, -1, -1,    -1, -1, -1, -1,  -1, -1, -1, -1,
};

int sxi_hex2bin(const char *src, uint32_t src_len, uint8_t *dst, uint32_t dst_len)
{
    if((src_len % 2) || (dst_len < src_len / 2))
	return -1;
    for (uint32_t i = 0; i < src_len; i += 2) {
        int32_t h = (hexchars[(unsigned int)src[i]] << 4) | hexchars[(unsigned int)src[i+1]];
        if (h < 0)
            return -1;
        dst[i >> 1] = h;
    }
    return 0;
}

int sxi_uuid_parse(const char *uuid_str, uint8_t *uuid)
{

    if(strlen(uuid_str) != 36 ||
	sxi_hex2bin(uuid_str, 8, uuid, 4) ||
	uuid_str[8] != '-' ||
	sxi_hex2bin(uuid_str+9, 4, uuid+4, 2) ||
	uuid_str[13] != '-' ||
	sxi_hex2bin(uuid_str+14, 4, uuid+6, 2) ||
	uuid_str[18] != '-' ||
	sxi_hex2bin(uuid_str+19, 4, uuid+8, 2) ||
	uuid_str[23] != '-' ||
	sxi_hex2bin(uuid_str+24, 12, uuid+10, 6)
    ) return -1;

    return 0;
}

void sxi_uuid_unparse(const uint8_t *uuid, char *uuid_str)
{
    sprintf(uuid_str, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
	uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

char *sxi_make_tempfile(sxc_client_t *sx, const char *basedir, FILE **f) {
    unsigned int len;
    char *tmpname;
    int fd;

    if(!f) {
	SXDEBUG("called with NULL arg");
	sxi_seterr(sx, SXE_EARG, "Cannot create temporary file: invalid argument");
	return NULL;
    }
    if(!basedir)
	basedir = sxi_get_tempdir(sx);
    if(!basedir)
	basedir = getenv("TMPDIR");
    if(!basedir)
	basedir = getenv("TEMP");
    if(!basedir)
	basedir = "/tmp";

    len = strlen(basedir);

    tmpname = malloc(len + sizeof("/.sxtmpXXXXXX"));
    if(!tmpname) {
	SXDEBUG("OOM allocating tempname (%u bytes)", len);
	sxi_seterr(sx, SXE_EMEM, "Cannot create temporary file: out of memory");
	return NULL;
    }
    memcpy(tmpname, basedir, len);
    memcpy(tmpname + len, "/.sxtmpXXXXXX", sizeof("/.sxtmpXXXXXX"));
    fd = mkstemp(tmpname);
    if(fd < 0) {
	SXDEBUG("failed to create %s", tmpname);
	sxi_setsyserr(sx, SXE_ETMP, "Cannot create unique temporary file");
	free(tmpname);
	return NULL;
    }

    if(!(*f = fdopen(fd, "wb+"))) {
	SXDEBUG("failed to fdopen %s", tmpname);
	sxi_setsyserr(sx, SXE_ETMP, "Cannot create temporary file stream");
	close(fd);
	unlink(tmpname);
	free(tmpname);
	return NULL;
    }

    return tmpname;
}

char *sxi_tempfile_track(sxc_client_t *sx, const char *basedir, FILE **f)
{
    struct tempfile_track *temptrack;
    int i, slot = -1;
    char **newnames;

    if(!sx)
	return NULL;

    temptrack = sxi_get_temptrack(sx);
    for(i = 0; i < temptrack->slots; i++) {
	if(!temptrack->names[i]) {
	    slot = i;
	    break;
	}
    }

    if(slot == -1) {
	newnames = (char **) realloc(temptrack->names, (temptrack->slots + 1) * sizeof(char *));
	if(!newnames) {
	    sxi_seterr(sx, SXE_EMEM, "Out of memory");
	    return NULL;
	}
	temptrack->names = newnames;
	slot = temptrack->slots++;
    }

    temptrack->names[slot] = sxi_make_tempfile(sx, basedir, f);

    return temptrack->names[slot];
}

void sxi_tempfile_unlink_untrack(sxc_client_t *sx, const char *name) {
    unlink(name);
    sxi_tempfile_untrack(sx, name);
}

int sxi_tempfile_untrack(sxc_client_t *sx, const char *name)
{
    struct tempfile_track *temptrack;
    int i;

    if(!sx || !name)
	return 1;

    temptrack = sxi_get_temptrack(sx);
    for(i = 0; i < temptrack->slots; i++) {
	if(temptrack->names[i] && !strcmp(temptrack->names[i], name)) {
	    free(temptrack->names[i]);
	    temptrack->names[i] = NULL;
	    return 0;
	}
    }
    return 1;
}

int sxi_tempfile_istracked(sxc_client_t *sx, const char *name)
{
    struct tempfile_track *temptrack;
    int i;

    if(!sx || !name)
	return 0;

    temptrack = sxi_get_temptrack(sx);
    for(i = 0; i < temptrack->slots; i++) {
	if(temptrack->names[i] && !strcmp(temptrack->names[i], name)) {
	    return 1;
	}
    }
    return 0;
}

/*
 * mixing/hashing functions by Bob Jenkins, December 1996, Public Domain.
 * http://burtleburtle.net/bob/c/lookup2.c
 */
#define mix(a,b,c) \
{ \
  a=a-b;  a=a-c;  a=a^(c>>13); \
  b=b-c;  b=b-a;  b=b^(a<<8);  \
  c=c-a;  c=c-b;  c=c^(b>>13); \
  a=a-b;  a=a-c;  a=a^(c>>12); \
  b=b-c;  b=b-a;  b=b^(a<<16); \
  c=c-a;  c=c-b;  c=c^(b>>5);  \
  a=a-b;  a=a-c;  a=a^(c>>3);  \
  b=b-c;  b=b-a;  b=b^(a<<10); \
  c=c-a;  c=c-b;  c=c^(b>>15); \
}

static uint32_t hashfn(const void *key, unsigned int key_length) {
    uint32_t a,b,c,len;
    const uint8_t *k = key;

    /* Set up the internal state */
    len = key_length;
    a = b = c = 0x9e3779b9;  /* the golden ratio; an arbitrary value */

    /*---------------------------------------- handle most of the key */
    while (len >= 12) {
	a += (k[0] +((uint32_t)k[1]<<8) +((uint32_t)k[2]<<16) +((uint32_t)k[3]<<24));
	b += (k[4] +((uint32_t)k[5]<<8) +((uint32_t)k[6]<<16) +((uint32_t)k[7]<<24));
	c += (k[8] +((uint32_t)k[9]<<8) +((uint32_t)k[10]<<16)+((uint32_t)k[11]<<24));
	mix(a,b,c);
	k += 12; len -= 12;
    }

   /*------------------------------------- handle the last 11 bytes */
   c += key_length;
   switch(len) { /* all the case statements fall through */
   case 11: c+=((uint32_t)k[10]<<24);
   case 10: c+=((uint32_t)k[9]<<16);
   case 9 : c+=((uint32_t)k[8]<<8);
       /* the first byte of c is reserved for the length */
   case 8 : b+=((uint32_t)k[7]<<24);
   case 7 : b+=((uint32_t)k[6]<<16);
   case 6 : b+=((uint32_t)k[5]<<8);
   case 5 : b+=k[4];
   case 4 : a+=((uint32_t)k[3]<<24);
   case 3 : a+=((uint32_t)k[2]<<16);
   case 2 : a+=((uint32_t)k[1]<<8);
   case 1 : a+=k[0];
       /* case 0: nothing left to add */
   }
   mix(a,b,c);
   /*-------------------------------------------- report the result */
   return c;
}

static unsigned int next_pow2(unsigned int i) {
    i--;
    i |= i >> 1;
    i |= i >> 2;
    i |= i >> 4;
    i |= i >> 8;
    i |= i >> 16;
    i++;
    return i;
}

static const char *HT_DELETED = "DELETED";
struct sxi_ht_item_t {
    void *key;
    unsigned int key_len;
    void *value;
};

struct _sxi_ht_t {
    sxc_client_t *sx;
    struct sxi_ht_item_t **tab;
    unsigned int items;
    unsigned int deleted;
    unsigned int size;
    unsigned int current;
};


sxi_ht *sxi_ht_new(sxc_client_t *sx, unsigned int initial_size) {
    sxi_ht *ht;
    if(initial_size<128)
	initial_size = 128;
    else
	initial_size = next_pow2(initial_size);
    if(!(ht = malloc(sizeof(*ht)))) {
	SXDEBUG("failed to allocate hash struct");
	sxi_seterr(sx, SXE_EMEM, "Cannot create new hash table: out of memory");
	return NULL;
    }

    if(!(ht->tab = calloc(sizeof(struct sxi_ht_item_t *), initial_size))) {
	SXDEBUG("failed to create a hash with %u items", initial_size);
	sxi_seterr(sx, SXE_EMEM, "Cannot create new hash table: out of memory");
	free(ht);
	return NULL;
    }

    ht->sx = sx;
    ht->items = 0;
    ht->size = initial_size;
    ht->deleted = 0;
    ht->current = 0;
    return ht;
}

static unsigned int gethashpos(unsigned int i) {
    return i*(i-1)/2;
}

int sxi_ht_add(sxi_ht *ht, const void *key, unsigned int key_length, void *value) {
    uint32_t h = hashfn(key, key_length), pos;
    struct sxi_ht_item_t *item;
    sxc_client_t *sx = ht->sx;
    unsigned int i;

    for(i=1; ;i++) {
	pos = (h + gethashpos(i)) & (ht->size - 1);
	item = ht->tab[pos];

	if(!item)
	    break;

	if(key_length != item->key_len || memcmp(key, item->key, key_length))
	    continue;

	if (item->value == HT_DELETED)
		ht->deleted--;
	item->value = value;
	return 0;
    }

    item = malloc(sizeof(*item) + key_length);
    if(!item) {
	SXDEBUG("OOM allocating new item (key len: %u)", key_length);
	sxi_seterr(sx, SXE_EMEM, "Cannot add item to hash table: out of memory");
	return 1;
    }

    item->key = item+1;
    item->key_len = key_length;
    item->value = value;
    memcpy(item->key, key, key_length);
    ht->tab[pos] = item;
    ht->items++;

    if(ht->items * 100 / ht->size > 78) {
	unsigned int j;
	sxi_ht new_ht;

	memcpy(&new_ht, ht, sizeof(new_ht));

	if((new_ht.items - new_ht.deleted) * 100 / new_ht.size > 50)
	    new_ht.size *= 2;

	new_ht.tab = calloc(sizeof(struct sxi_ht_item_t *), new_ht.size);
	if(!new_ht.tab) {
	    SXDEBUG("OOM growing hash from %u to %u items", ht->size, new_ht.size);
	    sxi_seterr(sx, SXE_EMEM, "Cannot add item to hash table: out of memory");
	    return 1;
	}
	new_ht.items = 0;
	new_ht.deleted = 0;

	for(i=0; i<ht->size; i++) {
	    item = ht->tab[i];
	    if(!item)
		continue;
	    if(item->value == HT_DELETED) {
		free(item);
		continue;
	    }

	    new_ht.items++;
	    h = hashfn(item->key, item->key_len);
	    for(j=1; ;j++) {
		pos = (h + gethashpos(j)) & (new_ht.size - 1);
		if(new_ht.tab[pos])
		    continue;
		new_ht.tab[pos] = item;
		break;
	    }
	}
	free(ht->tab);
	memcpy(ht, &new_ht, sizeof(*ht));
    }

    return 0;
}

unsigned int sxi_ht_count(sxi_ht *ht) {
    return ht ? ht->items : 0;
}

int sxi_ht_get(sxi_ht *ht, const void *key, unsigned int key_length, void **value) {
    uint32_t h = hashfn(key, key_length), pos;
    struct sxi_ht_item_t *item;
    unsigned int i;

    for(i=1; ;i++) {
	pos = (h + gethashpos(i)) & (ht->size - 1);
	item = ht->tab[pos];

	if(!item)
	    return 1;

	if(key_length != item->key_len || memcmp(key, item->key, key_length))
	    continue;

	if(item->value == HT_DELETED)
	    return 1;

	if(value)
	    *value = item->value;
	return 0;
    }
}

void sxi_ht_del(sxi_ht *ht, const void *key, unsigned int key_length) {
    uint32_t h = hashfn(key, key_length), pos;
    struct sxi_ht_item_t *item;
    unsigned int i;

    for(i=1; ;i++) {
	pos = (h + gethashpos(i)) & (ht->size - 1);
	item = ht->tab[pos];

	if(!item)
	    return;

	if(key_length != item->key_len || memcmp(key, item->key, key_length))
	    continue;

	ht->deleted++;
	item->value = (void *)HT_DELETED;
	if(ht->items == ht->deleted)
	    sxi_ht_empty(ht);
	return;
    }
}

void sxi_ht_empty(sxi_ht *ht) {
    unsigned int i;
    if(!ht)
	return;
    for(i=0;i<ht->size; i++) {
	if(!ht->tab[i])
	    continue;
	free(ht->tab[i]);
    }
    memset(ht->tab, 0, sizeof(struct sxi_ht_item_t *) * ht->size);
    ht->items = ht->deleted = 0;
}

void sxi_ht_enum_reset(sxi_ht *ht) {
    ht->current = 0;
}

int sxi_ht_enum_getnext(sxi_ht *ht, const void **key, unsigned int *key_len, const void **value) {
    while(ht->current < ht->size) {
	struct sxi_ht_item_t *item = ht->tab[ht->current++];
	if(!item || item->value == HT_DELETED)
	    continue;
	if(key)
	    *key = item->key;
	if(key_len)
	    *key_len = item->key_len;
	if(value)
	    *value = item->value;
	return 0;
    }
    sxi_ht_enum_reset(ht);
    return 1;
}

void sxi_ht_free(sxi_ht *ht) {
    unsigned int i;
    if(!ht)
	return;
    for(i=0; i<ht->size;i++)
	free(ht->tab[i]);
    free(ht->tab);
    free(ht);
}

double sxi_timediff(const struct timeval *a, const struct timeval *b) {
    double rs = a->tv_sec - b->tv_sec;
    double ru = a->tv_usec - b->tv_usec;
    if(ru < 0) {
	rs = rs - 1;
	ru += 1000000;
    }
    return rs + ru/1000000.0;
}

int sxi_utf8_validate(const char *str)
{
  uint8_t c;
  while ((c = *str++)) {
    if (c < 0x80)
      continue;
    /* validate UTF-8 according to RFC3629 */
    if (c >= 0xC2 && c <= 0xDF) {
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
    } else if (c == 0xE0) {
      c = *str++;
      if (c < 0xA0 || c > 0xBF)
          return -1;
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
    } else if (c >= 0xE1 && c <= 0xEC) {
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
    } else if (c == 0xED) {
      c = *str++;
      if (c < 0x80 || c > 0x9F)
          return -1;
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
    } else if (c >= 0xEE && c <= 0xEF) {
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
    } else if (c == 0xF0) {
      c = *str++;
      if (c < 0x90 || c > 0xBF)
          return -1;
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
    } else if (c >= 0xF1 && c <= 0xF3) {
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
    } else if (c == 0xF4) {
      c = *str++;
      if (c < 0x80 || c > 0x8F)
          return -1;
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
      c = *str++;
      if (c < 0x80 || c > 0xBF)
          return -1;
   } else
       return -1;
  }
  return 0;
}


char *sxi_json_quote_string(const char *s) {
    const char *hex_digits = "0123456789abcdef", *begin = s;
    unsigned int pos = 0;
    char *p, *ret = malloc(strlen(s) * 6 + 3);

    if(!ret)
	return NULL;
    *ret = '"';
    p = ret + 1;
    while(1) {
        unsigned char c = begin[pos];
        /* flush on end of string and escape quotation mark, reverse solidus,
         * and the control characters (U+0000 through U+001F) */
        if(c < ' ' || c == '"' || c== '\\') {
            if(pos) { /* flush */
		memcpy(p, begin, pos);
		p += pos;
	    }
            begin = &begin[pos+1];
            pos = 0;
            if(!c) {
                p[0] = '"';
		p[1] = '\0';
                return ret;
            }
	    p[0] = '\\';
	    p[1] = 'u';
	    p[2] = '0';
	    p[3] = '0';
	    p[4] = hex_digits[c >> 4];
            p[5] = hex_digits[c & 0xf];
	    p += 6;
        } else
            pos++;
    }
}


struct meta_val_t {
    uint8_t *value;
    unsigned int value_len;
};

sxc_meta_t *sxc_meta_new(sxc_client_t *sx) {
    return sxi_ht_new(sx, 0);
}

void sxc_meta_empty(sxc_meta_t *meta) {
    void *item;

    if(!meta)
	return;

    sxi_ht_enum_reset(meta);
    while(!sxi_ht_enum_getnext(meta, NULL, NULL, (const void **)&item))
	free(item);

    sxi_ht_empty(meta);
}

void sxc_meta_free(sxc_meta_t *meta) {
    sxc_meta_empty(meta);
    sxi_ht_free(meta);
}

int sxc_meta_getval(sxc_meta_t *meta, const char *key, const void **value, unsigned int *value_len) {
    const struct meta_val_t *item;

    if(!meta)
	return -1;
    if(!key) {
	sxi_seterr(meta->sx, SXE_EARG, "Cannot lookup key: invalid argument");
	return -1;
    }

    if(sxi_ht_get(meta, key, strlen(key)+1, (void **)&item))
	return 1;

    if(value)
	*value = item->value;
    if(value_len)
	*value_len = item->value_len;

    return 0;
}

void sxc_meta_delval(sxc_meta_t *meta, const char *key) {
    unsigned int klen;
    void *freeme;

    if(!meta || !key)
	return;

    klen = strlen(key)+1;

    if(!sxi_ht_get(meta, key, klen, &freeme)) {
	free(freeme);
	sxi_ht_del(meta, key, klen);
    }
}

unsigned int sxc_meta_count(sxc_meta_t *meta) {
    return meta ? sxi_ht_count(meta) : 0;
}

int sxc_meta_getkeyval(sxc_meta_t *meta, unsigned int itemno, const char **key, const void **value, unsigned int *value_len) {
    unsigned int i, nitems = sxc_meta_count(meta);
    const struct meta_val_t *item;

    if(!meta)
	return -1;
    if(itemno >= nitems) {
	sxi_seterr(meta->sx, SXE_EARG, "Cannot lookup item: index out of bounds");
	return -1;
    }

    sxi_ht_enum_reset(meta);

    for(i=0; i < itemno ; i++)
	if(sxi_ht_enum_getnext(meta, NULL, NULL, NULL))
	    return -1;

    if(sxi_ht_enum_getnext(meta, (const void **)key, NULL, (const void **)&item))
	return -1;

    if(value)
	*value = item->value;
    if(value_len)
	*value_len = item->value_len;

    return 0;
}

int sxc_meta_setval(sxc_meta_t *meta, const char *key, const void *value, unsigned int value_len) {
    struct meta_val_t *item;

    if(!meta)
	return -1;
    if(!key || (!value && value_len)) {
	sxi_seterr(meta->sx, SXE_EARG, "Cannot set meta value: invalid argument");
	return -1;
    }

    item = malloc(sizeof(*item) + value_len);
    if(!item) {
	sxi_seterr(meta->sx, SXE_EMEM, "Cannot set meta value: out of memory");
	return 1;
    }

    item->value = (uint8_t *)(item + 1);
    item->value_len = value_len;
    memcpy(item->value, value, value_len);

    sxc_meta_delval(meta, key);

    if(sxi_ht_add(meta, key, strlen(key)+1, item))
	return -1;

    return 0;
}

int sxc_meta_setval_fromhex(sxc_meta_t *meta, const char *key, const char *valuehex, unsigned int valuehex_len) {
    struct meta_val_t *item;

    if(!meta)
	return -1;
    if(!key) {
	sxi_seterr(meta->sx, SXE_EARG, "Cannot set meta value: invalid key");
	return -1;
    }
    if(valuehex) {
	if(!valuehex_len)
	    valuehex_len = strlen(valuehex);
	if(valuehex_len & 1) {
	    sxi_seterr(meta->sx, SXE_EARG, "Cannot set meta value: invalid value");
	    return -1;
	}
    } else if(valuehex_len) {
	sxi_seterr(meta->sx, SXE_EARG, "Cannot set meta value: invalid value length");
	return -1;
    }

    item = malloc(sizeof(*item) + valuehex_len / 2);
    if(!item) {
	sxi_seterr(meta->sx, SXE_EMEM, "Cannot set meta value: out of memory");
	return 1;
    }

    item->value = (uint8_t *)(item + 1);
    item->value_len = valuehex_len / 2;
    if(sxi_hex2bin(valuehex, valuehex_len, item->value, item->value_len)) {
	sxi_seterr(meta->sx, SXE_EARG, "Cannot set meta value: invalid value");
	return -1;
    }

    sxc_meta_delval(meta, key);

    if(sxi_ht_add(meta, key, strlen(key)+1, item))
	return -1;

    return 0;
}

char sxi_read_one_char(void)
{
    char line[3];
    if (!fgets(line, sizeof(line), stdin)) {
        putchar('\n');
        return EOF;
    }
    if (line[0] == '\n' || (line[0] && line[1] == '\n'))
        return line[0]; /* one character, terminated by a newline */
    /* skip till EOL */
    while (fgets(line, 2, stdin) && line[0] && line[0] != '\n') {}
    /* more than one character read */
    return '\0';
}

/*
 * def == 1 -> [Y/n], 0 ==> [y/N]
 * return 1 ==> yes, 0 ==> no
 */
int sxi_yesno(const char *prompt, int def)
{
    char c;
    while(1) {
	if(def)
	    printf("%s [Y/n] ", prompt);
	else
	    printf("%s [y/N] ", prompt);
	fflush(stdout);
	c = sxi_read_one_char();
	if(c == 'y' || c == 'Y')
	    return 1;
	if(c == 'n' || c == 'N')
	    return 0;
	if(c == '\n' || c == EOF)
	    return def;
    }
    return 0;
}

static int rm_fn(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    if(typeflag == FTW_F || typeflag == FTW_SL || typeflag == FTW_SLN)
	return unlink(path);
    if(typeflag == FTW_DP) {
	if(rmdir(path) == -1)
	    return -1;
        return 0;
    }
    return -1;
}

int sxi_rmdirs(const char *dir)
{
    if(access(dir, F_OK) == -1 && errno == ENOENT)
	return 0;
    return nftw(dir, rm_fn, 10, FTW_MOUNT | FTW_PHYS | FTW_DEPTH);
}
