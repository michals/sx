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

#ifndef _MISC_H
#define _MISC_H

#include "sx.h"
#include <sys/time.h>

void *sxi_realloc(sxc_client_t *sx, void *ptr, unsigned int newlen);
int sxi_is_valid_authtoken(sxc_client_t *sx, const char *token);
char *sxi_b64_enc(sxc_client_t *sx, const void *data, unsigned int data_size);
int sxi_b64_dec(sxc_client_t *sx, const char *string, void *buf, unsigned int *buf_size);
char *sxi_b64_enc_core(const void *data, unsigned int data_size);
int sxi_b64_dec_core(const char *string, void *buf, unsigned int *buf_size);
void sxi_bin2hex(const void *bin, unsigned int len, char *hex);
int sxi_uuid_parse(const char *uuid_str, uint8_t *uuid);
void sxi_uuid_unparse(const uint8_t *uuid, char *uuid_str);
int sxi_hex2bin(const char *src, uint32_t src_len, uint8_t *dst, uint32_t dst_len);

typedef struct _sxi_ht_t sxi_ht;
sxi_ht *sxi_ht_new(sxc_client_t *sx, unsigned int initial_size);
int sxi_ht_add(sxi_ht *ht, const void *key, unsigned int key_length, void *value);
int sxi_ht_get(sxi_ht *ht, const void *key, unsigned int key_length, void **value);
void sxi_ht_del(sxi_ht *ht, const void *key, unsigned int key_length);
char *sxi_make_tempfile(sxc_client_t *sx, const char *basedir, FILE **f);
char *sxi_tempfile_track(sxc_client_t *sx, const char *basedir, FILE **f);
int sxi_tempfile_untrack(sxc_client_t *sx, const char *name);
void sxi_tempfile_unlink_untrack(sxc_client_t *sx, const char *name);
int sxi_tempfile_istracked(sxc_client_t *sx, const char *name);
char *sxi_urlencode(sxc_client_t *sx, const char *string, int encode_slash);

unsigned int sxi_ht_count(sxi_ht *ht);
void sxi_ht_enum_reset(sxi_ht *ht);
int sxi_ht_enum_getnext(sxi_ht *ht, const void **key, unsigned int *key_len, const void **value);
void sxi_ht_empty(sxi_ht *ht);
void sxi_ht_free(sxi_ht *ht);

double sxi_timediff(const struct timeval *a, const struct timeval *b);
int sxi_utf8_validate(const char *str);

char *sxi_json_quote_string(const char *s);
int sxi_uri_is_sx(sxc_client_t *sx, const char *uri);

char sxi_read_one_char(void);
int sxi_yesno(const char *prompt, int def);
int sxi_mkdir_hier(sxc_client_t *sx, const char *fullpath);
int sxi_rmdirs(const char *dir);

#endif

