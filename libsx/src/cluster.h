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

#ifndef _CLUSTER_H
#define _CLUSTER_H

#include "default.h"
#include "curlevents-common.h"
#include "hostlist.h"
#include "misc.h"
#include "sxproto.h"
#define UUID_LEN 36

typedef struct sxi_hashop sxi_hashop_t;
typedef struct _sxi_conns_t sxi_conns_t;

typedef int (*cluster_datacb)(sxi_conns_t *conns, void *context, const void *data, size_t size);
sxi_conns_t *sxi_conns_new(sxc_client_t *sx);
void sxi_conns_free(sxi_conns_t *conns);
int sxi_conns_set_dnsname(sxi_conns_t *conns, const char *dnsname);
int sxi_conns_set_sslname(sxi_conns_t *conns, const char *sslname);
int sxi_conns_is_secure(sxi_conns_t *conns);
const char *sxi_conns_get_dnsname(const sxi_conns_t *conns);
const char *sxi_conns_get_sslname(const sxi_conns_t *conns);
sxc_client_t *sxi_conns_get_client(sxi_conns_t *conns);
curl_events_t *sxi_conns_get_curlev(sxi_conns_t *conns);
int sxi_conns_set_uuid(sxi_conns_t *conns, const char *uuid);
void sxi_conns_remove_uuid(sxi_conns_t *conns);
const char *sxi_conns_get_uuid(const sxi_conns_t *conns);
int sxi_conns_set_auth(sxi_conns_t *conns, const char *token);
const char *sxi_conns_get_auth(const sxi_conns_t *conns);
time_t sxi_conns_get_timediff(const sxi_conns_t *conns);
void sxi_conns_set_timediff(sxi_conns_t *conns, time_t timediff);
void sxi_conns_set_cafile(sxi_conns_t *conns, const char *cafile);
int sxi_conns_set_hostlist(sxi_conns_t *conns, const sxi_hostlist_t *hlist);
sxi_hostlist_t *sxi_conns_get_hostlist(sxi_conns_t *conns);
unsigned int sxi_conns_get_timeout(sxi_conns_t *conns, const char *host);
int sxi_conns_set_timeout(sxi_conns_t *conns, const char *host, int timeout_action);

typedef int (*cluster_setupcb)(sxi_conns_t *conns, void *context, const char *host);
int sxi_cluster_query(sxi_conns_t *conns, const sxi_hostlist_t *hlist, enum sxi_cluster_verb verb, const char *query, void *content, size_t content_size, cluster_setupcb setup_callback, cluster_datacb data_callback, void *context);
int sxi_conns_hashcalc(const sxi_conns_t *conns, const void *buffer, unsigned int len, char *hash);
int sxi_conns_hashcalc_core(const sxi_conns_t *conns, const char *salt, const void *buffer, unsigned int len, char *hash);
int sxi_cluster_query_ev(curlev_context_t *cbdata,
                         sxi_conns_t *conns, const char *host,
                         enum sxi_cluster_verb verb, const char *query,
                         void *content, size_t content_size,
                         ctx_setup_cb_t setup_callback,
                         body_cb_t callback);
int sxi_cluster_query_ev_retry(curlev_context_t *cbdata,
                         sxi_conns_t *conns, const sxi_hostlist_t *hlist,
                         enum sxi_cluster_verb verb, const char *query,
                         void *content, size_t content_size,
                         ctx_setup_cb_t setup_callback,
                         body_cb_t callback);
int sxi_conns_root_noauth(sxi_conns_t *conns, const char *tmpcafile, int quiet);

int sxi_upload_block_from_buf(sxi_conns_t *conns, sxi_hostlist_t *hlist, const char *token, uint8_t *block, unsigned int block_size, int64_t upload_size);
void sxi_retry_throttle(sxc_client_t *sx, unsigned retry);

#endif
