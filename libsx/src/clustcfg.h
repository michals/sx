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

#ifndef _CLUSTCFG_H
#define _CLUSTCFG_H

#include "sx.h"
#include "cluster.h"
#include "misc.h"
#include "jobpoll.h"

sxc_client_t *sxi_cluster_get_client(const sxc_cluster_t *cluster);
int sxi_is_valid_cluster(const sxc_cluster_t *cluster);
int sxi_cluster_hashcalc(const sxc_cluster_t *cluster, const void *buffer, unsigned int len, char *hash);
sxc_cluster_lf_t *sxi_cluster_list_local_files(sxc_client_t *sx, const char *path, int recursive, unsigned int *nfiles);
char *sxi_urlencode(sxc_client_t *sx, const char *string, int encode_slash);
sxi_conns_t *sxi_cluster_get_conns(sxc_cluster_t *cluster);
#define sxi_cluster_get_name(CLUSTER) sxc_cluster_get_sslname(CLUSTER)
int sxi_locate_volume(sxc_cluster_t *cluster, const char *volume, sxi_hostlist_t *nodes, int64_t *size);
int sxi_volume_info(sxc_cluster_t *cluster, const char *volume, sxi_hostlist_t *nodes, int64_t *size, sxi_ht *metadata);
const char *sxi_cluster_get_confdir(const sxc_cluster_t *cluster);

/* Note: volume/path may be freed after exit from cb, make a copy if needed
 * inside! */

typedef sxi_job_t* (*file_list_cb_t)(sxc_file_list_t *target, sxc_file_t *pattern, sxc_cluster_t *cfg, sxi_hostlist_t *hlist,
                                   const char *vol, const char *path, void *ctx);
typedef int (*multi_cb_t)(sxc_file_list_t *target, void *ctx);
int sxi_file_list_foreach(sxc_file_list_t *target, sxc_cluster_t *wait_cluster, multi_cb_t multi_cb, file_list_cb_t cb, int need_locate, void *ctx);
char *sxi_ith_slash(char *s, unsigned int i);
unsigned sxi_count_slashes(const char *str);

#endif
