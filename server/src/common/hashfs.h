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

#ifndef __HASHFS_H
#define __HASHFS_H

#include "default.h"
#include "utils.h"
#include "nodes.h"
#include "job_common.h"
#include "../libsx/src/cluster.h"
#include "sxdbi.h"

typedef struct _sx_hash_t {
    uint8_t b[HASH_BIN_LEN];
} sx_hash_t;

#include "hashop.h"

#define TOKEN_RAND_BYTES 16
#define REV_TIME_LEN lenof("YYYY-MM-DD hh:mm:ss.sss")
#define REV_LEN (REV_TIME_LEN + 1 + TOKEN_RAND_BYTES * 2)

/* Number of fds required to open the databases */
#define MAX_FDS 1024

/* various constants, see bug #335, all times in seconds */
/* FIXME: find a better place, make admin settable */
#define JOB_FILE_MAX_TIME (2*24*60*60 /* 2 days */)
#define JOBMGR_DELAY_MIN 1
#define JOBMGR_DELAY_MAX 7
#define TOPUSH_EXPIRE 900
#define BLOCKMGR_DELAY 3
#define BLOCKMGR_RESCHEDULE 24
#define GC_GRACE_PERIOD JOB_FILE_MAX_TIME
#define GC_FALLBACK_EXPIRES (86400 * 7)
#define GC_UPLOAD_MINSPEED 65536 /* in bytes / s */
#define GC_MIN_LATENCY 200 /* ms */
/* maximum number of operations to perform in a single transaction */
#define GC_MAX_OPS 50

#define SXLIMIT_MIN_VOLNAME_LEN 2
#define SXLIMIT_MAX_VOLNAME_LEN 255
#define SXLIMIT_MIN_VOLUME_SIZE (1*1024*1024)
#define SXLIMIT_MAX_VOLUME_SIZE (1LL*1024LL*1024LL*1024LL*1024LL*1024LL)

#define SXLIMIT_MIN_FILENAME_LEN 1
#define SXLIMIT_MAX_FILENAME_LEN 511
#define SXLIMIT_MIN_FILE_SIZE 0LL
#define SXLIMIT_MAX_FILE_SIZE (10LL*1024LL*1024LL*1024LL*1024LL)

#define SXLIMIT_META_MIN_KEY_LEN 1
#define SXLIMIT_META_MAX_KEY_LEN 256
#define SXLIMIT_META_MIN_VALUE_LEN 0
#define SXLIMIT_META_MAX_VALUE_LEN 1024
#define SXLIMIT_META_MAX_ITEMS 128

#define SXLIMIT_MIN_USERNAME_LEN 2
#define SXLIMIT_MAX_USERNAME_LEN 256

typedef enum {
    NL_PREV,
    NL_NEXT,
    NL_PREVNEXT,
    NL_NEXTPREV
} sx_hashfs_nl_t;

typedef int64_t sx_uid_t;

/* HashFS main actions */
rc_ty sx_storage_create(const char *dir, sx_uuid_t *cluster, uint8_t *key, int key_size);
typedef struct _sx_hashfs_t sx_hashfs_t;
sx_hashfs_t *sx_hashfs_open(const char *dir, sxc_client_t *sx);
rc_ty sx_hashfs_gc_open(sx_hashfs_t *h);
void sx_hashfs_checkpoint(sx_hashfs_t *h);
int sx_storage_is_bare(sx_hashfs_t *h);
int sx_hashfs_is_rebalancing(sx_hashfs_t *h);
const char *sx_hashfs_cluster_name(sx_hashfs_t *h);
const char *sx_hashfs_ca_file(sx_hashfs_t *h);
void sx_storage_usage(sx_hashfs_t *h, int64_t *allocated, int64_t *committed);
const sx_uuid_t *sx_hashfs_distinfo(sx_hashfs_t *h, unsigned int *version, uint64_t *checksum);
rc_ty sx_storage_activate(sx_hashfs_t *h, const char *name, const sx_uuid_t *node_uuid, uint8_t *admin_uid, unsigned int uid_size, uint8_t *admin_key, int key_size, const char *ssl_ca_file, const sx_nodelist_t *allnodes);
rc_ty sx_hashfs_setnodedata(sx_hashfs_t *h, const char *name, const sx_uuid_t *node_uuid, int use_ssl, const char *ssl_ca_crt);
int sx_hashfs_uses_secure_proto(sx_hashfs_t *h);
void sx_hashfs_set_triggers(sx_hashfs_t *h, int job_trigger, int xfer_trigger, int gc_trigger);
void sx_hashfs_close(sx_hashfs_t *h);
int sx_hashfs_check(sx_hashfs_t *h, int verbose);
void sx_hashfs_stats(sx_hashfs_t *h);
void sx_hashfs_analyze(sx_hashfs_t *h);
sx_nodelist_t *sx_hashfs_hashnodes(sx_hashfs_t *h, sx_hashfs_nl_t which, const sx_hash_t *hash, unsigned int replica_count);
sx_nodelist_t *sx_hashfs_putfile_hashnodes(sx_hashfs_t *h, const sx_hash_t *hash);
rc_ty sx_hashfs_check_blocksize(unsigned int bs);
int sx_hashfs_distcheck(sx_hashfs_t *h);
time_t sx_hashfs_disttime(sx_hashfs_t *h);
sxi_db_t *sx_hashfs_eventdb(sx_hashfs_t *h);
sxi_db_t *sx_hashfs_xferdb(sx_hashfs_t *h);
sxc_client_t *sx_hashfs_client(sx_hashfs_t *h);
sxi_conns_t *sx_hashfs_conns(sx_hashfs_t *h);

typedef struct _sx_hash_challenge_t {
    uint8_t challenge[TOKEN_RAND_BYTES];
    uint8_t response[AUTH_KEY_LEN];
} sx_hash_challenge_t;
rc_ty sx_hashfs_challenge_gen(sx_hashfs_t *h, sx_hash_challenge_t *c, int random_challenge);

int sx_hashfs_check_volume_name(const char *name);
int sx_hashfs_check_meta(const char *key, const void *value, unsigned int value_len);
int sx_hashfs_check_username(const char *name);

rc_ty sx_hashfs_derive_key(sx_hashfs_t *h, unsigned char *key, int len, const char *info);

/* HashFS properties */
rc_ty sx_hashfs_modhdist(sx_hashfs_t *h, const sx_nodelist_t *list);
rc_ty sx_hashfs_hdist_change_req(sx_hashfs_t *h, const sx_nodelist_t *newdist, job_t *job_id);
rc_ty sx_hashfs_hdist_change_add(sx_hashfs_t *h, const void *cfg, unsigned int cfg_len);
rc_ty sx_hashfs_hdist_change_commit(sx_hashfs_t *h);
const sx_nodelist_t *sx_hashfs_nodelist(sx_hashfs_t *h, sx_hashfs_nl_t which);
const sx_node_t *sx_hashfs_self(sx_hashfs_t *h);
rc_ty sx_hashfs_self_uuid(sx_hashfs_t *h, sx_uuid_t *uuid);
const char *sx_hashfs_self_unique(sx_hashfs_t *h);
const char *sx_hashfs_version(sx_hashfs_t *h);
const sx_uuid_t *sx_hashfs_uuid(sx_hashfs_t *h);

rc_ty sx_hashfs_create_user(sx_hashfs_t *h, const char *user, const uint8_t *uid, unsigned uid_size, const uint8_t *key, unsigned key_size, int role);
rc_ty sx_hashfs_get_uid(sx_hashfs_t *h, const char *user, int64_t *uid);
rc_ty sx_hashfs_get_uid_role(sx_hashfs_t *h, const char *user, int64_t *uid, int *role);
rc_ty sx_hashfs_get_user_by_uid(sx_hashfs_t *h, sx_uid_t uid, uint8_t *user);
rc_ty sx_hashfs_get_user_by_name(sx_hashfs_t *h, const char *name, uint8_t *user);
const char *sx_hashfs_authtoken(sx_hashfs_t *h);
char *sxi_hashfs_admintoken(sx_hashfs_t *h);
rc_ty sx_hashfs_uid_get_name(sx_hashfs_t *h, uint64_t uid, char *name, unsigned len);
rc_ty sx_hashfs_user_onoff(sx_hashfs_t *h, const char *user, int enable);

typedef int (*user_list_cb_t)(sx_uid_t user_id, const char *username, const uint8_t *user, const uint8_t *key, int is_admin, void *ctx);
rc_ty sx_hashfs_list_users(sx_hashfs_t *h, user_list_cb_t cb, void *ctx);

#define CLUSTER_USER (const uint8_t*)"\x08\xb5\x12\x4c\x44\x7f\x00\xb2\xcd\x38\x31\x3f\x44\xe3\x93\xfd\x44\x84\x47"
#define ADMIN_USER (const uint8_t*)"\xd0\x33\xe2\x2a\xe3\x48\xae\xb5\x66\x0f\xc2\x14\x0a\xec\x35\x85\x0c\x4d\xa9\x97"
rc_ty sx_hashfs_grant(sx_hashfs_t *h, uint64_t uid, const char *volume, int priv);
rc_ty sx_hashfs_revoke(sx_hashfs_t *h, uint64_t uid, const char *volume, int priv);

#define ROLE_USER 0
#define ROLE_ADMIN 1
#define ROLE_CLUSTER 2
/* Volume ops */
void sx_hashfs_volume_new_begin(sx_hashfs_t *h);
rc_ty sx_hashfs_volume_new_addmeta(sx_hashfs_t *h, const char *key, const void *value, unsigned int value_len);
rc_ty sx_hashfs_volume_new_finish(sx_hashfs_t *h, const char *volume, int64_t size, unsigned int replica, sx_uid_t owner_uid);
/* Returns (and logs reason/error):
 *  - EFAULT
 *  - EINVAL
 */
rc_ty sx_hashfs_volume_enable(sx_hashfs_t *h, const char *volume);
rc_ty sx_hashfs_volume_disable(sx_hashfs_t *h, const char *volume);
rc_ty sx_hashfs_volume_delete(sx_hashfs_t *h, const char *volume);
typedef struct _sx_hashfs_volume_t {
    int64_t id;
    int64_t size;
    unsigned int replica_count;
    char name[SXLIMIT_MAX_VOLNAME_LEN + 1];
    sx_uid_t owner;
} sx_hashfs_volume_t;
rc_ty sx_hashfs_volume_first(sx_hashfs_t *h, const sx_hashfs_volume_t **volume, int64_t uid);
rc_ty sx_hashfs_volume_next(sx_hashfs_t *h);
rc_ty sx_hashfs_volume_by_name(sx_hashfs_t *h, const char *name, const sx_hashfs_volume_t **volume);
rc_ty sx_hashfs_volume_by_id(sx_hashfs_t *h, int64_t id, const sx_hashfs_volume_t **volume);
rc_ty sx_hashfs_volumemeta_begin(sx_hashfs_t *h, const sx_hashfs_volume_t *volume);
rc_ty sx_hashfs_volumemeta_next(sx_hashfs_t *h, const char **key, const void **value, unsigned int *value_len);
rc_ty sx_hashfs_volnodes(sx_hashfs_t *h, sx_hashfs_nl_t which, const sx_hashfs_volume_t *volume, int64_t size, sx_nodelist_t **nodes, unsigned int *block_size);
int sx_hashfs_is_or_was_my_volume(sx_hashfs_t *h, const sx_hashfs_volume_t *vol);
typedef int (*acl_list_cb_t)(const char *username, int priv, void *ctx);
rc_ty sx_hashfs_list_acl(sx_hashfs_t *h, const sx_hashfs_volume_t *vol, sx_uid_t uid, int uid_priv, acl_list_cb_t cb, void *ctx);


/* File list */
typedef struct _sx_hashfs_file_t {
    int64_t file_size;
    unsigned int block_size;
    unsigned int nblocks;
    unsigned int created_at;
    char name[SXLIMIT_MAX_FILENAME_LEN+2];
    char revision[REV_LEN+1];
    /* below fields are used internally during iteration */
    char itername[SXLIMIT_MAX_FILENAME_LEN+2];
    char lastname[SXLIMIT_MAX_FILENAME_LEN+2];
} sx_hashfs_file_t;
rc_ty sx_hashfs_list_first(sx_hashfs_t *h, const sx_hashfs_volume_t *volume, const char *pattern, const sx_hashfs_file_t **file, int recurse);
rc_ty sx_hashfs_list_next(sx_hashfs_t *h);
rc_ty sx_hashfs_revision_first(sx_hashfs_t *h, const sx_hashfs_volume_t *volume, const char *name, const sx_hashfs_file_t **file);
rc_ty sx_hashfs_revision_next(sx_hashfs_t *h);

/* File get */
rc_ty sx_hashfs_getfile_begin(sx_hashfs_t *h, const char *volume, const char *filename, const char *revision, int64_t *file_size, unsigned int *block_size, unsigned int *created_at, sx_hash_t *etag);
rc_ty sx_hashfs_getfile_block(sx_hashfs_t *h, const sx_hash_t **hash, sx_nodelist_t **nodes);
void sx_hashfs_getfile_end(sx_hashfs_t *h);

rc_ty sx_hashfs_getfilemeta_begin(sx_hashfs_t *h, const char *volume, const char *filename, const char *revision, unsigned int *created_at, sx_hash_t *etag);
rc_ty sx_hashfs_getfilemeta_next(sx_hashfs_t *h, const char **key, const void **value, unsigned int *value_len);

/* Block xfer */
rc_ty sx_hashfs_block_get(sx_hashfs_t *h, unsigned int bs, const sx_hash_t *hash, const uint8_t **block);
rc_ty sx_hashfs_block_put(sx_hashfs_t *h, const uint8_t *data, unsigned int bs, unsigned int replica_count, int propagate);

/* hash batch ops for GC */
rc_ty sx_hashfs_hashop_begin(sx_hashfs_t *h, unsigned bs);
rc_ty sx_hashfs_hashop_perform(sx_hashfs_t *h, enum sxi_hashop_kind kind, const sx_hash_t *hash, const char *id);
rc_ty sx_hashfs_hashop_finish(sx_hashfs_t *h, rc_ty rc);
rc_ty sx_hashfs_gc_periodic(sx_hashfs_t *h);
rc_ty sx_hashfs_gc_run(sx_hashfs_t *h);

/* File put */

const char *sx_hashfs_geterrmsg(sx_hashfs_t *h);
rc_ty sx_hashfs_putfile_begin(sx_hashfs_t *h, sx_uid_t user_id, const char *volume, const char *file);
rc_ty sx_hashfs_putfile_extend_begin(sx_hashfs_t *h, sx_uid_t user_id, const uint8_t *user, const char *token);
rc_ty sx_hashfs_putfile_putblock(sx_hashfs_t *h, sx_hash_t *hash);
rc_ty sx_hashfs_putfile_putmeta(sx_hashfs_t *h, const char *key, void *value, unsigned int value_len);
rc_ty sx_hashfs_putfile_gettoken(sx_hashfs_t *h, const uint8_t *user, int64_t size_or_seq, const char **token, hash_presence_cb_t hdck_cb, void *hdck_cb_ctx);
rc_ty sx_hashfs_putfile_getblock(sx_hashfs_t *h);
void sx_hashfs_putfile_end(sx_hashfs_t *h);
rc_ty sx_hashfs_createfile_begin(sx_hashfs_t *h);
rc_ty sx_hashfs_createfile_commit(sx_hashfs_t *h, const char *volume, const char *name, const char *revision, int64_t size);
void sx_hashfs_createfile_end(sx_hashfs_t *h);

rc_ty sx_hashfs_make_token(sx_hashfs_t *h, const uint8_t *user, const char *rndhex, unsigned int replica, int64_t expires_at, const char **token);
rc_ty sx_hashfs_token_get(sx_hashfs_t *h, const uint8_t *user, const char *token, unsigned int *replica_count, int64_t *expires_at);
rc_ty sx_hashfs_putfile_commitjob(sx_hashfs_t *h, const uint8_t *user, sx_uid_t user_id, const char *token, job_t *job_id);

typedef struct _sx_hashfs_missing_t {
    int64_t volume_id;
    int64_t file_size;
    int64_t tmpfile_id;
    int64_t expires_at;
    const sx_nodelist_t *allnodes; /* The ordered list of nodes to which the nidx's refer to */
    sx_hash_t *all_blocks; /* All unsorted blocks - nblocks items */
    unsigned int *uniq_ids; /* Unique block index (from all_blocks) - nuniq items */
    unsigned int *nidxs; /* Unique block node index (parallel to all_blocks) - nblocks * replica_count items */
    uint8_t *avlblty; /* Block availablity (0 = unavail, !0 = avail) flag index (parallel to all_blocks) - nblocks * replica_count items */
    unsigned int nall; /* Number of blocks */
    unsigned int nuniq; /* Number of unique blocks */
    unsigned int block_size; /* Block size */
    unsigned int replica_count; /* Replica count */
    unsigned int current_replica; /* Replica being presence checked */
    char name[SXLIMIT_MAX_FILENAME_LEN+1]; /* File name */
    char revision[128]; /* File revision */
    int somestatechanged;
} sx_hashfs_missing_t;
rc_ty sx_hashfs_tmp_getmeta(sx_hashfs_t *h, const char *name, int64_t tmpfile_id, sxc_meta_t *metadata);
rc_ty sx_hashfs_tmp_getmissing(sx_hashfs_t *h, int64_t tmpfile_id, sx_hashfs_missing_t **missing, int commit);
rc_ty sx_hashfs_tmp_tofile(sx_hashfs_t *h, const sx_hashfs_missing_t *missing);

/* File delete */
rc_ty sx_hashfs_file_delete(sx_hashfs_t *h, const sx_hashfs_volume_t *volume, const char *file, const char *revision);

/* Users */
typedef enum {
  PRIV_NONE = 0,
  PRIV_READ = 1,
  PRIV_WRITE = 2,
  PRIV_OWNER = 4,
  PRIV_ADMIN = 8,
  PRIV_CLUSTER = 16} sx_priv_t;
rc_ty sx_hashfs_get_user_info(sx_hashfs_t *h, const uint8_t *user, sx_uid_t *uid, uint8_t *key, sx_priv_t *basepriv);
rc_ty sx_hashfs_get_access(sx_hashfs_t *h, sx_uid_t uid, const char *volume, sx_priv_t *access);


/* Jobs */
rc_ty sx_hashfs_job_result(sx_hashfs_t *h, job_t job, sx_uid_t uid, job_status_t *status, const char **message);
rc_ty sx_hashfs_job_new(sx_hashfs_t *h, sx_uid_t user_id, job_t *job_id, jobtype_t type, unsigned int timeout_secs, const char *lock, const void *data, unsigned int datalen, const sx_nodelist_t *targets);
rc_ty sx_hashfs_job_new_notrigger(sx_hashfs_t *h, sx_uid_t user_id, job_t *job_id, jobtype_t type, unsigned int timeout_secs, const char *lock, const void *data, unsigned int datalen, const sx_nodelist_t *targets);
void sx_hashfs_job_trigger(sx_hashfs_t *h);
rc_ty sx_hashfs_countjobs(sx_hashfs_t *h, sx_uid_t user_id);

/* Xfers */
rc_ty sx_hashfs_xfer_tonodes(sx_hashfs_t *h, sx_hash_t *block, unsigned int size, const sx_nodelist_t *targets);
void sx_hashfs_xfer_trigger(sx_hashfs_t *h);

void sx_hashfs_gc_trigger(sx_hashfs_t *h);

#endif
