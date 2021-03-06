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

#ifndef JOB_COMMON_H
#define JOB_COMMON_H

#include <yajl/yajl_parse.h>
#include "blob.h"
#include "../../libsx/src/sxproto.h"

typedef int64_t job_t;

#define JOB_FAILURE (-1LL)
#define JOB_FAIL_REASON_SIZE 512

typedef enum _job_status_t {
    JOB_ERROR = -1,
    JOB_OK = 0,
    JOB_PENDING = 1
} job_status_t;

typedef enum _jobtype_t {
    JOBTYPE_CREATE_VOLUME = 0,
    JOBTYPE_CREATE_USER,
    JOBTYPE_VOLUME_ACL,
    JOBTYPE_FLUSH_FILE,
    JOBTYPE_DELETE_FILE,
    JOBTYPE_DISTRIBUTION
} jobtype_t;

typedef enum {
    JOBPHASE_REQUEST,
    JOBPHASE_COMMIT,
    JOBPHASE_ABORT,
    JOBPHASE_UNDO
} jobphase_t;

struct _sx_hashfs_t; /* fwd */
typedef struct {
    const yajl_callbacks *parser;
    int job_type;
    int (*parse_complete)(void *ctx);
    const char* (*get_lock)(sx_blob_t *blob);
    int (*to_blob)(sxc_client_t *sx, void *ctx, sx_blob_t *blob);
    rc_ty (*execute_blob)(struct _sx_hashfs_t *hashfs, sx_blob_t *blob, jobphase_t phase);
    sxi_query_t* (*proto_from_blob)(sxc_client_t *sx, sx_blob_t *blob, jobphase_t phase);
    int (*nodes)(sxc_client_t *sx, sx_blob_t *blob, sx_nodelist_t **nodes);
} job_2pc_t;

extern const job_2pc_t acl_spec;

void job_2pc_handle_request(sxc_client_t *sx, const job_2pc_t *spec, void *yctx);
#endif
