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

#include "default.h"

/* temporary work-around for OS X: to be investigated.
 * 2 issues: BIND_8_COMPAT required for nameser_compat.h
 * and sth from default.h messing with the endian stuff
 */
#if __APPLE__ 
# define BIND_8_COMPAT
# ifdef WORDS_BIGENDIAN
#  undef LITTLE_ENDIAN
#  define BIG_ENDIAN 1
#  define BYTE_ORDER BIG_ENDIAN
# else
#  undef BIG_ENDIAN
#  define LITTLE_ENDIAN 1
#  define BYTE_ORDER LITTLE_ENDIAN
# endif
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <openssl/rand.h>

#include "../libsx/src/sxproto.h"
#include "../libsx/src/misc.h"
#include "../libsx/src/curlevents.h"
#include "hashfs.h"
#include "hdist.h"
#include "job_common.h"
#include "log.h"
#include "jobmgr.h"
#include "blob.h"
#include "nodes.h"
#include "version.h"

typedef enum _act_result_t {
    ACT_RESULT_UNSET = 0,
    ACT_RESULT_OK = 1,
    ACT_RESULT_TEMPFAIL = -1,
    ACT_RESULT_PERMFAIL = -2
} act_result_t;

typedef struct _job_data_t {
    void *ptr;
    unsigned int len;
} job_data_t;

typedef act_result_t (*job_action_t)(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *node, int *succeeded, int *fail_code, char *fail_msg);

#define action_set_fail(retcode, failcode, failmsg)	    \
    do {						    \
	ret = (retcode);				    \
	*fail_code = (failcode);			    \
	strncpy(fail_msg, (failmsg), JOB_FAIL_REASON_SIZE); \
	fail_msg[JOB_FAIL_REASON_SIZE - 1] = '\0';	    \
        DEBUG("fail set to: %s\n", fail_msg); \
    } while(0)

#define action_error(retcode, failcode, failmsg)	    \
    do {						    \
	action_set_fail((retcode), (failcode), (failmsg));  \
	goto action_failed;				    \
    } while(0)

#define DEBUGHASH(MSG, X) do {				\
    char _debughash[sizeof(sx_hash_t)*2+1];		\
    if (UNLIKELY(sxi_log_is_debug(&logger))) {          \
        bin2hex((X)->b, sizeof(*X), _debughash, sizeof(_debughash));	\
        DEBUG("%s: #%s#", MSG, _debughash); \
    }\
    } while(0)
static act_result_t http2actres(int code) {
    int ch = code / 100;
    if (code < 0)
        return ACT_RESULT_PERMFAIL;
    if(ch == 2)
	return ACT_RESULT_OK;
    if(ch == 4)
	return ACT_RESULT_PERMFAIL;
    if(code == 503 || ch != 5)
	return ACT_RESULT_TEMPFAIL;
    return ACT_RESULT_PERMFAIL;
}

static act_result_t rc2actres(rc_ty rc) {
    return http2actres(rc2http(rc));
}

typedef struct {
	curlev_context_t *cbdata;
	int query_sent;
} query_list_t;

static void query_list_free(query_list_t *qrylist, unsigned nnodes)
{
    unsigned i;
    if (!qrylist)
        return;
    for (i=0;i<nnodes;i++) {
        sxi_cbdata_unref(&qrylist[i].cbdata);
    }

    free(qrylist);
}

static act_result_t createuser_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    sx_blob_t *b;
    const void *auth;
    unsigned auth_len;
    unsigned role;
    const char *name;
    unsigned nnode, nnodes;
    act_result_t ret = ACT_RESULT_PERMFAIL;
    sxi_query_t *proto = NULL;
    query_list_t *qrylist = NULL;
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);

    if (!job_data) {
	NULLARG();
	action_set_fail(ACT_RESULT_PERMFAIL, 500, "Null job");
	return ret;
    }
    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if (!b) {
	OOM();
	action_set_fail(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
	return ret;
    }
    if (sx_blob_get_string(b, &name) ||
	sx_blob_get_blob(b, &auth, &auth_len) ||
	sx_blob_get_int32(b, &role)) {
	sx_blob_free(b);
	/* why? OOM on get_string should be TEMPFAIL */
	action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
	return ret;
    }
    INFO("Create user %s, auth_len: %d", name, auth_len);
    nnodes = sx_nodelist_count(nodes);
    qrylist = wrap_calloc(nnodes, sizeof(*qrylist));
    if(!qrylist) {
	OOM();
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform operation");
    }
    for(nnode = 0; nnode<nnodes; nnode++) {
	const sx_node_t *me = sx_hashfs_self(hashfs);
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);
	if (!sx_node_cmp(me, node)) {
	    rc_ty rc;
	    /* FIXME: there is code duplication between here and
	     * has_priv(CLUSTER) in fcgi-actions-* */
	    rc = sx_hashfs_create_user(hashfs, name, NULL, 0, auth, auth_len, role);
	    if (rc == EEXIST) {
		WARN("user already exists '%s'", name);
		action_error(ACT_RESULT_PERMFAIL, 409, "User already exists");
	    }
	    if (rc != OK) {
		action_error(rc2actres(rc), rc2http(rc), rc2str(rc));
	    }
	    succeeded[nnode] = 1;
	} else {
	    if(!proto) {
		proto = sxi_useradd_proto(sx_hashfs_client(hashfs), name, auth, (role == ROLE_ADMIN));
		if(!proto) {
		    OOM();
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform operation");
		}
	    }
	    INFO("req %.*s", proto->content_len, (char *)proto->content);
            qrylist[nnode].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
	    if (sxi_cluster_query_ev(qrylist[nnode].cbdata, clust, sx_node_internal_addr(node), proto->verb, proto->path, proto->content, proto->content_len, NULL, NULL)) {
		WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx_hashfs_client(hashfs)));
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }
	    qrylist[nnode].query_sent = 1;
	}
    }
    ret = ACT_RESULT_OK;
action_failed:
    if (proto) {
	for(nnode=0; nnode<nnodes; nnode++) {
	    int rc = 0;
	    if(!qrylist[nnode].query_sent)
		continue;
	    INFO("Polling");
            rc = sxi_cbdata_wait(qrylist[nnode].cbdata, sxi_conns_get_curlev(clust), NULL);
	    INFO("Polling done");
	    if(rc == -1) {
		CRIT("Failed to wait for query");
		ret = ACT_RESULT_PERMFAIL;
		/* FIXME should abort here */
		continue;
	    }
            rc = sxi_cbdata_result(qrylist[nnode].cbdata, NULL);
	    if(sxi_cbdata_result_fail(qrylist[nnode].cbdata) ||
               rc / 100 == 5) {
		WARN("Query failed with %d", rc);
		if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
		    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxc_geterrmsg(sx_hashfs_client(hashfs)));
	    } else if(rc == 200)
		succeeded[nnode] = 1;
	    else
		ret = ACT_RESULT_PERMFAIL; /* Raise OK and TEMP to PERMFAIL */
            sxi_cbdata_unref(&qrylist[nnode].cbdata);
	}
	sxi_query_free(proto);
    }
    query_list_free(qrylist, nnodes);
    sx_blob_free(b);
    INFO("createuser_request returning: %d", ret);
    return ret;
}

static act_result_t createuser_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    unsigned nnode, s, ret = ACT_RESULT_OK;
    unsigned nnodes = sx_nodelist_count(nodes);
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    query_list_t *qrylist = NULL;
    sx_blob_t *b;
    const char *username;
    char *query = NULL;

    INFO("createuser_commit");
    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
	WARN("Cannot allocate blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_string(b, &username)) {
	WARN("Cannot get volume data from blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    for (nnode=0;nnode<nnodes;nnode++) {
	const sx_node_t *me = sx_hashfs_self(hashfs);
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);
	if (!sx_node_cmp(me, node)) {
	    if ((s = sx_hashfs_user_onoff(hashfs, username, 1))) {
		WARN("Failed to enable user '%s' for job %lld", username, (long long)job_id);
		action_error(ACT_RESULT_PERMFAIL, rc2http(s), "Failed to enable user");
	    }
	    succeeded[nnode] = 1;
	} else {
	    if(!query) {
		char *path = sxi_urlencode(sx, username, 0);
		if(!path) {
		    WARN("Cannot encode path");
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}
		unsigned n = 1024;/* TODO: calc */
		query = wrap_malloc(n);
		if(!query) {
		    free(path);
		    WARN("Cannot allocate query");
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}
		snprintf(query, n, ".users/%s?o=enable", path);
		free(path);

		qrylist = wrap_calloc(nnodes, sizeof(*qrylist));
		if(!qrylist) {
		    WARN("Cannot allocate result space");
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}
	    }

            qrylist[nnode].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
	    if(sxi_cluster_query_ev(qrylist[nnode].cbdata, clust, sx_node_internal_addr(node), REQ_PUT, query, NULL, 0, NULL, NULL)) {
		WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx));
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }
	    qrylist[nnode].query_sent = 1;
	}
    }
 action_failed:
    sx_blob_free(b);
    if(query) {
	for(nnode=0; nnode<nnodes; nnode++) {
	    int rc = 0;
	    if(!qrylist[nnode].query_sent)
		continue;
            rc = sxi_cbdata_wait(qrylist[nnode].cbdata, sxi_conns_get_curlev(clust), NULL);
	    if(rc == -1) {
		CRIT("Failed to wait for query");
		action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
		/* FIXME should abort here */
		continue;
	    }
            rc = sxi_cbdata_result(qrylist[nnode].cbdata, NULL);
	    if(sxi_cbdata_result_fail(qrylist[nnode].cbdata)) {
		WARN("Query failed with %d", rc);
		if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
		    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxc_geterrmsg(sx));
	    } else if(rc == 200) {
		succeeded[nnode] = 1;
	    } else {
		act_result_t newret = http2actres(rc);
		if(newret < ret) /* Severity shall only be raised */
		    action_set_fail(newret, rc, sxc_geterrmsg(sx));
	    }
            sxi_cbdata_unref(&qrylist[nnode].cbdata);
	}
        query_list_free(qrylist, nnodes);
	free(query);
    }
    return ret;
}

static act_result_t createuser_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    INFO("createuser_abort");
    return ACT_RESULT_PERMFAIL;
}
static act_result_t createuser_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg){
    INFO("createuser_undo");
    return ACT_RESULT_PERMFAIL;
}

static act_result_t createvol_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    const char *volname, *owner;
    int64_t volsize, owner_uid;
    unsigned int nnode, nnodes;
    int i, replica, nmeta;
    sx_blob_t *b = NULL;
    act_result_t ret = ACT_RESULT_OK;
    sxi_query_t *proto = NULL;
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    sxc_meta_t *vmeta = NULL;
    query_list_t *qrylist = NULL;
    rc_ty s;

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
	WARN("Cannot allocate blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_string(b, &volname) ||
       sx_blob_get_string(b, &owner) ||
       sx_blob_get_int64(b, &volsize) ||
       sx_blob_get_int32(b, &replica) ||
       sx_blob_get_int32(b, &nmeta)) {
	WARN("Cannot get volume data from blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    if((s = sx_hashfs_get_uid(hashfs, owner, &owner_uid))) {
	WARN("Cannot find owner '%s' for job %lld", owner, (long long)job_id);
	action_error(ACT_RESULT_PERMFAIL, rc2http(s), "Invalid user");
    }

    sx_blob_savepos(b);

    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++) {
	const sx_node_t *me = sx_hashfs_self(hashfs);
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);

	INFO("Making volume %s - owner: %s, size: %lld, replica: %d, meta: %d on %s", volname, owner, (long long)volsize, replica, nmeta, sx_node_uuid_str(node));

	if(!sx_node_cmp(me, node)) {
	    sx_hashfs_volume_new_begin(hashfs);

	    if(nmeta) {
		sx_blob_loadpos(b);
		for(i=0; i<nmeta; i++) {
		    const char *mkey;
		    const void *mval;
		    unsigned int mval_len;
		    if(sx_blob_get_string(b, &mkey) ||
		       sx_blob_get_blob(b, &mval, &mval_len)) {
			WARN("Cannot get volume metadata from blob for job %lld", (long long)job_id);
			action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
		    }
		    if((s = sx_hashfs_volume_new_addmeta(hashfs, mkey, mval, mval_len))) {
			WARN("Cannot add meta data to volume for job %lld", (long long)job_id);
			action_error(ACT_RESULT_PERMFAIL, rc2http(s), "Invalid volume metadata");
		    }
		}
	    }

	    s = sx_hashfs_volume_new_finish(hashfs, volname, volsize, replica, owner_uid);
	    if(s != OK) {
                const char *msg = s == EINVAL ? msg_get_reason() : rc2str(s);
		action_error(rc2actres(s), rc2http(s), msg);
            }
	    succeeded[nnode] = 1;
	} else {
	    if(!proto) {
		if(nmeta) {
		    sx_blob_loadpos(b);
		    if(!(vmeta = sxc_meta_new(sx))) {
			WARN("Cannot build a list of volume metadata for job %lld", (long long)job_id);
			action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		    }

		    for(i=0; i<nmeta; i++) {
			const char *mkey;
			const void *mval;
			unsigned int mval_len;
			if(sx_blob_get_string(b, &mkey) ||
			   sx_blob_get_blob(b, &mval, &mval_len)) {
			    WARN("Cannot get volume metadata from blob for job %lld", (long long)job_id);
			    action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
			}
			if(sxc_meta_setval(vmeta, mkey, mval, mval_len)) {
			    WARN("Cannot build a list of volume metadata for job %lld", (long long)job_id);
			    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
			}
		    }
		}

		proto = sxi_volumeadd_proto(sx, volname, owner, volsize, replica, vmeta);
		if(!proto) {
		    WARN("Cannot allocate proto for job %lld", (long long)job_id);
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}

		qrylist = wrap_calloc(nnodes, sizeof(*qrylist));
		if(!qrylist) {
		    WARN("Cannot allocate result space");
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}
	    }

            qrylist[nnode].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
	    if(sxi_cluster_query_ev(qrylist[nnode].cbdata, clust, sx_node_internal_addr(node), proto->verb, proto->path, proto->content, proto->content_len, NULL, NULL)) {
		WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx));
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }
	    qrylist[nnode].query_sent = 1;
	}
    }

 action_failed:
    sx_blob_free(b);
    if(proto) {
	for(nnode=0; nnode<nnodes; nnode++) {
	    int rc = 0;
	    if(!qrylist[nnode].query_sent)
		continue;
            rc = sxi_cbdata_wait(qrylist[nnode].cbdata, sxi_conns_get_curlev(clust), NULL);
	    if(rc == -1) {
		CRIT("Failed to wait for query");
		action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
		/* FIXME should abort here */
		continue;
	    }
            rc = sxi_cbdata_result(qrylist[nnode].cbdata, NULL);
	    if(sxi_cbdata_result_fail(qrylist[nnode].cbdata)) {
		WARN("Query failed with %d", rc);
		if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
		    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxc_geterrmsg(sx));
	    } else if(rc == 200) {
		succeeded[nnode] = 1;
	    } else {
		act_result_t newret = http2actres(rc);
		if(newret < ret) /* Severity shall only be raised */
		    action_set_fail(newret, rc, sxc_geterrmsg(sx));
	    }
            sxi_cbdata_unref(&qrylist[nnode].cbdata);
	}
	sxc_meta_free(vmeta);
        query_list_free(qrylist, nnodes);
	sxi_query_free(proto);
    }
    return ret;
}

static act_result_t createvol_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    unsigned int nnode, nnodes;
    const char *volname;
    act_result_t ret = ACT_RESULT_OK;
    sx_blob_t *b = NULL;
    char *query = NULL;
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    query_list_t *qrylist = NULL;
    rc_ty s;

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
	WARN("Cannot allocate blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_string(b, &volname)) {
	WARN("Cannot get volume data from blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++) {
	const sx_node_t *me = sx_hashfs_self(hashfs);
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);

	INFO("Enabling volume %s on %s", volname, sx_node_uuid_str(node));

	if(!sx_node_cmp(me, node)) {
	    if((s = sx_hashfs_volume_enable(hashfs, volname))) {
		WARN("Failed to enable volume '%s' for job %lld", volname, (long long)job_id);
		action_error(ACT_RESULT_PERMFAIL, rc2http(s), "Failed to enable volume");
	    }
	    succeeded[nnode] = 1;
	} else {
	    if(!query) {
		char *path = sxi_urlencode(sx, volname, 0);
		if(!path) {
		    WARN("Cannot encode path");
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}
		query = wrap_malloc(strlen(path) + sizeof("?o=enable"));
		if(!query) {
		    free(path);
		    WARN("Cannot allocate query");
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}
		sprintf(query, "%s?o=enable", path);/* FIXME: unsafe */
		free(path);

		qrylist = wrap_calloc(nnodes, sizeof(*qrylist));
		if(!qrylist) {
		    WARN("Cannot allocate result space");
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}
	    }

            qrylist[nnode].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
	    if(sxi_cluster_query_ev(qrylist[nnode].cbdata, clust, sx_node_internal_addr(node), REQ_PUT, query, NULL, 0, NULL, NULL)) {
		WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx));
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }
	    qrylist[nnode].query_sent = 1;
	}
    }

 action_failed:
    sx_blob_free(b);
    if(query) {
	for(nnode=0; nnode<nnodes; nnode++) {
	    int rc = 0;
	    if(!qrylist[nnode].query_sent)
		continue;
            rc = sxi_cbdata_wait(qrylist[nnode].cbdata, sxi_conns_get_curlev(clust), NULL);
	    if(rc == -1) {
		CRIT("Failed to wait for query");
		action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
		/* FIXME should abort here */
		continue;
	    }
            rc = sxi_cbdata_result(qrylist[nnode].cbdata, NULL);
	    if(sxi_cbdata_result_fail(qrylist[nnode].cbdata)) {
		WARN("Query failed with %d", rc);
		if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
		    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxc_geterrmsg(sx));
	    } else if(rc == 200) {
		succeeded[nnode] = 1;
	    } else {
		act_result_t newret = http2actres(rc);
		if(newret < ret) /* Severity shall only be raised */
		    action_set_fail(newret, rc, sxc_geterrmsg(sx));
	    }
            sxi_cbdata_unref(&qrylist[nnode].cbdata);
	}
        query_list_free(qrylist, nnodes);
	free(query);
    }
    return ret;
}

static act_result_t createvol_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    unsigned int nnode, nnodes;
    const char *volname;
    act_result_t ret = ACT_RESULT_OK;
    sx_blob_t *b = NULL;
    char *query = NULL;
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    query_list_t *qrylist = NULL;
    rc_ty s;

    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
	WARN("Cannot allocate blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_string(b, &volname)) {
	WARN("Cannot get volume data from blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++) {
	const sx_node_t *me = sx_hashfs_self(hashfs);
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);

	INFO("Deleting volume %s on %s", volname, sx_node_uuid_str(node));

	if(!sx_node_cmp(me, node)) {
	    if((s = sx_hashfs_volume_delete(hashfs, volname))) {
		WARN("Failed to delete volume '%s' for job %lld", volname, (long long)job_id);
		action_error(ACT_RESULT_PERMFAIL, rc2http(s), "Failed to enable volume");
	    }
	    succeeded[nnode] = 1;
	} else {
	    if(!query) {
		query = sxi_urlencode(sx, volname, 0);
		if(!query) {
		    WARN("Cannot encode path");
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}

		qrylist = wrap_calloc(nnodes, sizeof(*qrylist));
		if(!qrylist) {
		    WARN("Cannot allocate result space");
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		}
	    }

            qrylist[nnode].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
	    if(sxi_cluster_query_ev(qrylist[nnode].cbdata, clust, sx_node_internal_addr(node), REQ_DELETE, query, NULL, 0, NULL, NULL)) {
		WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx));
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }
	    qrylist[nnode].query_sent = 1;
	}
    }

 action_failed:
    sx_blob_free(b);
    if(query) {
	for(nnode=0; nnode<nnodes; nnode++) {
	    int rc = 0;
	    if(!qrylist[nnode].query_sent)
		continue;
            rc = sxi_cbdata_wait(qrylist[nnode].cbdata, sxi_conns_get_curlev(clust), NULL);
	    if(rc == -1) {
		CRIT("Failed to wait for query");
		action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
		/* FIXME should abort here */
		continue;
	    }
            rc = sxi_cbdata_result(qrylist[nnode].cbdata, NULL);
	    if(sxi_cbdata_result_fail(qrylist[nnode].cbdata)) {
		WARN("Query failed with %d", rc);
		if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
		    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxc_geterrmsg(sx));
	    } else if (rc == 200) {
		succeeded[nnode] = 1;
	    } else {
		act_result_t newret = http2actres(rc);
		if(newret < ret) /* Severity shall only be raised */
		    action_set_fail(newret, rc, sxc_geterrmsg(sx));
	    }
            sxi_cbdata_unref(&qrylist[nnode].cbdata);
	}
        query_list_free(qrylist, nnodes);
	free(query);
    }
    return ret;
}

static act_result_t createvol_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    unsigned int nnode, nnodes;
    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++)
	succeeded[nnode] = 0;
    return ACT_RESULT_PERMFAIL;
}

static act_result_t job_twophase_execute(const job_2pc_t *spec, jobphase_t phase, sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    act_result_t ret = ACT_RESULT_OK;
    query_list_t *qrylist = NULL;
    unsigned int nnode, nnodes;
    sxi_query_t *proto = NULL;
    rc_ty rc;

    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    sx_blob_t *b = sx_blob_from_data(job_data->ptr, job_data->len);
    if (!b) {
        WARN("Cannot allocate blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }
    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++) {
	const sx_node_t *me = sx_hashfs_self(hashfs);
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);
        sx_blob_reset(b);

	if(!sx_node_cmp(me, node)) {
            /* execute locally */
            rc = spec->execute_blob(hashfs, b, phase);
            if (rc != OK) {
                const char *msg = rc == EINVAL ? msg_get_reason() : rc2str(rc);
                action_error(rc2actres(rc), rc2http(rc), msg);
            }
	    succeeded[nnode] = 1;
        } else {
            /* execute remotely */
            if (!proto) {
                proto = spec->proto_from_blob(sx_hashfs_client(hashfs), b, phase);
                if (!proto) {
                    WARN("Cannot allocate proto for job %lld", (long long)job_id);
                    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
                }
                qrylist = wrap_calloc(nnodes, sizeof(*qrylist));
                if(!qrylist) {
                    WARN("Cannot allocate result space");
                    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
                }
            }
            qrylist[nnode].cbdata = sxi_cbdata_create_generic(clust, NULL, NULL);
	    if(sxi_cluster_query_ev(qrylist[nnode].cbdata, clust, sx_node_internal_addr(node), proto->verb, proto->path, proto->content, proto->content_len, NULL, NULL)) {
		WARN("Failed to query node %s: %s", sx_node_uuid_str(node), sxc_geterrmsg(sx_hashfs_client(hashfs)));
		action_error(ACT_RESULT_TEMPFAIL, 503, "Failed to setup cluster communication");
	    }
	    qrylist[nnode].query_sent = 1;
        }
    }

 action_failed: /* or succeeded */
    sx_blob_free(b);
    if(proto) {
	for(nnode=0; nnode<nnodes; nnode++) {
	    int rc = 0;
	    if(!qrylist[nnode].query_sent)
		continue;
            rc = sxi_cbdata_wait(qrylist[nnode].cbdata, sxi_conns_get_curlev(clust), NULL);
	    if(rc == -1) {
		CRIT("Failed to wait for query");
		action_set_fail(ACT_RESULT_PERMFAIL, 500, "Internal error in cluster communication");
		/* FIXME should abort here */
		continue;
	    }
            rc = sxi_cbdata_result(qrylist[nnode].cbdata, NULL);
	    if(sxi_cbdata_result_fail(qrylist[nnode].cbdata)) {
		WARN("Query failed with %d", rc);
		if(ret > ACT_RESULT_TEMPFAIL) /* Only raise OK to TEMP */
		    action_set_fail(ACT_RESULT_TEMPFAIL, 503, sxc_geterrmsg(sx_hashfs_client(hashfs)));
	    } else if(rc == 200) {
		succeeded[nnode] = 1;
	    } else {
		act_result_t newret = http2actres(rc);
		if(newret < ret) /* Severity shall only be raised */
		    action_set_fail(newret, rc, sxc_geterrmsg(sx_hashfs_client(hashfs)));
	    }
            sxi_cbdata_unref(&qrylist[nnode].cbdata);
	}
        query_list_free(qrylist, nnodes);
	sxi_query_free(proto);
    }
    return ret;
}

static act_result_t acl_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
   return job_twophase_execute(&acl_spec, JOBPHASE_REQUEST, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg);
}

static act_result_t acl_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
   return job_twophase_execute(&acl_spec, JOBPHASE_COMMIT, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg);
}

static act_result_t acl_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
   return job_twophase_execute(&acl_spec, JOBPHASE_ABORT, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg);
}

static act_result_t acl_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
   return job_twophase_execute(&acl_spec, JOBPHASE_UNDO, hashfs, job_id, job_data, nodes, succeeded, fail_code, fail_msg);
}

static int req_append(char **req, unsigned int *req_len, const char *append_me) {
    unsigned int current_len, append_len;

    if(!*req_len) {
	*req = NULL;
	current_len = 0;
    } else
	current_len = strlen(*req);
    append_len = strlen(append_me) + 1;
    if(current_len + append_len > *req_len) {
	*req_len += MAX(1024, append_len);
	*req = wrap_realloc_or_free(*req, *req_len);
    }
    if(!*req) {
        WARN("Failed to append string to request");
        return 1;
    }

    memcpy(*req + current_len, append_me, append_len);
    return 0;
}

static act_result_t fileflush_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    unsigned int i, j, worstcase_rpl;
    act_result_t ret = ACT_RESULT_OK;
    sx_hashfs_missing_t *mis = NULL;
    sxi_hostlist_t hlist;
    int64_t tmpfile_id;
    int qret;
    rc_ty s;

    if(job_data->len != sizeof(tmpfile_id)) {
	CRIT("Bad job data");
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal job data error");
    }

    memcpy(&tmpfile_id, job_data->ptr, sizeof(tmpfile_id));
    DEBUG("fileflush_request for file %lld", (long long)tmpfile_id);
    s = sx_hashfs_tmp_getmissing(hashfs, tmpfile_id, &mis, 0);

    if(s == EFAULT || s == EINVAL) {
	CRIT("Error getting missing blocks: %s", msg_get_reason());
	action_error(ACT_RESULT_PERMFAIL, 500, msg_get_reason());
    }
    if(s == ENOENT) {
	WARN("Token %lld could not be found", (long long)tmpfile_id);
	action_error(ACT_RESULT_PERMFAIL, 500, msg_get_reason());
    }
    if(s == EAGAIN)
	action_error(ACT_RESULT_TEMPFAIL, 500, "Job data temporary unavailable");

    if(s != OK)
	action_error(rc2actres(s), rc2http(s), "Failed to check missing blocks");

    worstcase_rpl = mis->replica_count;

    /* Loop through all blocks to check availability */
    for(i=0; i<mis->nuniq; i++) {
	unsigned int ndone = 0, ndone_or_pending = 0, pushingidx = 0, blockno = mis->uniq_ids[i];

	/* For DEBUG()ging purposes */
	char blockname[HASH_TEXT_LEN + 1];
	bin2hex(&mis->all_blocks[blockno], sizeof(mis->all_blocks[0]), blockname, sizeof(blockname));

	/* Compute the current replica level for this block */
	for(j=0; j<mis->replica_count; j++) {
	    uint8_t avlbl = mis->avlblty[blockno * mis->replica_count + j];
	    if(avlbl == 1) {
		ndone++;
		ndone_or_pending++;
		pushingidx = mis->nidxs[blockno * mis->replica_count + j];
		DEBUG("Block %s is available on set %u (node %u)", blockname, j, mis->nidxs[blockno * mis->replica_count + j]);
	    } else if(avlbl) {
		ndone_or_pending++;
		DEBUG("Block %s pending upload on set %u (node %u)", blockname, j, mis->nidxs[blockno * mis->replica_count + j]);
	    } else {
		DEBUG("Block %s is NOT available on set %u (node %u)", blockname, j, mis->nidxs[blockno * mis->replica_count + j]);
	    }
	}

	DEBUG("Block %s has got %u replicas (%u including pending xfers) out of %u", blockname, ndone, ndone_or_pending, mis->replica_count);

	/* Update the worst case replica */
	if(ndone < worstcase_rpl)
	    worstcase_rpl = ndone;

	/* If the replica is already satisfied, then there is nothing to do for this block */
	if(ndone_or_pending == mis->replica_count)
	    continue;

	/* No node has got this block: job failed */
	if(!ndone) {
	    char missing_block[HASH_TEXT_LEN + 1];
	    bin2hex(&mis->all_blocks[blockno], sizeof(mis->all_blocks[0]), missing_block, sizeof(missing_block));
	    WARN("Early flush on job %lld: hash %s could not be located ", (long long)tmpfile_id, missing_block);
	    action_error(ACT_RESULT_PERMFAIL, 400, "Some block is missing");
	}

	/* We land here IF at least one node has got the block AND at least one node doesn't have the block */
	/* NOTE:
	 * If the pushing node is the local node then a transfer request is added to the local block queue
	 * If the pushing node is not the local node, then we submit the request via HTTP
	 * This unfortunately makes the following code a little bit more convoluted than it could be */

	/* Variables used for both remote and local mode */
	const sx_node_t *pusher = sx_nodelist_get(mis->allnodes, pushingidx);
	int remote = (sx_node_cmp(pusher, sx_hashfs_self(hashfs)) != 0);
	unsigned int current_hash_idx;

	/* Variables used in remote mode only */
	unsigned int req_len = 0;
	char *req = NULL;

	if(remote) {
	    /* query format: { "hash1":["target_node_id1","target_node_id2"],"hash2":["target_node_id3","target_node_id4"] } */
	    if(req_append(&req, &req_len, "{"))
		action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory to dispatch block transfer request");
	}

	DEBUG("Selected pusher is %s node %u (%s)", remote ? "remote" : "local", pushingidx, sx_node_internal_addr(pusher));

	/* Look ahead a little (not too much to avoid congesting the pusher) and collect all blocks
	 * that are available on the selected pusher and unavailable on some other replica nodes */
	for(j=0, current_hash_idx = i; j < DOWNLOAD_MAX_BLOCKS && current_hash_idx < mis->nuniq; current_hash_idx++) {
	    unsigned int current_replica, have_pusher = 0, have_junkies = 0, current_blockno = mis->uniq_ids[current_hash_idx];

	    bin2hex(&mis->all_blocks[current_blockno], sizeof(mis->all_blocks[0]), blockname, sizeof(blockname));
	    DEBUG("Considering block %s for pusher %u...", blockname, pushingidx);

	    /* Scan the replica set of the current block... */
	    for(current_replica = 0; current_replica < mis->replica_count; current_replica++) {
		/* ...checking for some node in need of this block...  */
		if(!mis->avlblty[current_blockno * mis->replica_count + current_replica]) {
		    DEBUG("Followup block %s is NOT available on set %u (node %u)", blockname, current_replica, mis->nidxs[current_blockno * mis->replica_count + current_replica]);
		    have_junkies = 1;
		    continue;
		} else if(mis->avlblty[current_blockno * mis->replica_count + current_replica] == 2)
		    DEBUG("Followup block %s is pending upload on set %u (node %u)", blockname, current_replica, mis->nidxs[current_blockno * mis->replica_count + current_replica]);
		else
		    DEBUG("Followup block %s is available on set %u (node %u)", blockname, current_replica, mis->nidxs[current_blockno * mis->replica_count + current_replica]);

		/* ...and checking if the selected pusher is in possession of the block */
		if(mis->avlblty[current_blockno * mis->replica_count + current_replica] == 1 &&
		   mis->nidxs[current_blockno * mis->replica_count + current_replica] == pushingidx)
		    have_pusher = 1;
	    }

	    if(have_junkies && have_pusher)
		DEBUG("Followup block %s needs to be replicated and CAN be replicated by %s pusher %u", blockname, remote ? "remote" : "local", pushingidx);
	    else if(have_junkies)
		DEBUG("Followup block %s needs to be replicated but CANNOT be replicated by %s pusher %u", blockname, remote ? "remote" : "local", pushingidx);
	    else
		DEBUG("Followup block %s needs NOT to be replicated", blockname);

	    /* If we don't have both, then move on to the next block */
	    if(!have_pusher || !have_junkies)
		continue;

	    j++; /* This acts a look-ahead limiter */

	    sx_hash_t *current_hash = &mis->all_blocks[current_blockno];
            DEBUGHASH("asking hash to be pushed", current_hash);
	    sx_nodelist_t *xfertargets = NULL; /* used in local mode only */

	    if(remote) {
		char key[HASH_TEXT_LEN + sizeof("\"\":[")];
		key[0] = '"';
		bin2hex(current_hash, sizeof(mis->all_blocks[0]), key+1, HASH_TEXT_LEN+1);
		memcpy(&key[1+HASH_TEXT_LEN], "\":[", sizeof("\":["));
		if(req_append(&req, &req_len, key))
		    action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory to dispatch block transfer request");
	    } else {
		xfertargets = sx_nodelist_new();
		if(!xfertargets)
		    action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory for local block transfer");
	    }

	    /* Go through the replica set again */
	    for(current_replica = 0; current_replica < mis->replica_count; current_replica++) {
		const sx_node_t *target;

		/* Skip all nodes that have the block already */
		if(mis->avlblty[current_blockno * mis->replica_count + current_replica])
		    continue;

		DEBUG("Block %s is set to be transfered to node %u", blockname, mis->nidxs[current_blockno * mis->replica_count + current_replica]);

		/* Mark the block as being transferred so it's not picked up again later */
		mis->avlblty[current_blockno * mis->replica_count + current_replica] = 2;
		target = sx_nodelist_get(mis->allnodes, mis->nidxs[current_blockno * mis->replica_count + current_replica]);
		if(!target) {
		    WARN("Target no longer exists");
		    if(remote)
			free(req);
		    else
			sx_nodelist_delete(xfertargets);
		    action_error(ACT_RESULT_TEMPFAIL, 500, "Internal error looking up target nodes");
		}

		/* Add this node as a transfer target */
		if(remote) {
		    const sx_uuid_t *target_uuid;
		    target_uuid = sx_node_uuid(target);
		    if(req_append(&req, &req_len, "\"") ||
		       req_append(&req, &req_len, target_uuid->string) ||
		       req_append(&req, &req_len, "\","))
			action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory to dispatch block transfer request");
		} else {
		    if(sx_nodelist_add(xfertargets, sx_node_dup(target))) {
			sx_nodelist_delete(xfertargets);
			action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory for local block transfer");
		    }
		}
		DEBUG("Block %s added to %s push queue for target %s", blockname, remote ? "remote" : "local", sx_node_internal_addr(target));
	    }

	    if(remote) {
		req[strlen(req)-1] = '\0';
		if(req_append(&req, &req_len, "],"))
		    action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory to dispatch block transfer request");
	    } else {
		/* Local xfers are flushed at each block */
		s = sx_hashfs_xfer_tonodes(hashfs, current_hash, mis->block_size, xfertargets);
		sx_nodelist_delete(xfertargets);
		if(s)
		    action_error(rc2actres(s), rc2http(s), "Failed to request local block transfer");
	    }
	}

	if(remote) {
	    /* Remote xfers are flushed at each pushing node */
	    char url[sizeof(".pushto/")+64];

	    sxi_hostlist_init(&hlist);
	    req[strlen(req)-1] = '}';
	    if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(pusher))) {
		free(req);
		action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory to dispatch block transfer request");
	    }
	    snprintf(url, sizeof(url), ".pushto/%u", mis->block_size);

	    qret = sxi_cluster_query(clust, &hlist, REQ_PUT, url, req, strlen(req), NULL, NULL, NULL); /* FIXME: shall i use query_ev here? */
	    sxi_hostlist_empty(&hlist);
	    free(req);

            if (qret == 404)
                action_error(ACT_RESULT_PERMFAIL, 400, "Some remote blocks are missing");

	    if(qret != 200)
		action_error(http2actres(qret), qret, sxc_geterrmsg(sx));
	} else
	    sx_hashfs_xfer_trigger(hashfs);
    }

    INFO("Job id %lld - current replica %u out of %u", (long long)job_id, worstcase_rpl, mis->replica_count);

    if(worstcase_rpl < mis->replica_count) // FIXME: check all vs one (or min required)
	action_error(ACT_RESULT_TEMPFAIL, 500, "Replica not yet completed");
    else {
	const sx_node_t *me = sx_hashfs_self(hashfs);
	sxi_query_t *proto = NULL;
	j = sx_nodelist_count(nodes);
	for(i=0; i<j; i++) {
	    const sx_node_t *node = sx_nodelist_get(nodes, i);
	    if(sx_node_cmp(me, node)) {
		/* Remote only - local tmpfile will be handled in fileflush_commit */
		if(!proto) {
		    const sx_hashfs_volume_t *volume;
		    unsigned int blockno;
		    sxc_meta_t *fmeta;

		    if(!(fmeta = sxc_meta_new(sx)))
			action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to dispatch block transfer request");

		    s = sx_hashfs_volume_by_id(hashfs, mis->volume_id, &volume);
		    if(s == OK)
			s = sx_hashfs_tmp_getmeta(hashfs, mis->name, tmpfile_id, fmeta);
		    if(s != OK) {
			sxc_meta_free(fmeta);
			action_error(rc2actres(s), rc2http(s), msg_get_reason());
		    }

		    proto = sxi_fileadd_proto_begin(sx, volume->name, mis->name, mis->revision, 0, mis->block_size, mis->file_size);

		    blockno = 0;
		    while(proto && blockno < mis->nall) {
			char hexblock[HASH_TEXT_LEN + 1];
			bin2hex(&mis->all_blocks[blockno], sizeof(mis->all_blocks[0]), hexblock, sizeof(hexblock));
			blockno++;
			proto = sxi_fileadd_proto_addhash(sx, proto, hexblock);
		    }

		    if(proto)
			proto = sxi_fileadd_proto_end(sx, proto, fmeta);
		    sxc_meta_free(fmeta);

		    if(!proto)
			action_error(rc2actres(ENOMEM), rc2http(ENOMEM), "Failed to prepare query");
		}

		sxi_hostlist_init(&hlist);
		if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(node))) {
		    sxi_query_free(proto);
		    action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to dispatch block transfer request");
		}
		qret = sxi_cluster_query(clust, &hlist, proto->verb, proto->path, proto->content, proto->content_len, NULL, NULL, NULL); /* FIXME: shall i use query_ev here? */
		sxi_hostlist_empty(&hlist);

		if(qret != 200) {
		    sxi_query_free(proto);
		    action_error(http2actres(qret), qret, sxc_geterrmsg(sx));
		}
	    }
	    succeeded[i] = 1;
	}
	sxi_query_free(proto);
    }

 action_failed:
    free(mis);
    return ret;
}

static act_result_t fileflush_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    act_result_t ret = ACT_RESULT_OK;
    sx_hashfs_missing_t *mis = NULL;
    const sx_node_t *me, *node;
    unsigned int i, nnodes;
    int64_t tmpfile_id;
    rc_ty s;

    if(job_data->len != sizeof(tmpfile_id)) {
	CRIT("Bad job data");
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal job data error");
    }
    memcpy(&tmpfile_id, job_data->ptr, sizeof(tmpfile_id));

    DEBUG("fileflush_commit for file %lld", (long long)tmpfile_id);
    s = sx_hashfs_tmp_getmissing(hashfs, tmpfile_id, &mis, 1);
    if(s == EFAULT || s == EINVAL) {
	CRIT("Error getting missing blocks: %s", msg_get_reason());
	action_error(ACT_RESULT_PERMFAIL, 500, msg_get_reason());
    }
    if(s == ENOENT) {
	WARN("Token %lld could not be found", (long long)tmpfile_id);
	action_error(ACT_RESULT_PERMFAIL, 500, msg_get_reason());
    }
    if(s != OK)
	action_error(rc2actres(s), rc2http(s), "Failed to check missing blocks");

    nnodes = sx_nodelist_count(nodes);
    me = sx_hashfs_self(hashfs);
    for(i=0; i<nnodes; i++) {
	node = sx_nodelist_get(nodes, i);
	if(!sx_node_cmp(me, node)) {
	    /* Local only - remote file created in fileflush_request */
	    s = sx_hashfs_tmp_tofile(hashfs, mis);
	    if(s != OK) {
		CRIT("Error creating file: %s", msg_get_reason());
		action_error(rc2actres(s), rc2http(s), msg_get_reason());
	    }
	}
	succeeded[i] = 1;
    }

 action_failed:
    free(mis);
    return ret;
}

static act_result_t fileflush_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    unsigned int nnode, nnodes;
    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++)
	succeeded[nnode] = 1;
    /* TODO: must DECUSE all the hashes of the token */
    return ACT_RESULT_OK;
}

static act_result_t fileflush_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    unsigned int nnode, nnodes;
    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++)
	succeeded[nnode] = 1;
    /* TODO: must DECUSE all the hashes of the token */
    return ACT_RESULT_OK;
}

static act_result_t filedelete_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    const char *volname, *filename, *revision;
    const sx_hashfs_volume_t *volume;
    act_result_t ret = ACT_RESULT_OK;
    unsigned int nnode, nnodes, gotrev = 0;
    sxi_query_t *proto = NULL;
    sx_blob_t *b = NULL;
    rc_ty s;

    if(!job_data) {
	NULLARG();
	action_set_fail(ACT_RESULT_PERMFAIL, 500, "Null job");
	return ret;
    }
    b = sx_blob_from_data(job_data->ptr, job_data->len);
    if(!b) {
	WARN("Cannot allocate blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }

    if(sx_blob_get_string(b, &volname) ||
       sx_blob_get_string(b, &filename)) {
	WARN("Cannot get job data from blob for job %lld", (long long)job_id);
	action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
    }

    s = sx_hashfs_volume_by_name(hashfs, volname, &volume);
    if(s != OK) {
	WARN("Cannot get volume %s", volname);
	action_error(rc2actres(s), rc2http(s), msg_get_reason());
    }

    nnodes = sx_nodelist_count(nodes);
    while(1) {
	const sx_node_t *me = sx_hashfs_self(hashfs);
	if(sx_blob_get_string(b, &revision)) {
	    WARN("Cannot get revision data from blob for job %lld", (long long)job_id);
	    action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
	}

	if(!*revision) {
	    if(!gotrev) {
		WARN("Cannot job %lld has got no revisions", (long long)job_id);
		action_error(ACT_RESULT_PERMFAIL, 500, "Internal error: data corruption detected");
	    }
	    break;
	}

	gotrev = 1;
	sxi_query_free(proto);
	proto = NULL;
	INFO("Deleting '%s' on '%s' revision '%s'", filename, volname, revision);

	for(nnode = 0; nnode<nnodes; nnode++) {
	    const sx_node_t *node = sx_nodelist_get(nodes, nnode);
	    if(!sx_node_cmp(me, node)) {
		/* Local node */
		s = sx_hashfs_file_delete(hashfs, volume, filename, revision);
		if(s == OK || s == ENOENT)
		    succeeded[nnode] = 1;
		else
		    action_error(rc2actres(s), rc2http(s), msg_get_reason());
	    } else {
		/* Remote node */
		sxi_hostlist_t hlist;
		int qret;

		if(!proto) {
		    proto = sxi_filedel_proto(sx, volname, filename, revision);
		    if(!proto) {
			WARN("Cannot allocate proto for job %lld", (long long)job_id);
			action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
		    }
		}

		sxi_hostlist_init(&hlist);
		if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(node)))
		    action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory to dispatch file delete request");
		qret = sxi_cluster_query(clust, &hlist, proto->verb, proto->path, proto->content, proto->content_len, NULL, NULL, NULL); /* FIXME: shall i use query_ev here? */
		sxi_hostlist_empty(&hlist);

		if(qret != 200 && qret != 404)
		    action_error(http2actres(qret), qret, sxc_geterrmsg(sx));

		succeeded[nnode] = 1;
	    }
	}
    }

 action_failed:
    sxi_query_free(proto);
    sx_blob_free(b);
    return ret;
}

static act_result_t filedelete_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    unsigned int nnode, nnodes;
    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++)
	succeeded[nnode] = 1;
    return ACT_RESULT_OK;
}

static act_result_t filedelete_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    unsigned int nnode, nnodes;
    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++)
	succeeded[nnode] = 1;
    return ACT_RESULT_OK;
}

static act_result_t filedelete_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    unsigned int nnode, nnodes;
    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++)
	succeeded[nnode] = 1;
    return ACT_RESULT_OK;
}


struct cb_challenge_ctx {
    sx_hash_challenge_t chlrsp;
    unsigned int at;
};

static int challenge_cb(sxi_conns_t *conns, void *ctx, const void *data, size_t size) {
    struct cb_challenge_ctx *c = (struct cb_challenge_ctx *)ctx;
    if(c->at + size > sizeof(c->chlrsp.response))
	return 1;
    memcpy(&c->chlrsp.response[c->at], data, size);
    c->at += size;
    return 0;
}

struct sync_ctx {
    sx_hashfs_t *hashfs;
    const sxi_hostlist_t *hlist;
    char buffer[2*1024*1024]; /* Need to fit entirely the largest possible object */
    char *volname;
    unsigned int at;
    enum { DOING_NOTHING, SYNCING_USERS, SYNCING_VOLUMES, SYNCING_PERMS_VOLUME, SYNCING_PERMS_USERS } what;
    struct {
	char key[(2+SXLIMIT_META_MAX_KEY_LEN)*6+1];
	char hexvalue[SXLIMIT_META_MAX_VALUE_LEN * 2 + 1];
    } meta[SXLIMIT_META_MAX_ITEMS];
    unsigned int nmeta;
};

static int sync_flush(struct sync_ctx *ctx) {
    int qret;

    if(ctx->what == DOING_NOTHING || !ctx->at) {
	WARN("Out of seq call");
	return -1;
    }

    strcpy(&ctx->buffer[ctx->at], "}}");

    qret = sxi_cluster_query(sx_hashfs_conns(ctx->hashfs), ctx->hlist, REQ_PUT, ".sync", ctx->buffer, ctx->at+2, NULL, NULL, NULL);
    if(qret != 200)
	return -1;

    ctx->what = DOING_NOTHING;
    ctx->at = 0;
    ctx->buffer[0] = '\0';

    return 0;
}

static int syncusers_cb(sx_uid_t user_id, const char *username, const uint8_t *user, const uint8_t *key, int is_admin, void *ctx) {
    struct sync_ctx *sy = (struct sync_ctx *)ctx;
    unsigned int left = sizeof(sy->buffer) - sy->at;
    char *enc_name, hexkey[AUTH_KEY_LEN*2+1];

    /* Check if we fit:
       - the preliminary '{"users":' part - 10 bytes
       - a fully encoded username - 2 + length(username) * 6 bytes
       - the key - 40 bytes
       - the json skeleton ':{"key":"","admin":true} - 25 bytes
       - the trailing '}}\0' - 3 bytes
    */
    if(left < strlen(username) * 6 + 128) {
	if(sync_flush(sy))
	    return -1;
    }

    if(sy->what == DOING_NOTHING) {
	strcpy(sy->buffer, "{\"users\":{");
	sy->at = lenof("{\"users\":{");
    } else if(sy->what == SYNCING_USERS) {
	sy->buffer[sy->at++] = ',';
    } else {
	WARN("Called out of sequence");
	return -1;
    }
    enc_name = sxi_json_quote_string(username);
    if(!enc_name) {
	WARN("Cannot quote username %s", username);
	return -1;
    }
    bin2hex(key, AUTH_KEY_LEN, hexkey, sizeof(hexkey));
    sprintf(&sy->buffer[sy->at], "%s:{\"key\":\"%s\",\"admin\":%s}", enc_name, hexkey, is_admin ? "true" : "false");
    free(enc_name);

    sy->what = SYNCING_USERS;
    sy->at = strlen(sy->buffer);

    return 0;
}

static int syncperms_cb(const char *username, int priv, void *ctx) {
    struct sync_ctx *sy = (struct sync_ctx *)ctx;
    unsigned int left = sizeof(sy->buffer) - sy->at;
    char userhex[AUTH_UID_LEN * 2 + 1];
    uint8_t user[AUTH_UID_LEN];

    if(!(priv & (PRIV_READ | PRIV_WRITE)))
	return 0;

    /* Check if we fit:
       - the preliminary '{"perms":' part - 9 bytes
       - the encoded volume name - length(volname) bytes
       - the encoded user - 40 bytes
       - the json skeleton ':{"":"rw",}' - 11 bytes
       - the trailing '}}\0' - 3 bytes
    */
    if(left < strlen(username) * 6 + 64) {
	if(sy->what == SYNCING_PERMS_USERS)
	    strcat(&sy->buffer[sy->at++], "}");
	if(sync_flush(sy))
	    return -1;
    }

    if(sx_hashfs_get_user_by_name(sy->hashfs, username, user)) {
	WARN("Failed to lookup user %s", username);
	return -1;
    }
    bin2hex(user, sizeof(user), userhex, sizeof(userhex));
    if(sy->what == DOING_NOTHING) {
	sprintf(sy->buffer, "{\"perms\":{%s:{",sy->volname);
	sy->at = strlen(sy->buffer);
    } else if(sy->what == SYNCING_PERMS_VOLUME) {
	sprintf(&sy->buffer[sy->at], ",%s:{",sy->volname);
	sy->at = strlen(sy->buffer);
    } else if(sy->what == SYNCING_PERMS_USERS) {
	sy->buffer[sy->at++] = ',';
    } else {
	WARN("Called out of sequence");
	return -1;
    }

    sy->what = SYNCING_PERMS_USERS;
    sprintf(&sy->buffer[sy->at], "\"%s\":\"%s%s\"",
	    userhex,
	    (priv & PRIV_READ) ? "r" : "",
	    (priv & PRIV_WRITE) ? "w" : "");
    sy->at = strlen(sy->buffer);
    return 0;
}

static int sync_global_objects(sx_hashfs_t *hashfs, const sxi_hostlist_t *hlist) {
    const sx_hashfs_volume_t *vol;
    struct sync_ctx ctx;
    rc_ty s;

    ctx.what = DOING_NOTHING;
    ctx.at = 0;
    ctx.hashfs = hashfs;
    ctx.hlist = hlist;

    if(sx_hashfs_list_users(hashfs, syncusers_cb, &ctx))
	return -1;

    /* Force flush after all users */
    if(ctx.what != DOING_NOTHING && sync_flush(&ctx))
	return -1;

    s = sx_hashfs_volume_first(hashfs, &vol, 0);
    while(s == OK) {
	uint8_t user[AUTH_UID_LEN];
	char userhex[AUTH_UID_LEN * 2 + 1], *enc_name;
	unsigned int need = strlen(vol->name) * 6 + 256;
	unsigned int left = sizeof(ctx.buffer) - ctx.at;

	/* Need to fit:
	   - the preliminary '},"volumes":' part - 13 bytes
	   - the fully encoded volume name - 2 + length(name) * 6
	   - the owner - 40 bytes
	   - the meta (computed and added later)
	   - the json skeleton ':{"owner":"","size":,"replica":,"meta":{}},' - ~95 bytes
	   - the trailing '}}\0' - 3 bytes
	*/

	if(sx_hashfs_get_user_by_uid(hashfs, vol->owner, user)) {
	    WARN("Cannot find user %lld (owner of %s)", (long long)vol->owner, vol->name);
	    return -1;
	}
	bin2hex(user, AUTH_UID_LEN, userhex, sizeof(userhex));
	s = sx_hashfs_volumemeta_begin(hashfs, vol);
	if(s == OK) {
	    const char *key;
	    const void *val;
	    unsigned int val_len;

	    ctx.nmeta = 0;
	    while((s=sx_hashfs_volumemeta_next(hashfs, &key, &val, &val_len)) == OK) {
		enc_name = sxi_json_quote_string(key);
		if(!enc_name) {
		    WARN("Cannot encode key %s of volume %s", key, vol->name);
		    s = ENOMEM;
		    break;
		}
		/* encoded key and value lengths + quoting, colon and comma */
		need += strlen(enc_name) + val_len * 2 + 4;
		strcpy(ctx.meta[ctx.nmeta].key, enc_name);
		free(enc_name);
		bin2hex(val, val_len, ctx.meta[ctx.nmeta].hexvalue, sizeof(ctx.meta[0].hexvalue));
		ctx.nmeta++;
	    }
	    if(s == ITER_NO_MORE)
		s = OK;
	}
	if(s != OK) {
	    WARN("Failed to manage metadata for volume %s", vol->name);
	    break;
	}

	if(left < need) {
	    if(sync_flush(&ctx))
		return -1;
	}

	if(ctx.what == DOING_NOTHING) {
	    strcpy(ctx.buffer, "{\"volumes\":{");
	    ctx.at = lenof("{\"volumes\":{");
	} else if(ctx.what == SYNCING_VOLUMES) {
	    ctx.buffer[ctx.at++] = ',';
	} else {
	    WARN("Called out of sequence");
	    return -1;
	}

	enc_name = sxi_json_quote_string(vol->name);
	if(!enc_name) {
	    WARN("Failed to encode volume name %s", vol->name);
	    s = ENOMEM;
	    break;
	}
	sprintf(&ctx.buffer[ctx.at], "%s:{\"owner\":\"%s\",\"size\":%lld,\"replica\":%u", enc_name, userhex, (long long)vol->size, vol->replica_count);
	free(enc_name);
	if(ctx.nmeta) {
	    unsigned int i;
	    strcat(ctx.buffer, ",\"meta\":{");
	    for(i=0; i<ctx.nmeta; i++) {
		ctx.at = strlen(ctx.buffer);
		sprintf(&ctx.buffer[ctx.at], "%s%s:\"%s\"",
			i ? "," : "",
			ctx.meta[i].key,
			ctx.meta[i].hexvalue);
	    }
	    strcat(ctx.buffer, "}");
	}
	ctx.at = strlen(ctx.buffer);
	strcat(&ctx.buffer[ctx.at++], "}");
	ctx.what = SYNCING_VOLUMES;
	s = sx_hashfs_volume_next(hashfs);
    }
    if(s != ITER_NO_MORE) {
	WARN("Sending failed with %d", s);
	return -1;
    }

    /* Force flush after all volumes */
    if(ctx.what != DOING_NOTHING && sync_flush(&ctx))
	return -1;

    s = sx_hashfs_volume_first(hashfs, &vol, 0);
    while(s == OK) {
	ctx.volname = sxi_json_quote_string(vol->name);
	if(!ctx.volname) {
	    WARN("Failed to encode volume %s", vol->name);
	    return -1;
	}
	if(sx_hashfs_list_acl(hashfs, vol, 0, PRIV_ADMIN, syncperms_cb, &ctx)) {
	    WARN("Failed to list permissions");
	    free(ctx.volname);
	    return -1;
	}
	free(ctx.volname);

	if(ctx.what == SYNCING_PERMS_USERS) {
	    strcat(&ctx.buffer[ctx.at++], "}");
	    ctx.what = SYNCING_PERMS_VOLUME;
	}
	s = sx_hashfs_volume_next(hashfs);
    }

    if(ctx.what != DOING_NOTHING) {
	if(ctx.what == SYNCING_PERMS_USERS)
	    strcat(&ctx.buffer[ctx.at++], "}");
	if(sync_flush(&ctx))
	    return -1;
    }

    return 0;
}



static act_result_t distribution_request(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    sxi_hdist_t *hdist;
    const sx_nodelist_t *prev, *next;
    act_result_t ret = ACT_RESULT_OK;
    unsigned int nnode, nnodes;
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    sxi_query_t *proto = NULL;
    sxi_hostlist_t hlist;
    int qret;
    rc_ty s;

    if(!job_data) {
	NULLARG();
	action_set_fail(ACT_RESULT_PERMFAIL, 500, "Null job");
	return ret;
    }

    hdist = sxi_hdist_from_cfg(job_data->ptr, job_data->len);
    if(!hdist) {
	WARN("Cannot load hdist config");
	s = ENOMEM;
	action_set_fail(rc2actres(s), rc2http(s), msg_get_reason());
	return ret;
    }

    sxi_hostlist_init(&hlist);

    if(sxi_hdist_buildcnt(hdist) != 2) {
	WARN("Invalid distribution found (builds = %d)", sxi_hdist_buildcnt(hdist));
	action_error(ACT_RESULT_PERMFAIL, 500, "Bad distribution data");
    }

    prev = sxi_hdist_nodelist(hdist, 1);
    next = sxi_hdist_nodelist(hdist, 0);
    if(!prev || !next) {
	WARN("Invalid distribution found");
	action_error(ACT_RESULT_PERMFAIL, 500, "Bad distribution data");
    }

    proto = sxi_distribution_proto(sx, job_data->ptr, job_data->len);
    if(!proto) {
	WARN("Cannot allocate proto for job %lld", (long long)job_id);
	action_error(ACT_RESULT_TEMPFAIL, 503, "Not enough memory to perform the requested action");
    }
    const sx_node_t *me = sx_hashfs_self(hashfs);
    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode < nnodes; nnode++) {
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);
	int was_in = sx_nodelist_lookup(prev, sx_node_uuid(node)) != NULL;
	int is_in = sx_nodelist_lookup(next, sx_node_uuid(node)) != NULL;

	if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(node)))
	    action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory to perform challenge request");

	if(!was_in) {
	    if(!is_in) {
		sxi_hdist_free(hdist);
		WARN("Node %s is not part of either the old and the new distributions", sx_node_uuid_str(node));
		action_error(ACT_RESULT_PERMFAIL, 500, "Bad distribution data");
	    }

	    if(!sx_node_cmp(me, node)) {
		WARN("This node cannot be both a distribution change initiator and a new node");
		action_error(ACT_RESULT_PERMFAIL, 500, "Something is really out of place");
	    }

	    /* Challenge new node */
	    struct cb_challenge_ctx ctx;
	    sx_hash_challenge_t chlrsp;
	    char challenge[lenof(".challenge/") + sizeof(chlrsp.challenge) * 2 + 1];

	    ctx.at = 0;
	    if(sx_hashfs_challenge_gen(hashfs, &chlrsp, 1))
		action_error(ACT_RESULT_TEMPFAIL, 500, "Cannot generate challenge for new node");
	    strcpy(challenge, ".challenge/");
	    bin2hex(chlrsp.challenge, sizeof(chlrsp.challenge), challenge + lenof(".challenge/"), sizeof(challenge) - lenof(".challenge/"));
	    qret = sxi_cluster_query(clust, &hlist, REQ_GET, challenge, NULL, 0, NULL, challenge_cb, &ctx);
	    if(qret != 200 || ctx.at != sizeof(chlrsp.response))
		action_error(http2actres(qret), qret, sxc_geterrmsg(sx));
	    if(memcmp(chlrsp.response, ctx.chlrsp.response, sizeof(chlrsp.response)))
		action_error(ACT_RESULT_PERMFAIL, 500, "Bad challenge response");

	    sxi_query_t *initproto = sxi_nodeinit_proto(sx,
							    sx_hashfs_cluster_name(hashfs),
							    sx_node_uuid_str(node),
							    sx_hashfs_uses_secure_proto(hashfs),
							    sx_hashfs_ca_file(hashfs));
	    if(!initproto)
		action_error(rc2actres(ENOMEM), rc2http(ENOMEM), "Failed to prepare query");

	    qret = sxi_cluster_query(clust, &hlist, initproto->verb, initproto->path, initproto->content, initproto->content_len, NULL, NULL, NULL);
	    sxi_query_free(initproto);
	    if(qret != 200)
		action_error(http2actres(qret), qret, "Failed to initialize new node");

	    /* MOHDIST: Create users and volumes */
	    do {
		sync_global_objects(hashfs, &hlist);
	    } while(0);
	}

	if(sx_node_cmp(me, node)) {
	    qret = sxi_cluster_query(clust, &hlist, proto->verb, proto->path, proto->content, proto->content_len, NULL, NULL, NULL);
	    if(qret != 200)
		action_error(http2actres(qret), qret, sxc_geterrmsg(sx));
	} else {
	    s = sx_hashfs_hdist_change_add(hashfs, job_data->ptr, job_data->len);
	    if(s)
		action_set_fail(rc2actres(s), rc2http(s), msg_get_reason());
	}

	sxi_hostlist_empty(&hlist);
	succeeded[nnode] = 1;
    }


action_failed:
    sxi_query_free(proto);
    sxi_hostlist_empty(&hlist);
    sxi_hdist_free(hdist);

    return ret;
}

static act_result_t distribution_commit(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    sxi_hdist_t *hdist;
    act_result_t ret = ACT_RESULT_OK;
    sxi_hostlist_t hlist;
    sxi_conns_t *clust = sx_hashfs_conns(hashfs);
    sxc_client_t *sx = sx_hashfs_client(hashfs);
    rc_ty s;

    if(!job_data) {
	NULLARG();
	action_set_fail(ACT_RESULT_PERMFAIL, 500, "Null job");
	return ret;
    }

    hdist = sxi_hdist_from_cfg(job_data->ptr, job_data->len);
    if(!hdist) {
	WARN("Cannot load hdist config");
	s = ENOMEM;
	action_set_fail(rc2actres(s), rc2http(s), msg_get_reason());
	return ret;
    }

    sxi_hostlist_init(&hlist);

    if(sxi_hdist_buildcnt(hdist) != 2) {
	WARN("Invalid distribution found (builds = %d)", sxi_hdist_buildcnt(hdist));
	action_error(ACT_RESULT_PERMFAIL, 500, "Bad distribution data");
    }

    const sx_node_t *me = sx_hashfs_self(hashfs);
    unsigned int nnode, nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode < nnodes; nnode++) {
	const sx_node_t *node = sx_nodelist_get(nodes, nnode);

	if(sxi_hostlist_add_host(sx, &hlist, sx_node_internal_addr(node)))
	    action_error(ACT_RESULT_TEMPFAIL, 500, "Not enough memory to perform challenge request");

	if(sx_node_cmp(me, node)) {
	    int qret = sxi_cluster_query(clust, &hlist, REQ_PUT, ".dist", NULL, 0, NULL, NULL, NULL);
	    if(qret != 200)
		action_error(http2actres(qret), qret, sxc_geterrmsg(sx));
	} else {
	    s = sx_hashfs_hdist_change_commit(hashfs);
	    if(s)
		action_set_fail(rc2actres(s), rc2http(s), msg_get_reason());
	}

	sxi_hostlist_empty(&hlist);
	succeeded[nnode] = 1;
    }

    /* MODHDIST: unlock all and create jobs for rebalancing
     * --- see fcgi_enable_distribution --- */

action_failed:
    sxi_hostlist_empty(&hlist);
    sxi_hdist_free(hdist);

    return ret;
}

static act_result_t distribution_abort(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    unsigned int nnode, nnodes;
    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++)
	succeeded[nnode] = 1;
    return ACT_RESULT_OK;
}

static act_result_t distribution_undo(sx_hashfs_t *hashfs, job_t job_id, job_data_t *job_data, const sx_nodelist_t *nodes, int *succeeded, int *fail_code, char *fail_msg) {
    unsigned int nnode, nnodes;
    nnodes = sx_nodelist_count(nodes);
    for(nnode = 0; nnode<nnodes; nnode++)
	succeeded[nnode] = 1;
    return ACT_RESULT_OK;
}

static struct {
    job_action_t fn_request;
    job_action_t fn_commit;
    job_action_t fn_abort;
    job_action_t fn_undo;
} actions[] = {
    { createvol_request, createvol_commit, createvol_abort, createvol_undo }, /* JOBTYPE_CREATE_VOLUME */
    { createuser_request, createuser_commit, createuser_abort, createuser_undo }, /* JOBTYPE_CREATE_USER */
    { acl_request, acl_commit, acl_abort, acl_undo }, /* JOBTYPE_VOLUME_ACL */
    { fileflush_request, fileflush_commit, fileflush_abort, fileflush_undo }, /* JOBTYPE_FLUSH_FILE */
    { filedelete_request, filedelete_commit, filedelete_abort, filedelete_undo }, /* JOBTYPE_DELETE_FILE */
    { distribution_request, distribution_commit, distribution_abort, distribution_undo }, /* JOBTYPE_DISTRIBUTION */
};


static job_data_t *make_jobdata(const void *data, unsigned int data_len) {
    job_data_t *ret;

    if(!data && data_len)
	return NULL;
    if(!(ret = wrap_malloc(sizeof(*ret) + data_len)))
	return NULL;
    ret->ptr = (void *)(ret+1);
    ret->len = data_len;
    memcpy(ret->ptr, data, data_len);
    return ret;
}

static int terminate = 0;
static void sighandler(int signum) {
    if (signum == SIGHUP || signum == SIGUSR1) {
	log_reopen();
	return;
    }
    terminate = 1;
}

#define JOB_PHASE_REQUEST 0
#define JOB_PHASE_COMMIT 1
#define JOB_PHASE_DONE 2
#define JOB_PHASE_FAIL 3

#define BATCH_ACT_NUM 64

struct jobmgr_data_t {
    /* The following items are filled in once by jobmgr() */
    sx_hashfs_t *hashfs;
    sqlite3_stmt *qjob;
    sqlite3_stmt *qact;
    sqlite3_stmt *qres;
    sqlite3_stmt *qcpl;
    sqlite3_stmt *qphs;
    sqlite3_stmt *qdly;
    sqlite3_stmt *qvbump;
    time_t next_vcheck;

    /* The following items are filled in by:
     * jobmgr_process_queue(): sets job_id, job_type, job_expired, job_failed, job_data (from the db)
     * jobmgr_run_job(): job_failed gets updated if job fails or expires
     * jobmgr_get_actions_batch(): sets act_phase and nacts then fills the targets and act_ids arrays
     * jobmgr_execute_actions_batch(): fail_reason in case of failure
     */
    sx_nodelist_t *targets;
    job_data_t *job_data;
    int64_t act_ids[BATCH_ACT_NUM];
    int job_expired, job_failed;
    job_t job_id;
    jobtype_t job_type;
    unsigned int nacts;
    int act_phase;
    char fail_reason[JOB_FAIL_REASON_SIZE];
};


static act_result_t jobmgr_execute_actions_batch(int *http_status, struct jobmgr_data_t *q) {
    act_result_t act_res = ACT_RESULT_UNSET;
    unsigned int nacts = q->nacts;
    int act_succeeded[BATCH_ACT_NUM];

    memset(act_succeeded, 0, sizeof(act_succeeded));
    *http_status = 0;
    q->fail_reason[0] = '\0';

    if(q->job_failed) {
	if(q->act_phase == JOB_PHASE_REQUEST) {
	    /* Nothing to (un)do */
	    act_res = ACT_RESULT_OK;
	} else if(q->act_phase == JOB_PHASE_COMMIT) {
	    act_res = actions[q->job_type].fn_abort(q->hashfs, q->job_id, q->job_data, q->targets, act_succeeded, http_status, q->fail_reason);
	} else { /* act_phase == JOB_PHASE_DONE */
	    act_res = actions[q->job_type].fn_undo(q->hashfs, q->job_id, q->job_data, q->targets, act_succeeded, http_status, q->fail_reason);
	}
	if(act_res == ACT_RESULT_PERMFAIL) {
	    CRIT("Some undo action permanently failed for job %lld.", (long long)q->job_id);
	    act_res = ACT_RESULT_OK;
	}
    } else {
	if(q->act_phase == JOB_PHASE_REQUEST) {
	    act_res = actions[q->job_type].fn_request(q->hashfs, q->job_id, q->job_data, q->targets, act_succeeded, http_status, q->fail_reason);
	} else { /* act_phase == JOB_PHASE_COMMIT */
	    act_res = actions[q->job_type].fn_commit(q->hashfs, q->job_id, q->job_data, q->targets, act_succeeded, http_status, q->fail_reason);
	}
    }
    if(act_res != ACT_RESULT_OK && act_res != ACT_RESULT_TEMPFAIL && act_res != ACT_RESULT_PERMFAIL) {
	WARN("Unknown action return code %d: changing to PERMFAIL", act_res);
	act_res = ACT_RESULT_PERMFAIL;
    }

    while(nacts--) { /* Bump phase of successful actions */
	if(act_succeeded[nacts] || (q->job_failed && act_res == ACT_RESULT_OK)) {
	    if(qbind_int64(q->qphs, ":act", q->act_ids[nacts]) ||
	       qbind_int(q->qphs, ":phase", q->job_failed ? JOB_PHASE_FAIL : q->act_phase + 1) ||
	       qstep_noret(q->qphs))
		WARN("Cannot advance action phase for %lld.%lld", (long long)q->job_id, (long long)q->act_ids[nacts]);
	    else
		INFO("Action %lld advanced to phase %d", (long long)q->act_ids[nacts], q->job_failed ? JOB_PHASE_FAIL : q->act_phase + 1);
	}
    }

    return act_res;
}

static int jobmgr_get_actions_batch(struct jobmgr_data_t *q) {
    unsigned int nacts;
    int r;

    q->nacts = 0;

    if(qbind_int64(q->qact, ":job", q->job_id) ||
       qbind_int(q->qact, ":maxphase", q->job_failed ? JOB_PHASE_FAIL : JOB_PHASE_DONE)) {
	WARN("Cannot lookup actions for job %lld", (long long)q->job_id);
	return -1;
    }
    r = qstep(q->qact);
    if(r == SQLITE_DONE) {
	if(qbind_int64(q->qcpl, ":job", q->job_id) ||
	   qstep_noret(q->qcpl))
	    WARN("Cannot set job %lld to complete", (long long)q->job_id);
	else
	    INFO("No actions for job %lld", (long long)q->job_id);
	return 1; /* Job completed */
    } else if(r == SQLITE_ROW)
	q->act_phase = sqlite3_column_int(q->qact, 1); /* Define the current batch phase */

    for(nacts=0; nacts<BATCH_ACT_NUM; nacts++) {
	const sx_node_t *node, *myself;
	sx_node_t *target;
	int64_t act_id;
	sx_uuid_t uuid;
	const void *ptr;
	unsigned int plen;
	rc_ty rc;

	if(r == SQLITE_DONE)
	    break; /* set batch_size and return success */

	if(r != SQLITE_ROW) {
	    WARN("Failed to retrieve actions for job %lld", (long long)q->job_id);
	    return -1;
	}
	if(sqlite3_column_int(q->qact, 1) != q->act_phase)
	    break; /* set batch_size and return success */

	act_id = sqlite3_column_int64(q->qact, 0);
	ptr = sqlite3_column_blob(q->qact, 2);
	plen = sqlite3_column_bytes(q->qact, 2);
	if(plen != sizeof(uuid.binary)) {
	    WARN("Bad action target for job %lld.%lld", (long long)q->job_id, (long long)act_id);
	    sqlite3_reset(q->qact);
	    return -1;
	}
	uuid_from_binary(&uuid, ptr);
	node = sx_nodelist_lookup(sx_hashfs_nodelist(q->hashfs, NL_NEXTPREV), &uuid);
	if(!node)
	    target = sx_node_new(&uuid, sqlite3_column_text(q->qact, 3), sqlite3_column_text(q->qact, 4), sqlite3_column_int64(q->qact, 5));
	else
	    target = sx_node_dup(node);
	myself = sx_hashfs_self(q->hashfs);
	if(!sx_node_cmp(myself, target)) {
	    rc = sx_nodelist_prepend(q->targets, target);
	    if(nacts)
		memmove(&q->act_ids[1], &q->act_ids[0], nacts * sizeof(act_id));
	    q->act_ids[0] = act_id;
	} else {
	    rc = sx_nodelist_add(q->targets, target);
	    q->act_ids[nacts] = act_id;
	}
	if(rc != OK) {
	    WARN("Cannot add action target");
	    sqlite3_reset(q->qact);
	    return -1;
	}
	INFO("Action %lld (phase %d, target %s) loaded", (long long)act_id, q->act_phase, uuid.string);
	r = qstep(q->qact);
    }

    sqlite3_reset(q->qact);
    q->nacts = nacts;
    return 0;
}

static void jobmgr_run_job(struct jobmgr_data_t *q) {
    int r;

    if(q->job_expired && !q->job_failed) {
	/* FIXME: we could keep a trace of the reason of the last delay
	 * which is stored in db in case of tempfail.
	 * Of limited use but maybe nice to have */
	if(qbind_int64(q->qres, ":job", q->job_id) ||
	   qbind_int(q->qres, ":res", 500) ||
	   qbind_text(q->qres, ":reason", "Cluster time out") ||
	   qstep_noret(q->qres)) {
	    WARN("Cannot update status of expired job %lld", (long long)q->job_id);
	    return;
	}
	INFO("Job %lld is now expired", (long long)q->job_id);
	q->job_failed = 1;
    }

    while(!terminate) {
	act_result_t act_res;
	int http_status;

	/* Collect a batch of actions but just for the current phase */
	sx_nodelist_empty(q->targets);
	r = jobmgr_get_actions_batch(q);
	if(r > 0) /* Job complete */
	    break;
	if(r < 0) { /* Error getting actions */
	    WARN("Failed to collect actions for job %lld", (long long)q->job_id);
	    break;
	}

	/* Execute actions */
	act_res = jobmgr_execute_actions_batch(&http_status, q);

	/* Temporary failure: mark job as to-be-retried and stop processing it for now */
	if(act_res == ACT_RESULT_TEMPFAIL) {
	    if(qbind_int64(q->qdly, ":job", q->job_id) ||
	       qbind_text(q->qdly, ":reason", q->fail_reason[0] ? q->fail_reason : "Unknown delay reason") ||
	       qbind_text(q->qdly, ":delay",
                          q->job_type == JOBTYPE_FLUSH_FILE ?
                          STRIFY(JOBMGR_DELAY_MIN) " seconds" : STRIFY(JOBMGR_DELAY_MAX) " seconds") ||
	       qstep_noret(q->qdly))
		CRIT("Cannot reschedule job %lld (you are gonna see this again!)", (long long)q->job_id);
	    else
		INFO("Job %lld will be retried later", (long long)q->job_id);
	    break;
	}

	/* Permanent failure: mark job as failed and go on (with cleanup actions) */
	if(act_res == ACT_RESULT_PERMFAIL) {
	    if(qbind_int64(q->qres, ":job", q->job_id) ||
	       qbind_int(q->qres, ":res", http_status) ||
	       qbind_text(q->qres, ":reason", q->fail_reason[0] ? q->fail_reason : "Unknown failure") ||
	       qstep_noret(q->qres)) {
		WARN("Cannot update status of failed job %lld", (long long)q->job_id);
		break;
	    }
	    INFO("Job %lld failed", (long long)q->job_id);
	    q->job_failed = 1;
	}

	/* Success: go on with the next batch */
    }

    sx_nodelist_empty(q->targets); /* Explicit free, just in case */
}

static uint16_t to_u16(const uint8_t *ptr) {
    return ((uint16_t)ptr[0] << 8) | ptr[1];
}

static void check_version(struct jobmgr_data_t *q) {
    char buf[1024], resbuf[1024], *p1, *p2;
    uint16_t rrcount[ns_s_max];
    const uint8_t *rd, *eom;
    time_t now = time(NULL);
    int i, vmaj, vmin, secflag, len;

    if(q->next_vcheck > now)
	return;
    q->next_vcheck += 24 * 60 * 60 + (rand() % (60 * 60)) - 30 * 60;
    if(q->next_vcheck <= now)
	q->next_vcheck = now + 24 * 60 * 60 + (rand() % (60 * 60)) - 30 * 60;
    if(qbind_int(q->qvbump, ":next", q->next_vcheck) ||
       qstep_noret(q->qvbump))
	WARN("Cannot update check time");

    if(res_init()) {
	WARN("Failed to initialize resolver");
	return;
    }

    snprintf(buf, sizeof(buf), "%lld.%s.sxver.skylable.com", (long long)q->job_id, sx_hashfs_self_unique(q->hashfs));
    len = res_query(buf, C_IN, T_TXT, resbuf, sizeof(resbuf));
    if(len < 0) {
	WARN("Failed to check version: query failed");
	return;
    }

    rd = resbuf;
    eom = resbuf + len;
    do {
	if(len < sizeof(uint16_t) + sizeof(uint16_t) + ns_s_max * sizeof(uint16_t))
	    break;
	rd += sizeof(uint16_t) + sizeof(uint16_t); /* id + flags */
	for(i=0; i<ns_s_max; i++) {
	    rrcount[i] = to_u16(rd);
	    rd += 2;
	}
	if(rrcount[ns_s_qd] != 1 || rrcount[ns_s_an] != 1)
	    break;
	/* At question section: name + type + class */
	i = dn_skipname(rd, eom);
	if(i < 0 || rd + i + sizeof(uint16_t) + sizeof(uint16_t) > eom)
	    break;
	rd += i + sizeof(uint16_t) + sizeof(uint16_t);
	/* At answer section: name + type + class + ttl + rdlen (+rdata) */
	i = dn_skipname(rd, eom);
	if(i < 0 || rd + i + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint16_t) > eom)
	    break;
	rd += i;
	if(to_u16(rd) != T_TXT || to_u16(rd+2) != C_IN)
	    break;
	rd += sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t);
	len = to_u16(rd);
	rd += sizeof(uint16_t);
	if(len < 1 || rd + len > eom)
	    break;
	/* At rdata of the first record of the answer section: string_lenght + string */
	if(*rd != len - 1)
	    break;
	rd++;
	len = MIN(len, sizeof(buf)) - 1;
	memcpy(buf, rd, len);
	buf[len] = '\0';
	eom = NULL;
    } while(0);
    if(eom) {
	WARN("Failed to check version: bad DNS reply");
	return;
    }

    vmaj = strtol(buf, &p1, 10);
    if(p1 == buf || *p1 != '.') {
	WARN("Failed to check version: bad version received");
	return;
    }
    p1++;
    vmin = strtol(p1, &p2, 10);
    if(p2 == p1 || *p2 != '.') {
	WARN("Failed to check version: bad version received");
	return;
    }
    p2++;
    secflag = strtol(p2, &p1, 10);
    if(p2 == p1 || (*p1 != '.' && *p1 != '\0')) {
	WARN("Failed to check version: bad version received");
	return;
    }

    i=0;
    if(vmaj > SRC_MAJOR_VERSION)
	secflag = 1;
    else if(vmaj == SRC_MAJOR_VERSION) {
	if(secflag || vmin > SRC_MINOR_VERSION + 1)
	    secflag = 1;
	else if(vmin > SRC_MINOR_VERSION)
	    secflag = 0;
	else
	    i = 1;
    } else
	i = 1;
    if(!i) {
	if(secflag) {
	    CRIT("CRITICAL update found! Skylable SX %d.%d is available (this node is running version %d.%d)", vmaj, vmin, SRC_MAJOR_VERSION, SRC_MINOR_VERSION);
	    CRIT("See http://www.skylable.com/products/sx/release/%d.%d for upgrade instructions", vmaj, vmin);
	} else {
	    INFO("Skylable SX %d.%d is available (this node is running version %d.%d)", vmaj, vmin, SRC_MAJOR_VERSION, SRC_MINOR_VERSION);
	    INFO("See http://www.skylable.com/products/sx/release/%d.%d for more info", vmaj, vmin);
	}
    }

}

static void jobmgr_process_queue(struct jobmgr_data_t *q, int forced) {
    while(!terminate) {
	const void *ptr;
	unsigned int plen;
	int r;

	r = qstep(q->qjob);
	if(r == SQLITE_DONE && forced) {
	    unsigned int waitus = 200000;
	    do {
		usleep(waitus);
		waitus *= 2;
		r = qstep(q->qjob);
	    } while(r == SQLITE_DONE && waitus <= 800000);
	    if(r == SQLITE_DONE)
		DEBUG("Triggered run without jobs");
	}
        forced = 0;
	if(r == SQLITE_DONE) {
	    DEBUG("No more pending jobs");
	    break; /* Stop processing jobs */
	}
	if(r != SQLITE_ROW) {
	    WARN("Failed to retrieve the next job to execute");
	    break; /* Stop processing jobs */
	}

	q->job_id = sqlite3_column_int64(q->qjob, 0);
	q->job_type = sqlite3_column_int(q->qjob, 1);
	ptr = sqlite3_column_blob(q->qjob, 2);
	plen = sqlite3_column_bytes(q->qjob, 2);
	q->job_expired = sqlite3_column_int(q->qjob, 3);
	q->job_failed = (sqlite3_column_int(q->qjob, 4) < 0);
	q->job_data = make_jobdata(ptr, plen);
	sqlite3_reset(q->qjob);

	if(!q->job_data) {
	    WARN("Job %lld has got invalid data", (long long)q->job_id);
	    continue; /* Process next job */
	}

	INFO("Running job %lld (type %d, %s, %s)", (long long)q->job_id, q->job_type, q->job_expired?"expired":"not expired", q->job_failed?"failed":"not failed");
	jobmgr_run_job(q);
	free(q->job_data);
	INFO("Finished running job %lld", (long long)q->job_id);
	/* Process next job */
    }

    if(!terminate)
	check_version(q);
}


int jobmgr(sxc_client_t *sx, const char *self, const char *dir, int pipe) {
    sqlite3_stmt *q_vcheck = NULL;
    struct jobmgr_data_t q;
    struct sigaction act;
    sxi_db_t *eventdb;

    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = sighandler;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGUSR2, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGQUIT, &act, NULL);
    signal(SIGPIPE, SIG_IGN);

    act.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGHUP, &act, NULL);

    memset(&q, 0, sizeof(q));
    q.hashfs = sx_hashfs_open(dir, sx);
    if(!q.hashfs) {
	CRIT("Failed to initialize the hash server interface");
	goto jobmgr_err;
    }
    if (sx_hashfs_gc_open(q.hashfs))
        goto jobmgr_err;

    q.targets = sx_nodelist_new();
    if(!q.targets) {
	WARN("Cannot create target nodelist");
	goto jobmgr_err;
    }

    eventdb = sx_hashfs_eventdb(q.hashfs);

    if(qprep(eventdb, &q.qjob, "SELECT job, type, data, expiry_time < datetime('now'), result FROM jobs WHERE complete = 0 AND sched_time <= strftime('%Y-%m-%d %H:%M:%f') ORDER BY sched_time ASC LIMIT 1") ||
       qprep(eventdb, &q.qact, "SELECT id, phase, target, addr, internaladdr, capacity FROM actions WHERE job_id = :job AND phase < :maxphase ORDER BY phase") ||
       qprep(eventdb, &q.qres, "UPDATE jobs SET result = :res, reason = :reason WHERE job = :job AND result = 0") ||
       qprep(eventdb, &q.qcpl, "UPDATE jobs SET complete = 1, lock = NULL WHERE job = :job") ||
       qprep(eventdb, &q.qphs, "UPDATE actions SET phase = :phase WHERE id = :act") ||
       qprep(eventdb, &q.qdly, "UPDATE jobs SET sched_time = strftime('%Y-%m-%d %H:%M:%f', 'now', :delay), reason = :reason WHERE job = :job") ||
       qprep(eventdb, &q.qvbump, "INSERT OR REPLACE INTO hashfs (key, value) VALUES ('next_version_check', datetime(:next, 'unixepoch'))") ||
       qprep(eventdb, &q_vcheck, "SELECT strftime('%s', value) FROM hashfs WHERE key = 'next_version_check'"))
	goto jobmgr_err;

    if(qstep(q_vcheck) == SQLITE_ROW)
	q.next_vcheck = sqlite3_column_int(q_vcheck, 0);
    else
	q.next_vcheck = time(NULL);
    qnullify(q_vcheck);

    while(!terminate) {
	int dc, forced_awake = 0;

        if (wait_trigger(pipe, JOBMGR_DELAY_MIN, &forced_awake))
            break;

	DEBUG("Start processing job queue");
	dc = sx_hashfs_distcheck(q.hashfs);
	if(dc < 0) {
	    CRIT("Failed to reload distribution");
	    goto jobmgr_err;
	} else if(dc > 0) {
	    /* MODHDIST: the model has changed, what do ? */
	    INFO("Distribution reloaded");
	}
	jobmgr_process_queue(&q, forced_awake);
	DEBUG("Done processing job queue");
        sx_hashfs_checkpoint(q.hashfs);
    }

 jobmgr_err:
    sqlite3_finalize(q.qjob);
    sqlite3_finalize(q.qact);
    sqlite3_finalize(q.qres);
    sqlite3_finalize(q.qcpl);
    sqlite3_finalize(q.qphs);
    sqlite3_finalize(q.qdly);
    sqlite3_finalize(q.qvbump);
    sqlite3_finalize(q_vcheck);
    sx_nodelist_delete(q.targets);
    sx_hashfs_close(q.hashfs);
    close(pipe);
    return terminate ? EXIT_SUCCESS : EXIT_FAILURE;
}
