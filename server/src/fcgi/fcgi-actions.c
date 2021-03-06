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
#include <string.h>
#include "fcgi-utils.h"
#include "fcgi-actions.h"
#include "fcgi-actions-cluster.h"
#include "fcgi-actions-volume.h"
#include "fcgi-actions-node.h"
#include "fcgi-actions-block.h"
#include "fcgi-actions-file.h"
#include "fcgi-actions-user.h"
#include "fcgi-actions-job.h"
#include "hashfs.h"
#include "sx.h"

void cluster_ops(void) {
    if(verb != VERB_HEAD && verb != VERB_GET) {
	CGI_PUTS("Allow: GET,HEAD,OPTIONS\r\n");
	quit_errmsg(405, "Method Not Allowed");
    }

    /* If not authed we serve the homepage back */
    if(!is_sky())
	quit_home();

    /* Cluster queries - require either a valid user or ADMIN 
     * priv enforcement in fcgi_handle_cluster_requests() */
    quit_unless_authed();
    fcgi_handle_cluster_requests();
}

void volume_ops(void) {
    rc_ty s;
    quit_unless_authed();

    if(verb != VERB_HEAD && verb != VERB_GET && verb != VERB_PUT && verb != VERB_DELETE) {
	CGI_PUTS("Allow: GET,HEAD,OPTIONS,PUT,DELETE\r\n");
	quit_errmsg(405, "Method Not Allowed");
    }

    if(verb == VERB_HEAD || verb == VERB_GET) {
	const sx_hashfs_volume_t *vol;

	if(!strcmp(volume, ".users")) {
	    /* List users - ADMIN required */
	    quit_unless_has(PRIV_ADMIN);
	    fcgi_list_users();
	    return;
	}

	if(is_reserved())
	    quit_errmsg(403, "Volume name is reserved");

	s = sx_hashfs_volume_by_name(hashfs, volume, &vol);
	switch(s) {
	case OK:
	    break;
	case ENOENT:
	    quit_errmsg(404, "No such volume");
	case EINVAL:
	    quit_errnum(400);
	default:
	    quit_errnum(500);
	}

	/* Locating or listing volume data requires READ|WRITE|OWNER access or better */
        if (!has_priv(PRIV_READ) && !has_priv(PRIV_WRITE) && !has_priv(PRIV_OWNER) && !has_priv(PRIV_ADMIN))
            quit_errmsg(403, "Permission denied: not enough privileges");

	if(has_arg("o")) {
	    if(arg_is("o", "locate")) {
		/* Locate volume, i.e. find the nodes that manage it - READ required */
		fcgi_locate_volume(vol);
		return;
	    } else if(arg_is("o", "acl")) {
		/* List privs - every user can list its own privileges, admin
                 * can list everything. You need to have some privileges though */
		fcgi_list_acl(vol);
		return;
	    }
	}

        quit_unless_has(PRIV_READ);

	if(!has_arg("o") || arg_is("o", "list")) {
	    /* List volume content - READ required */
	    fcgi_list_volume(vol);
	} else
	    quit_errnum(404);

	return;
    }

    if (verb == VERB_PUT && arg_is("o","acl")) {
	/* Update volume privs - ADMIN or OWNER required */
	if(is_reserved())
	    quit_errmsg(403, "Volume name is reserved");
	if(!has_priv(PRIV_ADMIN))
	    quit_unless_has(PRIV_OWNER);
	fcgi_acl_volume();
	return;
    }

    /* Only ADMIN or better allowed beyond this point */
    quit_unless_has(PRIV_ADMIN);

    if(verb == VERB_PUT && (arg_is("o","disable") || arg_is("o","enable"))) {
	/* Enable / disable volume (2pc/s2s) - CLUSTER required */
	quit_unless_has(PRIV_CLUSTER);
	if(is_reserved())
	    quit_errmsg(403, "Volume name is reserved");
	fcgi_volume_onoff(arg_is("o","enable"));
	return;
    }

    if(verb == VERB_PUT) {
	if(!strcmp(".node", volume)) {
	    /* Initialize bare node into a cluster (s2s) - CLUSTER required */
	    quit_unless_has(PRIV_CLUSTER);
	    fcgi_node_init();
	} else if(!strcmp(".dist", volume)) {
	    /* Create/enable new distribution (s2s entry) - CLUSTER required */
	    quit_unless_has(PRIV_CLUSTER);
	    if(content_len())
		fcgi_new_distribution();
	    else
		fcgi_enable_distribution();
	} else if(!strcmp(volume, ".sync")) {
	    /* Syncronize global objects (s2s) - CLUSTER required */
	    quit_unless_has(PRIV_CLUSTER);
            fcgi_sync_globs();
        } else if (!strcmp(volume, ".gc")) {
	    quit_unless_has(PRIV_ADMIN);
            fcgi_trigger_gc();
	} else if(!strcmp(".nodes", volume)) {
	    /* Update distribution (sxadm entry) - ADMIN required */
	    fcgi_set_nodes();
	} else if (!strcmp(".users", volume)) {
	    /* Create new user - ADMIN required */
	    if(is_https() < sx_hashfs_uses_secure_proto(hashfs)) {
                WARN("Key operations require SECURE mode");
                quit_errmsg(403, "Key operations require SECURE mode");
            }
	    fcgi_create_user();
	} else {
	    /* Create new volume - ADMIN required */
	    if(is_reserved())
		quit_errmsg(403, "Volume name is reserved");
	    fcgi_create_volume();
	}
	return;
    }

    if(verb == VERB_DELETE) {
	/* Delete volume (currently s2s only) - CLUSTER required */
	quit_unless_has(PRIV_CLUSTER);
	if(is_reserved())
	    quit_errmsg(403, "Volume name is reserved");
	fcgi_delete_volume();
	return;
    }
}


void file_ops(void) {
    quit_unless_authed();

    if(verb != VERB_HEAD && verb != VERB_GET && verb != VERB_PUT && verb != VERB_DELETE) {
	CGI_PUTS("Allow: GET,HEAD,OPTIONS,PUT,DELETE\r\n");
	quit_errmsg(405, "Method not allowed");
    }

    if(verb == VERB_HEAD || verb == VERB_GET) {
	if(!strcmp(volume, ".data")) {
	    /* Get block content - any valid user allowed */
	    fcgi_send_blocks();
	} else if(!strcmp(volume, ".results")) {
	    /* Get job result - job owner or ADMIN required (enforcement in fcgi_job_result()) */
	    fcgi_job_result();
        } else if (!strcmp(volume, ".users")) {
	    /* Get user data - ADMIN required */
	    quit_unless_has(PRIV_ADMIN);
            if(is_https() < sx_hashfs_uses_secure_proto(hashfs)) {
                WARN("key operations require SECURE mode");
                quit_errmsg(403, "Key operations require SECURE mode");
            }
            fcgi_send_user();
        } else if(!strcmp(volume, ".challenge")) {
	    /* Response to challenge (s2s) - CLUSTER required */
	    quit_unless_has(PRIV_CLUSTER);
            fcgi_challenge_response();
	} else {
	    /* Get file (meta)data - READ required */
	    quit_unless_has(PRIV_READ);
	    if(has_arg("fileMeta")) {
		/* Get file metadata */
		fcgi_send_file_meta();
	    } else {
		/* Get file content */
		fcgi_send_file();
	    }
	}
	return;
    }

    if(verb == VERB_PUT) {
	if(!strcmp(volume, ".upload")) {
	    if(content_len()) {
		/* Phase 1-extra (extend tempfile) - valid token required */
		fcgi_extend_tempfile();
	    } else {
		/* Phase 3 (flush tempfile) - valid token required */
		fcgi_flush_tempfile();
	    }
	    return;
	}

	if(!strcmp(volume, ".users") && (arg_is("o","disable") || arg_is("o","enable"))) {
	    /* Enable/disable users (2pc/s2s) - CLUSTER required */
	    quit_unless_has(PRIV_CLUSTER);
	    fcgi_user_onoff(arg_is("o","enable"));
	    return;
	}

	if(!strcmp(volume, ".data")) {
            if (has_arg("o")) {
		/* Hashop reserve/inuse (s2s) - CLUSTER required */
                enum sxi_hashop_kind kind;
                quit_unless_has(PRIV_CLUSTER);
                if (arg_is("o","reserve"))
                    kind = HASHOP_RESERVE;
                else if (arg_is("o","inuse"))
                    kind = HASHOP_INUSE;
                else if (arg_is("o","check"))
                    kind = HASHOP_CHECK;
                else
                    quit_errmsg(400,"Invalid operation requested on hash batch");
                fcgi_hashop_blocks(kind);
                return;
            }
	    /* Phase 2 (blocks upload) - valid token required */
	    fcgi_save_blocks();
	    return;
	}

	if(!strcmp(volume, ".pushto")) {
	    /* Instruct this node to push some blocks to other nodes (s2s) - CLUSTER required */
	    quit_unless_has(PRIV_CLUSTER);
	    fcgi_push_blocks();
	    return;
	}

	if(has_priv(PRIV_CLUSTER)) {
	    /* New file propagation (s2s) - CLUSTER required */
	    fcgi_create_file();
	} else {
	    /* Phase 1 (create tempfile) - WRITE required */
	    quit_unless_has(PRIV_WRITE);
	    fcgi_create_tempfile();
	}
	return;
    }

    if(verb == VERB_DELETE) {
	if(!strcmp(volume, ".data")) {
	    /* Hashop delete (gc/s2s) - CLUSTER required */
            quit_unless_has(PRIV_CLUSTER);
            fcgi_hashop_blocks(HASHOP_DELETE);
            return;
	}
	/* File deletion - WRITE required */
	quit_unless_has(PRIV_WRITE);
	fcgi_delete_file();
	return;
    }
}

void job_2pc_handle_request(sxc_client_t *sx, const job_2pc_t *spec, void *yctx)
{
    yajl_handle yh = yajl_alloc(spec->parser, NULL, yctx);
    if (!yh)
	quit_errmsg(500, "Cannot allocate json parser");
    int len;
    while((len = get_body_chunk(hashbuf, sizeof(hashbuf))) > 0)
	if(yajl_parse(yh, hashbuf, len) != yajl_status_ok) break;
    if(len || yajl_complete_parse(yh) != yajl_status_ok || !spec->parse_complete(yctx)) {
	yajl_free(yh);
	quit_errmsg(400, "Invalid request content");
    }
    yajl_free(yh);

    auth_complete();
    quit_unless_authed();

    sx_blob_t *joblb = sx_blob_new();
    if (!joblb)
        quit_errmsg(500, "Cannot allocate job blob");
    if (spec->to_blob(sx, yctx, joblb)) {
        const char *msg = msg_get_reason();
        sx_blob_free(joblb);
        if(!msg || !*msg)
            msg = "Cannot create job blob";
        quit_errmsg(500, msg);
    }
    if(has_priv(PRIV_CLUSTER)) {
        msg_set_reason("cannot execute blob");
        sx_blob_reset(joblb);
        rc_ty rc = spec->execute_blob(hashfs, joblb, JOBPHASE_REQUEST);
        sx_blob_free(joblb);
        if (rc != OK)
            quit_errmsg(rc2http(rc), msg_get_reason());
	CGI_PUTS("\r\n");
    } else {
	const void *job_data;
	unsigned int job_datalen;
	job_t job;
        int res;
        sx_nodelist_t *nodes = NULL;
	unsigned int job_timeout;

        /* create job, must not reset yet */
        sx_blob_to_data(joblb, &job_data, &job_datalen);
        /* must reset now */
        sx_blob_reset(joblb);
        const char *lock = spec->get_lock(joblb);
        sx_blob_reset(joblb);
        res = spec->nodes(sx, joblb, &nodes);
	job_timeout = 12 * sx_nodelist_count(nodes); /* FIXME: this should be jobtype specific */
        if (res == OK)
            res = sx_hashfs_job_new(hashfs, uid, &job, spec->job_type, job_timeout, lock, job_data, job_datalen, nodes);
        sx_nodelist_delete(nodes);
        sx_blob_free(joblb);
        if (res != OK)
            quit_errmsg(rc2http(res), msg_get_reason());
        send_job_info(job);
    }
}
