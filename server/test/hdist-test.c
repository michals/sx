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

/* run with --debug to get the spam */

#include "default.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "hdist.h"
#include "utils.h"
#include "nodes.h"
#include "log.h"
#include "init.h"

#define MAXBUILDS 2
static int dbg = 0;

uint64_t hashes[] = {	0x855594d66b4839d3LL, 0x76992ccc2b51ad85LL,
			0xfa8ed848438c498bLL, 0x1c1f96193cdf14b8LL,
			0xd8472a3d6d156626LL, 0x20c358f7ee877a3fLL,
			0x76992ccc2b51ad85LL, 0x9031e875f6787a94LL,
			0x5690ff1bf6d3239fLL, 0xf6b93a8fa6b9ad9cLL,
			0xc7831e7f58d4acc4LL, 0xce59202a83b6d11fLL,
			0x0a4c09fca0d8ae3dLL, 0x64ee5a8b44b4bccdLL
		    };

const struct _nodes {
    const char *uuid;
    const char *addr;
    const char *int_addr;
    uint64_t capacity;
} nodes[] = {
    { "6def60c0-89c5-4613-9299-7195a6a703ec", "127.0.0.1", "127.0.1.1", 1000000	},
    { "afd667cb-f1eb-4f28-8d0f-0c3d3db19e0b", "127.0.0.2", "127.0.1.2", 3000000 },
    { "465fe5ba-1860-42e9-85d5-2766c423cb5b", "127.0.0.3", "127.0.1.3", 5000000 },
    { "b7a86616-e1bf-4fbc-b359-c7e4d2639dcd", "127.0.0.4", "127.0.1.4", 5500000 },
    { "e3b945a7-a0d4-41f0-941c-ab22770dc555", "127.0.0.5", "127.0.1.5", 6000000 },
    { "58bdbe66-60ee-434f-b691-4e6a94516552", "127.0.0.6", "127.0.1.6", 6800000 },
    { "289b762b-00b7-4877-83c8-1209e5b97914", "127.0.0.7", "127.0.1.7", 7700000 },
    { "9cdc0c7c-c3e2-42b9-a798-70c08821197a", "127.0.0.8", "127.0.1.8", 9000000 },
    { "300d77c5-6859-484e-9e65-ade5ab8c2d00", "127.0.0.9", "127.0.1.9", 9100000 },
    { "d29c5622-04cb-4d92-aba4-52f32d8b0a16", "127.0.0.10", "127.0.1.10", 10000000 }
};

#define FINAL_CHECKSUM -7428575550933394894LL

int locate_cmp(sxi_hdist_t *model1, sxi_hdist_t *model2, uint64_t hash, int replica, int bidx)
{
    sx_nodelist_t *nodelist1, *nodelist2;
    int i;

    nodelist1 = sxi_hdist_locate(model1, hash, replica, bidx);
    if(!nodelist1) {
	CRIT("Can't locate hash with model1");
	return 1;
    }

    nodelist2 = sxi_hdist_locate(model2, hash, replica, bidx);
    if(!nodelist1) {
	CRIT("Can't locate hash with model2");
	sx_nodelist_delete(nodelist1);
	return 1;
    }

    if(sx_nodelist_count(nodelist1) != sx_nodelist_count(nodelist2) || sx_nodelist_count(nodelist1) != replica) {
	CRIT("Numbers of target nodes don't match");
	sx_nodelist_delete(nodelist1);
	sx_nodelist_delete(nodelist2);
	return 1;
    }

    if(dbg)
	fprintf(stderr, "Locate (hash: %llx, replica: %u, bidx: %d) = ", (unsigned long long) hash, replica, bidx);
    for(i = 0; i < sx_nodelist_count(nodelist1); i++) {
	if(strcmp(sx_node_uuid_str(sx_nodelist_get(nodelist1, i)), sx_node_uuid_str(sx_nodelist_get(nodelist2, i)))) {
	    CRIT("Different nodes reported for duplicate models");
	    sx_nodelist_delete(nodelist1);
	    sx_nodelist_delete(nodelist2);
	    return 1;
	}
	if(dbg)
	    fprintf(stderr, "%s ", sx_node_addr(sx_nodelist_get(nodelist1, i)));
    }
    if(dbg)
	fprintf(stderr, "\n");
    sx_nodelist_delete(nodelist1);
    sx_nodelist_delete(nodelist2);
    return 0;
}

int print_nodes(sxi_hdist_t *model, int bidx)
{
    const sx_nodelist_t *nodelist;
    int i;

    nodelist = sxi_hdist_nodelist(model, bidx);
    if(!nodelist)
	return 1;
    fprintf(stderr, "Nodelist[%d]: ", bidx);
    for(i = 0; i < sx_nodelist_count(nodelist); i++)
	fprintf(stderr, "%s, ", sx_node_addr(sx_nodelist_get(nodelist, i)));
    fprintf(stderr, "\n");
    return 0;
}

int main(int argc, char **argv)
{
    sxi_hdist_t *hdist = NULL, *hdist2 = NULL;
    unsigned int i, j, cfg_len;
    sx_uuid_t uuid;
    const sx_nodelist_t *nodelist;
    const sx_node_t *node;
    const void *cfg;
    int ret = 1;
    sxc_client_t *sx = server_init(NULL, NULL, NULL, 0, argc, argv);

    if(argc == 2 && !strcmp(argv[1], "--debug")) {
	log_setminlevel(sx, SX_LOG_DEBUG);
	dbg = 1;
    }

    if(!(hdist = sxi_hdist_new(1337, MAXBUILDS, NULL))) {
	CRIT("Can't build hdist");
	return 1;
    }

    for(i = 0; i < 5; i++) {
	uuid_from_string(&uuid, nodes[i].uuid);
	if(sxi_hdist_addnode(hdist, &uuid, nodes[i].addr, nodes[i].int_addr, nodes[i].capacity)) {
	    CRIT("addnode failed (1)");
	    goto main_err;
	}
    }

    if(sxi_hdist_build(hdist) != OK) {
	CRIT("Can't build distribution model (1)");
	goto main_err;
    }

    if(sxi_hdist_newbuild(hdist) != OK) {
	CRIT("Can't create new build (1)");
	goto main_err;
    }

    /* get nodes from build 1 (previous 0) */
    nodelist = sxi_hdist_nodelist(hdist, 1);
    if(!nodelist) {
	CRIT("sxi_hdist_nodelist failed");
	goto main_err;
    }
    DEBUG("Re-adding %d nodes from previous build", sx_nodelist_count(nodelist));
    for(i = 0; i < sx_nodelist_count(nodelist); i++) {
	node = sx_nodelist_get(nodelist, i);
	if(sxi_hdist_addnode(hdist, sx_node_uuid(node), sx_node_addr(node), sx_node_internal_addr(node), sx_node_capacity(node))) {
	    CRIT("addnode failed (2)");
	    goto main_err;
	}
    }

    DEBUG("Adding 3 new nodes");
    /* add 3 new nodes */
    for(i = 5; i < 8; i++) {
	uuid_from_string(&uuid, nodes[i].uuid);
	if(sxi_hdist_addnode(hdist, &uuid, nodes[i].addr, nodes[i].int_addr, nodes[i].capacity)) {
	    CRIT("addnode failed (3)");
	    goto main_err;
	}
    }

    if(sxi_hdist_build(hdist) != OK) {
	CRIT("Can't build distribution model (2)");
	goto main_err;
    }

    DEBUG("Number of builds: %d", sxi_hdist_buildcnt(hdist));

    DEBUG("Assuming the cluster was rebalanced");
    if(sxi_hdist_rebalanced(hdist) != OK) {
	CRIT("sxi_hdist_rebalanced failed");
	goto main_err;
    }

    DEBUG("Creating new build");
    if(sxi_hdist_newbuild(hdist) != OK) {
	CRIT("Can't create new build (2)");
	goto main_err;
    }

    /* get nodes from build 1 (previous 0) */
    nodelist = sxi_hdist_nodelist(hdist, 1);
    if(!nodelist) {
	CRIT("sxi_hdist_nodelist failed");
	goto main_err;
    }
    DEBUG("Re-adding %d nodes from previous build", sx_nodelist_count(nodelist));
    for(i = 0; i < sx_nodelist_count(nodelist); i++) {
	node = sx_nodelist_get(nodelist, i);
	if(sxi_hdist_addnode(hdist, sx_node_uuid(node), sx_node_addr(node), sx_node_internal_addr(node), sx_node_capacity(node))) {
	    CRIT("addnode failed (4)");
	    goto main_err;
	}
    }

    DEBUG("Adding 2 new nodes");
    /* add 2 new nodes */
    for(i = 8; i < 10; i++) {
	uuid_from_string(&uuid, nodes[i].uuid);
	if(sxi_hdist_addnode(hdist, &uuid, nodes[i].addr, nodes[i].int_addr, nodes[i].capacity)) {
	    CRIT("addnode failed (4)");
	    goto main_err;
	}
    }

    if(sxi_hdist_build(hdist) != OK) {
	CRIT("Can't build distribution model (3)");
	goto main_err;
    }
    DEBUG("Number of builds: %d", sxi_hdist_buildcnt(hdist));

    if(dbg) {
	print_nodes(hdist, 0);
	print_nodes(hdist, 1);
    }

    if((uint64_t) FINAL_CHECKSUM != sxi_hdist_checksum(hdist)) {
	CRIT("Unexpected checksum: %lld", (long long int) sxi_hdist_checksum(hdist));
	goto main_err;
    }

    DEBUG("*** Creating exact copy of HDIST based on existing config ***");
    if(sxi_hdist_get_cfg(hdist, &cfg, &cfg_len)) {
	CRIT("Can't get config");
	goto main_err;
    } else {
	DEBUG("Compressed config size: %u", (unsigned int) cfg_len);
    }

    if(!(hdist2 = sxi_hdist_from_cfg(cfg, cfg_len))) {
	CRIT("Can't build HDIST from config");
	goto main_err;
    }

    if(!sxi_hdist_same_origin(hdist, hdist2)) {
	CRIT("UUIDs are different for old and new model");
	goto main_err;
    }

    if(sxi_hdist_checksum(hdist) != sxi_hdist_checksum(hdist2)) {
	CRIT("Checksums don't match for original and copied build");
	goto main_err;
    } else {
	DEBUG("Models' checksums OK");
    }

    /* test bidx 0 (10 nodes) */
    for(i = 0; i < sizeof(hashes) / 8; i++)
	for(j = 1; j <= 10; j++)
	    if(locate_cmp(hdist, hdist2, hashes[i], j, 0))
		goto main_err;

    /* test bidx 1 (8 nodes) */
    for(i = 0; i < sizeof(hashes) / 8; i++)
	for(j = 1; j <= 8; j++)
	    if(locate_cmp(hdist, hdist2, hashes[i], j, 1))
		goto main_err;

    ret = 0;

main_err:

    sxi_hdist_free(hdist);
    sxi_hdist_free(hdist2);
    server_done(&sx);
    return ret;
}
