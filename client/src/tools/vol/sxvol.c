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
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>

#include "cmd_main.h"
#include "cmd_create.h"
#include "cmd_filter.h"

#include "sx.h"
#include "libsx/src/misc.h"
#include "libsx/src/volops.h"
#include "libsx/src/clustcfg.h"
#include "version.h"

struct main_args_info main_args;
struct create_args_info create_args;
struct filter_args_info filter_args;

static sxc_client_t *gsx = NULL;

static void sighandler(int signal)
{
    struct termios tcur;
    if(gsx)
	sxc_shutdown(gsx, signal);

    /* work around for ctrl+c during getpassword() in the aes filter */
    tcgetattr(0, &tcur);
    tcur.c_lflag |= ECHO;
    tcsetattr(0, TCSANOW, &tcur);

    fprintf(stderr, "Process interrupted\n");
    exit(1);
}

static int filter_list(sxc_client_t *sx)
{
	const sxf_handle_t *filters;
	int count, i;

    filters = sxc_filter_list(sx, &count);
    if(!filters) {
	printf("No filters available\n");
	return 1;
    }
    printf("Name\t\tVer\tType\t\tFull name\n");
    printf("----\t\t---\t----\t\t---------\n");
    for(i = 0; i < count; i++) {
         const sxc_filter_t *f = sxc_get_filter(&filters[i]);
	printf("%s\t\t%d.%d\t%s\t%s%s\n", f->shortname, f->version[0], f->version[1], f->tname, strlen(f->tname) >= 8 ? "" : "\t", f->fullname);
    }

    return 0;
}

static int filter_info(sxc_client_t *sx, const char *name)
{
	const sxf_handle_t *filters;
	int count, i, found = 0;

    filters = sxc_filter_list(sx, &count);
    if(!filters) {
	printf("No filters available\n");
	return 1;
    }
    for(i = 0; i < count; i++) {
         const sxc_filter_t *f = sxc_get_filter(&filters[i]);
	if(!strcmp(f->shortname, name)) {
	    printf("'%s' filter details:\n", f->shortname);
	    printf("Full name: %s\n", f->fullname);
	    printf("Summary: %s\n", f->summary);
	    printf("Options: %s\n", f->options ? f->options : "No options");
	    printf("UUID: %s\n", f->uuid);
	    printf("Type: %s\n", f->tname);
	    printf("Version: %d.%d\n", f->version[0], f->version[1]);
	    found = 1;
	}
    }

    if(!found) {
	printf("Filter '%s' not found\n", name);
	return 1;
    }

    return 0;
}

static int volume_create(sxc_client_t *sx, const char *owner)
{
	sxc_cluster_t *cluster;
	sxc_uri_t *uri;
	const char *volname, *suffixes = "kKmMgGtT", *confdir;
	char *ptr, *voldir;
	int ret = 1;
	int64_t size;
	sxc_meta_t *vmeta = NULL;
        const sxc_filter_t *filter = NULL;
	void *cfgdata = NULL;
	unsigned int cfgdata_len = 0;

    size = strtoll(create_args.size_arg, (char **)&ptr, 0);
    if(size < 0 || size == LLONG_MAX) {
	fprintf(stderr, "Bad size %s\n", create_args.size_arg);
	return 1;
    }
    if(*ptr) {
        unsigned int shl;
        ptr = strchr(suffixes, *ptr);
        if(!ptr) {
	    fprintf(stderr, "Bad size %s\n", create_args.size_arg);
            return 1;
        }
        shl = (((ptr-suffixes)/2) + 1) * 10;
        size <<= shl;
    }

    volname = create_args.inputs[0];

    uri = sxc_parse_uri(sx, volname);
    if(!uri) {
	fprintf(stderr, "Bad uri %s: %s\n", volname, sxc_geterrmsg(sx));
	return 1;
    }
    if(!uri->volume) {
	fprintf(stderr, "Bad path %s\n", volname);
	sxc_free_uri(uri);
	return 1;
    }
    if(uri->path) {
	fprintf(stderr, "Bad path %s\n", volname);
	sxc_free_uri(uri);
	return 1;
    }	

    cluster = sxc_cluster_load_and_update(sx, create_args.config_dir_arg, uri->host, uri->profile);
    if(!cluster) {
	fprintf(stderr, "Failed to load config for %s: %s\n", uri->host, sxc_geterrmsg(sx));
	sxc_free_uri(uri);
	return 1;
    }
    confdir = sxi_cluster_get_confdir(cluster);

    /* wipe existing local config */
    voldir = malloc(strlen(confdir) + strlen(uri->volume) + 10);
    if(!voldir) {
	fprintf(stderr, "Out of memory\n");
	sxc_free_uri(uri);
	return 1;
    }
    sprintf(voldir, "%s/volumes/%s", confdir, uri->volume);
    if(!access(voldir, F_OK) && sxi_rmdirs(voldir)) {
	fprintf(stderr, "Can't wipe old volume configuration directory %s\n", voldir);
	sxc_free_uri(uri);
	free(voldir);
	return 1;
    }

    if(create_args.filter_given) {
	    const sxf_handle_t *filters;
	    int fcount, i;
	    char *farg;
	    char uuidcfg[41];

	filters = sxc_filter_list(sx, &fcount);
	if(!filters) {
	    fprintf(stderr, "ERROR: Can't use filter '%s' - no filters available\n", create_args.filter_arg);
	    goto create_err;
	}
	farg = strchr(create_args.filter_arg, '=');
	if(farg)
	    *farg++ = 0;

	vmeta = sxc_meta_new(sx);
	if(!vmeta) {
	    fprintf(stderr, "ERROR: Out of memory\n");
	    goto create_err;
	}

	for(i = 0; i < fcount; i++) {
            const sxc_filter_t *f = sxc_get_filter(&filters[i]);
	    if(!strcmp(f->shortname, create_args.filter_arg)) {
		filter = f;
		uint8_t uuid[16];

		sxi_uuid_parse(f->uuid, uuid);
		if(sxc_meta_setval(vmeta, "filterActive", uuid, 16)) {
		    fprintf(stderr, "ERROR: Can't use filter '%s' - metadata error\n", create_args.filter_arg);
		    sxc_meta_free(vmeta);
		    goto create_err;
		}
		snprintf(uuidcfg, sizeof(uuidcfg), "%s-cfg", f->uuid);
		if(f->configure) {
		    char *fdir = NULL;

		    if(confdir) {
			fdir = malloc(strlen(confdir) + strlen(f->uuid) + strlen(uri->volume) + 11);
			if(!fdir) {
			    fprintf(stderr, "ERROR: Out of memory\n");
			    sxc_meta_free(vmeta);
			    goto create_err;
			}
			sprintf(fdir, "%s/volumes/%s", confdir, uri->volume);
			if(access(fdir, F_OK))
			    mkdir(fdir, 0700);
			sprintf(fdir, "%s/volumes/%s/%s", confdir, uri->volume, f->uuid);
			if(access(fdir, F_OK)) {
			    if(mkdir(fdir, 0700) == -1) {
				fprintf(stderr, "ERROR: Can't create filter configuration directory %s\n", fdir);
				sxc_meta_free(vmeta);
				free(fdir);
				goto create_err;
			    }
			}
		    }
		    if(f->configure(&filters[i], farg, fdir, &cfgdata, &cfgdata_len)) {
			fprintf(stderr, "ERROR: Can't configure filter '%s'\n", create_args.filter_arg);
			sxc_meta_free(vmeta);
			free(fdir);
			goto create_err;
		    }
		    free(fdir);
		    if(cfgdata) {
			if(sxc_meta_setval(vmeta, uuidcfg, cfgdata, cfgdata_len)) {
			    fprintf(stderr, "ERROR: Can't store configuration for filter '%s' - metadata error\n", create_args.filter_arg);
			    sxc_meta_free(vmeta);
			    free(cfgdata);
			    goto create_err;
			}
		    }
		}
		break;
	    }
	}
	if(i == fcount) {
	    fprintf(stderr, "ERROR: Filter '%s' not found\n", create_args.filter_arg);
	    sxc_meta_free(vmeta);
	    goto create_err;
	}
    }

    ret = sxc_volume_add(cluster, uri->volume, size, create_args.replica_arg, vmeta, owner);
    sxc_meta_free(vmeta);

    if(!ret)
	ret = sxi_volume_cfg_store(sx, cluster, uri->volume, filter ? filter->uuid : NULL, cfgdata, cfgdata_len);
    free(cfgdata);
    if(ret)
	fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
    else
	printf("Volume '%s' (replica: %d, size: %lld) created.\n", uri->volume, create_args.replica_arg, (long long) size);

create_err:
    if(ret && voldir && !access(voldir, F_OK))
	sxi_rmdirs(voldir);

    free(voldir);
    sxc_free_uri(uri);
    sxc_cluster_free(cluster);
    return ret;
}

static int setup_filters(sxc_client_t *sx, const char *fdir)
{
	char *filter_dir;

    if(fdir) {
	filter_dir = strdup(fdir);
    } else {
	const char *pt = getenv("SX_FILTER_DIR");
	if(pt)
	    filter_dir = strdup(pt);
	else
	    filter_dir = strdup(SX_FILTER_DIR);
    }
    if(!filter_dir) {
	fprintf(stderr, "Failed to set filter dir\n");
	return 1;
    }
    sxc_filter_loadall(sx, filter_dir);
    free(filter_dir);
    return 0;
}

int main(int argc, char **argv) {
    int ret = 0;
    sxc_client_t *sx;
    sxc_logger_t log;

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    if(!(sx = gsx = sxc_init(SRC_VERSION, sxc_default_logger(&log, argv[0]), sxi_yesno))) {
	if(!strcmp(SRC_VERSION, sxc_get_version()))
	    fprintf(stderr, "Version mismatch: our version '%s' - library version '%s'\n", SRC_VERSION, sxc_get_version());
	else
	    fprintf(stderr, "Failed to init libsx\n");
	return 1;
    }

    if(argc < 2) {
	printf("No command specified (see 'sxvol --help')\n");
	return 1;
    }

    if(!strcmp(argv[1], "create")) {
	if(create_cmdline_parser(argc - 1, &argv[1], &create_args)) {
	    ret = 1;
	    goto main_err;
	}

	if(create_args.version_given) {
	    printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, SRC_VERSION);
	    goto main_err;
	}

	if(create_args.inputs_num != 1) {
	    fprintf(stderr, "ERROR: Invalid number of arguments (see 'sxvol create --help')\n");
	    create_cmdline_parser_free(&create_args);
	    ret = 1;
	    goto main_err;
	}

	sxc_set_debug(sx, create_args.debug_flag);

	if(setup_filters(sx, create_args.filter_dir_arg)) {
	    create_cmdline_parser_free(&create_args);
	    ret = 1;
	    goto main_err;
	}

	ret = volume_create(sx, create_args.owner_arg);
	create_cmdline_parser_free(&create_args);

    } else if(!strcmp(argv[1], "filter")) {
	if(argc < 3) {
	    fprintf(stderr, "ERROR: No option given (see 'sxvol filter --help')\n");
	    ret = 1;
	    goto main_err;
	}

	if(filter_cmdline_parser(argc - 1, &argv[1], &filter_args)) {
	    ret = 1;
	    goto main_err;
	}

	if(filter_args.version_given) {
	    printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, SRC_VERSION);
	    goto main_err;
	}

	sxc_set_debug(sx, filter_args.debug_flag);

	if(setup_filters(sx, filter_args.filter_dir_arg)) {
	    filter_cmdline_parser_free(&filter_args);
	    ret = 1;
	    goto main_err;
	}

	if(filter_args.list_given)
	    ret = filter_list(sx);
	else if(filter_args.info_given)
	    ret = filter_info(sx, filter_args.info_arg);
	else {
	    fprintf(stderr, "ERROR: Invalid arguments (see 'sxvol filter --help')\n");
	    ret = 1;
	    goto main_err;
	}

	filter_cmdline_parser_free(&filter_args);

    } else {
	if(argc > 2) {
	    fprintf(stderr, "ERROR: Unknown command '%s'\n", argv[1]);
	    ret = 1;
	    goto main_err;
	}

	if(main_cmdline_parser(argc, argv, &main_args)) {
	    ret = 1;
	    goto main_err;
	}

	if(main_args.version_given) {
	    printf("%s %s\n", MAIN_CMDLINE_PARSER_PACKAGE, SRC_VERSION);
	} else {
	    fprintf(stderr, "ERROR: Unknown command '%s'\n", argv[1]);
	    ret = 1;
	}
	main_cmdline_parser_free(&main_args);
    }

main_err:

    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    sxc_shutdown(sx, 0);

    return ret;
}
