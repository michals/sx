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

#include "sx.h"
#include "cmdline.h"
#include "version.h"
#include "libsx/src/misc.h"
#include "libsx/src/clustcfg.h"

static sxc_client_t *sx = NULL;

static void sighandler(int signal)
{
    if(sx)
	sxc_shutdown(sx, signal);
    fprintf(stderr, "Process interrupted\n");
    exit(1);
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
    	free(filter_dir);
	return 1;
    }
    sxc_filter_loadall(sx, filter_dir);
    free(filter_dir);
    return 0;
}

static const char* get_filter_name(const char *uuid_string, const sxf_handle_t *filters, int filters_count) {
    int i = 0;

    /* Check if input is not bad */
    if( !uuid_string || !filters || filters_count <= 0 ) {
	return NULL;
    }

    /* Iterate over filters to find the right one */
    for(i = 0; i < filters_count; i++) {
        const sxc_filter_t *f = sxc_get_filter(&filters[i]);
        if(strncmp(f->uuid, uuid_string, 36)) continue; /* Leave this step loop if this is not right filter */
        return f -> shortname;
    }
    /* No filter has been found */
    return NULL;
}

/* Change file size into human readable form, e.g. 1.34T. 
 * Remember to free result of this function.
*/
static char *process_size(long long size){
    double dsize = (double)size;
    int i = 0;
    const char *units[] = { "", "K", "M", "G", "T", "P" };
    char buffer[20];
    while( dsize > 1024 ) {
        dsize /= 1024;
        i++;
    }

    if(i >= sizeof(units)/sizeof(const char*)) return NULL;
    if(i)
	snprintf(buffer, sizeof(buffer), "%.2f%s", dsize, units[i]);
    else
	snprintf(buffer, sizeof(buffer), "%u", (unsigned int) size);

    return strdup(buffer);
}

int main(int argc, char **argv) {
    int ret = 0;
    unsigned int i;
    sxc_cluster_t *cluster;
    sxc_uri_t *u;
    struct gengetopt_args_info args;
    sxc_logger_t log;
    char remote_filter_uuid[37]; 
    int filters_count = 0;
    const sxf_handle_t *filters = NULL;

    if(cmdline_parser(argc, argv, &args))
	exit(1);

    if(args.version_given) {
	printf("%s %s\n", CMDLINE_PARSER_PACKAGE, SRC_VERSION);
	cmdline_parser_free(&args);
	exit(0);
    }

    if(!args.inputs_num) {
	fprintf(stderr, "Wrong number of arguments (see --help)\n");
	cmdline_parser_free(&args);
	exit(1);
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    if(!(sx = sxc_init(SRC_VERSION, sxc_default_logger(&log, argv[0]), sxi_yesno))) {
	cmdline_parser_free(&args);
	return 1;
    }

    sxc_set_verbose(sx, args.verbose_flag);
    sxc_set_debug(sx, args.debug_flag);

    for(i = 0; i < args.inputs_num; i++) {
	u = sxc_parse_uri(sx, args.inputs[i]);
	if(!u) {
	    fprintf(stderr, "Error parsing URI %s: %s\n", args.inputs[i], sxc_geterrmsg(sx));
	    ret = 1;
	    continue;
	}

	cluster = sxc_cluster_load_and_update(sx, args.config_dir_arg, u->host, u->profile);
	if(!cluster) {
	    fprintf(stderr, "Failed to load config for %s: %s\n", u->host, sxc_geterrmsg(sx));
	    sxc_free_uri(u);
	    ret = 1;
	    continue;
	}

	if(args.long_format_given) {
	    if(setup_filters(sx, args.filter_dir_arg) ) {
		sxc_free_uri(u);
		ret = 1;
		continue;
	    }

	    filters = sxc_filter_list(sx, &filters_count);
	    if(!filters) {
	    	fprintf(stderr, "Failed to load filters\n");
		sxc_free_uri(u);
		ret = 1;
		continue;
	    }
	}

	if(!u->volume) {
	    sxc_cluster_lv_t *fv = sxc_cluster_listvolumes(cluster);
	    if(fv) {
		while(1) {
		    char *vname;
		    int64_t vsize;
		    unsigned int vreplica;
		    int n = sxc_cluster_listvolumes_next(fv, &vname, &vsize, &vreplica);
		    if(n<=0) {
			if(n)
			    fprintf(stderr, "Failed to retrieve file name for %s\n", args.inputs[i]);
			break;
		    }

		    if(args.long_format_given) {
			sxc_meta_t *vmeta = NULL;
			const void *mval = NULL;
			unsigned int mval_len;
			sxc_file_t* volume_file = NULL;
			const char *filter_name = NULL;
                        char *human_str = NULL;

			/* Initialize volume file structure */
			if(!(volume_file = sxc_file_remote(cluster, vname, NULL))) {
			    fprintf(stderr, "%s\n", "sxc_file_remote failed!\n");
			    free(vname);
			    break;
			}

			/* Retrieve metainformation about volume */
			if(!(vmeta = sxc_volumemeta_new(volume_file))) {
			    fprintf(stderr, "Failed to retrieve meta information for %s\n", args.inputs[i]);
			    sxc_file_free(volume_file);
			    free(vname);
			    break;
			}

			if(vmeta && !sxc_meta_getval(vmeta, "filterActive", &mval, &mval_len)) {
			    if(mval_len != 16) {
				filter_name = "*invalid*";
			    } else {
				sxi_uuid_unparse(mval, remote_filter_uuid);
				filter_name = get_filter_name(remote_filter_uuid, filters, filters_count);
				if(!filter_name)
				    filter_name = "*unknown*";
			    }
			} else {
			    filter_name = "-";
			}

			printf("    VOL %-3u %10s", vreplica, filter_name);

			sxc_file_free(volume_file);
			sxc_meta_free(vmeta);

		        if(args.human_readable_flag && (human_str = process_size((long long)vsize))) {
                            printf("      %12s ", human_str);
                            free(human_str);
			} else {
			    printf("      %12lld ", (long long)vsize);
			}
		    }

		    if(u->profile)
			printf("sx://%s@%s/%s\n", u->profile, u->host, vname);
		    else
			printf("sx://%s/%s\n", u->host, vname);
		    free(vname);
		}
		sxc_cluster_listvolumes_free(fv);
	    } else {
		fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
                ret = 1;
            }
	} else {
	    sxc_cluster_lf_t *fl = sxc_cluster_listfiles(cluster, u->volume, u->path, args.recursive_flag, NULL, NULL, NULL, 0);
	    if(fl) {
		while(1) {
		    char *fname;
		    int64_t fsize;
		    time_t ftime;
                    char *human_str = NULL;
		    int n = sxc_cluster_listfiles_next(fl, &fname, &fsize, &ftime);
		    if(n<=0) {
			if(n)
			    fprintf(stderr, "Failed to retrieve file name for %s\n", args.inputs[i]);
			break;
		    }

		    if(args.long_format_given) {
			unsigned int namelen = strlen(fname);
			if(namelen && fname[namelen-1] == '/')
			    printf("    DIR                       ");
			else {
			    struct tm *gt = gmtime(&ftime);
			    printf("%04d-%02d-%02d %02d:%02d ",
				   gt->tm_year + 1900,
				   gt->tm_mon + 1,
				   gt->tm_mday,
				   gt->tm_hour,
				   gt->tm_min);
			    if(args.human_readable_flag  && (human_str = process_size((long long)fsize))) {
				printf("%12s ", human_str);
				free(human_str);
			    } else {
				printf("%12lld ", (long long)fsize);
			    }
		        } 
		    }
		    if(u->profile)
			printf("sx://%s@%s/%s%s\n", u->profile, u->host, u->volume, fname);
		    else
			printf("sx://%s/%s%s\n", u->host, u->volume, fname);
		    free(fname);
		}
		sxc_cluster_listfiles_free(fl);
	    } else {
		fprintf(stderr, "ERROR: %s\n", sxc_geterrmsg(sx));
                ret = 1;
            }
	}
	sxc_cluster_free(cluster);
	sxc_free_uri(u);
    }

    cmdline_parser_free(&args);
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    sxc_shutdown(sx, 0);
    return ret;
}
