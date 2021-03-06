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

static sxc_client_t *sx = NULL;

static void sighandler(int signal)
{
    if(sx)
	sxc_shutdown(sx, signal);
    fprintf(stderr, "Process interrupted\n");
    exit(1);
}


int main(int argc, char **argv) {
    sxc_client_t *sx;
    int ret = 0;
    unsigned int i;
    struct gengetopt_args_info args;
    sxc_logger_t log;
    sxc_cluster_t *cluster = NULL;
    sxc_file_list_t *lst = NULL;

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

    lst = sxc_file_list_new(sx, args.recursive_given);
    for(i = 0; lst && i < args.inputs_num; i++) {
        const char *url = args.inputs[i];
        sxc_file_t *target = sxc_file_from_url(sx, &cluster, args.config_dir_arg, url);
        if (!target) {
            fprintf(stderr,"Error processing URL '%s': %s\n", url, sxc_geterrmsg(sx));
            ret = 1;
            break;
        }
        if (!sxc_file_is_sx(target)) {
            fprintf(stderr,"Will not remove local file '%s'\n", url);
            ret = 1;
        }
        if (sxc_file_list_add(lst, target, 1)) {
            fprintf(stderr,"Cannot add file list entry '%s': %s\n", url, sxc_geterrmsg(sx));
            ret = 1;
            sxc_file_free(target);
        }
    }
    if (sxc_rm(lst)) {
        fprintf(stderr,"Failed to remove file(s): %s\n", sxc_geterrmsg(sx));
        ret = 1;
    }
    printf("Deleted %d file(s)\n", sxc_file_list_get_successful(lst));
    sxc_file_list_free(lst);
    sxc_cluster_free(cluster);

    cmdline_parser_free(&args);
    sxc_shutdown(sx, 0);
    return ret;
}
