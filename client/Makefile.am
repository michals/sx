ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src/filters/null src/filters/zcomp src/filters/attribs src/filters/aes256

AM_CPPFLAGS = -I $(top_srcdir)/../libsx/include -I $(top_srcdir)/../ -DSX_FILTER_DIR=\"$(pkglibdir)\"

bin_PROGRAMS = src/tools/init/sxinit src/tools/ls/sxls src/tools/cp/sxcp src/tools/cat/sxcat src/tools/vol/sxvol src/tools/acl/sxacl src/tools/sxreport-client/sxreport-client src/tools/rm/sxrm

src_tools_init_sxinit_SOURCES = \
	src/tools/init/sxinit.c \
	src/tools/init/cmdline.c \
	src/tools/init/cmdline.h
src_tools_init_sxinit_LDADD = $(top_builddir)/../libsx/src/libsx.la

src_tools_sxreport_client_sxreport_client_SOURCES = \
	src/tools/sxreport-client/sxreport-client.c \
	src/tools/sxreport-client/cmdline.c \
	src/tools/sxreport-client/cmdline.h
src_tools_sxreport_client_sxreport_client_LDADD = $(top_builddir)/../libsx/src/libsx.la
src_tools_sxreport_client_sxreport_client_CPPFLAGS = $(AM_CPPFLAGS)\
			-DINFO_CPPFLAGS="\"$(CPPFLAGS)\""\
			-DINFO_CFLAGS="\"$(AM_CFLAGS) $(CFLAGS)\""\
			-DINFO_LDFLAGS="\"$(AM_LDFLAGS) $(LDFLAGS)\""\
			-DINFO_SYSCONFDIR="\"$(sysconfdir)\""\
			-DINFO_BINDIR="\"$(bindir)\""\
			-DINFO_LOCALSTATEDIR="\"$(localstatedir)\""


src_tools_ls_sxls_SOURCES = \
	src/tools/ls/sxls.c \
	src/tools/ls/cmdline.c \
	src/tools/ls/cmdline.h
src_tools_ls_sxls_LDADD = $(top_builddir)/../libsx/src/libsx.la

src_tools_cp_sxcp_SOURCES = \
	src/tools/cp/sxcp.c \
	src/tools/cp/cmdline.c \
	src/tools/cp/cmdline.h
src_tools_cp_sxcp_LDADD = $(top_builddir)/../libsx/src/libsx.la

src_tools_cat_sxcat_SOURCES = \
	src/tools/cat/sxcat.c \
	src/tools/cat/cmdline.c \
	src/tools/cat/cmdline.h
src_tools_cat_sxcat_LDADD = $(top_builddir)/../libsx/src/libsx.la

src_tools_vol_sxvol_SOURCES = \
	src/tools/vol/sxvol.c \
	src/tools/vol/cmd_main.c \
	src/tools/vol/cmd_main.h \
	src/tools/vol/cmd_create.c \
	src/tools/vol/cmd_create.h \
	src/tools/vol/cmd_filter.c \
	src/tools/vol/cmd_filter.h

src_tools_vol_sxvol_LDADD = $(top_builddir)/../libsx/src/libsx.la

src_tools_acl_sxacl_SOURCES = \
	src/tools/acl/sxacl.c \
	src/tools/acl/cmd_main.c \
	src/tools/acl/cmd_perm.c \
	src/tools/acl/cmd_list.c \
	src/tools/acl/cmd_useradd.c \
	src/tools/acl/cmd_userlist.c \
	src/tools/acl/cmd_usergetkey.c \
	src/tools/acl/cmd_main.h \
	src/tools/acl/cmd_perm.h \
	src/tools/acl/cmd_list.h \
	src/tools/acl/cmd_useradd.h \
	src/tools/acl/cmd_userlist.h
src_tools_acl_sxacl_LDADD = $(top_builddir)/../libsx/src/libsx.la

src_tools_rm_sxrm_SOURCES = \
	src/tools/rm/sxrm.c \
	src/tools/rm/cmdline.c \
	src/tools/rm/cmdline.h
src_tools_rm_sxrm_LDADD = $(top_builddir)/../libsx/src/libsx.la
