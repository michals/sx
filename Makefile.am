SUBDIRS=
if BUILD_CHECK
SUBDIRS += 3rdparty/check
endif
if BUILD_LIBFCGI
SUBDIRS += 3rdparty/fcgi
endif
if BUILD_SXHTTPD
SUBDIRS += 3rdparty/sxhttpd
endif
if BUILD_YAJL
SUBDIRS += 3rdparty/yajl_build
endif
EXTRA_DIST=3rdparty/yajl 3rdparty/nginx 3rdparty/check 3rdparty/fcgi 3rdparty/sxhttpd 3rdparty/yajl_build

SUBDIRS += libsx client server
DIST_SUBDIRS = $(SUBDIRS)

clean-local:
	rm -f test-suite.log

test: check
	true
