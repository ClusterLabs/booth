MAINTAINERCLEANFILES	= Makefile.in

AM_CFLAGS		= -fPIC -Werror -funsigned-char -Wno-pointer-sign


AM_CPPFLAGS		= -I$(top_builddir)/include

sbin_PROGRAMS		= boothd

boothd_SOURCES	 	= attr.c config.c handler.c main.c \
			  manual.c pacemaker.c raft.c request.c \
			  ticket.c transport.c utils.c

noinst_HEADERS		= attr.h booth.h config.h handler.h log.h \
			  manual.h pacemaker.h raft.h request.h \
			  ticket.h transport.h utils.h

if BUILD_TIMER_C
boothd_SOURCES += timer.c
endif

if BUILD_AUTH_C
boothd_SOURCES += auth.c
endif

boothd_LDFLAGS		= $(OS_DYFLAGS) -L./
boothd_LDADD		= -lm $(GLIB_LIBS) $(ZLIB_LIBS)
boothd_CFLAGS		= $(GLIB_CFLAGS)

if !LOGGING_LIBQB
boothd_LDADD		+= -lplumb
else
boothd_LDADD		+= $(LIBQB_LIBS)
boothd_SOURCES		+= alt/logging_libqb.c
noinst_HEADERS		+= alt/logging_libqb.h
endif

if !RANGE2RANDOM_GLIB
boothd_LDADD		+= -lplumb
else
boothd_LDADD		+= $(GLIB_LIBS)
boothd_SOURCES		+= alt/range2random_glib.c
noinst_HEADERS		+= alt/range2random_glib.h
endif

if !NAMETAG_LIBSYSTEMD
boothd_LDADD		+= -lplumbgpl
else
boothd_LDADD		+= $(LIBSYSTEMD_LIBS)
boothd_SOURCES		+= alt/nametag_libsystemd.c
noinst_HEADERS		+= alt/nametag_libsystemd.h
endif

if COREDUMP_NURSING
boothd_LDADD		+= -lplumb
endif

lint:
	-splint $(INCLUDES) $(LINT_FLAGS) $(CFLAGS) *.c
