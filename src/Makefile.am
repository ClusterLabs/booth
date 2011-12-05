MAINTAINERCLEANFILES	= Makefile.in

AM_CFLAGS		= -fPIC

INCLUDES		= -I$(top_builddir)/include

sbin_PROGRAMS		= boothd

boothd_SOURCES	 	= config.c main.c paxos.c ticket.c  transport.c \
			  log.c pacemaker.c paxos_lease.c timer.c

boothd_LDADD	  	= -lpthread
boothd_LDFLAGS		= $(OS_DYFLAGS) -L./

noinst_HEADERS		= booth.h list.h pacemaker.h paxos_lease.h timer.h \
			  config.h log.h paxos.h ticket.h transport.h

lint:
	-splint $(INCLUDES) $(LINT_FLAGS) $(CFLAGS) *.c
