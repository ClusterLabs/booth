# Copyright (c) 2009 Red Hat, Inc.
#
# Authors: Andrew Beekhof
#	   Steven Dake (sdake@redhat.com)
#
# This software licensed under BSD license, the text of which follows:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# - Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
# - Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# - Neither the name of the MontaVista Software, Inc. nor the names of its
#   contributors may be used to endorse or promote products derived from this
#   software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.

SPEC			= $(PACKAGE_NAME).spec

TARFILE			= $(PACKAGE_NAME)-$(VERSION).tar.gz

EXTRA_DIST		= autogen.sh conf/booth.conf.example \
			  script/booth-keygen script/lsb script/ocf script/service-runnable.in script/crmv1.in \
			  script/unit-test.py.in script/wireshark-dissector.lua \
			  test/arbtests.py test/assertions.py test/booth_path test/boothrunner.py \
			  test/boothtestenv.py.in test/clientenv.py test/clienttests.py test/live_test.sh \
			  test/runtests.py.in test/serverenv.py test/servertests.py test/sitetests.py \
			  test/utils.py \
			  unit-tests \
			  contrib \
			  icons \
			  $(SPEC).in booth-rpmlintrc \
			  .version build-aux/git-version-gen build-aux/PKG_CHECK_VAR.m4 \
			  build-aux/gitlog-to-changelog build-aux/release.mk

AUTOMAKE_OPTIONS	= foreign

MAINTAINERCLEANFILES	= Makefile.in aclocal.m4 configure depcomp \
			  config.guess config.sub missing install-sh \
			  autoheader automake autoconf test_lense.sh \
			  compile

# Don't try to install files outside build directory for "make distcheck".
AM_DISTCHECK_CONFIGURE_FLAGS = --with-ocfdir="$$dc_install_base/lib/ocf"

dist_doc_DATA		= AUTHORS README COPYING README.upgrade-from-v0.1 README-testing

boothconfdir		= ${BOOTHSYSCONFDIR}

boothconf_DATA		= conf/booth.conf.example

boothsitedir		= $(ocfdir)/resource.d/pacemaker
boothsite_SCRIPTS	= script/ocf/booth-site

boothocfdir		= $(ocfdir)/resource.d/booth
boothocf_SCRIPTS	= script/ocf/sharedrsc script/ocf/geostore

boothocflibdir		= $(ocfdir)/lib/booth
boothocflib_DATA	= script/ocf/geo_attr.sh

bootharbitratordir	= ${INITDDIR}

bootharbitrator_SCRIPTS	= script/lsb/booth-arbitrator

boothnoarchdir		= $(datadir)/$(PACKAGE_NAME)

nodist_boothnoarch_SCRIPTS = script/service-runnable

sbin_SCRIPTS		= script/booth-keygen

pkgconfigdir		= $(datadir)/pkgconfig
pkgconfig_DATA		= booth.pc

TESTS			= test/runtests.py

SUBDIRS			= src docs conf

coverity:
	cov-build --dir=cov make
	cov-analyze --dir cov --concurrency --wait-for-license
	cov-format-errors --dir cov

install-exec-local:
	$(INSTALL) -d $(DESTDIR)/${boothconfdir}
	$(INSTALL) -d $(DESTDIR)/${bootharbitratordir}
	$(INSTALL) -d $(DESTDIR)/${boothsitedir}
	$(INSTALL) -d $(DESTDIR)/${boothocfdir}
	$(INSTALL) -d $(DESTDIR)/${BOOTH_LIB_DIR} -m 750
	-chown $(CRM_DAEMON_USER):$(CRM_DAEMON_GROUP) $(DESTDIR)/${BOOTH_LIB_DIR} 
	$(INSTALL) -d $(DESTDIR)/${BOOTH_CORE_DIR} -m 750
	-chown $(CRM_DAEMON_USER):$(CRM_DAEMON_GROUP) $(DESTDIR)/${BOOTH_CORE_DIR}

install-exec-hook:
	ln -sf ${sbindir}/boothd $(DESTDIR)/${sbindir}/booth
	ln -sf ${sbindir}/boothd $(DESTDIR)/${sbindir}/geostore

uninstall-local:
	rmdir $(DESTDIR)/${boothconfdir} || :;
	rmdir $(DESTDIR)/${bootharbitratordir} || :;
	rmdir $(DESTDIR)/${boothsitedir} || :;
	rmdir $(DESTDIR)/${BOOTH_CORE_DIR} || :;
	rmdir $(DESTDIR)/${BOOTH_LIB_DIR} || :;

test: check

lint:
	for dir in src; do make -C $$dir lint; done

clean-local:
	rm -rf test/*.pyc test/__pycache__ test/runtests.py test/boothtestenv.py cov* $(SPEC)

dist-clean-local:
	rm -f autoconf automake autoheader

# release/versioning
BUILT_SOURCES = .version
.version:
	echo $(VERSION) > $@-t && mv $@-t $@

dist-hook: gen-ChangeLog
	echo $(VERSION) > $(distdir)/.tarball-version


test/runtests.py: test/runtests.py.in test/boothtestenv.py
	rm -f $@-t $@
	mkdir -p ${abs_top_builddir}/test
	sed \
	    -e 's#PYTHON_SHEBANG#${PYTHON_SHEBANG}#g' \
	    -e 's#TEST_SRC_DIR#${abs_top_srcdir}/test#g' \
	    -e 's#TEST_BUILD_DIR#${abs_top_builddir}/test#g' \
		$< > $@-t;
	chmod a-w $@-t
	chmod u+x $@-t
	mv $@-t $@

test/boothtestenv.py: test/boothtestenv.py.in
	rm -f $@-t $@
	mkdir -p ${abs_top_builddir}/test
	sed \
	    -e 's#TEST_SRC_DIR#${abs_top_srcdir}/test#g' \
	    -e 's#TEST_BUILD_DIR#${abs_top_builddir}/test#g' \
		$< > $@-t;
	chmod a-w $@-t
	mv $@-t $@

## make rpm/srpm section.
$(abs_builddir)/booth-rpmlintrc:
	cat $(abs_srcdir)/booth-rpmlintrc > booth-rpmlintrc

$(SPEC): $(SPEC).in .version config.status $(abs_builddir)/booth-rpmlintrc
	rm -f $@-t $@
	date="$(shell LC_ALL=C date "+%a %b %d %Y")" && \
	gvgver="`cd $(abs_srcdir); build-aux/git-version-gen --fallback $(VERSION) .tarball-version .gitarchivever`" && \
	if [ "$$gvgver" = "`echo $$gvgver | sed 's/-/./'`" ];then \
		rpmver="$$gvgver" && \
		alphatag="" && \
		dirty="" && \
		numcomm="0"; \
	else \
		gitver="`echo $$gvgver | sed 's/\(.*\)\./\1-/'`" && \
		rpmver=`echo $$gitver | sed 's/-.*//g'` && \
		alphatag=`echo $$gvgver | sed 's/[^-]*-\([^-]*\).*/\1/'` && \
		numcomm=`echo $$gitver | sed 's/[^-]*-\([^-]*\).*/\1/'` && \
		dirty="" && \
		if [ "`echo $$gitver | sed 's/^.*-dirty$$//g'`" = "" ];then \
			dirty="dirty"; \
		fi \
	fi && \
	if [ "$$numcomm" = "0" ]; then numcomm=""; fi && \
	if [ -n "$$numcomm" ]; then numcomm="%global numcomm $$numcomm"; fi && \
	if [ "$$alphatag" = "$$gitver" ]; then alphatag=""; fi && \
	if [ -n "$$alphatag" ]; then alphatag="%global alphatag $$alphatag"; fi && \
	if [ -n "$$dirty" ]; then dirty="%global dirty dirty"; fi && \
	sed \
		-e "s#@version@#$$rpmver#g" \
		-e "s#@ALPHATAG@#$$alphatag#g" \
		-e "s#@NUMCOMM@#$$numcomm#g" \
		-e "s#@DIRTY@#$$dirty#g" \
		-e "s#@date@#$$date#g" \
	$(abs_srcdir)/$@.in > $@-t;
	sed -i -e "s#@uname@#$(CRM_DAEMON_USER)#g" $@-t
	sed -i -e "s#@gname@#$(CRM_DAEMON_GROUP)#g" $@-t
if BUILD_ASCIIDOC_HTML_MAN
	sed -i -e "s#@bcond_html_man@#bcond_without#g" $@-t
else
	sed -i -e "s#@bcond_html_man@#bcond_with#g" $@-t
endif
if IS_ASCIIDOC
	sed -i -e "s#@asciidoc@#asciidoc#g" $@-t
else
	sed -i -e "s#@asciidoc@#asciidoctor#g" $@-t
endif
if LOGGING_LIBQB
	sed -i -e "s#@bcond_glue@#bcond_with#g" $@-t
else
	sed -i -e "s#@bcond_glue@#bcond_without#g" $@-t
endif
if PYTHON_IS_VERSION3
	sed -i -e "s#@bcond_python3@#bcond_without#g" $@-t
else
	sed -i -e "s#@bcond_python3@#bcond_with#g" $@-t
endif
if RUN_BUILD_TESTS
	sed -i -e "s#@bcond_run_build_tests@#bcond_without#g" $@-t
else
	sed -i -e "s#@bcond_run_build_tests@#bcond_with#g" $@-t
endif
	chmod a-w $@-t
	mv $@-t $@
	rm -f $@-t*

$(TARFILE):
	$(MAKE) dist

RPMBUILDOPTS	= --define "_sourcedir $(abs_builddir)" \
		  --define "_specdir $(abs_builddir)" \
		  --define "_builddir $(abs_builddir)" \
		  --define "_srcrpmdir $(abs_builddir)" \
		  --define "_rpmdir $(abs_builddir)"

srpm: clean
	$(MAKE) $(SPEC) $(TARFILE)
	rpmbuild $(RPMBUILDOPTS) --nodeps -bs $(SPEC)

rpm: clean
	$(MAKE) $(SPEC) $(TARFILE)
	rpmbuild $(RPMBUILDOPTS) -ba $(SPEC)

gen_start_date = 2000-01-01
.PHONY: gen-ChangeLog
gen-ChangeLog:
	if test -d $(abs_srcdir)/.git; then				\
		LC_ALL=C $(top_srcdir)/build-aux/gitlog-to-changelog	\
			--since=$(gen_start_date) > $(distdir)/cl-t;	\
		rm -f $(distdir)/ChangeLog;				\
		mv $(distdir)/cl-t $(distdir)/ChangeLog;		\
	fi
