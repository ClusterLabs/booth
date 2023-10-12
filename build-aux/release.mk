# to build official release tarballs, handle tagging and publish.

# example:
# make -f build-aux/release.mk all version=1.1 release=yes

project=booth

all: checks setup tag tarballs sha256

checks:
ifeq (,$(version))
	@echo ERROR: need to define version=
	@exit 1
endif
	@if [ ! -d .git ]; then \
		echo This script needs to be executed from top level cluster git tree; \
		exit 1; \
	fi

	@if ! grep "fallback $(version)" configure.ac > /dev/null; then \
		echo "Don't forget update fallback version in configure.ac before release"; \
		exit 1; \
	fi

setup: checks
	./autogen.sh
	./configure --without-glue
	make maintainer-clean

tag: setup ./tag-$(version)

tag-$(version):
ifeq (,$(release))
	@echo Building test release $(version), no tagging
else
	git tag -a -m "v$(version) release" v$(version) HEAD
	@touch $@
endif

tarballs: tag
	./autogen.sh
	./configure --without-glue
	BOOTH_RUNTESTS_ROOT_USER=1 make distcheck DISTCHECK_CONFIGURE_FLAGS="--without-glue"

sha256: tarballs $(project)-$(version).sha256

$(project)-$(version).sha256:
ifeq (,$(release))
	@echo Building test release $(version), no sha256
else
	sha256sum $(project)-$(version)*tar* | sort -k2 > $@
endif

clean:
	rm -rf $(project)-* tag-*
