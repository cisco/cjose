SUBDIRS = . include src test doc platform
EXTRA_DIST = CHANGELOG.md README.md LICENSE

ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = cjose.pc

doxygen:
	cd doc && $(MAKE) doxygen

test : check
	cat test/check_cjose.log

clean-local :
	rm -rf dist/*

distclean-local :
	rm -rf dist/*

package-prepare : dist
	mkdir -p dist && \
	rm -rf dist/cjose-$(PACKAGE_VERSION).tar.gz && \
	cp cjose-$(PACKAGE_VERSION).tar.gz dist

package-local : package-prepare
	@echo packages built

clang-format:
	clang-format -i `find . -name *.[ch]`
