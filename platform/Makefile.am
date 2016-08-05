SUBDIRS = centos debian

package-local :
	mkdir -p $(top_builddir)/dist && \
	rm -rf $(top_builddir)/dist/cjose-$(PACKAGE_VERSION).tar.gz && \
	cp $(top_builddir)/cjose-$(PACKAGE_VERSION).tar.gz $(top_builddir)/dist
