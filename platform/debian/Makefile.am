PLATFORMS := $(patsubst %.dockerfile,%,$(wildcard *.dockerfile))
PLATFORM_SRCS := $(patsubst %,%.dockerfile,%(PLATFORMS))
PLATFORM_IMGS := $(patsubst %,%.img-tag,$(PLATFORMS))
PLATFORM_PKGS := $(patsubst %,%.pkg-tag,$(PLATFORMS))

%.img-tag : %.dockerfile
	docker build --force-rm --tag cjose_build:$(shell basename $< .dockerfile) --file $< . && \
	echo "$(shell date -ju)" > $@

%.pkg-tag : %.img-tag $(top_builddir)/cjose-$(PACKAGE_VERSION).tar.gz
	docker run --rm --env PACKAGE_VERSION=$(PACKAGE_VERSION) \
		--volume $(abs_top_builddir)/dist:/opt/dist \
		--volume $(abs_builddir):/opt/src \
		cjose_build:$(shell basename $< .img-tag) && \
        echo "$(shell date -ju)" > $@

package-local : $(PLATFORM_PKGS)
	@echo built $(PLATFORMS)

clean-local :
	rm -rf *.img-tag *.pkg-tag

.PRECIOUS: $(PLATFORM_IMGS)
