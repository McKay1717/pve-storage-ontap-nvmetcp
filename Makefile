PACKAGE = pve-storage-ontap-nvmetcp
VERSION = 1.0
PKGREL = 1
ARCH = all

DESTDIR =
PREFIX = /usr
PERLDIR = $(PREFIX)/share/perl5

DEB = $(PACKAGE)_$(VERSION)-$(PKGREL)_$(ARCH).deb

PERL_SOURCES = \
	PVE/Storage/Custom/OntapNvmeTcpPlugin.pm \
	PVE/Storage/OntapNvmeTcp/Api.pm

all: deb

.PHONY: tidy
tidy:
	echo $(PERL_SOURCES) | xargs proxmox-perltidy

.PHONY: install
install:
	install -d $(DESTDIR)$(PERLDIR)/PVE/Storage/Custom
	install -d $(DESTDIR)$(PERLDIR)/PVE/Storage/OntapNvmeTcp
	install -m 0644 PVE/Storage/Custom/OntapNvmeTcpPlugin.pm \
		$(DESTDIR)$(PERLDIR)/PVE/Storage/Custom/OntapNvmeTcpPlugin.pm
	install -m 0644 PVE/Storage/OntapNvmeTcp/Api.pm \
		$(DESTDIR)$(PERLDIR)/PVE/Storage/OntapNvmeTcp/Api.pm

.PHONY: deb $(DEB)
deb $(DEB):
	rm -rf debian_build
	mkdir -p debian_build
	$(MAKE) DESTDIR=$(CURDIR)/debian_build install
	install -d -m 0755 debian_build/DEBIAN
	sed -e 's/@@VERSION@@/$(VERSION)/' \
	    -e 's/@@PKGRELEASE@@/$(PKGREL)/' \
	    -e 's/@@ARCH@@/$(ARCH)/' \
	    < debian/control.in > debian_build/DEBIAN/control
	install -m 0644 debian/triggers debian_build/DEBIAN/triggers
	install -m 0755 debian/postinst debian_build/DEBIAN/postinst
	install -d -m 0755 debian_build/$(PREFIX)/share/doc/$(PACKAGE)
	install -m 0644 debian/copyright \
		debian_build/$(PREFIX)/share/doc/$(PACKAGE)/
	install -m 0644 debian/changelog \
		debian_build/$(PREFIX)/share/doc/$(PACKAGE)/changelog.Debian
	gzip -9 debian_build/$(PREFIX)/share/doc/$(PACKAGE)/changelog.Debian
	dpkg-deb --build debian_build
	mv debian_build.deb $(DEB)
	rm -rf debian_build

.PHONY: clean
clean:
	rm -rf debian_build *.deb
