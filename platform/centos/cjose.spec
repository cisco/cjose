Name:           cjose
Version:        %{release}
Release:        1%{?dist}
Summary:        C library implementing the Javascript Object Signing and Encryption (JOSE)
Group:          System Environment/Libraries
License:        MIT
URL:            https://github.com/cisco/cjose
Source0:        cjose-%{version}.tar.gz

BuildRoot:      %{_tmppath}/cjose-%{version}-%{release}-build
Requires:       openssl, jansson
BuildRequires:  openssl-devel, jansson-devel, check-devel

%define _topdir /opt/rpmbuild
%define debug_package %{nil}

%description
Implementation of JOSE for C/C++

%package devel
Summary:        Development files for CJOSE
Group:          System Environment/Libraries
Provides:       cjose-devel

%description devel
This package contains the necessary header files to develop applications using CJOSE.

%prep
%setup -q

%build

%configure
make test
make doxygen

%install
%make_install

%clean
rm -rf $PRM_BUILD_ROOT

%files
%{_libdir}/libcjose*

%files devel
%{_includedir}/cjose/*\.h
%{_libdir}/pkgconfig/cjose.pc
%{_docdir}/cjose/html/*
