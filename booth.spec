%bcond_with html_man

%if 0%{?suse_version}
%global booth_docdir %{_defaultdocdir}/%{name}
%else
# newer fedora distros have _pkgdocdir, rely on that when
# available
%{!?_pkgdocdir: %global _pkgdocdir %%{_docdir}/%{name}-%{version}}
# Directory where we install documentation
%global booth_docdir %{_pkgdocdir}
%endif

%global test_path   	%{_datadir}/booth/tests

%if 0%{?suse_version}
%define _libexecdir %{_libdir}
%endif
%define with_extra_warnings   	0
%define with_debugging  	0
%define without_fatal_warnings 	1
%define _fwdefdir /etc/sysconfig/SuSEfirewall2.d/services
%if 0%{?fedora} || 0%{?centos} || 0%{?rhel}
%define pkg_group System Environment/Daemons
%else
%define pkg_group Productivity/Clustering/HA
%endif

Name:           booth
Url:            https://github.com/ClusterLabs/booth
Summary:        Ticket Manager for Multi-site Clusters
%if 0%{?suse_version}
License:        GPL-2.0+
%else
License:        GPLv2+
%endif
Group:          %{pkg_group}
Version:        1.0
Release:        0
Source:         booth.tar.bz2
Source1:        %name-rpmlintrc
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildRequires:  asciidoc
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  pkgconfig
%if 0%{?suse_version}
BuildRequires:  glib2-devel
%else
BuildRequires:  pkgconfig(glib-2.0)
%fi
BuildRequires:  libgcrypt-devel
%if 0%{?fedora} || 0%{?centos} || 0%{?rhel}
BuildRequires:  cluster-glue-libs-devel
BuildRequires:  pacemaker-libs-devel
%else
BuildRequires:  libglue-devel
BuildRequires:  libpacemaker-devel
%endif
BuildRequires:  libxml2-devel
%if 0%{?fedora} || 0%{?centos} || 0%{?rhel}
Requires:       pacemaker >= 1.1.8
Requires:       cluster-glue-libs >= 1.0.6
%else
Requires:       pacemaker-ticket-support >= 2.0
%endif

%description
Booth manages tickets which authorize cluster sites located in
geographically dispersed locations to run resources. It
facilitates support of geographically distributed clustering in
Pacemaker.

%prep
%setup -q -n %{name}

%build
./autogen.sh
%configure \
	--with-initddir=%{_initrddir} \
	--docdir=%{booth_docdir} \
	%{!?with_html_man:--without-html_man}

make

%install
make DESTDIR=$RPM_BUILD_ROOT install docdir=%{booth_docdir}

mkdir -p %{buildroot}/%{_mandir}/man8/
gzip < docs/boothd.8 > %{buildroot}/%{_mandir}/man8/booth.8.gz
ln %{buildroot}/%{_mandir}/man8/booth.8.gz %{buildroot}/%{_mandir}/man8/boothd.8.gz 

%if %{defined _unitdir}
# systemd
mkdir -p %{buildroot}/%{_unitdir}
cp -a conf/booth@.service %{buildroot}/%{_unitdir}/booth@.service
cp -a conf/booth-arbitrator.service %{buildroot}/%{_unitdir}/booth-arbitrator.service
ln -s /usr/sbin/service %{buildroot}%{_sbindir}/rcbooth-arbitrator
%else
# sysV init
ln -s ../../%{_initddir}/booth-arbitrator %{buildroot}%{_sbindir}/rcbooth-arbitrator
%endif

#install test-parts

mkdir -p %{buildroot}/%{test_path}
cp -a unit-tests/ script/unit-test.py test conf %{buildroot}/%{test_path}/
chmod +x %{buildroot}/%{test_path}/test/booth_path
chmod +x %{buildroot}/%{test_path}/test/live_test.sh

mkdir -p %{buildroot}/%{test_path}/src/
ln -s %{_sbindir}/boothd %{buildroot}/%{test_path}/src/
rm -f %{buildroot}/%{test_path}/test/*.pyc

%if 0%{?suse_version}
#SUSE firewall rule
mkdir -p $RPM_BUILD_ROOT/%{_fwdefdir}
install -m 644 %{S:2} $RPM_BUILD_ROOT/%{_fwdefdir}/booth
%endif

%check
%if 0%{?run_build_tests}
echo "%%run_build_tests set to %run_build_tests; including tests"
make check
%else
echo "%%run_build_tests set to %run_build_tests; skipping tests"
%endif

%files
%defattr(-,root,root,-)
%{_sbindir}/booth
%{_sbindir}/boothd
%{_sbindir}/booth-keygen
%{_sbindir}/geostore
%{_mandir}/man8/booth.8.gz
%{_mandir}/man8/boothd.8.gz
%{_mandir}/man8/booth-keygen.8.gz
%{_mandir}/man8/geostore.8.gz
%dir /usr/lib/ocf
%dir /usr/lib/ocf/resource.d
%dir /usr/lib/ocf/resource.d/pacemaker
%dir /usr/lib/ocf/resource.d/booth
%dir /usr/lib/ocf/lib
%dir /usr/lib/ocf/lib/booth
%dir %{_sysconfdir}/booth
%{_sbindir}/rcbooth-arbitrator
/usr/lib/ocf/resource.d/pacemaker/booth-site
/usr/lib/ocf/lib/booth/geo_attr.sh
/usr/lib/ocf/resource.d/booth/geostore
%config %{_sysconfdir}/booth/booth.conf.example
%if 0%{?suse_version}
%config %{_fwdefdir}/booth
%endif

%if %{defined _unitdir}
%{_unitdir}/booth@.service
%{_unitdir}/booth-arbitrator.service
%exclude %{_initddir}/booth-arbitrator
%else
%{_initddir}/booth-arbitrator
%endif

%dir %{_datadir}/booth
%{_datadir}/booth/service-runnable

%doc AUTHORS README COPYING
%doc README.upgrade-from-v0.1

%package test
Summary:        Test scripts for Booth
Group:          %{pkg_group}
Requires:       booth
Requires:       python

%description test
This package contains automated tests for Booth,
the Cluster Ticket Manager for Pacemaker.

%files test
%defattr(-,root,root)

%doc README-testing
%{test_path}
%dir /usr/lib/ocf
%dir /usr/lib/ocf/resource.d
%dir /usr/lib/ocf/resource.d/booth
/usr/lib/ocf/resource.d/booth/sharedrsc

%changelog
