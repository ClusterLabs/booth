
%global test_path   	%{_datadir}/booth/tests

%if 0%{?suse_version}
%define _libexecdir %{_libdir}
%endif
%define with_extra_warnings   	0
%define with_debugging  	0
%define without_fatal_warnings 	1
%if 0%{?fedora} || 0%{?centos} || 0%{?rhel}
%define pkg_group System Environment/Daemons
%else
%define pkg_group Productivity/Clustering/HA
%endif

Name:           booth
Summary:        Ticket Manager for Multi-site Clusters
License:        GPL-2.0+
Group:          %{pkg_group}
Version:        0.2.0
Release:        0
Source:         booth.tar.bz2
Source1:        %name-rpmlintrc
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildRequires:  asciidoc
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  glib2-devel
%if 0%{?fedora} || 0%{?centos} || 0%{?rhel}
BuildRequires:  cluster-glue-libs-devel
BuildRequires:  pacemaker-libs-devel
%else
BuildRequires:  libglue-devel
BuildRequires:  libpacemaker-devel
%endif
BuildRequires:  libxml2-devel
BuildRequires:  pkgconfig
%if 0%{?fedora} || 0%{?centos} || 0%{?rhel}
Requires:       pacemaker >= 1.1.8
Requires:       cluster-glue-libs >= 1.0.6
%else
Requires:       pacemaker-ticket-support >= 2.0
%endif

%description
Booth manages the ticket which authorizes one of the cluster sites located in
geographically dispersed distances to run certain resources. It is designed to
be an add-on of Pacemaker, which extends Pacemaker to support geographically
distributed clustering.

%prep
%setup -q -n %{name}

%build
./autogen.sh
%configure \
	--with-initddir=%{_initrddir}

make

#except check
#%check
#make check

%install
make DESTDIR=$RPM_BUILD_ROOT install docdir=%{_defaultdocdir}/%{name}

mkdir -p %{buildroot}/%{_mandir}/man8/
gzip < docs/boothd.8 > %{buildroot}/%{_mandir}/man8/booth.8.gz
ln %{buildroot}/%{_mandir}/man8/booth.8.gz %{buildroot}/%{_mandir}/man8/boothd.8.gz 

# systemd
mkdir -p %{buildroot}/usr/lib/systemd/system/
cp -a conf/booth@.service %{buildroot}/usr/lib/systemd/system/booth@.service

#install test-parts

mkdir -p %{buildroot}/%{test_path}
cp -a unit-tests/ script/unit-test.py test conf %{buildroot}/%{test_path}/
chmod +x %{buildroot}/%{test_path}/test/booth_path
chmod +x %{buildroot}/%{test_path}/test/live_test.sh

mkdir -p %{buildroot}/%{test_path}/src/
ln -s %{_sbindir}/boothd %{buildroot}/%{test_path}/src/
rm -f %{buildroot}/%{test_path}/test/*.pyc

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_sbindir}/booth
%{_sbindir}/boothd
%{_initrddir}/booth-arbitrator
%{_mandir}/man8/booth.8.gz
%{_mandir}/man8/boothd.8.gz
%{_datadir}/doc/booth/README
%{_datadir}/doc/booth/COPYING
%{_datadir}/doc/booth/boothd.8.html
%dir /usr/lib/ocf
%dir /usr/lib/ocf/resource.d
%dir /usr/lib/ocf/resource.d/pacemaker
%dir %{_sysconfdir}/booth
/usr/lib/ocf/resource.d/pacemaker/booth-site
%config %{_sysconfdir}/booth/booth.conf.example

/usr/lib/systemd/system/booth@.service

%dir %{_datadir}/booth
%{_datadir}/booth/service-runnable

%doc README COPYING


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

%changelog
