Summary: ProvBPF whole-system provenance daemon
Name: provbpf
Version: 0.1.0
Release: 1
Group: audit/provbpf
License: GPLv2
Source: %{expand:%%(pwd)}
BuildRoot: %{_topdir}/BUILD/%{name}-%{version}-%{release}
Requires: glibc, libbpf, libinih, libpthread, libprovenance

%description
%{summary}

%prep
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/bin
mkdir -p $RPM_BUILD_ROOT/etc/systemd/system
cd $RPM_BUILD_ROOT
cp -f %{SOURCEURL0}/provbpfd ./usr/bin/provbpfd
cp -f %{SOURCEURL0}/provbpfd.service ./etc/systemd/system/provbpfd.service
cp -f %{SOURCEURL0}/provbpf.ini ./etc/provbpf.ini

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(755,root,root)
/usr/bin/provbpfd
%defattr(644,root,root)
/etc/systemd/system/provbpfd.service
/etc/provbpf.ini
