# Copyright 2019 Cray Inc. All Rights Reserved.

Name: cray-conman-crayctldeploy
License: Cray Software License Agreement
Summary: Cray conman service
Group: System/Management
Version: %(cat .rpm_version)
Release: %(echo ${BUILD_METADATA})
Source: %{name}-%{version}.tar.bz2
Vendor: Cray Inc.
Requires: cray-crayctl
Requires: cray-cmstools-crayctldeploy
Requires: kubernetes-crayctldeploy

# Project level defines TODO: These should be defined in a central location; DST-892
%define afd /opt/cray/crayctl/ansible_framework
%define afd_roles %{afd}/roles

%description
This is a collection of resources for cms-conman

%prep
%setup -q

%build

%install

# Install smoke tests under /opt/cray/tests/crayctl-stage4
mkdir -p ${RPM_BUILD_ROOT}/opt/cray/tests/crayctl-stage4/cms/
mkdir -p ${RPM_BUILD_ROOT}/%{afd_roles}/
cp ct-tests/conman_stage4_ct_tests.sh ${RPM_BUILD_ROOT}/opt/cray/tests/crayctl-stage4/cms/conman_stage4_ct_tests.sh
cp -r ansible/roles/* ${RPM_BUILD_ROOT}/%{afd_roles}/

%clean
rm -rf ${RPM_BUILD_ROOT}/%{afd_roles}/*

%files
%defattr(755, root, root)

/opt/cray/tests/crayctl-stage4/cms/conman_stage4_ct_tests.sh

%dir %{afd_roles}
%{afd_roles}/conman_restart

%changelog
