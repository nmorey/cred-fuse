#
# spec file for package cred-fuse
#
# Copyright (c) 2026 SUSE LLC
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via https://bugs.opensuse.org/
#

%define         git_ver %{nil}
Name:           cred-fuse
Version:        0.1.0
Release:        0
Summary:        FUSE driver for TPM-encrypted credentials
License:        GPLv2
Group:          System/Filesystems
URL:            https://github.com/nmorey/homelab
Source0:        %{name}-%{version}%{?git_ver}.tar.gz
BuildRequires:  cmake
BuildRequires:  gcc
BuildRequires:  pkgconfig
BuildRequires:  fuse3
BuildRequires:  swtpm
BuildRequires:  pkgconfig(libcrypto)
BuildRequires:  pkgconfig(tss2-esys)
BuildRequires:  pkgconfig(tss2-tctildr)
Requires:       fuse3
Requires:       tpm2.0-abrmd

%description
cred-fuse is a FUSE filesystem that securely decrypts and exposes TPM-encrypted
credentials (RSA or AES+TPM) dynamically from a source directory, inheriting
POSIX DAC access controls.

%prep
%setup -q

%build
%cmake
%cmake_build

%install
%cmake_install

%check
%ctest

%files
%license LICENSE
%doc README.md
%{_sbindir}//cred-fuse

%changelog
