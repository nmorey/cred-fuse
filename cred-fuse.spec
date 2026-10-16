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
Version:        2.0
Release:        0
Summary:        FUSE driver and CLI tools for TPM-encrypted credentials
License:        GPL-2.0-only
Group:          System/Filesystems
URL:            https://github.com/nmorey/cred-fuse
Source0:        %{name}-%{version}%{?git_ver}.tar.gz
BuildRequires:  cmake
BuildRequires:  gcc
BuildRequires:  pkgconfig
BuildRequires:  pkgconfig(fuse3)
BuildRequires:  pkgconfig(libcrypto)
BuildRequires:  pkgconfig(tss2-esys)
BuildRequires:  pkgconfig(tss2-mu)
BuildRequires:  pkgconfig(tss2-rc)
BuildRequires:  pkgconfig(tss2-tctildr)
BuildRequires:  audit-devel
# For testing
BuildRequires:  tpm2.0-tools
BuildRequires:  swtpm
BuildRequires:  python3-base
Requires:       fuse3
Requires:       tpm2.0-abrmd

%description
cred-fuse is a read-only FUSE filesystem and accompanying CLI toolset
(cred-encrypt, cred-decrypt) that dynamically decrypts and exposes
TPM-bound hybrid envelope (CRED_ENV v1: RSA-OAEP-SHA256 + HKDF-SHA256 +
AES-256-GCM) credentials from an encrypted backing store while enforcing
POSIX DAC access controls and cryptographic metadata binding.

%prep
%setup -q -n  %{name}-%{version}%{?git_ver}

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
%{_sbindir}/mount.cred-fuse
%{_bindir}/cred-encrypt
%{_bindir}/cred-decrypt

%changelog
