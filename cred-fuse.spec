Name:           cred-fuse
Version:        0.1.0
Release:        0
Summary:        FUSE driver for TPM-encrypted credentials
License:        GPLv2
Group:          System/Filesystems
URL:            https://github.com/nmorey/homelab
Source0:        %{name}-%{version}.tar.bz2
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
