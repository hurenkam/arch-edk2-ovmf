# Maintainer: David Runge <dvzrv@archlinux.org>
# Contributor: Alexander Epaneshnikov <alex19ep@archlinux.org>

pkgbase=edk2
pkgname=(edk2-arm edk2-aarch64 edk2-shell edk2-ovmf)
pkgver=202311
pkgrel=1
pkgdesc="Modern, feature-rich firmware development environment for the UEFI specifications"
arch=(any)
url="https://github.com/tianocore/edk2"
license=(
  Apache-2.0
  BSD-2-Clause-Patent
  MIT
)
makedepends=(
  aarch64-linux-gnu-gcc
  arm-none-eabi-gcc
  acpica
  git
  util-linux-libs
  nasm
  python
)
options=(!makeflags)
source=(
  git+$url#tag=$pkgbase-stable$pkgver
  openssl::git+https://github.com/openssl/openssl.git
  pyca-cryptography::git+https://github.com/pyca/cryptography.git  # submodule for openssl
  krb5::git+https://github.com/krb5/krb5.git  # submodule for openssl
  gost-engine::git+https://github.com/gost-engine/engine.git  # submodule for openssl
  libprov::git+https://github.com/provider-corner/libprov.git  # submodule for gost-engine
  wycheproof::git+https://github.com/google/wycheproof.git  # submodule for openssl
  berkeley-softfloat-3::git+https://github.com/ucb-bar/berkeley-softfloat-3.git
  $pkgbase-cmocka::git+https://github.com/tianocore/edk2-cmocka.git
  oniguruma::git+https://github.com/kkos/oniguruma.git
  brotli::git+https://github.com/google/brotli.git
  jansson::git+https://github.com/akheron/jansson.git
  googletest::git+https://github.com/google/googletest.git  # also a submodule for public-mipi-sys-t
  # subhook::git+https://github.com/Zeex/subhook.git
  pylibfdt::git+https://github.com/devicetree-org/pylibfdt.git
  public-mipi-sys-t::git+https://github.com/MIPI-Alliance/public-mipi-sys-t.git
  pugixml::git+https://github.com/zeux/pugixml.git  # submodule for public-mipi-sys-t
  mbedtls::git+https://github.com/Mbed-TLS/mbedtls.git
  50-edk2-ovmf-i386-secure.json
  50-edk2-ovmf-i386-secure-4m.json
  50-edk2-ovmf-x86_64-secure.json
  50-edk2-ovmf-x86_64-secure-4m.json
  60-edk2-ovmf-i386.json
  60-edk2-ovmf-i386-4m.json
  60-edk2-ovmf-x86_64.json
  60-edk2-ovmf-x86_64-4m.json
  60-edk2-ovmf-microvm.json
  60-edk2-ovmf-microvm-4m.json
  60-edk2-aarch64.json
  60-edk2-arm.json
  80-edk2-ovmf-ia32-on-x86_64-secure.json
  80-edk2-ovmf-ia32-on-x86_64-secure-4m.json
  81-edk2-ovmf-ia32-on-x86_64.json
  81-edk2-ovmf-ia32-on-x86_64-4m.json
)
sha512sums=('3702666f06f8367de6174bc9646726d1c6e405ffa68e24a5eab9c5d1e9b8a74ad3cecb691ce1702729957935cbc71abd7fd75d833a2f57981996256c843152ba'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            '9182615c6f89e4f3c19f1b0f4434aa0a3293f982cf3ed783a2c140c2555d824b417c7c3c7a00ad10616188507f5068226c720b20ffd41d44449605ba0844bad2'
            '53604279dea69000cb036062d9617f1c7dc5ce3d83fbcb066b9087e4f412c2ea24ae3a37436ab17d5bf9dd6b2da380933c48400163d4b9fde65ea42d37956d5e'
            'e2e5f3eabb3ced681385ed9d57a3aa83e2155415ea6fd2c16eb15c5a1e685f92e90f1c6f270c1c8da23dde3a0e4a085399f65038b799430c713d1628eb44ac07'
            'c1f83b3c5f5c43803d4bb1084f6ebdd1987364cab59945a8226a8cf1229daba79c83f638c0a1395ea56acffbd4349b94459659705743a397ff03369b7794a1c6'
            '25df19b698081c7a21e4c5f37321150ab2f144f4888d887513c3ed926a844909cee390d3e5d80b02c084510074c874b21db3b3d119330342cf8877197ef0a425'
            'c886b3d6e5f23833c2dc9f8c9f3b21523c680dd2c6bfebbb488f54619d31e53d4019b05b4e1a3dc91abd6e0cab4540d750a2db1b9b4dcf8257e4ba9a2b9b487a'
            '99f5dcdbc54824976f51c45b939e8bcb4971a70dc2d50b24233d3125ce6cf687f92b8d3896d72280470a2c001637920da8d6e33d576c489beb7f0e898bfb22ab'
            '9da9de6717b610a181be8f7b34b379a56a1fa31f945f78198eec52359abd178bdf77fda4426157992e64329f53a204af042d5145cb5d3b4b1203915a48815449'
            'a86e294e5904f52441b86da220f37cc693d7066f7fcb75dafc472a3a72516e865c213be6d0ce245ec5dd680ca9272429d39dca4db4f3e6434b12c479227bc4b0'
            'b17d3ff5c9230c394ca4ee8229842c801b0cab3d88b546f2094dd0b42f2bc535f5bda3f9faee4b5418482185887648f906daaf0b7307c4c19747f5f0ab504f9a'
            '126822ef6198e87fb38014a5ba21969c9a163b41df3cdef6825317971ecc8df4a63099113e687634b88648acc93f24917d729e1c44295d2df7012288740307d3'
            'bbf663d539a985504d5fbc95552a2a60ac860a6bce4a62ecc551292d838b41cba3b5203f580a76a05e9f862ef98e7a3e5da39505c1f39d8ef48c08778fac584a'
            'cebf9c2cfe8ea7007c68112b4e64d61a98a1637d4b51bceefa22a205e57bb947c757cea8dcc2d01961d8b72b4f289f692d4034d3c38f062e06941b2cc4586377'
            '95661c2182112a76652507de84b7d0f9bb0d21f6b3b62134952bd7aada8df5cfc727658d11b71a7780a22049d9cafc4361d9a1d515b68d1463e7082465fd4f7e'
            '8ed6d1d749c3471421a02c41e0e8c3e1ceb62ca6bc09cf2bc85055e2b2661bc149a77b83f480af1aec2f9a948971c6b5aebc92fbc112508fc6293cc6edc7a8a7'
            'c9dbe7b2b6b8c18b7b8fdfef5bc329d9142c442f2f3dbae3ca4919255dcaf2ab576cd305648228d5dd48040ca3b14f44ee33b05cb6ca13b49e2836947b78ea53')
b2sums=('42410a203b7ab4b6b272a1a25675dafd18640972e8a319b01a53d5aeeebabfbeb331bd0afda4b4078305f85b0fb2a4cb7256a45cd6f1df64a3f63ee6b5bc9b13'
        'SKIP'
        'SKIP'
        'SKIP'
        'SKIP'
        'SKIP'
        'SKIP'
        'SKIP'
        'SKIP'
        'SKIP'
        'SKIP'
        'SKIP'
        'SKIP'
        'SKIP'
        'SKIP'
        'SKIP'
        'SKIP'
        '98742b83c2d605772a1bfa64ee434430413516db13d80235f0bc0be3a0e930aa17d737a6d2c95ce3d60f33de9f93679e09f421632d9e3fc9575d662fcf198f4b'
        'ee28940a8d13a7badf94bcceebd4371c79cd0194ca9f984f39cd75ee64f1ba53059d81f5826c6b5a564d50dce7b9fb5fe8d63ee8d38d38462bc070249124a16b'
        '8dfd44f35d35d699bb12eef771b08b978cf38ba64494b0eb8c153c72493d47c2d71445869c8d9115c29b28cd206f31be27b43024bd8796a50c8c41a67f87a859'
        'b9a488c2a6295f3d8eab80150dbfa7acea94720b08928d4e6a4613189fe24922f6c40e1ae8c9856ebb1bc31586ecfb1e02e099a11f7abde575d1f9aa78cc732d'
        '0a30e819e63b09207c664beca8845f73fb43482d19e831c7f915755594eeafcfc8dccb842f819fb7d20215d87452da31943488e201b9690b733db8169870afcc'
        'd5d3dc38bf8a09473075a2dd8ab4adcd3af80be30c0ae49fbf55f478b8e0d9a1fde90abceda7099ed3136ee9cadee406bef949a17a070be1b92250adb14c1a7c'
        'aa1144f31bd391e09d2bf0f55d6cb7a50fab38eca5967989463d58f2931267f7499414709c9692335376f8834b513d69249d995fdc9e90429eadd287348d57e8'
        '56562116024236f6bb5590fff241d47568a9c1755faa25a62011e8fa3f14b7d74014651b421f5a0c6fb269fb6c05f23b97a5b1ed13929e8141e1c3839f784a5b'
        'f55e220c6d6a8733bd9233115453e9aca10af91e4cd93be438b4951049198228bdd1b6765b2eae2a781cf3e90beab9b14540c9165ab76af38b9db35b09dde947'
        '01dbc4cad102535504eace2d9da225a481b62785d37365f1dea2d1210990ca6177485aa0134a074c09d253b539f12ae810706a77a46779ddb7dd4f1b9b934011'
        'f84ff505702e4b2a38b6fd23fbb732c25d3102a04bb6918b0cc3b3d7528a92626324199cea4ed91955aade98f308f1d1037255f26cc9ee21ace75fc6376e7df6'
        '04a7eb373d6ea1415d7cd6e8dea0d16b75cbb1fb88572a30b8ce9960dd0404adc7f25fce2ccfb103eb09405411dc4d4e0084236e4c814916d81e957dc6aedfd4'
        'c54eb05090280af70ceb44b601752ec38ca80d2af232385cf5ddd6f95ea0504d00a2dd2c82828aa07c41fb456fbb6f174b8bf89b851061206328ae66e589dd2a'
        'b53bbe532f9a7583bfbcc9436f2172f2dcaa75177c1480753a2a60d97a2fbd5bfb86b97b3f7c27d82e88eb2035c6607abb7e35d39a42e6a2d40c0b54d7c430ef'
        'dc9a98b8b6d6d8cc2f3aa2b314ba521a2fa8110abf199ca2a6c612ba53df3adad89e5ae0e4cfbe8f5ebf2cefd3cda1716d19f90304a138630f0b8d6e36cd4d10'
        '0c1e145109de9a25339633b563e47f6c09ea314f636023d09a58559a499dd0bd283a45e050fc99fe34c4d712bd00a035064fa8406734d57029c67b9adb4b11ce')
_arch_list=(ARM AARCH64 IA32 X64)
_build_type=RELEASE
_build_plugin=GCC5

prepare() {
  local submodule

  cd $pkgbase

  git submodule init
  git config submodule.CryptoPkg/Library/OpensslLib/openssl.url ../openssl
  git config submodule.SoftFloat.url ../berkeley-softfloat-3
  git config submodule.UnitTestFrameworkPkg/Library/CmockaLib/cmocka.url ../$pkgbase-cmocka
  git config submodule.MdeModulePkg/Universal/RegularExpressionDxe/oniguruma.url ../oniguruma
  git config submodule.MdeModulePkg/Library/BrotliCustomDecompressLib/brotli.url ../brotli
  git config submodule.BaseTools/Source/C/BrotliCompress/brotli.url ../brotli
  git config submodule.RedfishPkg/Library/JsonLib/jansson.url ../jansson
  git config submodule.UnitTestFrameworkPkg/Library/GoogleTestLib/googletest.url ../googletest
  # the subhook upstream is gone: https://github.com/tianocore/edk2/issues/6398
  git submodule deinit UnitTestFrameworkPkg/Library/SubhookLib/subhook
  # git config submodule.UnitTestFrameworkPkg/Library/SubhookLib/subhook.url ../subhook
  git config submodule.MdePkg/Library/BaseFdtLib/libfdt.url ../pylibfdt
  git config submodule.MdePkg/Library/MipiSysTLib/mipisyst.url ../public-mipi-sys-t
  git config submodule.CryptoPkg/Library/MbedTlsLib/mbedtls.url ../mbedtls
  git -c protocol.file.allow=always submodule update

  # submodule setup for CryptoPkg/Library/OpensslLib/openssl
  submodule=CryptoPkg/Library/OpensslLib/openssl
  git -C $submodule submodule init
  git -C $submodule config submodule.pyca.cryptography.url "$srcdir/pyca-cryptography"
  git -C $submodule config submodule.krb5.url "$srcdir/krb5"
  git -C $submodule config submodule.gost-engine.url "$srcdir/gost-engine"
  git -C $submodule config submodule.wycheproof.url "$srcdir/wycheproof"
  git -C $submodule -c protocol.file.allow=always submodule update

  # submodule setup for CryptoPkg/Library/OpensslLib/openssl/gost-engine
  submodule=CryptoPkg/Library/OpensslLib/openssl/gost-engine
  git -C $submodule submodule init
  git -C $submodule config submodule.libprov.url "$srcdir/libprov"
  git -C $submodule -c protocol.file.allow=always submodule update

  # submodule setup for MdePkg/Library/MipiSysTLib/mipisyst
  submodule=MdePkg/Library/MipiSysTLib/mipisyst
  git -C $submodule submodule init
  git -C $submodule config submodule.external/pugixml.url "$srcdir/pugixml"
  git -C $submodule config submodule.external/googletest.url "$srcdir/googletest"
  git -C $submodule -c protocol.file.allow=always submodule update

  # -Werror, not even once
  sed -e 's/ -Werror//g' -i BaseTools/Conf/*.template BaseTools/Source/C/Makefiles/*.makefile
}

# TODO: check TPM_ENABLE/TPM2_ENABLE
build() {
  local _arch
  local _build_options=()
  # shared targets for all
  local _common_args=(
    -b "$_build_type"
    -n "$(nproc)"
    -t "$_build_plugin"
  )
  # shared targets for all EFI binaries
  local _efi_args=(
    -D NETWORK_IP6_ENABLE
    -D TPM_CONFIG_ENABLE
    -D TPM1_ENABLE
    -D TPM2_ENABLE
  )
  # shared targets x86_64 and i686
  local _x86_args=(
    -D FD_SIZE_2MB
  )
  # 4MB FD size variant
  local _4mb_args=(
    -D FD_SIZE_4MB
    -D FD_SIZE_IN_KB=4096
    -D NETWORK_HTTP_BOOT_ENABLE
    -D NETWORK_TLS_ENABLE
  )

  cd $pkgbase
  export GCC5_IA32_PREFIX="x86_64-linux-gnu-"
  export GCC5_X64_PREFIX="x86_64-linux-gnu-"
  export GCC5_AARCH64_PREFIX="aarch64-linux-gnu-"
  export GCC5_ARM_PREFIX="arm-none-eabi-"
  echo "Building base tools (AARCH64)"
  ARCH=AARCH64 make -C BaseTools
  echo "Building base tools (ARM)"
  ARCH=ARM make -C BaseTools
  echo "Building base tools"
  make -C BaseTools
  # expose build tooling in PATH
  . edksetup.sh

  for _arch in ${_arch_list[@]}; do
    # shell
    echo "Building shell ($_arch)."
    BaseTools/BinWrappers/PosixLike/build -p ShellPkg/ShellPkg.dsc -a "$_arch" "${_common_args[@]}"
    # ovmf
    case "$_arch" in
      IA32)
      echo "Building ovmf ($_arch) with secure boot support"
      BaseTools/BinWrappers/PosixLike/build -p OvmfPkg/OvmfPkgIa32.dsc \
                       -a "$_arch" \
                       "${_common_args[@]}" \
                       "${_efi_args[@]}" \
                       "${_x86_args[@]}" \
                       -D EXCLUDE_SHELL_FROM_FD \
                       -D LOAD_X64_ON_IA32_ENABLE \
                       -D SECURE_BOOT_ENABLE \
                       -D SMM_REQUIRE
      mv -v Build/Ovmf{Ia32,IA32-secure}
      echo "Building ovmf ($_arch) with secure boot support (4MB FD)"
      BaseTools/BinWrappers/PosixLike/build -p OvmfPkg/OvmfPkgIa32.dsc \
                       -a "$_arch" \
                       "${_common_args[@]}" \
                       "${_efi_args[@]}" \
                       "${_4mb_args[@]}" \
                       -D EXCLUDE_SHELL_FROM_FD \
                       -D LOAD_X64_ON_IA32_ENABLE \
                       -D SECURE_BOOT_ENABLE \
                       -D SMM_REQUIRE
      mv -v Build/Ovmf{Ia32,IA32-secure-4mb}
      echo "Building ovmf ($_arch) default"
      BaseTools/BinWrappers/PosixLike/build -p OvmfPkg/OvmfPkgIa32.dsc \
                       -a "$_arch" \
                       "${_common_args[@]}" \
                       "${_efi_args[@]}" \
                       "${_x86_args[@]}" \
                       -D LOAD_X64_ON_IA32_ENABLE
      mv -v Build/Ovmf{Ia32,IA32}
      echo "Building ovmf ($_arch) default (4MB FD)"
      BaseTools/BinWrappers/PosixLike/build -p OvmfPkg/OvmfPkgIa32.dsc \
                       -a "$_arch" \
                       "${_common_args[@]}" \
                       "${_efi_args[@]}" \
                       "${_4mb_args[@]}" \
                       -D LOAD_X64_ON_IA32_ENABLE
      mv -v Build/Ovmf{Ia32,IA32-4mb}
      ;;
      X64)
      echo "Building ovmf ($_arch) with microvm support (4MB FD)"
      BaseTools/BinWrappers/PosixLike/build -p OvmfPkg/Microvm/Microvm$_arch.dsc \
                       -a "$_arch" \
                       "${_common_args[@]}" \
                       "${_efi_args[@]}" \
                       "${_4mb_args[@]}"
      mv -v Build/MicrovmX64{,-4mb}
      echo "Building ovmf ($_arch) with microvm support"
      BaseTools/BinWrappers/PosixLike/build -p OvmfPkg/Microvm/Microvm$_arch.dsc \
                       -a "$_arch" \
                       "${_common_args[@]}" \
                       "${_efi_args[@]}" \
                       "${_x86_args[@]}"
      echo "Building ovmf ($_arch) with secure boot support"
      BaseTools/BinWrappers/PosixLike/build -p OvmfPkg/OvmfPkgIa32X64.dsc \
                       -a IA32 -a "$_arch" \
                       "${_common_args[@]}" \
                       "${_efi_args[@]}" \
                       "${_x86_args[@]}" \
                       -D SECURE_BOOT_ENABLE \
                       -D SMM_REQUIRE \
                       -D EXCLUDE_SHELL_FROM_FD
      mv -v Build/Ovmf3264{,-secure}
      echo "Building ovmf ($_arch) with secure boot support (4MB FD)"
      BaseTools/BinWrappers/PosixLike/build -p OvmfPkg/OvmfPkgIa32X64.dsc \
                       -a IA32 -a "$_arch" \
                       "${_common_args[@]}" \
                       "${_efi_args[@]}" \
                       "${_4mb_args[@]}" \
                       -D SECURE_BOOT_ENABLE \
                       -D SMM_REQUIRE \
                       -D EXCLUDE_SHELL_FROM_FD
      mv -v Build/Ovmf3264{,-secure-4mb}
      echo "Building ovmf (${_arch}) without secure boot (4MB FD)"
      BaseTools/BinWrappers/PosixLike/build -p OvmfPkg/OvmfPkg$_arch.dsc \
                       -a "$_arch" \
                       "${_common_args[@]}" \
                       "${_efi_args[@]}" \
                       "${_4mb_args[@]}"
      mv -v Build/OvmfX64{,-4mb}
      echo "Building ovmf (${_arch}) without secure boot"
      BaseTools/BinWrappers/PosixLike/build -p OvmfPkg/OvmfPkg$_arch.dsc \
                       -a "$_arch" \
                       "${_common_args[@]}" \
                       "${_efi_args[@]}" \
                       "${_x86_args[@]}"
      ;;
      AARCH64)
      echo "Building ArmVirtPkg ($_arch) with secure boot"
      local _build_options=(
        -p ArmVirtPkg/ArmVirtQemu.dsc
        -a "$_arch"
        "${_common_args[@]}"
        "${_efi_args[@]}"
        -D NETWORK_HTTP_BOOT_ENABLE
        -D NETWORK_TLS_ENABLE
        -D SECURE_BOOT_ENABLE
      )
      BaseTools/BinWrappers/PosixLike/build "${_build_options[@]}"
      dd if=/dev/zero of=Build/ArmVirtQemu-$_arch/${_build_type}_${_build_plugin}/FV/QEMU_CODE.fd bs=1M count=64
      dd if=Build/ArmVirtQemu-$_arch/${_build_type}_${_build_plugin}/FV/QEMU_EFI.fd of=Build/ArmVirtQemu-$_arch/${_build_type}_${_build_plugin}/FV/QEMU_CODE.fd conv=notrunc
      dd if=/dev/zero of=Build/ArmVirtQemu-$_arch/${_build_type}_${_build_plugin}/FV/QEMU_VARS.fd bs=1M count=64
      ;;
      ARM)
      echo "Building ovmf (${_arch}) with secure boot"
      local _build_options=(
        -p ArmVirtPkg/ArmVirtQemu.dsc
        -a "${_arch}"
        "${_common_args[@]}"
        "${_efi_args[@]}"
        -D NETWORK_HTTP_BOOT_ENABLE
        -D NETWORK_TLS_ENABLE
        -D SECURE_BOOT_ENABLE
        -D TPM_ENABLE
        -D TPM_CONFIG_ENABLE
      )
      BaseTools/BinWrappers/PosixLike/build "${_build_options[@]}"
      dd if=/dev/zero of=Build/ArmVirtQemu-$_arch/${_build_type}_$_build_plugin/FV/QEMU_CODE.fd bs=1M count=64
      dd if=Build/ArmVirtQemu-$_arch/${_build_type}_$_build_plugin/FV/QEMU_EFI.fd of=Build/ArmVirtQemu-$_arch/${_build_type}_$_build_plugin/FV/QEMU_CODE.fd conv=notrunc
      dd if=/dev/zero of=Build/ArmVirtQemu-$_arch/${_build_type}_$_build_plugin/FV/QEMU_VARS.fd bs=1M count=64
      ;;
    esac
  done
}

package_edk2-aarch64() {
  local _arch=AARCH64

  pkgdesc="Firmware for Virtual Machines (aarch64)"
  url="https://github.com/tianocore/tianocore.github.io/wiki/ArmVirtPkg"
  conflicts=('edk2-armvirt<202211')
  provides=(edk2-armvirt)
  replaces=('edk2-armvirt<202211')

  cd $pkgbase
  install -vDm 644 Build/ArmVirtQemu-$_arch/${_build_type}_${_build_plugin}/FV/*.fd -t "$pkgdir/usr/share/$pkgbase/${_arch,,}/"
  # add libvirt compatibility (which hardcodes the following paths)
  install -vdm 755 "$pkgdir/usr/share/AAVMF"
  ln -svf /usr/share/$pkgbase/${_arch,,}/QEMU_CODE.fd "$pkgdir/usr/share/AAVMF/AAVMF_CODE.fd"
  ln -svf /usr/share/$pkgbase/${_arch,,}/QEMU_VARS.fd "$pkgdir/usr/share/AAVMF/AAVMF_VARS.fd"
  # install qemu descriptors in accordance with qemu:
  # https://git.qemu.org/?p=qemu.git;a=tree;f=pc-bios/descriptors
  install -vDm 644 ../*$pkgname.json -t "$pkgdir/usr/share/qemu/firmware/"
  # license
  install -vDm 644 License.txt -t "$pkgdir/usr/share/licenses/$pkgname/"

  # add symlink for previous aarch64 location
  ln -svf /usr/share/$pkgbase "$pkgdir/usr/share/$pkgbase-armvirt"
}

package_edk2-arm() {
  local _arch=ARM

  pkgdesc="Firmware for Virtual Machines (armv7)"
  url="https://github.com/tianocore/tianocore.github.io/wiki/ArmVirtPkg"

  cd $pkgbase
  install -vDm 644 Build/ArmVirtQemu-$_arch/${_build_type}_$_build_plugin/FV/*.fd -t "$pkgdir/usr/share/$pkgbase/${_arch,,}/"
  # add libvirt compatibility (which hardcodes the following paths)
  install -vdm 755 "$pkgdir/usr/share/AAVMF"
  ln -svf /usr/share/$pkgbase/${_arch,,}/QEMU_CODE.fd "$pkgdir/usr/share/AAVMF/AAVMF32_CODE.fd"
  ln -svf /usr/share/$pkgbase/${_arch,,}/QEMU_VARS.fd "$pkgdir/usr/share/AAVMF/AAVMF32_VARS.fd"

  # install qemu descriptors in accordance with qemu:
  # https://git.qemu.org/?p=qemu.git;a=tree;f=pc-bios/descriptors
  install -vDm 644 ../*$pkgname.json -t "$pkgdir/usr/share/qemu/firmware/"
  # license
  install -vDm 644 License.txt -t "$pkgdir/usr/share/licenses/$pkgname/"
}

package_edk2-shell() {
  local _arch
  # minimal UEFI shell, as defined in ShellPkg/Application/Shell/ShellPkg.inf
  local _min='7C04A583-9E3E-4f1c-AD65-E05268D0B4D1'
  # full UEFI shell, as defined in ShellPkg/ShellPkg.dsc
  local _full='EA4BB293-2D7F-4456-A681-1F22F42CD0BC'

  pkgdesc="EDK2 UEFI Shell"
  provides=(uefi-shell)

  cd $pkgbase
  for _arch in ${_arch_list[@]}; do
    install -vDm 644 Build/Shell/${_build_type}_${_build_plugin}/$_arch/Shell_$_min.efi "$pkgdir/usr/share/$pkgname/${_arch,,}/Shell.efi"
    install -vDm 644 Build/Shell/${_build_type}_${_build_plugin}/$_arch/Shell_$_full.efi "$pkgdir/usr/share/$pkgname/${_arch,,}/Shell_Full.efi"
  done
  # license
  install -vDm 644 License.txt -t "$pkgdir/usr/share/licenses/$pkgname/"
  # docs
  install -vDm 644 {ReadMe.rst,Maintainers.txt} -t "$pkgdir/usr/share/doc/$pkgname/"
}

package_edk2-ovmf() {
  local _arch

  pkgdesc="Firmware for Virtual Machines (x86_64, i686)"
  url="https://github.com/tianocore/tianocore.github.io/wiki/OVMF"
  license+=(MIT)
  provides=(ovmf)
  conflicts=(ovmf)
  replaces=(ovmf)
  install=$pkgname.install

  cd $pkgbase
  # installing the various firmwares
  for _arch in IA32 X64; do
    # installing OVMF.fd for xen: https://bugs.archlinux.org/task/58635
    install -vDm 644 Build/Ovmf$_arch/${_build_type}_${_build_plugin}/FV/OVMF.fd -t "$pkgdir/usr/share/$pkgbase/${_arch,,}/"
    install -vDm 644 Build/Ovmf$_arch/${_build_type}_${_build_plugin}/FV/OVMF_CODE.fd -t "$pkgdir/usr/share/$pkgbase/${_arch,,}/"
    install -vDm 644 Build/Ovmf$_arch/${_build_type}_${_build_plugin}/FV/OVMF_VARS.fd -t "$pkgdir/usr/share/$pkgbase/${_arch,,}/"
    install -vDm 644 Build/Ovmf$_arch-4mb/${_build_type}_${_build_plugin}/FV/OVMF.fd "$pkgdir/usr/share/$pkgbase/${_arch,,}/OVMF.4m.fd"
    install -vDm 644 Build/Ovmf$_arch-4mb/${_build_type}_${_build_plugin}/FV/OVMF_CODE.fd "$pkgdir/usr/share/$pkgbase/${_arch,,}/OVMF_CODE.4m.fd"
    install -vDm 644 Build/Ovmf$_arch-4mb/${_build_type}_${_build_plugin}/FV/OVMF_VARS.fd "$pkgdir/usr/share/$pkgbase/${_arch,,}/OVMF_VARS.4m.fd"
    if [[ "${_arch}" == 'X64' ]]; then
      install -vDm 644 Build/Ovmf3264-secure/${_build_type}_${_build_plugin}/FV/OVMF_CODE.fd "$pkgdir/usr/share/$pkgbase/${_arch,,}/OVMF_CODE.secboot.fd"
      install -vDm 644 Build/Ovmf3264-secure-4mb/${_build_type}_${_build_plugin}/FV/OVMF_CODE.fd "$pkgdir/usr/share/$pkgbase/${_arch,,}/OVMF_CODE.secboot.4m.fd"
      install -vDm 644 Build/MicrovmX64/${_build_type}_${_build_plugin}/FV/MICROVM.fd -t "$pkgdir/usr/share/$pkgbase/${_arch,,}/"
      install -vDm 644 Build/MicrovmX64-4mb/${_build_type}_${_build_plugin}/FV/MICROVM.fd "$pkgdir/usr/share/$pkgbase/${_arch,,}/MICROVM.4m.fd"
    else
      install -vDm 644 Build/Ovmf$_arch-secure/${_build_type}_${_build_plugin}/FV/OVMF_CODE.fd "$pkgdir/usr/share/$pkgbase/${_arch,,}/OVMF_CODE.secboot.fd"
      install -vDm 644 Build/Ovmf$_arch-secure-4mb/${_build_type}_${_build_plugin}/FV/OVMF_CODE.fd "$pkgdir/usr/share/$pkgbase/${_arch,,}/OVMF_CODE.secboot.4m.fd"
    fi
  done
  # installing qemu descriptors in accordance with qemu:
  # https://git.qemu.org/?p=qemu.git;a=tree;f=pc-bios/descriptors
  # https://bugs.archlinux.org/task/64206
  install -vDm 644 ../*$pkgname*.json -t "$pkgdir/usr/share/qemu/firmware/"
  # add symlink for previous ovmf locations
  # https://bugs.archlinux.org/task/66528
  ln -svf /usr/share/$pkgbase "$pkgdir/usr/share/ovmf"
  ln -svf /usr/share/$pkgbase "$pkgdir/usr/share/$pkgbase-ovmf"
  # adding a symlink for applications with questionable heuristics (such as lxd)
  ln -svf /usr/share/$pkgbase "$pkgdir/usr/share/OVMF"
  # licenses
  install -vDm 644 License.txt -t "$pkgdir/usr/share/licenses/$pkgname/"
  install -vDm 644 OvmfPkg/License.txt "$pkgdir/usr/share/licenses/$pkgname/OvmfPkg.License.txt"
  # docs
  install -vDm 644 {OvmfPkg/README,ReadMe.rst,Maintainers.txt} -t "$pkgdir/usr/share/doc/$pkgname/"
}
