# Maintainer: ada-h00k

pkgname=corvus-cli
pkgver=1.4.0
pkgrel=1
pkgdesc='Signal backend for Corvus, compatible with signal-cli JSON-RPC'
arch=('x86_64')
url='https://github.com/ada-h00k/corvus-cli'
license=('AGPL-3.0-only')
depends=('gcc-libs' 'glibc' 'openssl')
makedepends=('cargo' 'clang' 'cmake' 'git' 'protobuf' 'pkgconf')
source=("${pkgname}::git+https://github.com/ada-h00k/corvus-cli.git#tag=v${pkgver}")
sha256sums=('SKIP')

prepare() {
  cd "${srcdir}/${pkgname}"

  # Fetch the Cargo.lock-pinned registry and Git dependencies before building
  # offline. This also makes the build fail rather than silently changing deps.
  cargo fetch --locked
}

build() {
  cd "${srcdir}/${pkgname}"

  CARGO_TARGET_DIR=target cargo build --release --locked --offline
}

package() {
  cd "${srcdir}/${pkgname}"

  install -Dm755 target/release/corvus-cli "${pkgdir}/usr/bin/corvus-cli"
  install -Dm644 LICENSE "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
  install -Dm644 README.md "${pkgdir}/usr/share/doc/${pkgname}/README.md"
}
