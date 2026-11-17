# Maintainer: ada-h00k

pkgname=corvus-cli
pkgver=1.4.2
pkgrel=1
pkgdesc='Signal backend for Corvus, compatible with signal-cli JSON-RPC'
arch=('x86_64')
url='https://github.com/ada-h00k/corvus-cli'
license=('AGPL-3.0-only')
depends=('gcc-libs' 'glibc' 'openssl')
source=('corvus-cli' 'LICENSE' 'README.md')
noextract=('corvus-cli')
sha256sums=('SKIP' 'SKIP' 'SKIP')

package() {
  install -Dm755 "${srcdir}/corvus-cli" "${pkgdir}/usr/bin/corvus-cli"
  install -Dm644 "${srcdir}/LICENSE" "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
  install -Dm644 "${srcdir}/README.md" "${pkgdir}/usr/share/doc/${pkgname}/README.md"
}
