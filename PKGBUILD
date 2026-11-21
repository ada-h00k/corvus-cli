# Maintainer: ada-h00k

pkgname=corvus-cli
pkgver=1.6.8
pkgrel=1
pkgdesc='Signal backend for Corvus, compatible with signal-cli JSON-RPC'
arch=('x86_64')
url='https://github.com/ada-h00k/corvus-cli'
license=('AGPL-3.0-only')
depends=('gcc-libs' 'glibc' 'openssl')
source=('corvus-cli' 'LICENSE' 'README.md')
noextract=('corvus-cli')
options=('!debug')
# The binary is produced by the release workflow (build-arch-package) and cannot have a
# static checksum here; its integrity is covered by the SHA256SUMS the release ships.
# The static files are pinned: makepkg verifies them against these sums.
sha256sums=('SKIP'
            '8486a10c4393cee1c25392769ddd3b2d6c242d6ec7928e1414efff7dfb2f07ef'
            '5dd5140c8c9fbe440a3b099db2143b42439cea0f779ce5d3dd699f54bb6ee7b4')

package() {
  install -Dm755 "${srcdir}/corvus-cli" "${pkgdir}/usr/bin/corvus-cli"
  install -Dm644 "${srcdir}/LICENSE" "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
  install -Dm644 "${srcdir}/README.md" "${pkgdir}/usr/share/doc/${pkgname}/README.md"
}
