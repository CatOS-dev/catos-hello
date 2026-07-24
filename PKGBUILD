# Maintainer: Aromatic <symwww@outlook.com>
pkgname=catos-hello
pkgver=0.1.0
pkgrel=6
pkgdesc="CatOS Hello - welcome application"
arch=('x86_64')
url="https://github.com/Aromatic05/catOS-hello"
license=('GPL')
depends=('qt6-base' 'rate-mirrors' 'lshw' 'inxi' 'lsb-release')
makedepends=('cmake' 'gcc' 'make' 'qt6-tools' 'qt5-translations')
source=("${pkgname}::git+$url.git")
sha256sums=('SKIP')

build() {
    cmake \
        -S catos-hello \
        -B build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr
    cmake --build build
}

package() {
    DESTDIR="$pkgdir" cmake --install build
}
