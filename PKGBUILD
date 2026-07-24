# Maintainer: Aromatic <symwww@outlook.com>
pkgname=catos-hello
pkgver=0.1.0
pkgrel=7
pkgdesc="CatOS Hello - welcome application + read-only system recovery backend"
arch=('x86_64')
url="https://github.com/Aromatic05/catOS-hello"
license=('GPL')
depends=('qt6-base' 'rate-mirrors' 'lshw' 'inxi' 'lsb-release')
# rustup provides rust, cargo, and the musl target std lib via the virtual
# provides `rust-musl`. The CatOS system backend is built as a fully static
# musl binary, so it has zero runtime dependencies and ships inside the same
# catos-hello package (no separate Rust sub-package).
makedepends=('cmake' 'gcc' 'make' 'qt6-tools' 'qt5-translations' 'rustup')
source=("${pkgname}::git+$url.git")
sha256sums=('SKIP')

build() {
    # Pre-fetch Cargo dependencies to a local registry cache so the actual
    # build phase never has to hit the network. This satisfies the
    # `--frozen --offline` requirements baked into apps/system/CMakeLists.txt.
    export CARGO_HOME="$srcdir/cargo-home"
    mkdir -p "$CARGO_HOME"

    cd "$pkgname/apps/system"
    cargo fetch --locked
    cd -

    cmake \
        -S "$pkgname" \
        -B build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_TESTS=OFF \
        -DCATOS_SYSTEM_OFFLINE=ON
    cmake --build build
}

# Optional check(): run static-link verification on the produced musl binary.
# Disabled by default; enable with `makepkg --check`.
check() {
    export CARGO_HOME="$srcdir/cargo-home"
    cmake --build build --target catos-system
    bash "$pkgname/apps/system/scripts/verify-static.sh" \
        "build/apps/system/cargo-target/x86_64-unknown-linux-musl/release/catos-system"
}

package() {
    DESTDIR="$pkgdir" cmake --install build
}
