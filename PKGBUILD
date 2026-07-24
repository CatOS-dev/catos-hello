# Maintainer: Aromatic <symwww@outlook.com>
pkgname=catos-hello
pkgver=0.1.0
pkgrel=8
pkgdesc="CatOS Hello - welcome application + read-only system recovery backend"
arch=('x86_64')
url="https://github.com/Aromatic05/catOS-hello"
license=('GPL')
depends=('qt6-base' 'rate-mirrors' 'lshw' 'inxi' 'lsb-release')
# Use the system 'rust' + 'rust-musl' packages rather than 'rustup'. The
# rustup package only ships shims; in a clean build environment (empty
# RUSTUP_HOME / CARGO_HOME) it cannot pick a default toolchain and the CMake
# configure step fails immediately on `rustc --print sysroot`.
# 'rust' provides cargo, rustc, and rustfmt directly.
# 'rust-musl' ships the x86_64-unknown-linux-musl standard library.
makedepends=('cmake' 'gcc' 'make' 'qt6-tools' 'qt5-translations' 'rust' 'rust-musl')
source=("${pkgname}::git+$url.git")
sha256sums=('SKIP')

prepare() {
    # Pre-fetch Cargo dependencies into a local registry cache so the build
    # phase never has to hit the network. This is the canonical Arch pattern
    # for offline-reproducible Rust packaging.
    export CARGO_HOME="$srcdir/cargo-home"
    mkdir -p "$CARGO_HOME"

    cd "$pkgname/apps/system"
    cargo fetch --locked
}

build() {
    # Re-use the registry cache populated in prepare(). Combined with
    # -DCATOS_SYSTEM_OFFLINE=ON this guarantees the build phase is fully
    # offline.
    export CARGO_HOME="$srcdir/cargo-home"

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
