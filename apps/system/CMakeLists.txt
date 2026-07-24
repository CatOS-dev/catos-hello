# CatOS system backend: Rust static binary providing three multicall
# entry points via symlinks.
#
# The actual build is delegated to Cargo via add_custom_command. CMake tracks
# Cargo.toml, Cargo.lock, and src/**/*.rs so incremental rebuilds work and
# `cargo build` is not unconditionally re-run.

# ---- locate cargo -----------------------------------------------------------
find_program(CARGO_CMD cargo REQUIRED)

# ---- target / options -------------------------------------------------------
# Default target is musl-static. This MUST stay the default for releases; the
# option exists so developers can override locally (e.g. when iterating on a
# host without the musl std).
set(CATOS_SYSTEM_TARGET "x86_64-unknown-linux-musl"
    CACHE STRING "Rust target triple for catos-system (must be musl-static for releases)")

# When ON, cargo is invoked with --offline. PKGBUILD sets this ON after a
# `cargo fetch` prepare step; local dev builds leave it OFF.
option(CATOS_SYSTEM_OFFLINE "Pass --offline to cargo (no network during build)" OFF)

# ---- verify the target's std is installed ----------------------------------
# Without this we'd get a cryptic "can't find crate for `core`" from cargo.
execute_process(
    COMMAND rustc --print sysroot
    OUTPUT_VARIABLE _rust_sysroot
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
set(_catos_target_lib "${_rust_sysroot}/lib/rustlib/${CATOS_SYSTEM_TARGET}")
if(NOT EXISTS "${_catos_target_lib}")
    message(FATAL_ERROR
        "Rust target '${CATOS_SYSTEM_TARGET}' is not installed.\n"
        "Expected std at: ${_catos_target_lib}\n"
        "Install it with:\n"
        "    rustup target add ${CATOS_SYSTEM_TARGET}\n"
        "or override locally with -DCATOS_SYSTEM_TARGET=<triple> "
        "(note: only musl-static targets produce the required static binary).")
endif()

# ---- output paths -----------------------------------------------------------
# Cargo target dir lives inside the CMake build tree so the source dir is never
# polluted and parallel CMake builds do not race on Cargo's lock.
set(CATOS_SYSTEM_CARGO_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/cargo-target")
set(CATOS_SYSTEM_BIN
    "${CATOS_SYSTEM_CARGO_TARGET_DIR}/${CATOS_SYSTEM_TARGET}/release/catos-system")

# ---- source dependencies ----------------------------------------------------
file(GLOB_RECURSE CATOS_SYSTEM_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.rs"
)
set(CATOS_SYSTEM_MANIFESTS
    "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml"
    "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.lock"
)

# ---- cargo invocation -------------------------------------------------------
set(_cargo_args build --release --locked --frozen --target ${CATOS_SYSTEM_TARGET})
if(CATOS_SYSTEM_OFFLINE)
    list(APPEND _cargo_args --offline)
endif()

add_custom_command(
    OUTPUT "${CATOS_SYSTEM_BIN}"
    COMMAND ${CMAKE_COMMAND} -E env
            "CARGO_TARGET_DIR=${CATOS_SYSTEM_CARGO_TARGET_DIR}"
            "${CARGO_CMD}" ${_cargo_args}
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    DEPENDS ${CATOS_SYSTEM_SOURCES} ${CATOS_SYSTEM_MANIFESTS}
    COMMENT "Building catos-system (Rust ${CATOS_SYSTEM_TARGET}, release)"
    VERBATIM
)

add_custom_target(catos-system ALL DEPENDS "${CATOS_SYSTEM_BIN}")

# ---- tests (CTest) ---------------------------------------------------------
# Three test surfaces:
#   cargo-test       Rust unit + integration tests on the host target
#                    (cheap; runs in seconds). Tests share the same
#                    CARGO_TARGET_DIR as the release musl build.
#   static-check     readelf-based static-linking verification on the
#                    produced musl binary. The only authoritative check that
#                    the binary is actually static (file output can be
#                    misleading on static-pie).
#   initramfs-smoke  QEMU boot of a minimal initramfs containing the binary.
#                    Opt-in: only added when CATOS_SYSTEM_INITRAMFS_SMOKE=ON
#                    because it needs QEMU, a usable kernel image, and
#                    busybox. Skips cleanly when prerequisites are missing.
if(BUILD_TESTS)
    find_program(BASH_CMD bash REQUIRED)

    add_test(
        NAME catos-system-cargo-test
        COMMAND ${CMAKE_COMMAND} -E env
                "CARGO_TARGET_DIR=${CATOS_SYSTEM_CARGO_TARGET_DIR}"
                "${CARGO_CMD}" test --no-fail-fast --locked
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    )
    set_tests_properties(catos-system-cargo-test PROPERTIES
        TIMEOUT 300
        LABELS "rust;unit"
    )

    add_test(
        NAME catos-system-static-check
        COMMAND "${BASH_CMD}"
                "${CMAKE_CURRENT_SOURCE_DIR}/scripts/verify-static.sh"
                "${CATOS_SYSTEM_BIN}"
    )
    set_tests_properties(catos-system-static-check PROPERTIES
        TIMEOUT 60
        LABELS "rust;static"
    )

    option(CATOS_SYSTEM_INITRAMFS_SMOKE
           "Enable initramfs/QEMU smoke test (opt-in; needs qemu + kernel + busybox)"
           OFF)
    option(CATOS_SYSTEM_STORAGE_SMOKE
           "Enable real ext4+ESP QEMU recovery test (opt-in)"
           OFF)
    if(CATOS_SYSTEM_INITRAMFS_SMOKE)
        # Two test variants:
        #   * bare:         no initramfs markers; verifies binary starts
        #                    without systemd/dbus/network and produces valid
        #                    JSON. Does NOT assert initramfs detection.
        #   * with-marker:  includes /etc/initrd-release; additionally asserts
        #                    is_initramfs.status == "detected". Catches the
        #                    false-green where the binary runs but the runtime
        #                    detector fails to recognise its environment.
        add_test(
            NAME catos-system-initramfs-smoke-bare
            COMMAND "${BASH_CMD}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/initramfs-smoke.sh"
                    --mode bare
                    --bin "${CATOS_SYSTEM_BIN}"
        )
        set_tests_properties(catos-system-initramfs-smoke-bare PROPERTIES
            TIMEOUT 180
            SKIP_RETURN_CODE 77
            LABELS "rust;integration;qemu"
        )
        add_test(
            NAME catos-system-initramfs-smoke-with-marker
            COMMAND "${BASH_CMD}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/initramfs-smoke.sh"
                    --mode with-marker
                    --bin "${CATOS_SYSTEM_BIN}"
        )
        set_tests_properties(catos-system-initramfs-smoke-with-marker PROPERTIES
            TIMEOUT 180
            SKIP_RETURN_CODE 77
            LABELS "rust;integration;qemu"
        )
    endif()
    if(CATOS_SYSTEM_STORAGE_SMOKE)
        add_test(
            NAME catos-system-storage-qemu-smoke
            COMMAND "${BASH_CMD}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/storage-qemu-smoke.sh"
                    --bin "${CATOS_SYSTEM_BIN}"
        )
        set_tests_properties(catos-system-storage-qemu-smoke PROPERTIES
            TIMEOUT 240
            SKIP_RETURN_CODE 77
            LABELS "rust;integration;qemu;storage"
        )
    endif()
endif()

# ---- install: binary + three relative symlinks -----------------------------
# Binary lives under /usr/lib/catos/ (not /usr/bin/) so the three symlinks can
# be relative ("../lib/catos/catos-system") and survive being moved as a group.
install(PROGRAMS "${CATOS_SYSTEM_BIN}"
        DESTINATION "lib/catos"
        RENAME catos-system)

# CMAKE_INSTALL_BINDIR is not available inside install(CODE) at install time
# (only CMAKE_INSTALL_PREFIX and ENV{DESTDIR} are). Capture it now at configure
# time and embed as a literal.
set(_catos_install_bindir "${CMAKE_INSTALL_BINDIR}")

# Create the three multicall symlinks at install time. We use install(CODE)
# so the links are produced in the staged install tree (respecting DESTDIR and
# CMAKE_INSTALL_PREFIX) and so we can make them relative.
install(CODE "
    set(_catos_bindir \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${_catos_install_bindir}\")
    file(MAKE_DIRECTORY \"\${_catos_bindir}\")
    foreach(_name catos-update catos-recovery catos-doctor)
        set(_link \"\${_catos_bindir}/\${_name}\")
        if(EXISTS \"\${_link}\" AND NOT IS_SYMLINK \"\${_link}\")
            message(FATAL_ERROR \"Refusing to overwrite non-symlink \${_link}\")
        endif()
        file(REMOVE \"\${_link}\")
        file(CREATE_LINK \"../lib/catos/catos-system\" \"\${_link}\" SYMBOLIC)
        message(STATUS \"install: \${_link} -> ../lib/catos/catos-system\")
    endforeach()
")
