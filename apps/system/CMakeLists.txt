# CatOS system backend: one Rust static binary exposed through four
# role-specific public aliases.
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
                "${CARGO_CMD}" test --no-fail-fast --all-targets
                --all-features --locked
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    )
    set_tests_properties(catos-system-cargo-test PROPERTIES
        TIMEOUT 300
        LABELS "rust;unit"
    )

    add_test(
        NAME catos-system-cargo-clippy
        COMMAND ${CMAKE_COMMAND} -E env
                "CARGO_TARGET_DIR=${CATOS_SYSTEM_CARGO_TARGET_DIR}"
                "${CARGO_CMD}" clippy --all-targets --all-features
                --locked -- -D warnings
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    )
    set_tests_properties(catos-system-cargo-clippy PROPERTIES
        TIMEOUT 300
        LABELS "rust;lint"
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
    option(CATOS_SYSTEM_RECOVERY_SMOKE
           "Enable real btrfs recovery crash/resume QEMU test (opt-in; requires a musl binary built with --features recovery_fault_injection)"
           OFF)
    option(CATOS_SYSTEM_REPAIR_SMOKE
           "Enable real ext4+vfat+btrfs+xfs repair QEMU test (opt-in; needs qemu + kernel + busybox + mkfs/e2fsck tools)"
           OFF)
    option(CATOS_SYSTEM_MOUNT_REPAIR_SMOKE
           "Enable real Btrfs mount-repair QEMU test (opt-in; needs qemu + kernel + busybox + btrfs-progs)"
           OFF)
    option(CATOS_SYSTEM_BOOT_REPAIR_SMOKE
           "Enable real boot-repair QEMU test matrix (opt-in; needs qemu + kernel + busybox + provider tools + OVMF for UEFI scenarios)"
           OFF)
    option(CATOS_SYSTEM_DOCTOR_SMOKE
           "Enable real catos-doctor QEMU acceptance (opt-in; needs qemu + kernel + busybox + mkfs.btrfs). Verifies byte-for-byte no-write guarantee."
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
    if(CATOS_SYSTEM_RECOVERY_SMOKE)
        # The recovery crash/resume test needs a second musl binary
        # built with the recovery_fault_injection cargo feature. We
        # route this build into a separate cargo target dir so the
        # default release binary stays unfeatured and the two
        # variants do not fight over the same target dir.
        set(CATOS_SYSTEM_FAULT_CARGO_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/cargo-target-fault")
        set(CATOS_SYSTEM_FAULT_BIN
            "${CATOS_SYSTEM_FAULT_CARGO_TARGET_DIR}/${CATOS_SYSTEM_TARGET}/release/catos-system")
        add_custom_command(
            OUTPUT "${CATOS_SYSTEM_FAULT_BIN}"
            COMMAND ${CMAKE_COMMAND} -E env
                    "CARGO_TARGET_DIR=${CATOS_SYSTEM_FAULT_CARGO_TARGET_DIR}"
                    "${CARGO_CMD}" build --release --locked --frozen
                    --target ${CATOS_SYSTEM_TARGET}
                    --features recovery_fault_injection
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            DEPENDS ${CATOS_SYSTEM_SOURCES} ${CATOS_SYSTEM_MANIFESTS}
            COMMENT "Building catos-system with recovery_fault_injection (Rust ${CATOS_SYSTEM_TARGET}, release)"
            VERBATIM
        )
        # ALL is intentional: CTest cannot build a custom target through
        # the test DEPENDS property. When recovery smoke is enabled, the
        # fault binary must exist after the normal build step.
        add_custom_target(catos-system-fault-bin ALL
                          DEPENDS "${CATOS_SYSTEM_FAULT_BIN}")

        add_test(
            NAME catos-system-recovery-qemu-smoke
            COMMAND "${BASH_CMD}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/recovery-qemu-smoke.sh"
                    --bin "${CATOS_SYSTEM_BIN}"
                    --test-bin "${CATOS_SYSTEM_FAULT_BIN}"
        )
        set_tests_properties(catos-system-recovery-qemu-smoke PROPERTIES
            TIMEOUT 1800
            SKIP_RETURN_CODE 77
            LABELS "rust;integration;qemu;recovery"
        )
    endif()
    if(CATOS_SYSTEM_REPAIR_SMOKE)
        # Stage-2 real-filesystem repair smoke test. It repairs damaged
        # ext4/vfat images, corrupts one metadata-DUP Btrfs mirror and proves
        # --repair plus clean recheck, exercises normal XFS repair, and creates
        # a real dirty XFS journal by killing a writer VM before proving -L.
        # Skips with exit 77 when qemu/kernel/busybox/mkfs tools are
        # missing.
        add_test(
            NAME catos-system-repair-qemu-smoke
            COMMAND "${BASH_CMD}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/repair-qemu-smoke.sh"
                    --bin "${CATOS_SYSTEM_BIN}"
        )
        set_tests_properties(catos-system-repair-qemu-smoke PROPERTIES
            TIMEOUT 600
            SKIP_RETURN_CODE 77
            LABELS "rust;integration;qemu;repair"
        )
    endif()
    if(CATOS_SYSTEM_MOUNT_REPAIR_SMOKE)
        # Stage-3 state-changing acceptance: all six boot/ESP layouts,
        # independent ext4 /boot, Btrfs @boot, offline/current ext4 roots,
        # complete mount verification, cleanup, and empty-object rollback.
        add_test(
            NAME catos-system-mount-repair-qemu-smoke
            COMMAND "${BASH_CMD}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/mount-repair-qemu-smoke.sh"
                    --bin "${CATOS_SYSTEM_BIN}"
        )
        set_tests_properties(catos-system-mount-repair-qemu-smoke PROPERTIES
            TIMEOUT 300
            SKIP_RETURN_CODE 77
            LABELS "rust;integration;qemu;mount-repair"
        )
    endif()
    if(CATOS_SYSTEM_BOOT_REPAIR_SMOKE)
        # Stage-4 boot-provider acceptance: a real CatOS target disk
        # per provider layout (GRUB BIOS, GRUB UEFI, Limine,
        # systemd-boot, UKI, EFI Stub). Each scenario constructs the
        # target's bootloadu-managed /etc files, then runs
        # catos-repair boot --json and asserts the provider is
        # detected from target-side evidence and the matching recipe
        # command is executed. Scenarios whose host lacks the matching
        # provider tool or OVMF firmware are skipped (exit 77) with a
        # clear reason; they are NEVER silently reported as passing.
        add_test(
            NAME catos-system-boot-repair-qemu-smoke
            COMMAND "${BASH_CMD}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/boot-repair-qemu-smoke.sh"
                    --bin "${CATOS_SYSTEM_BIN}"
        )
        set_tests_properties(catos-system-boot-repair-qemu-smoke PROPERTIES
            TIMEOUT 600
            SKIP_RETURN_CODE 77
            LABELS "rust;integration;qemu;boot-repair"
        )
    endif()
    if(CATOS_SYSTEM_DOCTOR_SMOKE)
        # Stage-5 Doctor acceptance. Real CatOS btrfs target images
        # (healthy, fs-corrupt, mount-break, ambiguous, doctor-fail).
        # Each scenario asserts exit code 0 per scheme B (except
        # doctor-fail, which must be non-zero) AND verifies by
        # sha256 byte-hash that the target image is unchanged before
        # vs. after the catos-doctor run. Skips with exit 77 when
        # qemu, busybox, or the kernel image is unavailable.
        add_test(
            NAME catos-system-doctor-qemu-smoke
            COMMAND "${BASH_CMD}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/doctor-qemu-smoke.sh"
                    --bin "${CATOS_SYSTEM_BIN}"
        )
        set_tests_properties(catos-system-doctor-qemu-smoke PROPERTIES
            TIMEOUT 480
            SKIP_RETURN_CODE 77
            LABELS "rust;integration;qemu;doctor"
        )
    endif()
endif()

# ---- install: binary + public entry points --------------------------------
# Binary lives under /usr/lib/catos/ (not /usr/bin/). Public aliases are
# relative so the installation remains relocatable as a group.
install(PROGRAMS "${CATOS_SYSTEM_BIN}"
        DESTINATION "lib/catos"
        RENAME catos-system)

# CMAKE_INSTALL_BINDIR is not available inside install(CODE) at install time
# (only CMAKE_INSTALL_PREFIX and ENV{DESTDIR} are). Capture it now at configure
# time and embed as a literal.
set(_catos_install_bindir "${CMAKE_INSTALL_BINDIR}")

# Create the four public multicall symlinks at install time. We use install(CODE)
# so the links are produced in the staged install tree (respecting DESTDIR and
# CMAKE_INSTALL_PREFIX) and so we can make them relative.
install(CODE "
    set(_catos_bindir \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${_catos_install_bindir}\")
    file(MAKE_DIRECTORY \"\${_catos_bindir}\")
    foreach(_name catos-update catos-recovery catos-doctor catos-repair)
        set(_link \"\${_catos_bindir}/\${_name}\")
        if(EXISTS \"\${_link}\" AND NOT IS_SYMLINK \"\${_link}\")
            message(FATAL_ERROR \"Refusing to overwrite non-symlink \${_link}\")
        endif()
        file(REMOVE \"\${_link}\")
        file(CREATE_LINK \"../lib/catos/catos-system\" \"\${_link}\" SYMBOLIC)
        message(STATUS \"install: \${_link} -> ../lib/catos/catos-system\")
    endforeach()
")
