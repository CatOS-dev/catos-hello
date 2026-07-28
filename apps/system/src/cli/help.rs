pub fn help_text() -> String {
    format!(
        "\
catos-system {version} - CatOS system maintenance

USAGE:
    catos-system
    catos-system <COMMAND> [OPTIONS]
    catos-system help [COMMAND]

COMMANDS:
    doctor      Check the installed system and explain detected problems.
    chroot      Find an installed CatOS system and open a maintenance shell.
    repair      Repair a filesystem, mount configuration, or boot setup.
    recovery    Recover a Btrfs system from a snapshot or resume a transaction.
    update      Check for updates and update the running system.
    advanced    Low-level read-only inspection and target-mount tools.
    help        Show help for one command.

OPTIONS:
    -h, --help       Show this help message.
    -V, --version    Print the program version.

Run without a command to open the interactive maintenance menu.

The same functions are also installed as catos-doctor, catos-chroot,
catos-repair, catos-recovery, and catos-update.
",
        version = crate::PROGRAM_VERSION,
    )
}

pub fn advanced_help_text() -> String {
    format!(
        "\
catos-system {version} - advanced inspection tools

USAGE:
    catos-system advanced <COMMAND> [OPTIONS]

COMMANDS:
    inspect          Show runtime, capability, and target information.
    environment      Show runtime-environment information.
    capabilities     Show available maintenance capabilities.
    storage scan     Scan block devices and possible CatOS targets.
    target plan      Build a read-only target mount plan.
    target mount     Mount and inspect a target read-only, then clean it up.

OPTIONS:
    --root PATH                  Inspect a mounted target root instead of /.
    --root-device /dev/...       Select an unmounted root device.
    --root-subvolume PATH        Select its Btrfs root subvolume.
    --esp-device /dev/...        Select the EFI System Partition.
    --json                       Emit machine-readable JSON.
    -h, --help                   Show this help message.

These commands are intended for diagnosis and automation. Normal recovery
work should start from `catos-system`, `catos-system doctor`, or
`catos-system chroot`.
",
        version = crate::PROGRAM_VERSION,
    )
}

pub fn version_text() -> String {
    format!("catos-system {}\n", crate::PROGRAM_VERSION)
}
