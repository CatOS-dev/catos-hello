# Applications

Each directory under `apps/` owns one executable and its local build files.

- `hello/` contains the existing Qt welcome application (`catos-hello`).
- `system/` contains the shared static backend (`catos-system`) for the
  `catos-update`, `catos-recovery`, `catos-doctor`, and `catos-repair` entry
  points. `catos-doctor` is argumentless and produces a single read-only
  aggregated diagnosis covering environment, storage, filesystem, mount
  layout, boot, Secure Boot, and recovery; `catos-recovery` handles durable
  Btrfs snapshot recovery; and `catos-repair` implements filesystem repair
  plus transactional fstab/subvolume/boot-mount repair and boot-provider
  repair. `catos-repair boot` re-applies the target's currently-selected
  bootloader provider (GRUB, Limine, systemd-boot, UKI, or EFI Stub) by
  porting the Calamares `bootloadu` module's behaviour to the static
  backend. `catos-update` is installed as a reserved entry point but still
  defines no update workflow.

Future executables should be added as sibling directories instead of placing
sources in the repository root.

Repository-wide packaging and shared data installation remain defined at the
top level.
