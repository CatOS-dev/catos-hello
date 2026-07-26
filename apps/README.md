# Applications

Each directory under `apps/` owns one executable and its local build files.

- `hello/` contains the existing Qt welcome application (`catos-hello`).
- `system/` contains the shared static backend (`catos-system`) for the
  `catos-update`, `catos-recovery`, `catos-doctor`, and `catos-repair` entry
  points. `catos-doctor` is argumentless, `catos-recovery` handles durable
  Btrfs snapshot recovery, and `catos-repair` implements filesystem repair
  plus transactional fstab/subvolume/boot-mount repair. `catos-repair boot`
  remains reserved for the boot-provider stage. `catos-update` is installed
  as a reserved entry point but still defines no update workflow.

Future executables should be added as sibling directories instead of placing
sources in the repository root.

Repository-wide packaging and shared data installation remain defined at the
top level.
