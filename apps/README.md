# Applications

Each directory under `apps/` owns one executable and its local build files.

- `hello/` contains the existing Qt welcome application (`catos-hello`).
- `system/` contains the shared static backend (`catos-system`) for the
  `catos-update`, `catos-recovery`, `catos-doctor`, and `catos-repair` entry
  points. `catos-doctor` is argumentless, `catos-recovery` handles snapshot
  recovery, and `catos-repair` owns fs/mount/boot repair. This change only
  preserves the `catos-update` entry point; it does not define its behaviour.

Future executables should be added as sibling directories instead of placing
sources in the repository root.

Repository-wide packaging and shared data installation remain defined at the
top level.
