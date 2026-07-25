# Applications

Each directory under `apps/` owns one executable and its local build files.

- `hello/` contains the existing Qt welcome application (`catos-hello`).
- `system/` contains the CatOS system backend (`catos-system`),
  built as a single static musl binary and exposed through three
  multicall symlinks: `catos-update`, `catos-recovery`,
  `catos-doctor`. Phases 1 and 2 are read-only with respect to the
  target device; phase 3 (`recovery apply`/`resume`/`revert`) is the
  only place that writes to the target device, bounded to an
  explicitly-authorized, transactional Btrfs root-snapshot swap.

Future executables should be added as sibling directories instead of placing
sources in the repository root.

Repository-wide packaging and shared data installation remain defined at the
top level.
