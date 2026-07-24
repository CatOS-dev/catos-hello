# Applications

Each directory under `apps/` owns one executable and its local build files.

- `hello/` contains the existing Qt welcome application (`catos-hello`).
- `system/` contains the read-only Rust system backend (`catos-system`),
  built as a single static musl binary and exposed through three multicall
  symlinks: `catos-update`, `catos-recovery`, `catos-doctor`.

Future executables should be added as sibling directories instead of placing
sources in the repository root.

Repository-wide packaging and shared data installation remain defined at the
top level.
