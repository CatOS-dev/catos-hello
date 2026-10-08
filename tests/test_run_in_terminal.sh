#!/bin/bash
set -euo pipefail
runner=$1
state=$(mktemp -d "${TMPDIR:-/tmp}/catos-terminal-test.XXXXXX")
trap 'rm -rf -- "$state"' EXIT
mkdir -p "$state/bin" "$state/home"
cat > "$state/bin/ghostty" <<'STUB'
#!/bin/sh
[ "$1" = '-e' ] || exit 99
shift
printf '\n' | "$@"
STUB
chmod +x "$state/bin/ghostty"
set +e
HOME="$state/home" PATH="$state/bin:/usr/bin:/bin" "$runner" --prompt 'Test error status' 'exit 7' >/dev/null 2>&1
status=$?
set -e
[ "$status" = 7 ] || { echo "Expected 7, got $status" >&2; exit 1; }
HOME="$state/home" PATH="$state/bin:/usr/bin:/bin" "$runner" --prompt 'Test success' 'exit 0' >/dev/null 2>&1
[ "$(find "$state/home/.cache" -type f | wc -l)" = 0 ] || { echo 'Temporary scripts not removed' >&2; exit 1; }
