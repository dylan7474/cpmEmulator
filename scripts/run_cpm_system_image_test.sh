#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cpm_b64="${repo_root}/third_party/cpm22/cpm.bin.base64"
bios_b64="${repo_root}/third_party/cpm22/bios.bin.base64"

if [[ ! -f "${cpm_b64}" || ! -f "${bios_b64}" ]]; then
  echo "Expected CP/M base64 payloads were not found in third_party/cpm22" >&2
  exit 1
fi

decode_base64_to_tmp() {
  local src="$1"
  local dst
  dst="$(mktemp)"
  python3 - <<'PY' "$src" "$dst"
import base64
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])

data = base64.b64decode(src.read_text())
dst.write_bytes(data)
PY
  printf '%s' "$dst"
}

cpm_bin="$(decode_base64_to_tmp "${cpm_b64}")"
bios_bin="$(decode_base64_to_tmp "${bios_b64}")"

cleanup_tmp_files() {
  rm -f "$cpm_bin" "$bios_bin"
}

trap cleanup_tmp_files EXIT

if [[ ! -x "${repo_root}/z80" ]]; then
  make -C "${repo_root}"
fi

make -C "${repo_root}" example >/dev/null

example_output="$("${repo_root}/z80" "${repo_root}/examples/hello.bin" 2>&1)"
printf '%s\n' "$example_output"
if ! grep -q "Hello from CP/M!" <<<"$example_output"; then
  echo "Hello-world transient program did not print the CP/M greeting" >&2
  exit 1
fi

output="$("${repo_root}/z80" \
  --no-cpm-traps \
  --entry 0xfa00 \
  --load "0xdc00:${cpm_bin}" \
  --load "0xfa00:${bios_bin}" \
  --cycles 500000 2>&1)"
status=$?
printf '%s\n' "$output"

if [[ $status -ne 0 ]]; then
  exit $status
fi

if grep -q "Unimplemented opcode" <<<"$output"; then
  echo "CP/M system exercise reported unimplemented opcodes" >&2
  exit 1
fi
