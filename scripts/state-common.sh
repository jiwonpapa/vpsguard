#!/usr/bin/env bash

# OPS-009, NFR-009: legacy snapshot adapters share only pure hashing and
# machine identity reads here. This compatibility helper never mutates OS state.
hash_stream() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

machine_id_hash() {
  local path
  path="$(root_path /etc/machine-id)"
  if [[ -f "${path}" ]]; then
    hash_file "${path}"
  elif [[ -n "${test_root}" ]]; then
    printf 'test-machine\n' | hash_stream
  else
    echo "missing"
  fi
}
