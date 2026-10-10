#!/usr/bin/env bash
# Build environment of VCall — meant to be *sourced*.
#
# Inside the Veydan monorepo (this folder is services/<name> there) the
# project-local toolchain is used; VEYDAN_TOOLCHAINS says where it is, the
# one place that knows. Anywhere else, whatever cargo is on PATH.

VCALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export VCALL_DIR

VEYDAN_TOOLCHAINS="${VEYDAN_TOOLCHAINS:-$VCALL_DIR/../../data/toolchains}"
if [ -x "$VEYDAN_TOOLCHAINS/cargo/bin/cargo" ]; then
  VCALL_TOOLS="$(cd "$VEYDAN_TOOLCHAINS" && pwd)"
  export RUSTUP_HOME="$VCALL_TOOLS/rustup"
  export CARGO_HOME="$VCALL_TOOLS/cargo"
  export PATH="$CARGO_HOME/bin:$PATH"
else
  # Tools VCall fetches for itself (zig) go here when it lives alone.
  VCALL_TOOLS="$VCALL_DIR/.tools"
fi
export VCALL_TOOLS

if ! command -v cargo >/dev/null 2>&1; then
  echo "vcall: cargo not found; install Rust from https://rustup.rs" >&2
  return 1 2>/dev/null || exit 1
fi

# The folder cargo builds into, as cargo resolves it: target/ of this folder
# when it stands alone, the monorepo's data/target inside the monorepo (its
# .cargo/config.toml), CARGO_TARGET_DIR when that is set.
cargo_target_dir() {
  cargo metadata --format-version 1 --no-deps --manifest-path "$VCALL_DIR/Cargo.toml" \
    | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p'
}
