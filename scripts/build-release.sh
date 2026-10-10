#!/usr/bin/env bash
# Builds the node: one static file that runs on any Linux server.
#
#   dist/vcall                the node
#   dist/SHA256SUMS           its checksum
#   dist/RELEASE              the release name, <version>-<build time>
#
# A static build needs a C compiler for musl. Order of choice: zig (fetched
# into the tools directory when missing), then musl-gcc from the system.
#
#   VCALL_TARGET=aarch64-unknown-linux-musl   another machine type
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
cd "$VCALL_DIR"

# The monorepo's build environment points C compilers at the desktop's
# glibc headers (CFLAGS) and the linker at its libraries (RUSTFLAGS). A
# static musl build must see none of that: the C of aws-lc (DTLS of the
# SFU) compiled against glibc 2.38+ headers wants __isoc23_sscanf, which
# musl has not.
unset CFLAGS CXXFLAGS CPPFLAGS RUSTFLAGS GCC_EXEC_PREFIX

TARGET="${VCALL_TARGET:-x86_64-unknown-linux-musl}"
ZIG_VERSION="${VCALL_ZIG_VERSION:-0.13.0}"
ZIG_DIR="$VCALL_TOOLS/zig"

say() { echo ">> $*"; }
die() { echo "vcall build: $*" >&2; exit 1; }

# --- toolchain ---------------------------------------------------------------
if command -v rustup >/dev/null 2>&1; then
  rustup target list --installed | grep -qx "$TARGET" || {
    say "adding rust target $TARGET"
    rustup target add "$TARGET" >/dev/null
  }
fi

fetch_zig() {
  [ "${VCALL_NO_FETCH:-0}" = 1 ] && return 1
  local arch sha archive name
  arch="$(uname -m)"
  # The archives of zig by the sha256 ziglang.org publishes
  # (https://ziglang.org/download/index.json): nothing unchecked runs here.
  case "$ZIG_VERSION-$arch" in
    0.13.0-x86_64) sha=d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea ;;
    0.13.0-aarch64) sha=041ac42323837eb5624068acd8b00cd5777dac4cf91179e8dad7a7e90dd0c556 ;;
    *) die "zig $ZIG_VERSION for $arch has no pinned sha256 in scripts/build-release.sh" ;;
  esac
  name="zig-linux-$arch-$ZIG_VERSION"
  say "fetching zig $ZIG_VERSION into $ZIG_DIR"
  mkdir -p "$ZIG_DIR"
  archive="$(mktemp)"
  curl -fsSL --proto '=https' "https://ziglang.org/download/$ZIG_VERSION/$name.tar.xz" -o "$archive"
  echo "$sha  $archive" | sha256sum -c --quiet - || { rm -f "$archive"; die "zig $ZIG_VERSION: the archive is not the pinned one"; }
  tar -xJ -C "$ZIG_DIR" --strip-components=1 -f "$archive"
  rm -f "$archive"
}

[ -x "$ZIG_DIR/zig" ] && export PATH="$ZIG_DIR:$PATH"

builder=""
if command -v zig >/dev/null 2>&1 || fetch_zig; then
  export PATH="$ZIG_DIR:$PATH"
  if ! command -v cargo-zigbuild >/dev/null 2>&1; then
    say "installing cargo-zigbuild"
    cargo install cargo-zigbuild --version 0.23.4 --locked >/dev/null 2>&1 || die "cannot install cargo-zigbuild 0.23.4"
  fi
  builder="zigbuild"
elif command -v musl-gcc >/dev/null 2>&1; then
  builder="build"
else
  die "no C compiler for $TARGET: install zig (https://ziglang.org) or musl-tools"
fi

# --- build -------------------------------------------------------------------
version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
release="$version-$(date -u +%Y%m%d%H%M%S)"
say "building vcall $release for $TARGET (cargo $builder)"
cargo "$builder" --release --locked --target "$TARGET" -p vcall

mkdir -p dist
bin="$(cargo_target_dir)/$TARGET/release/vcall"
[ -x "$bin" ] || die "no binary at $bin"
# A binary that needs libraries from the build machine is not a release.
if command -v ldd >/dev/null 2>&1 && ldd "$bin" 2>/dev/null | grep -q '=>'; then
  die "$bin is dynamically linked"
fi
# Renamed into place: a copy that is running cannot be written over.
cp "$bin" "dist/vcall.new"
mv -f "dist/vcall.new" "dist/vcall"
(cd dist && sha256sum vcall > SHA256SUMS)
echo "$release" > dist/RELEASE

say "dist/vcall  $(du -h dist/vcall | cut -f1)   $release"
