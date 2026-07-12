#!/usr/bin/env bash
#
# Build libduocb for iOS — both the device (aarch64-apple-ios) and the
# Simulator (aarch64-apple-ios-sim) slices — and bundle them into
# libduocb.xcframework in dist/ios, staged with the C header. This is the
# canonical local build output; the CI release workflow zips it into the
# libduocb-ios.xcframework.zip asset. The sibling Xcode project (../duocb-ios)
# links it via its own Swift package (Packages/Duocb/Package.swift) — by
# default a pinned release download, or this dist/ios build (reached through a
# committed symlink) when DUOCB_LOCAL_XCFRAMEWORK is set (FFI dev). This
# script only produces dist/ios; it does not write into ../duocb-ios.
#
# An XCFramework is required (not a lipo "fat" .a): the device and Simulator
# slices are both arm64 on Apple Silicon, and lipo refuses to combine two
# slices of the same architecture. The .xcframework lets one Xcode project
# link the right slice for whichever destination is selected.
#
# Usage:
#   ./build-ios.sh            # release build (default)
#   ./build-ios.sh debug      # debug build (faster compile, huge .a)
set -euo pipefail

PROFILE="${1:-release}"
DEVICE_TARGET="aarch64-apple-ios"
SIM_TARGET="aarch64-apple-ios-sim"
# Minimum iOS version. Must be <= the Xcode project's deployment target.
# Override via env.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-17.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

case "$PROFILE" in
  release) CARGO_FLAGS="--release"; OUT_SUBDIR="release" ;;
  debug)   CARGO_FLAGS="";          OUT_SUBDIR="debug"   ;;
  *) echo "unknown profile '$PROFILE' (use 'release' or 'debug')" >&2; exit 1 ;;
esac

for target in "$DEVICE_TARGET" "$SIM_TARGET"; do
  if ! rustup target list --installed | grep -q "^${target}$"; then
    echo "Installing Rust target ${target}..."
    rustup target add "$target"
  fi
done

for target in "$DEVICE_TARGET" "$SIM_TARGET"; do
  echo "Building libduocb.a [$PROFILE] for $target ..."
  cargo build --lib -p duocb-ffi ${CARGO_FLAGS} --target "$target"
done

DIST="$SCRIPT_DIR/dist/ios"
XCFRAMEWORK="$DIST/libduocb.xcframework"
mkdir -p "$DIST"
cp "ios/duocb.h" "$DIST/duocb.h"

echo "Creating libduocb.xcframework ..."
rm -rf "$XCFRAMEWORK"
xcodebuild -create-xcframework \
  -library "target/${DEVICE_TARGET}/${OUT_SUBDIR}/libduocb.a" -headers "ios" \
  -library "target/${SIM_TARGET}/${OUT_SUBDIR}/libduocb.a"    -headers "ios" \
  -output "$XCFRAMEWORK"

echo "Staged: $XCFRAMEWORK"
echo "        $DIST/duocb.h"
echo
echo "For local iOS FFI dev, build the app against this xcframework with:"
echo "    cd ../duocb-ios"
echo "    DUOCB_LOCAL_XCFRAMEWORK=1 xcodegen generate"
echo "    DUOCB_LOCAL_XCFRAMEWORK=1 xcodebuild -project Duocb.xcodeproj \\"
echo "        -scheme DuocbApp -destination 'platform=iOS Simulator,name=iPhone 17' build"
echo "Done."
