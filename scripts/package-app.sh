#!/bin/zsh
set -euo pipefail

project_dir=${0:A:h:h}
configuration=${1:-debug}
bundle_dir="$project_dir/build/Trailfox.app"
scratch_dir="$project_dir/.build"

build_args=(--disable-sandbox --scratch-path "$scratch_dir" --configuration "$configuration" --product Trailfox)
if [[ -n ${TRAILFOX_SDK_OVERRIDE:-} ]]; then
  build_args+=(-Xswiftc -sdk -Xswiftc "$TRAILFOX_SDK_OVERRIDE")
fi

swift build "${build_args[@]}"
binary_path=$(find "$scratch_dir" -type f -perm -111 -name Trailfox | head -1)
if [[ -z $binary_path ]]; then
  print -u2 "Trailfox binary was not found after a successful build."
  exit 1
fi

mkdir -p "$bundle_dir/Contents/MacOS" "$bundle_dir/Contents/Resources"
cp "$binary_path" "$bundle_dir/Contents/MacOS/Trailfox"
cp "$project_dir/Resources/Info.plist" "$bundle_dir/Contents/Info.plist"
cp "$project_dir/Resources/Assets.xcassets/AppIcon.appiconset/icon_512x512@2x.png" "$bundle_dir/Contents/Resources/TrailfoxIcon.png"
codesign --force --sign - "$bundle_dir"
print "$bundle_dir"
