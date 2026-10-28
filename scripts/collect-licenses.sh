#!/bin/sh
# Build-time only, inside the Go toolchain container.
set -eu
out=${1:?license output directory required}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir -p "$out/go"
cp "$(go env GOROOT)/LICENSE" "$out/go/LICENSE"
go list -m all > "$out/modules.txt"
go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}}|{{.Dir}}{{end}}{{end}}' ./cmd/repbridge > "$work/modules"
sort -u "$work/modules" > "$work/modules-sorted"
while IFS='|' read -r module directory; do
    test -n "$module" || continue
    test -n "$directory" || { echo "Missing module source: $module" >&2; exit 1; }
    destination="$out/$module"
    mkdir -p "$destination"
    found=0
    for file in "$directory"/LICENSE* "$directory"/LICENCE* "$directory"/COPYING* "$directory"/NOTICE* "$directory"/COPYRIGHT*; do
        test -f "$file" || continue
        cp "$file" "$destination/"
        found=1
    done
    test "$found" = 1 || { echo "Review missing license for $module" >&2; exit 1; }
done < "$work/modules-sorted"
