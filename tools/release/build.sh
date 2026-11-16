#!/usr/bin/env bash
# Build the release files from the committed tree, in Docker, with the same
# script as CI's package job (tests/ci/package.sh): each package is built,
# linted, installed and removed in its distribution before it is kept.
#
#   tools/release/build.sh [OUTDIR]          default: dist/release-<version>
#   DISTROS="debian12 arch" tools/release/build.sh   a subset
#
# Output in OUTDIR:
#   blockads-linux-<version>.tar.gz                    source (make dist)
#   blockads-linux_<version>_<distro>_all.deb          one per Debian/Ubuntu release
#   blockads-linux-<version>-1-any.pkg.tar.zst         Arch
#   SHA256SUMS
#   logs/<distro>/                                     package.log, build/lint logs
# Exit status: the number of distributions that failed.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' src/blockads_linux/__init__.py)
OUT=${1:-dist/release-$VERSION}
declare -A IMAGES=([debian12]=debian:12 [debian13]=debian:13 [ubuntu2404]=ubuntu:24.04
                   [ubuntu2604]=ubuntu:26.04 [arch]=archlinux:latest)
read -ra distros <<<"${DISTROS:-debian12 debian13 ubuntu2404 ubuntu2604 arch}"

if [[ -n $(git status --porcelain --untracked-files=no) && -z ${ALLOW_DIRTY:-} ]]; then
    echo "build.sh: the tree has uncommitted changes; commit them first (or ALLOW_DIRTY=1)" >&2; exit 2
fi
rm -rf "$OUT"; mkdir -p "$OUT/logs"
OUT=$(cd "$OUT" && pwd)

# A clean export of HEAD: the packages must hold what the tag will hold, not
# local build products (.qm, __pycache__, results/).
SRC=$(mktemp -d "${TMPDIR:-/tmp}/blockads-release.XXXXXX")
trap 'rm -rf "$SRC"' EXIT
git archive HEAD | tar -C "$SRC" -xf -

(cd "$SRC" && make -s dist >/dev/null) && mv "$SRC/blockads-linux-$VERSION.tar.gz" "$OUT/" \
    || { echo "build.sh: make dist failed" >&2; exit 1; }
echo "source  blockads-linux-$VERSION.tar.gz"

build_one() {
    local d=$1 res=$OUT/logs/$1
    mkdir -p "$res"
    docker run --rm -v "$SRC:/src:ro" -v "$res:/results" "${IMAGES[$d]}" bash /src/tests/ci/package.sh \
        >"$res/docker.log" 2>&1
}
for d in "${distros[@]}"; do
    [[ -n ${IMAGES[$d]:-} ]] || { echo "build.sh: unknown distro $d" >&2; exit 2; }
    build_one "$d" &
done
wait

failed=0
for d in "${distros[@]}"; do
    res=$OUT/logs/$d
    if [[ ! -s $res/package.log ]] || grep -q '^FAIL' "$res/package.log"; then
        echo "FAIL    $d (see $res/package.log, $res/docker.log)"; grep '^FAIL' "$res/package.log" 2>/dev/null | sed 's/^/        /'
        failed=$((failed + 1)); continue
    fi
    if [[ $d == arch ]]; then
        f=$(ls "$res"/blockads-linux-*.pkg.tar.* 2>/dev/null | head -1)
        [[ -n $f ]] && mv "$f" "$OUT/"
    else
        f=$(ls "$res"/blockads-linux_*_all.deb 2>/dev/null | head -1)
        # The plain version in the name: GitHub rewrites a Debian "~" in asset names.
        [[ -n $f ]] && { name=blockads-linux_${VERSION}_${d}_all.deb; mv "$f" "$OUT/$name"; f=$name; }
    fi
    if [[ -z $f ]]; then echo "FAIL    $d (no package in $res)"; failed=$((failed + 1)); continue; fi
    echo "ok      $d  $(basename "$f")  ($(grep -c '^PASS' "$res/package.log") checks)"
done

(cd "$OUT" && sha256sum -- *.tar.gz *.deb *.pkg.tar.* 2>/dev/null >SHA256SUMS)
echo "out     $OUT"
exit $failed
