#!/usr/bin/env sh
# Upload files to the GitHub release for a tag, from release.yml.
#
#   scripts/release-upload.sh v1.2.3 file [file...]
#
# POST only. The step this replaced (softprops/action-gh-release) also PATCHed
# the release on every upload -- name, body, draft and prerelease flags, read
# moments earlier and written back -- so four jobs rewrote the page the notes
# job and the person had set, and when GitHub refused that PATCH for v1.15.2
# ("Resource not accessible by integration", every job after 21:42 UTC, while
# the same POST kept landing on v1.15.0) the release shipped without its
# .dmg or its update feed. Uploading touches nothing but the asset.
#
# release-please makes the release before this runs. A tag pushed by hand has
# none, so one is created as a prerelease, which is what release-please now
# makes too: the `publish` job promotes it once everything is up.
set -eu
tag=$1
shift
[ $# -gt 0 ] || { echo "release-upload: nothing to upload for $tag" >&2; exit 2; }
repo=${GITHUB_REPOSITORY:?set by GitHub Actions}
if ! gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
    gh release create "$tag" --repo "$repo" --prerelease --title "$tag" \
        --notes "Building. release.yml fills this page in as the assets land."
fi
gh release upload "$tag" "$@" --clobber --repo "$repo"
