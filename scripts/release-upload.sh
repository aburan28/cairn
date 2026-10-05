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
# A published release's assets are what people have already downloaded and
# checksummed. Replacing them -- a re-run on the tag, which rebuilds with a
# newer toolchain -- would make every recorded checksum stop matching, with
# nothing saying why. Only a draft or a prerelease, which is every release
# until release.yml's `publish` job promotes it, takes a replacement.
unpublished=$(gh release view "$tag" --repo "$repo" --json isDraft,isPrerelease --jq '.isDraft or .isPrerelease')
if [ "$unpublished" != "true" ]; then
    echo "release-upload: $tag is published; its assets are not replaced. Cut a new version instead." >&2
    exit 1
fi
gh release upload "$tag" "$@" --clobber --repo "$repo"
