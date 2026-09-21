# shellcheck shell=bash
# Sourced, never run: one release version in, each package format's spelling
# of it out.
#
#   . packaging/version.sh
#   cairn_versions v1.4.0
#   echo "$DEB_VERSION"        # 1.4.0-1
#
# It is its own file because three builders need it and a version is the one
# thing they must not disagree about. A .deb that says 1.4.0 beside an .rpm that
# says 1.4.0~rc.1 for the same tag is two releases, and nobody finds out until
# one of them refuses to upgrade.
#
# What comes in is `VERSION` as `release.yml` computes it: a tag (`v1.4.0`), or
# `0.0.0-dispatch.<run id>` for a dry run. Both are semver, and neither is
# spelled the way any package manager wants:
#
#   * No leading `v`. dpkg requires a version to start with a digit and refuses
#     to build otherwise; rpm would accept it and then sort `v1.10.0` before
#     `v1.9.0`, comparing the two as text.
#   * A pre-release is `~`, not `-`. In both dpkg and rpm (4.10 and later) a
#     tilde sorts *before* the empty string, so `1.4.0~rc.1` is older than
#     `1.4.0` and the final release upgrades the candidate. With a hyphen the
#     candidate would sort as the newer of the two, and an operator who tried a
#     release candidate would be pinned to it. A hyphen is also simply illegal
#     in an rpm Version, and in a .deb it is the separator before the revision.
#   * macOS gets the three numbers and nothing else. Installer compares a
#     package version as dotted integers, and what it does with anything that
#     is not one is not documented anywhere worth relying on.
#
# The `-1` is the package revision, not part of the version: it is what a
# re-spin that changes only the packaging bumps, so that fixing a control file
# does not need a new tag.

cairn_versions() {
    local raw="${1:?cairn_versions needs a version}"
    local v="${raw#v}" core pre="" has_pre=0

    case "$v" in
        *-*) core="${v%%-*}"; pre="${v#*-}"; has_pre=1 ;;
        *)   core="$v" ;;
    esac

    # Refused rather than repaired. A version this cannot parse is a tag nobody
    # meant to cut, and guessing at it would publish a package under a number
    # that no source tree carries.
    if ! printf '%s\n' "$core" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "packaging: '$raw' is not a version this can package (want vX.Y.Z or X.Y.Z-pre)" >&2
        return 1
    fi
    # Asked of the hyphen and not of `$pre`: `v1.4.0-` has a hyphen and nothing
    # after it, and testing the empty string would wave it through as 1.4.0.
    if [ "$has_pre" -eq 1 ]; then
        if ! printf '%s\n' "$pre" | grep -Eq '^[0-9A-Za-z][0-9A-Za-z.-]*$'; then
            echo "packaging: '$raw' has a pre-release part no package format can spell" >&2
            return 1
        fi
        # Semver allows a hyphen inside a pre-release identifier; rpm does not
        # allow one anywhere in a Version.
        pre="${pre//-/.}"
    fi

    # Read by whoever sourced this; shellcheck cannot see across the `.`.
    # shellcheck disable=SC2034
    {
        UPSTREAM_VERSION="$v"
        MACOS_PKG_VERSION="$core"
        RPM_RELEASE=1
        if [ -n "$pre" ]; then
            DEB_VERSION="$core~$pre-1"
            RPM_VERSION="$core~$pre"
        else
            DEB_VERSION="$core-1"
            RPM_VERSION="$core"
        fi
    }
}
