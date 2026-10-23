#!/bin/sh
# Forced command for the docs deploy key on the host. Reads a gzip tarball on
# stdin; the original ssh command selects what it is:
#
#   publish <40-hex commit sha>   tarball holds docs/ (the latest docs from main)
#   publish-version <vX.Y.Z>      tarball holds one released version's built site
#
# Latest docs are published as immutable releases behind the "current" symlink.
# Released versions live in versions/ so they survive every latest deploy and
# are copied into each new release alongside versions.json.
set -eu
ROOT=/opt/mcp-auth-docs/site

usage() { echo "usage: publish <sha> | publish-version <vX.Y.Z>" >&2; exit 2; }

# versions.json lists released versions, newest first.
write_versions() {
  dest=$1
  out="$dest/versions.json"
  {
    printf '['
    sep=
    for v in $(ls -1 "$ROOT/versions" 2>/dev/null | sort -rV); do
      printf '%s"%s"' "$sep" "$v"
      sep=,
    done
    printf ']\n'
  } > "$out.tmp"
  mv "$out.tmp" "$out"
}

set -- $SSH_ORIGINAL_COMMAND
[ "$#" -eq 2 ] || usage
mkdir -p "$ROOT/releases" "$ROOT/versions"

case "$1" in
  publish)
    case "$2" in *[!0-9a-f]*|"") echo "bad revision" >&2; exit 2;; esac
    [ "${#2}" -eq 40 ] || { echo "bad revision" >&2; exit 2; }
    REL="$ROOT/releases/$2"
    TMP="$ROOT/releases/.tmp-$2"
    rm -rf "$TMP"; mkdir -p "$TMP"
    tar -xzf - -C "$TMP" --no-same-owner
    [ -f "$TMP/docs/index.html" ] || { rm -rf "$TMP"; echo "tarball has no docs/index.html" >&2; exit 1; }
    printf '{"revision":"%s"}\n' "$2" > "$TMP/docs/_deployment.json"
    for v in $(ls -1 "$ROOT/versions"); do
      rm -rf "$TMP/docs/$v"; cp -a "$ROOT/versions/$v" "$TMP/docs/$v"
    done
    write_versions "$TMP/docs"
    rm -rf "$REL"; mv "$TMP" "$REL"
    ln -sfn "releases/$2" "$ROOT/current.new"
    mv -T "$ROOT/current.new" "$ROOT/current"
    # keep the 5 newest releases
    ls -1dt "$ROOT"/releases/*/ | tail -n +6 | xargs -r rm -rf
    echo "published $2"
    ;;
  publish-version)
    case "$2" in
      v[0-9]*) ;;
      *) echo "bad version" >&2; exit 2;;
    esac
    case "$2" in *[!0-9A-Za-z.-]*|*..*) echo "bad version" >&2; exit 2;; esac
    TMP="$ROOT/versions/.tmp-$2"
    rm -rf "$TMP"; mkdir -p "$TMP"
    tar -xzf - -C "$TMP" --no-same-owner
    [ -f "$TMP/index.html" ] || { rm -rf "$TMP"; echo "tarball has no index.html" >&2; exit 1; }
    rm -rf "$ROOT/versions/$2"; mv "$TMP" "$ROOT/versions/$2"
    # make it live now, without waiting for the next latest deploy
    LIVE="$ROOT/current/docs"
    [ -d "$LIVE" ] || { echo "no current release to attach to" >&2; exit 1; }
    rm -rf "$LIVE/$2"; cp -a "$ROOT/versions/$2" "$LIVE/$2"
    write_versions "$LIVE"
    echo "published version $2"
    ;;
  *) usage;;
esac
