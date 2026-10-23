#!/bin/sh
# Forced command for the docs deploy key on the host. Reads a gzip tarball of
# the built site (containing docs/) on stdin and publishes it as an immutable
# release; the original ssh command is "publish <40-hex commit sha>".
set -eu
ROOT=/opt/mcp-auth-docs/site
set -- $SSH_ORIGINAL_COMMAND
[ "$#" -eq 2 ] && [ "$1" = publish ] || { echo "usage: publish <sha>" >&2; exit 2; }
case "$2" in *[!0-9a-f]*|"") echo "bad revision" >&2; exit 2;; esac
[ "${#2}" -eq 40 ] || { echo "bad revision" >&2; exit 2; }
REL="$ROOT/releases/$2"
TMP="$ROOT/releases/.tmp-$2"
rm -rf "$TMP"; mkdir -p "$TMP"
tar -xzf - -C "$TMP" --no-same-owner
[ -f "$TMP/docs/index.html" ] || { rm -rf "$TMP"; echo "tarball has no docs/index.html" >&2; exit 1; }
printf '{"revision":"%s"}\n' "$2" > "$TMP/docs/_deployment.json"
rm -rf "$REL"; mv "$TMP" "$REL"
ln -sfn "releases/$2" "$ROOT/current.new"
mv -T "$ROOT/current.new" "$ROOT/current"
# keep the 5 newest releases
ls -1dt "$ROOT"/releases/*/ | tail -n +6 | xargs -r rm -rf
echo "published $2"
