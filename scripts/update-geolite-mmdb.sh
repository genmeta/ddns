#!/usr/bin/env sh

set -eu

usage() {
    cat <<'EOF'
Usage:
  MAXMIND_ACCOUNT_ID=... MAXMIND_LICENSE_KEY=... ./scripts/update-geolite-mmdb.sh [target-dir]

Downloads or updates the GeoLite2 City and ASN mmdb databases with geoipupdate.

Arguments:
  target-dir    Optional output directory. Defaults to /var/lib/ddns/geoip.

Required environment variables:
  MAXMIND_ACCOUNT_ID
  MAXMIND_LICENSE_KEY

Optional environment variables:
  GEOIPUPDATE_BIN         geoipupdate binary name or path. Default: geoipupdate
  GEOIPUPDATE_VERBOSE     Set to 1 to pass -v to geoipupdate.

Example:
  MAXMIND_ACCOUNT_ID=12345 \
  MAXMIND_LICENSE_KEY=xxxx \
  ./scripts/update-geolite-mmdb.sh /etc/ddns
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

if [ "$#" -gt 1 ]; then
    usage >&2
    exit 64
fi

require_env() {
    name="$1"
    eval "value=\${$name:-}"
    if [ -z "$value" ]; then
        echo "missing required environment variable: $name" >&2
        exit 2
    fi
}

require_env MAXMIND_ACCOUNT_ID
require_env MAXMIND_LICENSE_KEY

geoipupdate_bin="${GEOIPUPDATE_BIN:-geoipupdate}"
target_dir="${1:-${GEOIP_TARGET_DIR:-/var/lib/ddns/geoip}}"

if ! command -v "$geoipupdate_bin" >/dev/null 2>&1; then
    echo "geoipupdate not found: $geoipupdate_bin" >&2
    echo "install it first, for example on macOS: brew install geoipupdate" >&2
    exit 127
fi

umask 077
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/geoipupdate.XXXXXX")"
cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$target_dir"

config_file="$tmp_dir/GeoIP.conf"
cat >"$config_file" <<EOF
AccountID ${MAXMIND_ACCOUNT_ID}
LicenseKey ${MAXMIND_LICENSE_KEY}
EditionIDs GeoLite2-City GeoLite2-ASN
DatabaseDirectory ${target_dir}
PreserveFileTimes 1
EOF

set -- "$geoipupdate_bin" -f "$config_file" -d "$target_dir"
if [ "${GEOIPUPDATE_VERBOSE:-0}" = "1" ]; then
    set -- "$@" -v
fi

"$@"

city_db="$target_dir/GeoLite2-City.mmdb"
asn_db="$target_dir/GeoLite2-ASN.mmdb"

if [ ! -f "$city_db" ] || [ ! -f "$asn_db" ]; then
    echo "geoipupdate completed but expected mmdb files were not found in $target_dir" >&2
    exit 1
fi

cat <<EOF
GeoLite databases updated:
  $city_db
  $asn_db

Set ddns-server config to:
  geoip_city_db = "$city_db"
  geoip_asn_db = "$asn_db"
EOF