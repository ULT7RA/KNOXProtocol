#!/usr/bin/env bash
set -euo pipefail

OUT_FILE="${1:-launch-mainnet/public-ips.txt}"
NAMES_CSV="${NAMES_CSV:-KNOX1,KNOX2,KNOX3,KNOX4,KNOX5,KNOX6}"

mkdir -p "$(dirname "$OUT_FILE")"
IFS=',' read -r -a NAMES <<< "$NAMES_CSV"

if [[ "${#NAMES[@]}" -ne 6 ]]; then
  echo "NAMES_CSV must contain exactly 6 instance names"
  exit 1
fi

if ! command -v oci >/dev/null 2>&1; then
  echo "oci CLI not found in PATH"
  exit 1
fi

tmp_out="$(mktemp)"
trap 'rm -f "$tmp_out"' EXIT

json_get() {
  local expr="$1"
  python3 - "$expr" <<'PY'
import json,sys
expr = sys.argv[1]
obj = json.load(sys.stdin)

def pick(d, *keys):
    for k in keys:
        if isinstance(d, dict) and k in d and d[k] not in ("", None):
            return d[k]
    return ""

if expr == "search.id":
    items = (((obj or {}).get("data") or {}).get("items") or [])
    it = items[0] if items else {}
    print(pick(it, "identifier", "id"))
elif expr == "search.comp":
    items = (((obj or {}).get("data") or {}).get("items") or [])
    it = items[0] if items else {}
    print(pick(it, "compartmentId", "compartment-id"))
elif expr == "attach.vnic":
    data = (obj or {}).get("data") or []
    sel = None
    for a in data:
        st = pick(a, "lifecycleState", "lifecycle-state")
        if st == "ATTACHED":
            sel = a
            break
    if sel is None and data:
        sel = data[0]
    print(pick(sel or {}, "vnicId", "vnic-id"))
elif expr == "vnic.public":
    data = (obj or {}).get("data") or {}
    print(pick(data, "publicIp", "public-ip"))
else:
    print("")
PY
}

for name in "${NAMES[@]}"; do
  echo "[lookup] $name"
  s_json="$(oci search resource structured-search --query-text "query instance resources where displayName = '$name'" --output json)"
  iid="$(printf '%s' "$s_json" | json_get "search.id")"
  comp="$(printf '%s' "$s_json" | json_get "search.comp")"
  if [[ -z "$iid" || -z "$comp" ]]; then
    echo "failed to resolve instance or compartment for: $name"
    exit 1
  fi

  a_json="$(oci compute vnic-attachment list --compartment-id "$comp" --instance-id "$iid" --all --output json)"
  vid="$(printf '%s' "$a_json" | json_get "attach.vnic")"
  if [[ -z "$vid" ]]; then
    echo "failed to resolve VNIC for: $name"
    exit 1
  fi

  v_json="$(oci network vnic get --vnic-id "$vid" --output json)"
  ip="$(printf '%s' "$v_json" | json_get "vnic.public")"
  if [[ -z "$ip" ]]; then
    echo "no public IP on: $name (vnic $vid)"
    exit 1
  fi

  echo "$ip" >> "$tmp_out"
  echo "[ok] $name -> $ip"
done

mv "$tmp_out" "$OUT_FILE"
echo "wrote $OUT_FILE"
