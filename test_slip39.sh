#!/usr/bin/env bash
#
# Verify the SLIP-39 implementation in mnemonic.py.
#
# 1. Recovery against the official SLIP-39 test vectors vendored from
#    trezor/python-shamir-mnemonic (slip39_vectors.json). The vectors cover
#    valid and invalid shares (bad checksum, bad padding, duplicate indices,
#    insufficient shares, mismatched identifiers, ...).
# 2. Generation -> recovery round trips: 1-of-1, 2-of-3, 3-of-5 and a
#    two-level 2-of-2 groups / 2-of-3 members scheme, with and without a
#    passphrase, for both 128-bit and 256-bit master secrets.
# 3. Cross-check with Electrum's own slip39 module (slip39.recover_ems) that
#    the master secret recovered by mnemonic.py matches Electrum's.
#
# Usage:
#   ./test_slip39.sh
#
# Environment overrides:
#   ELECTRUM_REPO  path to the Electrum source tree (default: ../bal/electrum)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ELECTRUM_REPO="${ELECTRUM_REPO:-$SCRIPT_DIR/../bal/electrum}"
ELECTRUM_PYTHON="${ELECTRUM_PYTHON:-$ELECTRUM_REPO/env/bin/python}"
MNEMONIC_PY="${MNEMONIC_PY:-$SCRIPT_DIR/mnemonic.py}"
VECTORS="$SCRIPT_DIR/slip39_vectors.json"
WORK="$(mktemp -d)"
PASS=0
FAIL=0

cleanup() {
    rm -rf "$WORK"
}
trap cleanup EXIT

if [[ ! -f "$MNEMONIC_PY" ]]; then
    echo "error: mnemonic.py not found at $MNEMONIC_PY" >&2
    exit 1
fi

# ---------- 1. Official reference vectors ----------

run_vector_check() {
    local passfail
    passfail="$("$ELECTRUM_PYTHON" - "$SCRIPT_DIR" "$VECTORS" <<'EOF'
import json
import sys

sys.path.insert(0, sys.argv[1])
import mnemonic

wordlist = mnemonic.slip39_load_wordlist(sys.argv[1] + '/slip39_english.txt')
vectors = json.load(open(sys.argv[2]))

ok = 0
for name, mnemonics, secret_hex, xprv in vectors:
    try:
        secret = mnemonic.slip39_recover(mnemonics, 'TREZOR', wordlist)
    except Exception as e:
        if secret_hex == '':
            ok += 1
        else:
            print(f'FAIL: {name}: unexpected error: {e}')
        continue
    if secret_hex == '':
        print(f'FAIL: {name}: expected error, recovered {secret.hex()}')
    elif secret.hex() == secret_hex:
        ok += 1
    else:
        print(f'FAIL: {name}: recovered {secret.hex()}, expected {secret_hex}')
print(f'{ok}/{len(vectors)}')
EOF
)"
    local summary
    summary="$(printf '%s\n' "$passfail" | tail -1)"
    local failures
    failures="$(printf '%s\n' "$passfail" | grep '^FAIL:' || true)"
    if [[ -z "$failures" ]]; then
        PASS=$((PASS + 1))
        echo "PASS: official trezor vectors ($summary)"
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: official trezor vectors"
        printf '%s\n' "$failures" | sed 's/^/    /'
    fi
}

if [[ -f "$VECTORS" ]]; then
    run_vector_check
else
    FAIL=$((FAIL + 1))
    echo "FAIL: missing $VECTORS (run from the repo root or set VECTORS)"
fi

# ---------- 2. Generation -> recovery round trips ----------

roundtrip() {
    local name="$1" entropy="$2" words="$3" shares="$4" threshold="$5" groups="$6" gt="$7" passphrase="$8"
    local out passphrase_flags share_flags
    out="$("$ELECTRUM_PYTHON" "$MNEMONIC_PY" --type slip39 --bitshex "$entropy" \
        --slip39-words "$words" --slip39-shares "$shares" --slip39-threshold "$threshold" \
        --slip39-groups "$groups" --slip39-group-threshold "$gt" \
        ${passphrase:+--passphrase "$passphrase"} --count 1 2>/dev/null)"
    local ms
    ms="$(printf '%s\n' "$out" | sed -n 's/^  Master secret ([^)]*): //p')"
    mapfile -t shares_list < <(printf '%s\n' "$out" | sed -n 's/^  Share [0-9][0-9]*: //p')
    if [[ -z "$ms" || "${#shares_list[@]}" -ne "$((groups * shares))" ]]; then
        FAIL=$((FAIL + 1))
        echo "FAIL: roundtrip/$name (bad script output)"
        return
    fi
    # pick `threshold` shares from each of `gt` groups
    local pick=()
    local g s idx
    for ((g = 0; g < gt; g++)); do
        for ((s = 0; s < threshold; s++)); do
            idx=$((g * shares + s))
            pick+=(--slip39-recover "${shares_list[$idx]}")
        done
    done
    local rec
    rec="$("$ELECTRUM_PYTHON" "$MNEMONIC_PY" --type slip39 "${pick[@]}" \
        ${passphrase:+--passphrase "$passphrase"} --count 1 2>/dev/null | sed -n 's/^  Master secret ([^)]*): //p')"
    if [[ "$rec" == "$ms" ]]; then
        PASS=$((PASS + 1))
        echo "PASS: roundtrip/$name"
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: roundtrip/$name (generated $ms, recovered $rec)"
    fi
}

Z128="$(printf '12%.0s' $(seq 1 16))"
Z256="$(printf 'ab%.0s' $(seq 1 32))"
roundtrip "1of1-128" "$Z128" 12 1 1 1 1 ""
roundtrip "2of3-128" "$Z128" 12 3 2 1 1 ""
roundtrip "2of3-128-passphrase" "$Z128" 12 3 2 1 1 "some passphrase"
roundtrip "3of5-128" "$Z128" 12 5 3 1 1 ""
roundtrip "1of1-256" "$Z256" 24 1 1 1 1 ""
roundtrip "2of3-256" "$Z256" 24 3 2 1 1 ""
roundtrip "groups-2x3-256" "$Z256" 24 3 2 2 2 ""

# ---------- 3. Cross-check against Electrum's slip39 module ----------

electrum_crosscheck() {
    local name="$1" entropy="$2" words="$3" shares="$4" threshold="$5" groups="$6" gt="$7" passphrase="$8"
    local out ms shares_list
    out="$("$ELECTRUM_PYTHON" "$MNEMONIC_PY" --type slip39 --bitshex "$entropy" \
        --slip39-words "$words" --slip39-shares "$shares" --slip39-threshold "$threshold" \
        --slip39-groups "$groups" --slip39-group-threshold "$gt" \
        ${passphrase:+--passphrase "$passphrase"} --count 1 2>/dev/null)"
    ms="$(printf '%s\n' "$out" | sed -n 's/^  Master secret ([^)]*): //p')"
    mapfile -t shares_list < <(printf '%s\n' "$out" | sed -n 's/^  Share [0-9][0-9]*: //p')
    if [[ -z "$ms" ]]; then
        FAIL=$((FAIL + 1))
        echo "FAIL: electrum-crosscheck/$name (bad script output)"
        return
    fi
    local pick=()
    local g s idx
    for ((g = 0; g < gt; g++)); do
        for ((s = 0; s < threshold; s++)); do
            idx=$((g * shares + s))
            pick+=("${shares_list[$idx]}")
        done
    done
    local ems_ms
    ems_ms="$("$ELECTRUM_PYTHON" - <<EOF
import sys
sys.path.insert(0, '$ELECTRUM_REPO')
from electrum.slip39 import recover_ems
mnemonics = $(python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "${pick[@]}")
print(recover_ems(mnemonics).decrypt('$passphrase').hex())
EOF
)"
    if [[ "$ems_ms" == "$ms" ]]; then
        PASS=$((PASS + 1))
        echo "PASS: electrum-crosscheck/$name"
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: electrum-crosscheck/$name (script $ms, electrum $ems_ms)"
    fi
}

electrum_crosscheck "2of3-128" "$Z128" 12 3 2 1 1 ""
electrum_crosscheck "2of3-128-passphrase" "$Z128" 12 3 2 1 1 "test phrase"
electrum_crosscheck "2of3-256" "$Z256" 24 3 2 1 1 ""
electrum_crosscheck "groups-2x3-256" "$Z256" 24 3 2 2 2 ""

echo
echo "Results: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
