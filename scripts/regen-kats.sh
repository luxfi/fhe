#!/usr/bin/env bash
# regen-kats.sh — deterministic regeneration + verification of every
# Lux FHE-KAT consumed by the C++ production runtime
# (luxcpp/crypto/fhe/test/cpp/fhe_kat_replay_test).
#
# LP-167 §"Cross-runtime KAT contract" is the binding spec; this
# script enforces the byte-equality invariant.
#
# Default output:
#   <luxcpp>/crypto/fhe/test/kat/sk_pn10qp27_seed_zero.json
#   <luxcpp>/crypto/fhe/test/kat/sk_pn10qp27_seed_lp167.json
#   <luxcpp>/crypto/fhe/test/kat/sk_pn11qp54_seed_zero.json
#   <luxcpp>/crypto/fhe/test/kat/sk_pn11qp54_seed_lp167.json
#
# Manifest:
#   <fhe>/scripts/regen-kats.manifest.sha256
#
# Modes:
#   regen-kats.sh               — regenerate corpus + write manifest
#   regen-kats.sh --verify      — regenerate corpus, diff against
#                                 existing manifest, fail on mismatch

set -euo pipefail

FHE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LUXCPP_DIR="${LUXCPP_DIR:-${HOME}/work/luxcpp}"
KAT_BASE="${LUXCPP_DIR}/crypto/fhe"
KAT_OUT="${KAT_BASE}/test/kat"

MANIFEST="${FHE_DIR}/scripts/regen-kats.manifest.sha256"

VERIFY=0
if [[ "${1:-}" == "--verify" ]]; then
  VERIFY=1
fi

cd "${FHE_DIR}"
mkdir -p "${KAT_OUT}"

echo "[1/2] kat_oracle --emit --out ${KAT_OUT}"
go run ./cmd/kat_oracle --emit --out "${KAT_OUT}" >/dev/null

echo "[2/2] in-tree determinism test"
go test -count=1 -run "TestNewKeyGeneratorFromSeed_Deterministic|TestNewKeyGeneratorFromSeed_DifferentSeeds" . >/dev/null

# Build sha256 manifest deterministically (sorted by file name).
TMP_MANIFEST="$(mktemp)"
trap 'rm -f "${TMP_MANIFEST}"' EXIT

# Stable order regardless of glob expansion. Paths in the manifest are
# relative to KAT_BASE so the manifest is portable across hosts (different
# ${HOME}).
find "${KAT_OUT}" -maxdepth 1 -name "*.json" -type f | sort | while read -r f; do
  rel="${f#${KAT_BASE}/}"
  shasum -a 256 "$f" | awk -v p="${rel}" '{print $1"  "p}'
done > "${TMP_MANIFEST}"

if [[ "${VERIFY}" == "1" ]]; then
  if [[ ! -f "${MANIFEST}" ]]; then
    echo "ERROR: --verify requested but no prior manifest at ${MANIFEST}"
    exit 2
  fi
  if ! diff -u "${MANIFEST}" "${TMP_MANIFEST}"; then
    echo "FAIL: manifest mismatch — Lux FHE KAT regeneration is non-deterministic" >&2
    exit 3
  fi
  echo "OK: Lux FHE KAT regeneration is byte-equal across runs ($(wc -l < "${MANIFEST}") files)"
else
  cp "${TMP_MANIFEST}" "${MANIFEST}"
  echo "wrote manifest: ${MANIFEST}"
  cat "${MANIFEST}"
fi
