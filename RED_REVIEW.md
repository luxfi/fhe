# Red Team Review — FHE-CRDT Stack (lux/fhe)

Review date: 2026-04-12

## Fixed Findings

| # | Severity | Title | Status |
|---|----------|-------|--------|
| 2 | HIGH | Reshare reconstructs secret in cleartext | FIXED: additive sub-sharing, no secret materialization |
| 5 | HIGH | MergeLWWN tie-break is left-biased | FIXED: value-based deterministic tie-break |
| 6 | MEDIUM | ORSet tags are plaintext | FIXED: HMAC-wrapped tags via NewPrivateORSet |
| 8 | MEDIUM | Unbounded allocation in gob deserialization | FIXED: maxBits=256, maxORSetElements=65536 |
| 9 | MEDIUM | GCounter accepts fabricated nodeIDs | FIXED: authorized node allowlist |
| 10 | MEDIUM | Feldman VSS uses g=2 (wrong subgroup) | FIXED: g=2^2 mod p (order-q element) |

## INFO Findings (not fixed, documented)

### INFO-1: FHE bootstrap cost not metered at application layer

The FHE merge operations (MergeLWW, MergeGCounter) can be expensive (~100ms
per bootstrap at PN10QP27). There is no application-layer budget or timeout
for merge operations. In production, the relay should enforce per-request
compute budgets to prevent resource exhaustion.

Mitigation: relay-side request timeouts (context.WithTimeout at the RPC
handler). Not a library concern.

### INFO-2: GCounter total is not encrypted

The total count of a GCounter (sum of all node counts) can only be computed
by a party holding the secret key. An untrusted relay cannot compute the
total. However, the relay CAN observe the number of participating nodes and
whether individual node counts changed (by observing ciphertext rotation).

Mitigation: this is an inherent property of the per-node counter structure.
If node participation itself is sensitive, use PrivateORSet wrapping.

### INFO-3: Document.MarshalBinary is deterministic but slow

The gob encoding in MarshalBinary iterates fields in sorted key order for
determinism. For large documents with many fields, this is O(n log n) per
serialization. Not a security concern but a performance consideration.
