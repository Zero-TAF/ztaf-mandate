# ztaf-mandate

The mandate-chain reference implementation for the Zero-Trust Agent Framework: canonical hashing, Ed25519 signing, chain verification with strict attenuation, revocation status lists, and the golden test vectors.

| Field | Value |
|---|---|
| Authority | Reference implementation — the normative format lives in [ztaf-spec](https://github.com/Zero-TAF/ztaf-spec) (mandate format document, including the registered constraint comparison rules §3a) |
| Tier | T3 (substrate) |
| Wave | W3 |
| Version | 0.1.0 |
| Status | Active |
| Licence | MIT |

## What this repository owns

- `ztaf_mandate/` — the reference library: canonical serialisation and hashing; Ed25519 keys; mandate minting and single-signature verification; chain verification (signatures, validity containment, attenuation, chain integrity, revocation, subject binding); the registered constraint vocabulary and its comparison rules; signed status-list revocation.
- `vectors/` — ten golden test vectors, deterministically regenerable (`tools/gen_vectors.py`, fixed seeds): the valid chain, broken signature, validity escape, loose budget, revoked intermediate, grade descent, parent-hash mismatch, unknown constraint type, subject mismatch, dropped parent constraint.
- `tests/` — vector replay plus unit tests mirroring the spec's comparison rules.

## What this repository does not own

- The normative mandate format, field semantics, and comparison rules — [ztaf-spec](https://github.com/Zero-TAF/ztaf-spec). This code implements that document; the two move together by change request.
- A production key registry, key distribution, or HSM integration — production deployments obtain public keys through the registry by `issuer_key_id`; the reference `KeyProvider` is dict-backed for tests.
- The decision-point integration — `ztaf-reference-harness` (Wave 4).

## Status and scope warning

**Reference only.** It is executable, tested specification — not production software. No CLI, no network, no persistence: minting and verification are library calls; revocation is a signed status list you supply. The registry interface and the wire-level key discovery are Wave-4 (`ztaf-reference-harness`, `ztaf-registry`) concerns.

## Running

```bash
python -m venv .venv && . .venv/bin/activate
pip install cryptography
python tools/gen_vectors.py     # regenerate vectors byte-identically (fixed seeds)
python -m unittest discover -s tests -v
```
