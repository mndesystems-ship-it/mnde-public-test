# Ledger anchoring parity vectors

Static Phase-1 inclusion-proof vectors. A verifier in ANY language must load
`proof-bundle.json` + `authority-bundle.public.json` and reproduce `expected.json`
(ok:true, assurance operator-signed-inclusion). Public material only — NO private
keys. Regenerating requires rerunning the anchor test with fresh keys.
