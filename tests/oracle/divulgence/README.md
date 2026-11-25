# Divulgence on the IDE ledger (U-4)

`daml/Dv.daml`: alice creates a `Secret`, then a `Proxy` (alice signatory, bob observer) and exercises `Pass`, whose body FETCHES the
secret, so bob witnesses a fetch of a contract he is no stakeholder of (what older Canton versions called immediate divulgence).
`divulgence` returns bob's `queryContractId` answer before the proxy exists, after the proxy is created and after `Pass`.

`expected.txt` is what `daml script --ide-ledger` printed on the Canton 3.7.2 toolchain image on 2026-11-12:
`["invisible", "invisible", "invisible"]`. A contract is **not** visible to a party because it was witnessed in a sub-transaction: the
Rust evaluator's rule (a stakeholder, `readAs`, a contract created in the same command, or explicitly disclosed) needs no divulgence.

Regenerate: copy `daml/` and `daml.yaml` (through `scripts/toolchain-yaml.sh`) to a directory, `daml build -o dv.dar`, then
`daml script --dar dv.dar --script-name Dv:divulgence --ide-ledger --static-time --output-file out.txt` in `daml-toolchain:canton-3.7.2`.
