# Party id order of a `Map Party` on the IDE ledger (U-8)

`daml/P.daml` allocates twelve parties with `allocateParty` (the IDE ledger makes the id `<name>-<hash>`), puts them into a
`DA.Map` and prints the names in map order. `expected.txt` is what the JVM (`daml script --ide-ledger`, Canton 3.7.2
toolchain image) printed on 2026-11-12. Regenerate: copy `daml/` and a `scripts/toolchain-yaml.sh daml.yaml` into a directory,
`daml build -o pid.dar`, then `daml script --dar pid.dar --script-name P:order --ide-ledger --static-time --output-file out.txt`
in the `daml-toolchain:canton-3.7.2` image.

Finding: for names made of letters, digits and `_` the order equals the order of the plain names, which is what the Rust
evaluator uses. A name that contains `-` (here `Sv-b`) is ordered by the *hash* of the other name, so it cannot be reproduced
without the IDE ledger's party-id hash. The Rust test `party_order_tests` (lf-eval) checks both statements.
