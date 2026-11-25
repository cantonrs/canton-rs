use lf_eval::ledger::run_case;

#[test]
fn checked_in_cases_match_the_ledger() {
    let cases = include_str!("../../../../tests/oracle/tx-corpus/expected.tsv");
    for line in cases.lines().filter(|line| !line.is_empty()) {
        let (name, expect) = line.split_once('\t').expect("case tsv");
        let actual = run_case(name).unwrap_or_else(|err| panic!("{name}: {err}"));
        assert_eq!(actual, expect, "{name}");
    }
}
