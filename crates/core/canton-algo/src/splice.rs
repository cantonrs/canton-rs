#[derive(Debug, PartialEq, Eq)]
pub struct ThresholdError;

pub fn f_plus_one_threshold(n: i32) -> i32 {
    if n < 1 {
        1
    } else {
        (n - 1) / 3 + 1
    }
}

pub fn governance_threshold(sv_num: i32) -> Result<i32, ThresholdError> {
    if sv_num < 1 {
        return Err(ThresholdError);
    }
    let faults = (sv_num - 1) / 3;
    let votes = sv_num + faults + 1;
    let required = (votes + 1) / 2;
    if required <= 0 {
        Err(ThresholdError)
    } else {
        Ok(required)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds_match_the_splice_formula_fixture() {
        let text = include_str!("../../../../tests/oracle/canton-hash/thresholds.tsv");
        for line in text.lines().filter(|line| !line.is_empty()) {
            let mut parts = line.split('\t');
            let kind = parts.next().unwrap();
            let n: i32 = parts.next().unwrap().parse().unwrap();
            let expect = parts.next().unwrap();
            let actual = match kind {
                "f_plus_one" => f_plus_one_threshold(n).to_string(),
                "governance" => match governance_threshold(n) {
                    Ok(value) => value.to_string(),
                    Err(ThresholdError) => "ERR".to_string(),
                },
                other => panic!("unknown row {other}"),
            };
            assert_eq!(actual, expect, "{kind} {n}");
        }
    }
}
