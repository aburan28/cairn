//! Path globs for space policy: `*`, `?` and `**`.
//!
//! Small and in-crate for the reason the argument parser is: the dependency
//! budget here is spent on things that end up in a hash, and a policy glob
//! *does* — the space's policy decides which writes are admissible, so two
//! replicas that disagree about what `ledger/**` matches disagree about what
//! the space contains. A twenty-line matcher spelled out here cannot drift
//! under a dependency update.
//!
//! Semantics, by path segment (`/` separates segments):
//!
//! - `**` as a whole segment matches zero or more segments;
//! - `*` matches any run of characters within one segment, including none;
//! - `?` matches exactly one character within one segment;
//! - everything else matches itself. There is no escaping and no character
//!   class, because no policy anyone has written needs one.

/// Whether `glob` matches `path`.
pub fn matches(glob: &str, path: &str) -> bool {
    let pattern: Vec<&str> = glob.split('/').collect();
    let segments: Vec<&str> = path.split('/').collect();
    match_segments(&pattern, &segments)
}

fn match_segments(pattern: &[&str], segments: &[&str]) -> bool {
    match pattern.split_first() {
        None => segments.is_empty(),
        Some((&"**", rest)) => {
            // Zero segments, or consume one and try again. Iterative over the
            // split point rather than recursive on both branches, so a
            // pattern with several `**` stays polynomial.
            (0..=segments.len()).any(|skip| match_segments(rest, &segments[skip..]))
        }
        Some((first, rest)) => match segments.split_first() {
            Some((segment, remaining)) => {
                match_segment(first.as_bytes(), segment.as_bytes())
                    && match_segments(rest, remaining)
            }
            None => false,
        },
    }
}

/// `*` and `?` within one segment. Works on chars, not bytes, so `?` matches
/// one character of a non-ASCII name rather than half of one.
fn match_segment(pattern: &[u8], text: &[u8]) -> bool {
    let pattern: Vec<char> = String::from_utf8_lossy(pattern).chars().collect();
    let text: Vec<char> = String::from_utf8_lossy(text).chars().collect();
    // The classic two-pointer wildcard match with backtracking to the last
    // star: linear in practice, never exponential.
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, t));
            p += 1;
        } else if let Some((star_p, star_t)) = star {
            p = star_p + 1;
            t = star_t + 1;
            star = Some((star_p, star_t + 1));
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn double_star_spans_any_number_of_segments() {
        assert!(matches("**", "a"));
        assert!(matches("**", "a/b/c"));
        assert!(matches("ledger/**", "ledger/goals/GOAL-X.yaml"));
        assert!(matches("ledger/**", "ledger/x"));
        assert!(!matches("ledger/**", "experiments/x"));
        assert!(matches(
            "coordination/**/dispatch_queue.json",
            "coordination/goals/G/batches/B/dispatch_queue.json"
        ));
        assert!(matches(
            "coordination/**/dispatch_queue.json",
            "coordination/dispatch_queue.json"
        ));
        assert!(matches("**/__pycache__/**", "tools/__pycache__/x.pyc"));
    }

    #[test]
    fn single_star_stays_inside_a_segment() {
        assert!(matches("ledger/goals/*.yaml", "ledger/goals/GOAL-A.yaml"));
        assert!(!matches(
            "ledger/goals/*.yaml",
            "ledger/goals/GOAL-A/goal.yaml"
        ));
        assert!(matches("*", "anything"));
        assert!(!matches("*", "a/b"));
        assert!(matches("a*b*c", "aXXbYYc"));
        assert!(!matches("a*b*c", "aXXbYY"));
    }

    #[test]
    fn question_mark_is_one_character() {
        assert!(matches("RUN-?", "RUN-a"));
        assert!(!matches("RUN-?", "RUN-ab"));
        assert!(matches("?", "ü"));
    }

    #[test]
    fn literal_segments_must_match_exactly() {
        assert!(matches("knowledge/INDEX.md", "knowledge/INDEX.md"));
        assert!(!matches("knowledge/INDEX.md", "knowledge/INDEX.mdx"));
        assert!(!matches("knowledge/INDEX.md", "knowledge"));
    }
}
