pub(super) fn count(text: &str) -> usize {
    tiktoken_rs::o200k_base_singleton().count_ordinary(text)
}

#[cfg(test)]
mod tests {
    use super::count;

    #[test]
    fn counts_plain_text_with_the_o200k_vocabulary() {
        assert_eq!(count(""), 0);
        assert_eq!(count("hello world"), 2);
        assert_eq!(count("お誕生日おめでとう"), 8);
        assert!(count("<|endoftext|>") > 1);
    }
}
