use rand::Rng;

use crate::traits::FlagsProvider;

pub struct Helper {}

impl Helper {
    pub fn new() -> Self {
        Helper {}
    }
}

impl FlagsProvider for Helper {
    fn build_flag(&self, alphabet: &str, length: usize, postfix: &str) -> String {
        let mut rng = rand::thread_rng();

        let chars = alphabet.chars().collect::<Vec<char>>();
        (0..length - postfix.len())
            .map(|_| chars[rng.gen_range(0..chars.len())])
            .collect::<String>()
            + postfix
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_flag() {
        let helper = Helper::new();
        let alphabet = "abcdef";
        let length = 5;
        let postfix = "=";

        let flag = helper.build_flag(alphabet, length, postfix);

        assert_eq!(flag.len(), length);
        assert_eq!(flag.ends_with(postfix), true);
    }
}
