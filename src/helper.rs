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
        (0..length)
            .map(|_| chars[rng.gen_range(0..chars.len() - postfix.len())])
            .collect::<String>()
            + postfix
    }
}
