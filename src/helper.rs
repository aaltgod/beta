use lazy_static::lazy_static;
use rand::distributions::{Alphanumeric, DistString};
use regex::Regex;

use crate::traits::FlagsProvider;

lazy_static! {
    pub static ref FLAG_REGEX: Regex = Regex::new("[A-Za-z0-9]{31}=").expect("invalid FLAG_REGEX");
}

const FLAG_LEN: usize = 31;

pub struct Helper {}

impl Helper {
    pub fn new() -> Self {
        Helper {}
    }
}

impl FlagsProvider for Helper {
    fn build_flag(&self) -> String {
        let mut rng = rand::thread_rng();

        let flag: String = Alphanumeric.sample_string(&mut rng, FLAG_LEN);

        flag + "="
    }
}
