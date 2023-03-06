use lazy_static::lazy_static;
use rand::distributions::{Alphanumeric, DistString};
use regex::Regex;

lazy_static! {
    pub static ref FLAG_REGEX: Regex = Regex::new("[A-Za-z0-9]{31}=").unwrap();
    pub static ref ENCODED_FLAG_REGEX: Regex = Regex::new("[A-Za-z0-9]{31}%3D").unwrap();
}

const FLAG_LEN: usize = 31;

pub fn build_flag(encoded: bool) -> String {
    let mut rng = rand::thread_rng();

    let flag: String = Alphanumeric.sample_string(&mut rng, FLAG_LEN);

    if encoded {
        flag + "%3D"
    } else {
        flag + "="
    }
}
