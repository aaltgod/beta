use rand::distributions::{Alphanumeric, DistString};

const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                         0123456789";
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