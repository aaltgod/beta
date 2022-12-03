use rand::Rng;

const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                         0123456789";
const FLAG_LEN: usize = 31;

pub fn build_flag(encoded: bool) -> String {
    let mut rng = rand::thread_rng();

    let flag: String = (0..FLAG_LEN)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    if encoded {
        flag + "%3D"
    } else {
        flag + "="
    }
}