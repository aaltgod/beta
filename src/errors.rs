use anyhow::Error as anyHowError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Changer {method_name:?} `{description:?}`: {error:?}")]
    Changer {
        method_name: String,
        description: String,
        error: anyHowError,
    },
    #[error("Cache {method_name:?}: {error:?}")]
    Cache {
        method_name: String,
        error: anyHowError,
    },
}
