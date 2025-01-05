use anyhow::Error as anyHowError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Changer {method_name} `{description}`: {error}")]
    Changer {
        method_name: String,
        description: String,
        error: anyHowError,
    },
}

#[derive(Error, Debug)]
pub enum CacheError {
    #[error("Cache {method_name}: {error}")]
    Cache {
        method_name: String,
        error: anyHowError,
    },
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("{description}: {error}")]
    Etc {
        description: String,
        error: anyHowError,
    },

    #[error(
        "
        {env_name} is not set in .env
    "
    )]
    Env { env_name: String },

    #[error(
        "
        `{key}` is not set, want(example):

        {key}:
    "
    )]
    NoKey { key: String },

    #[error(
        "
        `{key}` is not set, want(example):

        {group}:
            {key}: {value_example}
    "
    )]
    NoGroupKey {
        group: String,
        key: String,
        value_example: String,
    },

    #[error(
        "
        an element in `{list_name}` is not set or set not correctly, want(example):

        {list_name}:
            - {element_example}
    "
    )]
    NoListElement {
        list_name: String,
        element_example: String,
    },
}
