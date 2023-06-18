use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(
        "ChangerError: 
    [
        Method:         {method_name:?}
        Description:    {description:?}
        Text:           {error_text:?}
    ]
    "
    )]
    Changer {
        method_name: String,
        description: String,
        error_text: String,
    },
    #[error(
        "CacheError:
    [
        Method: {method_name:?}
        Text:   {error_text:?}
    ]
    "
    )]
    Cache {
        method_name: String,
        error_text: String,
    },
}
