//  LIB.rs
//    by Lut99
//
//  Created:
//    28 Jan 2024, 13:14:05
//  Last edited:
//    28 Jan 2024, 13:23:06
//  Auto updated?
//    Yes
//
//  Description:
//!   Provides procedural macros for the `auth`-crate.
//

mod password_auth;

use proc_macro::TokenStream;


/***** LIBRARY *****/
/// Implements the [`#[derive(PasswordAuth)`]-macro.
///
/// It's quite a simple macro. It simply checks if a default `pass` or `password` field is present and implement `PasswordAuth` for that.
///
/// Optional `#[auth(field = ...)]` attribute available.
#[cfg(feature = "password")]
#[proc_macro_derive(PasswordAuth, attributes(auth))]
#[inline]
pub fn derive_password_auth(tokens: TokenStream) -> TokenStream {
    // Pass to a dedicated file
    match password_auth::derive(tokens.into()) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.abort(),
    }
}
