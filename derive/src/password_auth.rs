//  PASSWORD AUTH.rs
//    by Lut99
//
//  Created:
//    28 Jan 2024, 13:18:39
//  Last edited:
//    28 Jan 2024, 13:35:46
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements the `PasswordAuth` derive macro.
//

use std::collections::HashSet;

use proc_macro2::TokenStream as TokenStream2;
use proc_macro_error::{Diagnostic, Level};
use syn::spanned::Spanned;
use syn::{Attribute, Data, DataStruct, DeriveInput, Ident};


/***** HELPER FUNCTIONS *****/
/// Parses the attribute input to `#[derive(PasswordAuth)]`-macro.
///
/// # Arguments
/// - `attrs`: A list of attributes given to us by [`syn`].
///
/// # Returns
/// A set of fields to look out for, or else [`None`] if the `#[auth(field = ...)]` attribute was not given.
///
/// # Errors
/// This function may error if we found the attribute, but the user gave us shit input.
fn parse_attrs(attrs: Vec<Attribute>) -> Result<Option<HashSet<String>>, Diagnostic> { Ok(None) }





/***** LIBRARY *****/
/// Implements the [`#[derive(PasswordAuth)`]-macro.
///
/// It's quite a simple macro. It simply checks if a default `pass` or `password` field is present and implement `PasswordAuth` for that.
///
/// Optional `#[auth(field = ...)]` attribute available.
pub fn derive(tokens: TokenStream2) -> Result<TokenStream2, Diagnostic> {
    // See if we parse what we think we parse (which is structs only; sorry enums/unions)
    let input: DeriveInput = match syn::parse2(tokens) {
        Ok(input) => input,
        Err(err) => return Err(Diagnostic::spanned(tokens.span(), Level::Error, format!("{err}"))),
    };
    let data: DataStruct = match input.data {
        Data::Struct(s) => s,
        Data::Enum(e) => return Err(Diagnostic::spanned(e.enum_token.span, Level::Error, "Can only derive `PasswordAuth` for structs".into())),
        Data::Union(u) => return Err(Diagnostic::spanned(u.union_token.span, Level::Error, "Can only derive `PasswordAuth` for structs".into())),
    };

    // Parse the attributes to find if we need to watch out for a particular field
    let fieldnames: HashSet<String> = parse_attrs(input.attrs)?.unwrap_or_else(|| HashSet::from(["pass".into(), "password".into()]));

    // Now search the fields to find it
    let mut password_field: Option<Ident> = None;
    for field in data.fields {
        if let Some(ident) = field.ident {
            if fieldnames.contains(&ident.to_string()) {
                if password_field.is_some() {
                    return Err(Diagnostic::spanned(ident.span(), Level::Error, "Found mu"));
                }
            }
        }
    }
    Ok(9)
}
