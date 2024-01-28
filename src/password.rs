//  PASSWORD.rs
//    by Lut99
//
//  Created:
//    28 Jan 2024, 12:37:13
//  Last edited:
//    28 Jan 2024, 13:09:30
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines a trait that can be used to encrypt & check the password of
//!   an account.
//

use std::error;
use std::fmt::{Display, Formatter, Result as FResult};

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHasher as _, SaltString};
use argon2::{Argon2, PasswordHash, PasswordVerifier};


/***** ERRORS *****/
/// Defines errors returned by the [`PasswordAuthExt`] trait.
///
/// Note that this error implements [`Error::source()`](error::Error::source()), so you may not receive all information unless you call it.
#[derive(Debug)]
pub enum Error {
    /// Failed to compute the hash of the given password.
    HashCompute { err: argon2::password_hash::Error },
    /// Failed to parse the given password hash.
    HashParse { err: argon2::password_hash::Error },
    /// Failed to verify the given password against the internal hash.
    HashVerify { err: argon2::password_hash::Error },
}
impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Error::*;
        match self {
            HashCompute { .. } => write!(f, "Failed to compute Argon2 hash"),
            HashParse { .. } => write!(f, "Failed to parse internal Argon2 password hash"),
            HashVerify { .. } => write!(f, "Failed to verify given attempt against internal Argon2 password hash"),
        }
    }
}
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use Error::*;
        match self {
            HashCompute { err } => Some(err),
            HashParse { err } => Some(err),
            HashVerify { err } => Some(err),
        }
    }
}





/***** LIBRARY *****/
/// Base trait that, when implemented, unlocks the password features of the [`PasswordAuthExt`] trait.
///
/// See that trait for a more practical example.
///
/// # Example
/// ```rust
/// use auth::password::PasswordAuth;
///
/// struct UserInfo {
///     name: String,
///     pass: String,
/// }
/// impl PasswordAuth for UserInfo {
///     #[inline]
///     fn password(&self) -> &str { self.pass.as_str() }
///
///     #[inline]
///     fn password_mut(&mut self) -> &mut String { &mut self.pass }
/// }
///
/// let mut user = UserInfo { name: "Amy".into(), pass: "topsecretdontletdanread".into() };
/// assert_eq!(user.password(), "topsecretdontletdanread");
/// *user.password_mut() = "hacked".into();
/// assert_eq!(user.password(), "hacked");
/// ```
pub trait PasswordAuth {
    /// Returns a reference to the (already hashed) internal password.
    ///
    /// This is used in [`PasswordAuthExt::check_password()`] to verify it against a newly hashed attempt.
    ///
    /// # Returns
    /// A reference to the internal password ([`str`])ing.
    fn password(&self) -> &str;

    /// Returns a mutable reference to the internal password.
    ///
    /// This is used in [`PasswordAuthExt::hash_password()`] to update the password in the user object to a hashed one.
    ///
    /// # Returns
    /// A mutable reference to the internal password [`String`].
    fn password_mut(&mut self) -> &mut String;
}

/// Trait that provides practical extensions over [`PasswordAuth`].
///
/// Most notably, provides wrappers that use the base methods in [`PasswordAuth`] to implement password hashing & checking.
///
/// # Example
/// ```rust
/// use auth::password::{PasswordAuth, PasswordAuthExt};
///
/// struct UserInfo {
///     name: String,
///     pass: String,
/// }
/// impl PasswordAuth for UserInfo {
/// #     #[inline]
/// #     fn password(&self) -> &str { self.pass.as_str() }
/// #
/// #     #[inline]
/// #     fn password_mut(&mut self) -> &mut String { &mut self.pass }
///     // ...
/// }
///
/// // Hash the password
/// let mut user = UserInfo { name: "Amy".into(), pass: "topsecretdontletdanread".into() };
/// assert_eq!(user.password(), "topsecretdontletdanread");
/// user.hash_password();
/// assert_eq!(&user.password()[..10], "$argon2id$");
///
/// // Check the password
/// assert_eq!(user.check_password("topsecretdontletdanread".as_bytes()).unwrap(), true);
/// assert_eq!(user.check_password("hacked".as_bytes()).unwrap(), false);
/// ```
pub trait PasswordAuthExt: PasswordAuth {
    /// Updates the internal password with its hashed counterpart.
    ///
    /// The [`argon2`] crate is used for the hashing the password returned by (and updated by) the [`PasswordAuth`] implementation.
    ///
    /// # Errors
    /// This function may error if the [`Argon2::hash_password()`] function on which it relies errors.
    fn hash_password(&mut self) -> Result<(), Error> {
        // Get the password & salt
        let password: &[u8] = self.password().as_bytes();
        let salt: SaltString = SaltString::generate(&mut OsRng);

        // Prepare the hasher with default settings, then hash!
        let argon2 = Argon2::default();
        let hpassword: String = match argon2.hash_password(password, &salt) {
            Ok(pwd) => pwd.to_string(),
            Err(err) => return Err(Error::HashCompute { err }),
        };

        // Alright that's it, update and done
        *self.password_mut() = hpassword;
        Ok(())
    }

    /// Checks the internal password with a given attempt.
    ///
    /// The [`argon2`] crate is used for this, and the password is retrieved using the [`PasswordAuth::password_bytes()`]-implementation.
    ///
    /// # Arguments
    /// - `attempt`: The password to verify.
    ///
    /// # Returns
    /// A boolean indicating if the password matched (true) or not (false).
    ///
    /// # Errors
    /// This function may error if it failed to either parse the internal hash or verify the given one against it.
    fn check_password(&self, attempt: impl AsRef<[u8]>) -> Result<bool, Error> {
        let attempt: &[u8] = attempt.as_ref();

        // Create a [`PasswordHash`] out of the internal one.
        let hash: PasswordHash = match PasswordHash::new(self.password()) {
            Ok(hash) => hash,
            Err(err) => return Err(Error::HashParse { err }),
        };

        // Compare the hashes
        let argon2 = Argon2::default();
        match argon2.verify_password(attempt, &hash) {
            Ok(_) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(err) => Err(Error::HashVerify { err }),
        }
    }
}
impl<T: PasswordAuth> PasswordAuthExt for T {}
