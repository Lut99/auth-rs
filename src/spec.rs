//  SPEC.rs
//    by Lut99
//
//  Created:
//    02 Jan 2024, 13:40:11
//  Last edited:
//    02 Jan 2024, 14:16:57
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines public traits on which this crate builds.
//

use std::error::Error;

use serde::{Deserialize, Serialize};


/***** LIBRARY *****/
/// Defines an object that, partly, contains authentication context to handle requests.
/// 
/// # Generics
/// - `U`: A struct that carries all information we might like to know of a user.
pub trait AuthContext<U> {
    /// Returns the connector object that we use to access the backend database for this context.
    ///
    /// # Returns
    /// A reference to a type implementing [`AuthConnector`].
    fn auth_connector(&self) -> &impl AuthConnector<U>;
}



/// Defines a connector with a backend database that provides the methods necessary for proper auth handling.
/// 
/// # Generics
/// - `U`: A struct that carries all information we might like to know of a user.
pub trait AuthConnector<U> {
    /// Errors to throw for this connector.
    type Error: Error;


    // Read-only methods
    /// Returns whether the given user exists.
    ///
    /// # Arguments
    /// - `name`: The name to check in the database.
    ///
    /// # Returns
    /// True if a user with this name exists, or false otherwise.
    ///
    /// # Errors
    /// This function may error if we failed to do the database stuff.
    fn user_exists(&self, name: &str) -> Result<bool, Self::Error>;


    // Write methods
    /// Inserts a new user into the database.
    /// 
    /// Note that a check for user uniqueness has already occurred (though it can never hurt to do it twice).
    /// 
    /// # Arguments
    /// - `info`: A type that should be written to the database for this user.
    /// 
    /// # Errors
    /// This function may error if it failed to do the database stuff or if it suspects foul play for some reason.
    fn insert_user(&self, info: U)
}



/// Defines the part of a user's information that this scheme needs to know about.
pub trait UserInfo<'de>: Deserialize<'de> + Serialize {
    /// Returns the name of the user.
    ///
    /// # Returns
    /// A reference to the user's name.
    fn name(&self) -> &str;

    /// Returns the password of this user, as stored in the database.
    ///
    /// Note that the authentication scheme takes care of hashing, so this should return what has been set by [`Self::update_password()`](UserInfo::update_password()).
    ///
    /// # Returns
    /// A reference to the hashed password.
    fn password(&self) -> &str;

    /// Sets a new password for this user.
    ///
    /// This is used when handling new users to hash their passwords before storage, or when users update their password.
    ///
    /// # Arguments
    /// - `password`: The new password to set internally.
    fn update_password(&mut self, password: String);
}
