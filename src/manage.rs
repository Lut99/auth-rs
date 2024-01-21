//  MANAGE.rs
//    by Lut99
//
//  Created:
//    02 Jan 2024, 13:45:31
//  Last edited:
//    21 Jan 2024, 17:55:45
//  Auto updated?
//    Yes
//
//  Description:
//!   Handles user management for the API (create users, change password,
//!   delete users).
//

use std::error;
use std::fmt::{Display, Formatter, Result as FResult};

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use error_trace::ErrorTrace as _;
use log::{debug, error, info};
use warp::hyper::{Body, StatusCode};
use warp::reject::Rejection;
use warp::reply::Response;

use crate::spec::{AuthConnector, AuthContext, ErrorReply, UserInfo};


/***** ERRORS *****/
/// Defines errors originating from user management.
#[derive(Debug)]
enum Error {
    /// The backed connector failed to find if a user exists.
    ConnectorUserExists { user: String, err: Box<dyn error::Error> },
    /// Failed to hash a password.
    PasswordHash { err: argon2::password_hash::Error },
    /// A user already exists in the database.
    UserExists { name: String },
}
impl Error {
    /// Converts this error into an appropriate [`Response`].
    ///
    /// # Returns
    /// A [`Response`] that can be send to the user.
    fn into_response(self) -> Response {
        use Error::*;
        match &self {
            ConnectorUserExists { .. } | PasswordHash { .. } => {
                // Log the internal error first
                error!("[{}] {}", StatusCode::INTERNAL_SERVER_ERROR.as_u16(), self.trace());

                // Show the error in the thing
                let mut res: Response = Response::new(
                    serde_json::to_string(&ErrorReply { id: "internal-error".into(), message: "An internal error has occurred".into() })
                        .unwrap()
                        .into(),
                );
                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;

                // Alright done
                res
            },

            UserExists { name } => {
                // Log the internal error first
                error!("[{}] {}", StatusCode::CONFLICT.as_u16(), self.trace());

                // Show the error in the thing
                let mut res: Response = Response::new(
                    serde_json::to_string(&ErrorReply {
                        id:      "user-exists".into(),
                        message: format!("A user with name '{name}' already exists"),
                    })
                    .unwrap()
                    .into(),
                );
                *res.status_mut() = StatusCode::CONFLICT;

                // Alright done
                res
            },
        }
    }
}
impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Error::*;
        match self {
            ConnectorUserExists { user, .. } => write!(f, "Database connector failed to check if user '{user}' exists"),
            PasswordHash { err } => write!(f, "Failed to hash password: {err}"),
            UserExists { name } => write!(f, "User with name '{name}' already exists"),
        }
    }
}
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use Error::*;
        match self {
            ConnectorUserExists { err, .. } => Some(&**err),
            PasswordHash { err } => None,
            UserExists { .. } => None,
        }
    }
}





/***** LIBRARY *****/
/// API path to create a new user.
///
/// # Generics
/// - `U`: A [`UserInfo`]-capable type that is read from the body to extract the information of the new user.
///
/// # Arguments
/// - `context`: An [`AuthContext`] that can be used to access the database containing users, as well as a key for signing stuff.
/// - `info`: The [`UserInfo`] that describes the user we're adding to the database.
///
/// # Returns
/// A [`Response`] that encodes what the client should know.
///
/// Note that this function never [`Reject`]s, and as such stops propagation of filters.
pub async fn create<'de, U: UserInfo<'de>>(context: impl AuthContext<U>, mut info: U) -> Result<Response, Rejection> {
    info!("Handling new user creation");

    /* Step 1. Check if user is unique */
    // Use the database connector for this
    let conn: &_ = context.auth_connector();
    match conn.user_exists(info.name()) {
        Ok(true) => {},
        Ok(false) => return Ok(Error::UserExists { name: info.name().into() }.into_response()),
        Err(err) => return Ok(Error::ConnectorUserExists { user: info.name().into(), err: Box::new(err) }.into_response()),
    }



    /* Step 2. Hash the password */
    // Get the password & salt
    let password: &[u8] = info.password().as_bytes();
    let salt: SaltString = SaltString::generate(&mut OsRng);

    // Prepare the hasher with default settings, then hash!
    let argon2 = Argon2::default();
    let hpassword: String = match argon2.hash_password(password, &salt) {
        Ok(pwd) => pwd.to_string(),
        Err(err) => return Ok(Error::PasswordHash { err }.into_response()),
    };

    // Update the password in the to-be-stored struct
    info.update_password(hpassword);



    /* Step 3. Insert into DB and return */
    // Done
    Ok(())
}
