//! QUIC tunnel: accept, connection lifetime, control-frame protocol, and registration policy.

mod accept;
mod connection;
mod protocol;
mod registration;

pub use accept::{accept_loop, await_accepting};
pub(crate) use registration::RegistrationError;
pub use registration::RegistrationPolicy;

#[cfg(test)]
mod tests;
