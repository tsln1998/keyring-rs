//! Shared key and provider contracts used across the workspace.
//!
//! This crate intentionally stays small. Provider-facing key contracts live in
//! [`provider`], while small concurrency primitives such as [`cell`] stay isolated in their own
//! module so future traits can be added without growing one large root module.

pub mod cell;
pub mod provider;
