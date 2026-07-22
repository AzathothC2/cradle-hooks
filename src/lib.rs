//! # cradle-hooks
//!
//! Contains the hooking logic in use by the cradle workspace (tools and plugins)
#![warn(missing_docs)]
/// Breakpoint definitions
pub mod breakpoints;
/// Definitions for the hooks, including utility functions
pub mod defs;
/// Contains the hook engine definition and logic. This is essentially the main logic of this crate
pub mod engine;
mod utils;

pub use defs::{HookAction, HookContext, HookHandler, HookResult};
pub use engine::{DispatchResult, HookEngine};
