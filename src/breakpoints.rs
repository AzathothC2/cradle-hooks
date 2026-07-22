use crate::defs::HookHandler;
use std::collections::HashMap;

/// A breakpoint object
/// Contains information about the hooked function, and the hooking function
pub struct Breakpoint {
    /// Original byte of the breakpoint. Used to restore the process after removal of the breakpoint
    pub original_byte: u8,
    /// Hook handler functions. When the breakpoint is called, these are executed in registration order
    pub handlers: Vec<HookHandler>,
    /// Hooked function module name
    pub module_name: String,
    /// Hooked function export name
    pub export_name: String,
}

impl Breakpoint {
    /// Creates a new breakpoint
    pub fn new(original_byte: u8, handler: HookHandler, module: String, export: String) -> Self {
        Self {
            original_byte,
            handlers: vec![handler],
            module_name: module,
            export_name: export,
        }
    }

    /// Adds a handler to an existing breakpoint
    pub fn push_handler(&mut self, handler: HookHandler) {
        self.handlers.push(handler);
    }
}

/// Small helper type
pub type BreakpointMap = HashMap<usize, Breakpoint>;
/// Small helper type
pub type ModuleBaseCache = HashMap<String, usize>;
