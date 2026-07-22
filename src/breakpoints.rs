use crate::defs::HookHandler;
use std::collections::HashMap;

/// A breakpoint object
/// Contains information about the hooked function, and the hooking function
pub struct Breakpoint {
    /// Original byte of the breakpoint. Used to restore the process after removal of the breakpoint
    pub original_byte: u8,
    /// Hook handler function. When the breakpoint is called, this is what gets executed
    pub handler: HookHandler,
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
            handler,
            module_name: module,
            export_name: export,
        }
    }
}

/// Small helper type
pub type BreakpointMap = HashMap<usize, Breakpoint>;
/// Small helper type
pub type ModuleBaseCache = HashMap<String, usize>;
