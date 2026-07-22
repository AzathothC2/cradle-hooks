use crate::breakpoints::{Breakpoint, BreakpointMap, ModuleBaseCache};
use crate::defs::{HookAction, HookContext, HookHandler};
use crate::utils::{
    get_thread_context, normalize_name, read_remote_or, read_single_byte, resolve_export,
    set_thread_context, write_process_memory, write_single_byte,
};
use cradle_shared::{CradleError, CradleResult};
use windows_sys::Win32::Foundation::HANDLE;

/// Result of the hooking operation
pub enum DispatchResult {
    /// The hooked event was handled correctly
    Handled,
    /// No registered hook handled this event
    Skip,
}

/// The core hooking engine
/// Responsible for dispatching, registering, and removing hooks from the target process
pub struct HookEngine {
    breakpoints: BreakpointMap,
    module_cache: ModuleBaseCache,
    process: HANDLE,
    pending_restore: Option<PendingRestore>,
}

struct PendingRestore {
    addr: usize,
    thread: HANDLE,
}

impl HookEngine {
    /// Creates an empty [`HookEngine`] object
    pub fn empty() -> HookEngine {
        Self {
            breakpoints: BreakpointMap::new(),
            module_cache: ModuleBaseCache::new(),
            process: HANDLE::default(),
            pending_restore: None,
        }
    }
}

impl HookEngine {
    /// Creates a new [`HookEngine`] object with the specified process handle
    pub fn new(process: HANDLE) -> Self {
        Self {
            breakpoints: BreakpointMap::new(),
            module_cache: ModuleBaseCache::new(),
            process,
            pending_restore: None,
        }
    }

    /// Registers a module to hook given its name and base address
    pub fn register_module(&mut self, name: &str, base: usize) {
        self.module_cache.insert(normalize_name(name), base);
    }

    /// Dispatches a hook on the given handle
    ///
    /// # Safety
    /// Calls `get_thread_context` to get the current registers. This function is unsafe and users should be aware of it
    pub unsafe fn dispatch(&mut self, thread: HANDLE) -> CradleResult<DispatchResult> {
        unsafe {
            let mut ctx = get_thread_context(thread)?;
            let bp_addr = (ctx.Rip - 1) as usize;
            let bp = match self.breakpoints.get(&bp_addr) {
                Some(bp) => bp,
                None => return Ok(DispatchResult::Skip),
            };
            let mut hook_ctx = HookContext {
                registers: &mut ctx,
                process: self.process,
                ret_value: 0,
                export_name: &bp.export_name,
                module_name: &bp.module_name,
                #[cfg(feature = "unstable")]
                return_hook: None,
            };
            let action = (bp.handler)(&mut hook_ctx);
            let ret = hook_ctx.ret_value;
            match action {
                Ok(HookAction::Continue) | Ok(HookAction::Modify) => {
                    write_process_memory(self.process, bp_addr, &[bp.original_byte])?;
                    ctx.Rip = bp_addr as u64;
                    ctx.EFlags |= 0x100;
                    set_thread_context(thread, &ctx)?;
                    self.pending_restore = Some(PendingRestore {
                        addr: bp_addr,
                        thread,
                    });
                }
                Ok(HookAction::Block(u)) => {
                    let ret_addr: u64 = read_remote_or(self.process, ctx.Rsp as usize, u);
                    ctx.Rip = ret_addr;
                    ctx.Rsp += 8;
                    ctx.Rax = ret;
                    set_thread_context(thread, &ctx)?;
                }
                Err(e) => return Err(e),
            }
            Ok(DispatchResult::Handled)
        }
    }

    /// Dispatches a single breakpoint by writing it to the process
    ///
    /// # Safety
    /// Calls `WriteProcessMemory` under the hood (via FFI). This may be unsafe
    pub unsafe fn dispatch_single_step(&mut self, thread: HANDLE) -> CradleResult<DispatchResult> {
        match self.pending_restore.take() {
            Some(restore) if restore.thread == thread => {
                if self.breakpoints.contains_key(&restore.addr) {
                    unsafe {
                        write_process_memory(self.process, restore.addr, &[0xCC])?;
                    }
                }
                Ok(DispatchResult::Handled)
            }
            Some(restore) => {
                self.pending_restore = Some(restore);
                Ok(DispatchResult::Skip)
            }
            None => Ok(DispatchResult::Skip),
        }
    }

    /// Attempts to hook an exported function in the specified module
    /// Will return an error if a hook is already installed there
    ///
    /// # Safety
    /// Reads and writes data to the process' memory, which is unsafe and should be treated as such
    pub unsafe fn hook_export(
        &mut self,
        module: &str,
        export: &str,
        handler: HookHandler,
    ) -> CradleResult {
        if self.module_cache.is_empty() {
            return Err(CradleError::ModuleNotFound(
                "module cache is empty".to_owned(),
            ));
        }
        let module_lower = normalize_name(module);
        let base = self
            .module_cache
            .get(&module_lower)
            .copied()
            .ok_or_else(|| CradleError::ModuleNotFound(module.to_string()))?;
        let addr = resolve_export(self.process, base, export)?;
        if self.breakpoints.contains_key(&addr) {
            return Err(CradleError::InvalidValue(format!(
                "{module}!{export} already hooked at {addr:#x}",
            )));
        }
        let mut orig = [0u8; 1];
        unsafe {
            read_single_byte(self.process, addr, &mut orig)?;
            write_single_byte(self.process, addr, &[0xCC])?;
        }
        self.breakpoints.insert(
            addr,
            Breakpoint::new(orig[0], handler, module_lower, export.to_string()),
        );

        Ok(())
    }
    /// Attempts to unhook the breakpoint at the given address
    ///
    /// # Safety
    /// Calls `WriteProcessMemory` under the hood (via FFI). This may be unsafe
    pub unsafe fn unhook(&mut self, addr: usize) -> CradleResult {
        if let Some(bp) = self.breakpoints.remove(&addr) {
            unsafe {
                write_process_memory(self.process, addr, &[bp.original_byte])?;
            }
        }
        Ok(())
    }

    /// Attempts to unhook all existing hooks
    ///
    /// # Safety
    /// Calls `self.unhook(addr)` on each hook. This function is unsafe
    pub unsafe fn unhook_all(&mut self) -> CradleResult {
        let addrs: Vec<usize> = self.breakpoints.keys().copied().collect();
        for addr in addrs {
            unsafe {
                self.unhook(addr)?;
            }
        }
        Ok(())
    }

    /// Returns the amount of breakpoints are currently installed
    pub fn hooked_count(&self) -> usize {
        self.breakpoints.len()
    }
}
unsafe impl Send for HookEngine {}
