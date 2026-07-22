use crate::utils::*;
use cradle_shared::bytes2wide;
use cradle_shared::errors::CradleResult;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;

/// Hook action
/// Specifies what action to take once a hook is triggered
pub enum HookAction {
    /// Continues normal operations after the hook
    Continue,
    /// Modifies the original hooked function arguments
    Modify,
    /// Blocks continuation after this breakpoint
    /// Inner `u64` is the custom return type to use
    Block(u64),
}

/// Context passed to the hook handler (see: [`HookHandler`])
pub struct HookContext<'a> {
    /// Mutable version of the Windows `CONTEXT` struct to allow editing the registers
    pub registers: &'a mut CONTEXT,
    /// Handle to the hooked process
    pub process: HANDLE,
    /// Return value to use. Defaults to 0
    pub ret_value: u64,
    /// Currently hooked export name
    pub export_name: &'a str,
    /// Currently hooked module name
    pub module_name: &'a str,
}

impl<'a> HookContext<'a> {
    /// Get the argument for a given index
    pub fn arg(&self, idx: usize) -> u64 {
        match idx {
            0 => self.registers.Rcx,
            1 => self.registers.Rdx,
            2 => self.registers.R8,
            3 => self.registers.R9,
            _ => {
                let addr = self.registers.Rsp + 0x28 + ((idx - 4) as u64) * 8;
                read_remote_or(self.process, addr as usize, 0u64)
            }
        }
    }

    /// Sets the argument for the given index
    pub fn set_arg(&mut self, idx: usize, val: u64) {
        match idx {
            0 => self.registers.Rcx = val,
            1 => self.registers.Rdx = val,
            2 => self.registers.R8 = val,
            3 => self.registers.R9 = val,
            _ => {
                let addr = self.registers.Rsp + 0x28 + ((idx - 4) as u64) * 8;
                let bytes = val.to_le_bytes();
                unsafe {
                    let _ = write_process_memory(self.process, addr as usize, &bytes);
                }
            }
        }
    }
    /// Reads a Wide (u16) string from memory at the specified address
    /// Returns a regular `String`
    pub fn read_wide_string(&self, addr: u64, max_bytes: usize) -> String {
        let raw = self.read_buf(addr, max_bytes);
        let wide = bytes2wide(&raw);
        String::from_utf16_lossy(&wide)
    }

    /// Reads a regular (u8) string from memory at the specified address
    /// Returns a regular `String`
    pub fn read_string(&self, addr: u64, max_len: usize) -> String {
        let raw = self.read_buf(addr, max_len);
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..end]).into_owned()
    }

    /// Tries to read a struct of type `T` from the specified address in the process
    pub fn read_struct<T: Copy>(&self, addr: u64) -> CradleResult<T> {
        read_remote::<T>(self.process, addr as usize)
    }
    /// Reads a buffer from the process' memory at the given address (with the specified length)
    ///
    /// # Safety
    /// Calls `ReadProcessMemory` via FFI under the hood. This may crash and should be treated as unsafe
    pub fn read_buf(&self, addr: u64, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        unsafe {
            read_process_memory(self.process, addr as usize, &mut buf, len).unwrap_or_default();
        }
        buf
    }

    /// Writes data to the process at the given address
    ///
    /// # Safety
    /// Calls `WriteProcessMemory` via FFI under the hood. This may crash and should be treated as unsafe
    pub fn write_buf(&self, addr: u64, data: &[u8]) -> CradleResult {
        unsafe { write_process_memory(self.process, addr as usize, data) }
    }

    /// Writes a struct pointer to the given address
    ///
    /// # Safety
    /// Calls `WriteProcessMemory` via FFI and `std::slice::from_raw_parts` which is unsafe as it doesn't validate pointers
    /// This may crash and should be treated as unsafe
    pub fn write_struct<T: Copy>(&self, addr: u64, val: &T) -> CradleResult {
        let bytes =
            unsafe { std::slice::from_raw_parts(val as *const T as *const u8, size_of::<T>()) };
        self.write_buf(addr, bytes)
    }
}
/// Wrapper around a `CradleResult<HookAction>` type
pub type HookResult = CradleResult<HookAction>;
/// Hook event handler. This is what gets called when a breakpoint is triggered
pub type HookHandler = Box<dyn Fn(&mut HookContext) -> HookResult + Send>;
