use cradle_shared::{CradleError, CradleResult};
use std::ffi::c_void;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, CONTEXT_ALL_X86, GetThreadContext, ReadProcessMemory, SetThreadContext,
    WriteProcessMemory,
};

pub unsafe fn set_thread_context(thread: HANDLE, ctx: &CONTEXT) -> CradleResult {
    unsafe {
        let ok = SetThreadContext(thread, ctx) != 0;
        if !ok {
            return Err(CradleError::WindowsError(GetLastError() as i32));
        }
        Ok(())
    }
}

pub unsafe fn get_thread_context(thread: HANDLE) -> CradleResult<CONTEXT> {
    unsafe {
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_ALL_X86;
        if GetThreadContext(thread, &mut ctx) == 0 {
            return Err(CradleError::WindowsError(GetLastError() as i32));
        }
        Ok(ctx)
    }
}

pub unsafe fn write_single_byte(proc: HANDLE, addr: usize, byte: &[u8; 1]) -> CradleResult {
    unsafe {
        let ok = WriteProcessMemory(
            proc,
            addr as *const c_void,
            byte.as_ptr() as _,
            1,
            null_mut(),
        ) != 0;
        if !ok {
            return Err(CradleError::WindowsError(GetLastError() as i32));
        }
    }
    Ok(())
}

pub unsafe fn write_process_memory(proc: HANDLE, addr: usize, byte: &[u8]) -> CradleResult {
    unsafe {
        let ok = WriteProcessMemory(
            proc,
            addr as *const c_void,
            byte.as_ptr() as _,
            byte.len(),
            null_mut(),
        ) != 0;
        if !ok {
            return Err(CradleError::WindowsError(GetLastError() as i32));
        }
    }
    Ok(())
}

pub unsafe fn read_single_byte(proc: HANDLE, addr: usize, buf: &mut [u8; 1]) -> CradleResult {
    unsafe {
        let ok = ReadProcessMemory(
            proc,
            addr as *const c_void,
            buf.as_mut_ptr() as _,
            1,
            null_mut(),
        ) != 0;
        if !ok {
            return Err(CradleError::WindowsError(GetLastError() as i32));
        }
    }
    Ok(())
}

pub unsafe fn read_process_memory(
    proc: HANDLE,
    addr: usize,
    buf: &mut [u8],
    len: usize,
) -> CradleResult {
    unsafe {
        let ok = ReadProcessMemory(
            proc,
            addr as *const c_void,
            buf.as_mut_ptr() as _,
            len,
            null_mut(),
        ) != 0;
        if !ok {
            return Err(CradleError::WindowsError(GetLastError() as i32));
        }
    }
    Ok(())
}

pub fn read_remote_or<T: Copy>(proc: HANDLE, addr: usize, default: T) -> T {
    read_remote::<T>(proc, addr).unwrap_or(default)
}

#[cfg(target_os = "linux")]
pub fn resolve_export(_: *mut c_void, _: usize, _: &str) -> CradleResult<usize> {
    Ok(0)
}
#[cfg(target_os = "windows")]
pub fn resolve_export(
    proc: std::os::windows::raw::HANDLE,
    base: usize,
    name: &str,
) -> CradleResult<usize> {
    unsafe {
        let e_lfanew: i32 = read_remote(proc, base + 0x3C)?;
        let nt_headers = base + e_lfanew as usize;
        let export_rva: u32 = read_remote(proc, nt_headers + 0x18 + 0x70)?;
        if export_rva == 0 {
            return Err(CradleError::InvalidValue("no export directory".into()));
        }
        let export_dir = base + export_rva as usize;
        let number_of_names: u32 = read_remote(proc, export_dir + 0x18)?;
        let addr_of_functions: u32 = read_remote(proc, export_dir + 0x1C)?;
        let addr_of_names: u32 = read_remote(proc, export_dir + 0x20)?;
        let addr_of_ordinals: u32 = read_remote(proc, export_dir + 0x24)?;

        let names_table = base + addr_of_names as usize;
        let ordinals_table = base + addr_of_ordinals as usize;
        let functions_table = base + addr_of_functions as usize;
        for i in 0..number_of_names as usize {
            let name_rva: u32 = read_remote(proc, names_table + i * 4)?;
            let name_addr = base + name_rva as usize;
            let mut buf = [0u8; 64];
            ReadProcessMemory(
                proc,
                name_addr as *const c_void,
                buf.as_mut_ptr() as _,
                buf.len(),
                null_mut(),
            );

            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            if &buf[..end] == name.as_bytes() {
                let ordinal: u16 = read_remote(proc, ordinals_table + i * 2)?;
                let func_rva: u32 = read_remote(proc, functions_table + ordinal as usize * 4)?;
                return Ok(base + func_rva as usize);
            }
        }

        Err(CradleError::InvalidValue(format!(
            "export '{name}' not found"
        )))
    }
}

pub fn read_remote<T>(proc: HANDLE, addr: usize) -> CradleResult<T> {
    unsafe {
        let mut val: T = std::mem::zeroed();
        let ok = ReadProcessMemory(
            proc,
            addr as *const c_void,
            &mut val as *mut T as _,
            size_of::<T>(),
            null_mut(),
        );
        if ok == 0 {
            return Err(CradleError::WindowsError(GetLastError() as i32));
        }
        Ok(val)
    }
}
