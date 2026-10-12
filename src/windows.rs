//! The windows stand-ins for the unix socket the cli and agent talk over.
//!
//! Named pipes live in one machine-wide namespace, so any local user can
//! create a pipe with our name first. Two things keep that safe: the agent
//! creates the pipe with a DACL that only admits the current user, and the
//! client refuses to talk to a pipe server running as anyone else.

use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::AsRawHandle as _;

use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_FILE_NOT_FOUND, HANDLE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeServerProcessId, WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // safety: the handle was opened by us and is closed exactly once
        unsafe { CloseHandle(self.0) };
    }
}

/// The `TOKEN_USER` of a process, in a buffer that keeps its SID alive.
struct TokenUserBuf(Vec<u64>);

impl TokenUserBuf {
    fn of_process(process: HANDLE) -> std::io::Result<Self> {
        let mut token = std::ptr::null_mut();
        // safety: token is a valid out pointer
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }
            == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let token = Handle(token);
        let mut len = 0;
        // safety: a null buffer with length 0 only asks for the size
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                std::ptr::null_mut(),
                0,
                &raw mut len,
            )
        };
        // u64 elements keep the buffer aligned for TOKEN_USER
        let mut buf = vec![0_u64; usize::try_from(len).unwrap().div_ceil(8)];
        // safety: buf holds at least len bytes
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buf.as_mut_ptr().cast(),
                len,
                &raw mut len,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(buf))
    }

    fn sid(&self) -> *mut std::ffi::c_void {
        // safety: the buffer was filled with a TOKEN_USER above
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
}

fn current_user() -> std::io::Result<TokenUserBuf> {
    // safety: the pseudo handle of the current process needs no closing
    TokenUserBuf::of_process(unsafe { GetCurrentProcess() })
}

fn current_user_sid_string() -> std::io::Result<String> {
    let user = current_user()?;
    let mut s = std::ptr::null_mut();
    // safety: the sid is valid while `user` lives; s is a valid out pointer
    if unsafe { ConvertSidToStringSidW(user.sid(), &raw mut s) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // safety: s is a nul-terminated string allocated by the call above
    let out = unsafe {
        let mut len = 0;
        while *s.add(len) != 0 {
            len += 1;
        }
        let out =
            String::from_utf16_lossy(std::slice::from_raw_parts(s, len));
        LocalFree(s.cast());
        out
    };
    Ok(out)
}

/// The pipe the cli and agent talk over, unique per user and profile.
pub fn pipe_name() -> String {
    let sid = current_user_sid_string().unwrap_or_default();
    format!(r"\\.\pipe\{}-{sid}", crate::dirs::profile())
}

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain([0]).collect()
}

/// Security attributes that admit only the current user (and SYSTEM).
pub struct PipeSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
    attributes: SECURITY_ATTRIBUTES,
}

// safety: the descriptor is immutable once built and only read by the os
unsafe impl Send for PipeSecurity {}
unsafe impl Sync for PipeSecurity {}

impl PipeSecurity {
    pub fn new() -> std::io::Result<Self> {
        let sddl = format!(
            "D:P(A;;GA;;;{})(A;;GA;;;SY)",
            current_user_sid_string()?
        );
        let mut descriptor = std::ptr::null_mut();
        // safety: sddl is nul-terminated; descriptor is a valid out pointer
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(&sddl).as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            descriptor,
            attributes: SECURITY_ATTRIBUTES {
                nLength: u32::try_from(std::mem::size_of::<
                    SECURITY_ATTRIBUTES,
                >())
                .unwrap(),
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            },
        })
    }

    pub fn as_ptr(&self) -> *mut std::ffi::c_void {
        std::ptr::from_ref(&self.attributes).cast_mut().cast()
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        // safety: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW
        unsafe { LocalFree(self.descriptor) };
    }
}

/// Fails unless the server end of `pipe` runs as the current user.
pub fn verify_pipe_server(pipe: &std::fs::File) -> std::io::Result<()> {
    let mut pid = 0;
    // safety: the handle is an open pipe client; pid is a valid out pointer
    if unsafe {
        GetNamedPipeServerProcessId(pipe.as_raw_handle(), &raw mut pid)
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // safety: plain call; a null result is handled below
    let process =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let process = Handle(process);
    let server = TokenUserBuf::of_process(process.0)?;
    let me = current_user()?;
    // safety: both sids are valid while their buffers live
    if unsafe { EqualSid(server.sid(), me.sid()) } == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "the rbw-agent pipe is owned by another user",
        ));
    }
    Ok(())
}

/// Whether an agent is listening, without taking up a connection.
pub fn pipe_exists(timeout_ms: u32) -> bool {
    // safety: the name is nul-terminated
    let ok =
        unsafe { WaitNamedPipeW(wide(&pipe_name()).as_ptr(), timeout_ms) };
    // a busy pipe still exists; only "not found" means there is none
    ok != 0
        || std::io::Error::last_os_error().raw_os_error()
            != Some(i32::try_from(ERROR_FILE_NOT_FOUND).unwrap())
}

/// Opens the client end of the agent pipe, waiting out a busy server.
pub fn connect() -> std::io::Result<std::fs::File> {
    const ERROR_PIPE_BUSY: i32 = 231;
    let name = pipe_name();
    let mut tries = 0;
    let pipe = loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&name)
        {
            Ok(pipe) => break pipe,
            Err(e)
                if e.raw_os_error() == Some(ERROR_PIPE_BUSY)
                    && tries < 50 =>
            {
                tries += 1;
                // safety: the name is nul-terminated
                unsafe { WaitNamedPipeW(wide(&name).as_ptr(), 100) };
            }
            Err(e) => return Err(e),
        }
    };
    verify_pipe_server(&pipe)?;
    Ok(pipe)
}
