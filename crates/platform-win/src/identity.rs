use crate::process::OwnedHandle;
use std::ffi::c_void;
use std::io;
use std::os::windows::io::AsRawHandle;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};
use windows::core::{HSTRING, PWSTR};

/// Who may connect to the service pipe: full control for SYSTEM and
/// administrators, read and write for interactively signed-in users.
/// Network logons are not included.
pub const SERVICE_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

/// The account SID (e.g. `S-1-5-21-...-1001`) a process runs as.
pub fn process_user_sid(pid: u32) -> Option<String> {
    // SAFETY: plain-value call; failure is reported through the Result.
    let process = OwnedHandle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?);
    let mut token = HANDLE::default();
    // SAFETY: `process` is a valid open process handle; `token` is a live
    // out-parameter.
    unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) }.ok()?;
    let token = OwnedHandle(token);

    // First call reports the size needed (and fails, as documented).
    let mut len = 0u32;
    // SAFETY: a null buffer with length 0 is the documented size query.
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut len) };
    if len == 0 {
        return None;
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` is writable for at least `len` bytes, 8-byte aligned.
    unsafe { GetTokenInformation(token.0, TokenUser, Some(buf.as_mut_ptr().cast()), len, &mut len) }.ok()?;
    // SAFETY: on success the buffer starts with a TOKEN_USER whose SID
    // pointer points into the same buffer, which is still alive.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };

    let mut text = PWSTR::null();
    // SAFETY: `sid` is valid (see above); `text` is a live out-parameter.
    unsafe { ConvertSidToStringSidW(sid, &mut text) }.ok()?;
    // SAFETY: on success `text` is a NUL-terminated string allocated with
    // LocalAlloc; it is read once and then freed exactly once.
    let result = unsafe { text.to_string() }.ok();
    // SAFETY: frees the LocalAlloc'd string above.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
    }
    result
}

/// The account SID of the program on the other end of a service pipe.
pub fn pipe_client_sid(pipe: &NamedPipeServer) -> Option<String> {
    let mut pid = 0u32;
    // SAFETY: the handle belongs to a live pipe owned by `pipe`; `pid` is a
    // live out-parameter.
    unsafe { GetNamedPipeClientProcessId(HANDLE(pipe.as_raw_handle()), &mut pid) }.ok()?;
    process_user_sid(pid)
}

/// A security descriptor built from SDDL, freed on drop.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW
        // with LocalAlloc and freed exactly once here.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0.0)));
        }
    }
}

/// Creates one instance of a named pipe restricted by `sddl` and closed to
/// remote clients.
pub fn create_secure_pipe(name: &str, first_instance: bool, sddl: &str) -> io::Result<NamedPipeServer> {
    let mut raw = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `HSTRING` is a valid NUL-terminated wide string for the call;
    // `raw` is a live out-parameter.
    unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(&HSTRING::from(sddl), SDDL_REVISION_1, &mut raw, None) }
        .map_err(io::Error::other)?;
    let descriptor = Descriptor(raw);
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: false.into(),
    };
    // SAFETY: `attrs` and the descriptor it points to stay alive until this
    // call returns; Windows copies the security information into the pipe.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first_instance)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(name, (&raw mut attrs).cast::<c_void>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_own_user_sid() {
        let sid = process_user_sid(std::process::id()).expect("own SID");
        assert!(sid.starts_with("S-1-5-"), "{sid}");
    }

    #[tokio::test]
    async fn secure_pipe_accepts_local_client_and_identifies_it() {
        let name = format!(r"\\.\pipe\guardian-angel-test-{}", std::process::id());
        let server = create_secure_pipe(&name, true, SERVICE_PIPE_SDDL).unwrap();
        let _client = tokio::net::windows::named_pipe::ClientOptions::new().open(&name).unwrap();
        server.connect().await.unwrap();
        assert_eq!(pipe_client_sid(&server), process_user_sid(std::process::id()));
    }
}
