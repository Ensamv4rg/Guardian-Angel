use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

/// Closes a handle exactly once.
pub(crate) struct OwnedHandle(pub(crate) HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful OpenProcess or
        // OpenProcessToken call, is owned only by this struct, and is closed
        // only here.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Full path of the executable running as `pid`, e.g.
/// `C:\Program Files\Google\Chrome\Application\chrome.exe`.
///
/// Returns `None` if the process has exited, or if this program lacks the
/// rights to query it (common for system services when not elevated).
pub fn process_image_path(pid: u32) -> Option<String> {
    // PID 0 is the System Idle Process and cannot be opened.
    if pid == 0 {
        return None;
    }

    // SAFETY: OpenProcess takes plain values and has no memory-safety
    // preconditions; failure is reported through the Result.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let handle = OwnedHandle(handle);

    // Long enough for extended-length paths; longer ones make the call fail.
    let mut buf = vec![0u16; 4096];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` is valid for writes of `len` u16 values and lives past the
    // call; `len` points to a live u32; the handle is open with the
    // query-limited-information right this API requires.
    unsafe {
        QueryFullProcessImageNameW(handle.0, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len)
    }
    .ok()?;

    buf.truncate(len as usize);
    Some(String::from_utf16_lossy(&buf))
}

#[cfg(test)]
mod tests {
    use super::process_image_path;

    #[test]
    fn finds_own_executable() {
        let path = process_image_path(std::process::id()).expect("own process must be queryable");
        let exe = std::env::current_exe().unwrap();
        assert!(path.eq_ignore_ascii_case(&exe.to_string_lossy()), "{path} vs {exe:?}");
    }

    #[test]
    fn unknown_or_idle_pid_is_none() {
        assert_eq!(process_image_path(0), None);
        // PIDs are multiples of 4 on Windows; an odd PID never exists.
        assert_eq!(process_image_path(u32::MAX - 2), None);
    }
}
