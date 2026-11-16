use std::collections::HashSet;
use windows::Win32::Foundation::{HWND, LPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GW_OWNER, GetWindow, GetWindowTextLengthW, GetWindowThreadProcessId, IsWindowVisible,
};
use windows::core::BOOL;

/// IDs of processes that show at least one visible, titled, top-level
/// window on the caller's desktop: the apps a person would call "open".
///
/// Must run in the user's session (the desktop app), not in the service:
/// services run in session 0 and cannot see users' windows.
pub fn processes_with_windows() -> HashSet<u32> {
    let mut pids: HashSet<u32> = HashSet::new();
    // SAFETY: `collect` only runs during this call, and the LPARAM it
    // receives points to `pids`, which outlives the call and is not touched
    // elsewhere while EnumWindows runs.
    let _ = unsafe { EnumWindows(Some(collect), LPARAM(&raw mut pids as isize)) };
    pids
}

unsafe extern "system" fn collect(hwnd: HWND, lparam: LPARAM) -> BOOL {
    // SAFETY: EnumWindows passes back the LPARAM given above, which points to
    // a live HashSet<u32> owned by `processes_with_windows`.
    let pids = unsafe { &mut *(lparam.0 as *mut HashSet<u32>) };
    // SAFETY: `hwnd` is a window handle EnumWindows is currently reporting;
    // these calls only read its state.
    unsafe {
        let visible = IsWindowVisible(hwnd).as_bool();
        let owned = GetWindow(hwnd, GW_OWNER).is_ok_and(|o| !o.is_invalid());
        let titled = GetWindowTextLengthW(hwnd) > 0;
        if visible && !owned && titled {
            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            if pid != 0 {
                pids.insert(pid);
            }
        }
    }
    // Keep enumerating.
    true.into()
}
