use crate::process::OwnedHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};

/// A running process: its ID and executable file name (e.g. `Discord.exe`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEntry {
    pub pid: u32,
    pub exe: String,
}

/// Every running process, from a ToolHelp snapshot.
pub fn running_processes() -> Vec<ProcessEntry> {
    // SAFETY: plain-value call; failure is reported through the Result.
    let Ok(snapshot) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return Vec::new();
    };
    let snapshot = OwnedHandle(snapshot);
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut out = Vec::new();
    // SAFETY: `snapshot` is a valid snapshot handle; `entry` is a live,
    // correctly sized PROCESSENTRY32W (dwSize set as the API requires).
    let mut ok = unsafe { Process32FirstW(snapshot.0, &mut entry) }.is_ok();
    while ok {
        let name = &entry.szExeFile;
        let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        out.push(ProcessEntry {
            pid: entry.th32ProcessID,
            exe: String::from_utf16_lossy(&name[..len]),
        });
        // SAFETY: as above; the same entry buffer is reused for each step.
        ok = unsafe { Process32NextW(snapshot.0, &mut entry) }.is_ok();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::running_processes;

    #[test]
    fn lists_this_test_process() {
        let me = std::process::id();
        let procs = running_processes();
        assert!(procs.len() > 5);
        let mine = procs.iter().find(|p| p.pid == me).expect("own process listed");
        assert!(mine.exe.to_lowercase().ends_with(".exe"), "{}", mine.exe);
    }
}
