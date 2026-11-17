; Guardian Angel installer hooks (Tauri NSIS).
; The installer runs elevated (per-machine install), so it can register the
; background service and, on uninstall, put back every setting it changed:
; privacy settings, DNS blocking (network adapters) and the proxy setting.

!macro NSIS_HOOK_PREINSTALL
  ; Upgrading: stop the running service so its program file can be replaced.
  nsExec::Exec 'sc.exe stop GuardianAngel'
  Pop $0
  Sleep 2000
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; Register (or update) and start the background service, running as SYSTEM.
  DetailPrint "Starting the Guardian Angel service..."
  nsExec::ExecToLog '"$INSTDIR\guardian-service.exe" install'
  Pop $0
  StrCmp $0 "0" +2
    MessageBox MB_ICONEXCLAMATION|MB_OK "Guardian Angel was installed, but its background service could not start (code $0). Try reinstalling, or restart Windows."
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; Put back every Windows setting Guardian Angel changed, then remove the service.
  DetailPrint "Restoring your Windows settings and removing the service..."
  nsExec::ExecToLog '"$INSTDIR\guardian-service.exe" uninstall'
  Pop $0
  ; Put this user's proxy setting back if apps were sent through Guardian Angel.
  ExecWait '"$INSTDIR\guardian-angel.exe" --restore-proxy'
  ; Remove the inspection certificate from this user's trusted list, if it was added.
  nsExec::Exec 'certutil.exe -user -delstore Root "Guardian Angel Local Inspection CA"'
  Pop $0
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; Delete Guardian Angel's data, including the inspection certificate's key.
  ReadEnvStr $0 ProgramData
  RMDir /r "$0\GuardianAngel"
!macroend
