!macro KillKnoxProcesses
  DetailPrint "Stopping running KNOX processes..."
  nsExec::ExecToLog 'taskkill /F /T /IM "KNOX WALLET.exe"'
  nsExec::ExecToLog 'taskkill /F /T /IM "knox-wallet.exe"'
  nsExec::ExecToLog 'taskkill /F /T /IM "knox-node.exe"'
  nsExec::ExecToLog 'taskkill /F /T /IM "knox-wallet-cli.exe"'
  Sleep 2000
!macroend

!macro ForceCleanOldInstalls
  SetShellVarContext current
  DetailPrint "Force removing previous KNOX WALLET installations..."
  nsExec::ExecToLog "cmd.exe /C rd /s /q $\"$LOCALAPPDATA\Programs\KNOX WALLET$\""
  nsExec::ExecToLog "cmd.exe /C rd /s /q $\"$PROGRAMFILES64\KNOX WALLET$\""
  nsExec::ExecToLog "cmd.exe /C rd /s /q $\"$PROGRAMFILES\KNOX WALLET$\""
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${INSTALL_REGISTRY_KEY}"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${INSTALL_REGISTRY_KEY}"
!macroend

!macro customInit
  !insertmacro KillKnoxProcesses
  !insertmacro ForceCleanOldInstalls
!macroend

!macro customUnInit
  !insertmacro KillKnoxProcesses
!macroend
