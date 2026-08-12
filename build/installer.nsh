; Custom setup page: collect server port + retention before install finishes.
; Values are written to %APPDATA%\WhatsApp Server\install.cfg, which the app
; reads once on first launch to seed its .env.

; only compile this into the installer pass, not the separate uninstaller pass
!ifndef BUILD_UNINSTALLER

!include nsDialogs.nsh
!include LogicLib.nsh

Var CfgDialog
Var PortInput
Var DaysInput
Var MediaInput

!macro customPageAfterChangeDir
  Page custom waOptionsCreate waOptionsLeave
!macroend

Function waOptionsCreate
  nsDialogs::Create 1018
  Pop $CfgDialog
  ${If} $CfgDialog == error
    Abort
  ${EndIf}

  ${NSD_CreateLabel} 0 2u 100% 20u "WhatsApp Server — choose your defaults. You can change all of these later inside the app."
  Pop $0

  ${NSD_CreateLabel} 0 30u 100% 12u "Server port for the HTTP API (your PHP code connects here):"
  Pop $0
  ${NSD_CreateNumber} 0 44u 30% 12u "3210"
  Pop $PortInput

  ${NSD_CreateLabel} 0 66u 100% 12u "Keep messages for how many days (older ones are auto-deleted):"
  Pop $0
  ${NSD_CreateNumber} 0 80u 30% 12u "90"
  Pop $DaysInput

  ${NSD_CreateLabel} 0 102u 100% 12u "Auto-download media from the last how many days:"
  Pop $0
  ${NSD_CreateNumber} 0 116u 30% 12u "30"
  Pop $MediaInput

  nsDialogs::Show
FunctionEnd

Function waOptionsLeave
  ${NSD_GetText} $PortInput $1
  ${NSD_GetText} $DaysInput $2
  ${NSD_GetText} $MediaInput $3
  ${If} $1 == ""
    StrCpy $1 "3210"
  ${EndIf}
  ${If} $2 == ""
    StrCpy $2 "90"
  ${EndIf}
  ${If} $3 == ""
    StrCpy $3 "30"
  ${EndIf}
  CreateDirectory "$APPDATA\WhatsApp Server"
  FileOpen $4 "$APPDATA\WhatsApp Server\install.cfg" w
  FileWrite $4 "PORT=$1$\r$\n"
  FileWrite $4 "KEEP_DAYS=$2$\r$\n"
  FileWrite $4 "MEDIA_SYNC_DAYS=$3$\r$\n"
  FileClose $4
FunctionEnd

!endif
