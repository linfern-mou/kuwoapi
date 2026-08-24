@ECHO OFF & CD /D %~DP0 & TITLE 卸载
>NUL 2>&1 REG.exe query "HKU\S-1-5-19" || (
    ECHO SET UAC = CreateObject^("Shell.Application"^) > "%TEMP%\Getadmin.vbs"
    ECHO UAC.ShellExecute "%~f0", "%1", "", "runas", 1 >> "%TEMP%\Getadmin.vbs"
    "%TEMP%\Getadmin.vbs"
    DEL /f /q "%TEMP%\Getadmin.vbs" 2>NUL
    Exit /b
)

taskkill /f /im KwMusic* >NUL 2>NUL
taskkill /f /im KwService* >NUL 2>NUL
taskkill /f /im KwWebKit*  >NUL 2>NUL
taskkill /f /im KwWallpaper* >NUL 2>NUL

rd/s/q "Bin\log" 
rd/s/q "Bin\bin" 2>NUL
rd/s/q "Bin\data" 2>NUL
rd/s/q "Bin\temp" 2>NUL
rd/s/q "Bin\Skin\nav" 2>NUL
rd/s/q "Bin\Skin\servertheme" 2>NUL
rd/s/q "bin\html\webpacket" 2>NUL
rd/s/q "bin\html\webdata\radio" 2>NUL
del/f  "Bin\kid.ini" >NUL 2>NUL
del/f  "Bin\plugin\in_wave.dll" >NUL 2>NUL
del/f  "Bin\plugin\dsp_omxe.dll" >NUL 2>NUL
del/f  "Bin\plugin\dsp_DeFX.dll" >NUL 2>NUL
del/f  "Bin\plugin\dsp_izOzone.dll" >NUL 2>NUL

rd/s/q "%ProgramData%\kuwodata" 2>NUL
rd/s/q "%UserProfile%\AppData\Local\kwmusic" 2>NUL
rd/s/q "%AllUsersProfile%\Application Data\Kuwodata" 2>NUL
rd/s/q "%UserProfile%\Local Settings\Application Data\kwmusic" 2>NUL

CLS && ECHO.&ECHO 卸载完成，任意键返回！&&PAUSE >NUL 