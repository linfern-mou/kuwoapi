@ECHO OFF & CD /D %~DP0 & TITLE 绿化
>NUL 2>&1 REG.exe query "HKU\S-1-5-19" || (
    ECHO SET UAC = CreateObject^("Shell.Application"^) > "%TEMP%\Getadmin.vbs"
    ECHO UAC.ShellExecute "%~f0", "%1", "", "runas", 1 >> "%TEMP%\Getadmin.vbs"
    "%TEMP%\Getadmin.vbs"
    DEL /f /q "%TEMP%\Getadmin.vbs" 2>NUL
    Exit /b
)

taskkill /f /im KwMusic* >NUL 2>NUL
taskkill /f /im KwService*  >NUL 2>NUL
taskkill /f /im KwWebKit*  >NUL 2>NUL
taskkill /f /im KwWallpaper* >NUL 2>NUL

rd/s/q "%ProgramData%\Kuwodata" 2>NUL
rd/s/q "%AllUsersProfile%\Application Data\Kuwodata" 2>NUL

if exist "%Public%" md "%ProgramData%\Kuwodata" 2>NUL
if exist "%Public%" xcopy /e/i/y  "$APPDATA\kuwodata" "%ProgramData%\Kuwodata" >NUL 2>NUL
if not exist "%Public%" md "%AllUsersProfile%\Application Data\kuwodata" 2>NUL
if not exist "%Public%" xcopy /e/i/y  "$APPDATA\kuwodata" "%AllUsersProfile%\Application Data\kuwodata" 
Attrib +r "%ProgramData%\kuwodata\kwmusic2013\ModuleData\ModMusicTool\conf.txt" >NUL 2>NUL
Attrib +r "%AllUsersProfile%\Application Data\kuwodata\kwmusic2013\ModuleData\ModMusicTool\conf.txt" >NUL 2>NUL

If Exist "%Public%"  reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /f /v "%~dp0KwMusic.exe" /d "~ RUNASADMIN" >NUL

CLS && ECHO.&ECHO.绿化完成! 是否创建桌面快捷方式？
ECHO.&ECHO.是请按任意键，否就直接关闭窗口！&PAUSE >NUL 2>NUL

mshta VBScript:Execute("Set a=CreateObject(""WScript.Shell""):Set b=a.CreateShortcut(a.SpecialFolders(""Desktop"") & ""\酷我音乐.lnk""):b.TargetPath=""%~dp0KwMusic.exe"":b.WorkingDirectory=""%~dp0"":b.Save:close")

CLS & ECHO.&ECHO 创建完成！按任意键退出！&PAUSE >NUL 2>NUL