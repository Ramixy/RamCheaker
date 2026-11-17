@echo off
rem Build RamCheaker with the C# compiler that ships with Windows (.NET Framework 4.x).
rem Everything in tools\ is embedded into the exe as resources "tool:<file name>".
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File make_icon.ps1 >nul
if not exist dist mkdir dist
> build.rsp echo /nologo /target:winexe /platform:anycpu /optimize+ /codepage:65001 /out:dist\RamCheaker.exe /win32manifest:app.manifest /win32icon:app.ico
>> build.rsp echo /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:System.IO.Compression.dll /r:System.Management.dll
>> build.rsp echo "/resource:rules\sizes.txt,rules.sizes"
for %%f in (tools\*) do >> build.rsp echo "/resource:tools\%%~nxf,tool:%%~nxf"
>> build.rsp echo src\*.cs
"%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" @build.rsp
if errorlevel 1 (echo BUILD FAILED & exit /b 1)
echo OK: dist\RamCheaker.exe
