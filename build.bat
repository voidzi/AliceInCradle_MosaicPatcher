@echo off
chcp 65001 >nul
cd /d "%~dp0"

set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
    echo [错误] 找不到 .NET Framework 编译器 csc.exe
    echo 请确认系统已安装 .NET Framework 4.x（Windows 10/11 自带）
    pause
    exit /b 1
)

echo 正在编译 MosaicPatcher.exe ...
"%CSC%" /nologo /target:winexe /platform:anycpu /optimize+ /codepage:65001 ^
    /win32icon:icon.ico /out:MosaicPatcher.exe ^
    /reference:System.dll /reference:System.Core.dll ^
    /reference:System.Drawing.dll /reference:System.Windows.Forms.dll ^
    MosaicPatcher.cs
echo.
if exist MosaicPatcher.exe (
    echo [完成] 已生成 MosaicPatcher.exe
    for %%F in (MosaicPatcher.exe) do echo         大小: %%~zF 字节
) else (
    echo [失败] 编译未生成 exe，请看上面的错误信息
)
pause
