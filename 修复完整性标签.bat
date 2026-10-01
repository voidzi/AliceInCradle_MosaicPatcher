@echo off
chcp 65001 >nul
setlocal
echo ============================================================
echo   修复目录的「完整性级别」标签（游戏目录整棵树）
echo ============================================================
echo.
echo 什么时候需要用它？
echo   程序日志里出现「完整性=低 Low」，或者出现下面这些症状：
echo     * 无法写入该文件（拒绝访问）
echo     * explorer.exe (0xc0000142)
echo     * Windows 无法访问指定设备、路径或文件
echo   这些都说明本目录被打上了「低完整性 + 禁止向上写」的标签，
echo   会导致程序以低权限运行，从而写不了文件、也用不了资源管理器。
echo.
echo 本脚本会把整个游戏目录树的标签恢复成 Medium（Windows 默认值）。
echo 正常情况下不需要运行它。
echo.

net session >nul 2>&1
if not %errorlevel%==0 (
    echo [需要管理员权限]
    echo 请关掉本窗口，然后右键本文件，选择「以管理员身份运行」。
    echo.
    pause
    exit /b 1
)

set "TARGET=%~dp0.."
echo 正在处理：%TARGET%
echo （文件较多，请稍等几秒）
echo.
icacls "%TARGET%" /setintegritylevel "(OI)(CI)Medium" /T /C /Q
echo.
echo 完成。重新打开 MosaicPatcher.exe 即可。
pause
