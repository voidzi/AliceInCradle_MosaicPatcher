@echo off
chcp 65001 >nul
cd /d "%~dp0"
rem 优先用 pythonw（无控制台窗口）启动本程序，避免任何 SmartScreen/未签名提示
where pythonw >nul 2>nul && (start "" pythonw "MosaicPatcher.pyw" & exit /b)
where pyw >nul 2>nul && (start "" pyw "MosaicPatcher.pyw" & exit /b)
echo 没有找到 pythonw，改用 python 启动（会带一个控制台窗口）...
python "MosaicPatcher.pyw"
pause
