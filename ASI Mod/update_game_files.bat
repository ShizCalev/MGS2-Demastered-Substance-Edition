@echo off

REM Skip everything if CI env var exists
if defined CI (
    echo CI environment detected. Skipping update.
    goto :EOF
)

set "DEST=G:\Steam\steamapps\common\MGS2\plugins\MGS2-Demastered-Substance-Edition.asi"
set "SRC=C:\Development\Git\MGS2-Demastered-Substance-Edition\ASI Mod\x64\Release\MGS2-Demastered-Substance-Edition.asi"

if exist "%DEST%" (
    echo Found existing ASI, updating...
    copy /Y "%SRC%" "%DEST%"
    echo Done.
) else (
    echo Target ASI not found. Nothing copied.
)

