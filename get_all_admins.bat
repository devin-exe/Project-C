@echo off
:: This script lists all members of the local Administrators group.
setlocal enabledelayedexpansion
set "OUT_FILE=system_admins.txt"
echo [+] Fetching all administrator accounts... >&2
>"%OUT_FILE%"

:: The output of 'net localgroup' is parsed to extract members.
for /f "tokens=*" %%A in ('net localgroup "Administrators"') do (
    set "line=%%A"
    if "!line:~0,4!"=="----" (
        set "start_processing=true"
    ) else if defined start_processing (
        if not "!line!"=="" if not "!line!"=="The command completed successfully." (
            for %%U in (!line!) do (
                echo %%U >> "%OUT_FILE%"
            )
        )
    )
)

echo     - Admin list saved to %OUT_FILE% >&2
