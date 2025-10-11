@echo off
:: This script lists all local users and saves them to a file.
set "OUT_FILE=system_users.txt"
echo [+] Fetching all user accounts... >&2

:: The output of 'net user' is parsed to extract just the usernames.
(for /f "skip=4 tokens=1" %%U in ('net user') do (
    echo %%U
)) > "%OUT_FILE%"

echo     - User list saved to %OUT_FILE% >&2
