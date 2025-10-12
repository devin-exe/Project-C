@echo off
:: ###################################################################
:: # Get All Local Users                                             #
:: # This script reliably lists all local user accounts, one per     #
:: # line. It is more reliable than parsing 'net user'.            #
:: ###################################################################

:: The 'wmic useraccount get name' command lists all users in a simple format.
:: The 'skip=1' option is used to ignore the header line ("Name").
:: The nested 'for' loop is a standard batch trick to remove trailing spaces
:: that wmic sometimes leaves, ensuring the output is clean.

echo [+] Fetching a list of all local users...
for /f "skip=1 delims=" %%i in ('wmic useraccount get name') do (
    for /f "tokens=*" %%j in ("%%i") do (
        echo %%j
    )
)

echo [+] Done.
