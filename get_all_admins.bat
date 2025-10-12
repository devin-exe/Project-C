@echo off
setlocal enabledelayedexpansion

:: ###################################################################
:: # Get All Local Administrators                                    #
:: # This script reliably lists all members of the local             #
:: # 'Administrators' group, one per line, correctly handling        #
:: # usernames that contain spaces.                                  #
:: ###################################################################

echo [+] Fetching a list of all local administrators...

:: We loop through the output of the 'net localgroup' command.
:: A flag 'start_processing' is used to start reading names only
:: after the "----" line is found.
for /f "tokens=*" %%A in ('net localgroup Administrators') do (
    set "line=%%A"
    
    :: Check for the line of dashes that separates the header from the members list
    if "!line:~0,4!"=="----" (
        set "start_processing=true"
    ) else if defined start_processing (
        :: Once processing has started, ignore blank lines and the final status message.
        if not "!line!"=="" if not "!line!"=="The command completed successfully." (
            :: Echo the entire line, which is the full username.
            echo !line!
        )
    )
)

echo [+] Done.
