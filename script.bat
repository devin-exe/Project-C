@echo off
setlocal enabledelayedexpansion

:: #############################################################################
:: #                                                                           #
:: #                       CyberPatriot Security Script                        #
:: #                                                                           #
:: #          Manages users, admins, and security settings.                    #
:: #          MUST BE RUN AS ADMINISTRATOR.                                    #
:: #                                                                           #
:: #############################################################################

cd /d "%~dp0"

:: ============================================================================
:: SCRIPT SETUP AND PRE-CHECKS
:: ============================================================================
title CyberPatriot Security Hardening Script
color 0A

:: 1. Check for Administrator Privileges
echo [+] Checking for Administrator privileges...
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] ERROR: This script must be run as an Administrator.
    pause
    exit /b
)
echo     ...Success. Privileges confirmed.

:: 2. Check for required files
if not exist "users.txt" (
    echo [!] ERROR: users.txt not found. Please create it.
    pause
    exit /b
)
if not exist "admins.txt" (
    echo [!] ERROR: admins.txt not found. Please create it.
    pause
    exit /b
)
echo [+] Required files (users.txt, admins.txt) found.

:: 3. Define accounts to ignore to prevent system breakage
set "IGNORE_USERS=Administrator Guest DefaultAccount WDAGUtilityAccount"
set "LOG_FILE=Password_Changes.log"

:: Clear previous log file and write header
echo Script run on %date% at %time% > %LOG_FILE%
echo ------------------------------------------ >> %LOG_FILE%
echo.

:: ============================================================================
:: SECTION 1: USER AND ADMINISTRATOR MANAGEMENT
:: ============================================================================
echo.
echo [--- Starting User and Administrator Management ---]

:: MODIFIED: Load approved users and admins into memory for reliable matching.
:: REASON: This avoids repeated file access and allows for more robust string comparison,
:: preventing issues caused by invisible characters or file formatting.
echo [+] Loading approved user and admin lists...
set "APPROVED_USERS=|"
for /f "delims=" %%u in (users.txt) do (
    set "APPROVED_USERS=!APPROVED_USERS!%%u|"
)
set "APPROVED_ADMINS=|"
for /f "delims=" %%a in (admins.txt) do (
    set "APPROVED_ADMINS=!APPROVED_ADMINS!%%a|"
)

:: --------------------------------------------------
:: 1a. Remove Unauthorized Users
:: --------------------------------------------------
echo [+] Checking for and removing unauthorized user accounts...
for /f "skip=1 delims=" %%i in ('wmic useraccount get name') do (
    for /f "tokens=*" %%U in ("%%i") do (
        set "user=%%U"
        set "is_ignored="
        set "is_approved="

        :: Check against ignore list
        for %%I in (%IGNORE_USERS%) do (
            if /i "%%I"=="!user!" set "is_ignored=true"
        )
        
        :: Check against approved users list
        echo "!APPROVED_USERS!" | findstr /i /c:"|!user!|" >nul
        if !errorlevel! equ 0 set "is_approved=true"
        
        if /i not "!user!"=="%USERNAME%" (
            if not defined is_ignored if not defined is_approved (
                echo     - Unauthorized user '!user!' found. DELETING account and profile...
                net user "!user!" /delete
            )
        )
    )
)

:: --------------------------------------------------
:: 1b. Remove Unauthorized Admins (Demote to Standard User)
:: --------------------------------------------------
echo [+] Checking for and removing unauthorized administrators...
set "start_processing="
for /f "tokens=*" %%L in ('net localgroup Administrators') do (
    set "raw_admin=%%L"
    if "!raw_admin:~0,4!"=="----" (
        set "start_processing=true"
    ) else if defined start_processing (
        if not "!raw_admin!"=="" if not "!raw_admin!"=="The command completed successfully." (
            set "clean_admin=!raw_admin!"
            
            :: This block checks for a '\' and splits the string to get the clean username
            echo "!raw_admin!" | find "\" >nul
            if !errorlevel! equ 0 (
                for /f "tokens=2 delims=\" %%n in ("!raw_admin!") do set "clean_admin=%%n"
            )

            set "is_ignored="
            set "is_approved="
            
            :: Check against ignore list
            for %%I in (%IGNORE_USERS%) do (
                if /i "%%I"=="!clean_admin!" set "is_ignored=true"
            )

            :: Check against approved admins list
            echo "!APPROVED_ADMINS!" | findstr /i /c:"|!clean_admin!|" >nul
            if !errorlevel! equ 0 set "is_approved=true"

            if not defined is_ignored if not defined is_approved (
                echo     - Unauthorized admin '!raw_admin!' found. Removing from Administrators group...
                net localgroup Administrators "!raw_admin!" /delete >nul
            )
        )
    )
)

:: --------------------------------------------------
:: 1c. Create Authorized Users and Reset Passwords
:: --------------------------------------------------
echo [+] Creating missing authorized users and resetting passwords...
for /f %%U in (users.txt) do (
    set "user=%%U"
    net user "!user!" >nul 2>&1
    if !errorlevel! neq 0 (
        echo     - User '!user!' does not exist. CREATING account...
        net user "!user!" /add /comment:"Account created by CyberPatriot script." >nul
    )
    
    if /i not "!user!"=="%USERNAME%" (
        call :GeneratePassword
        echo     - Setting new secure password for user '!user!'...
        net user "!user!" "!NEW_PASS!" >nul
        echo User: !user! --^> New Password: !NEW_PASS! >> %LOG_FILE%
    ) else (
        echo     - Skipping password reset for current user: !user!
    )
)

:: --------------------------------------------------
:: 1d. Ensure Authorized Admins Have Admin Rights
:: --------------------------------------------------
echo [+] Ensuring all authorized admins are in the Administrators group...
for /f "delims=" %%A in (admins.txt) do (
    echo     - Verifying admin rights for '%%A'...
    net localgroup Administrators "%%A" /add >nul 2>&1
)
echo [--- User and Administrator Management Complete ---]

:: ============================================================================
:: SECTION 2: SECURITY MANAGEMENT (Unchanged)
:: ============================================================================
echo.
echo [--- Starting Security Hardening ---]
echo [+] Enabling Windows Security features via PowerShell...
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false" >nul
echo     - Real-time Virus ^& Threat Protection: ENABLED
powershell -Command "Set-MpPreference -DisableBehaviorMonitoring $false" >nul
echo     - Behavior Monitoring: ENABLED
echo [+] Enabling Windows Firewall for all network profiles...
netsh advfirewall set allprofiles state on
echo     - Firewall: ENABLED
echo [+] Applying Local Group Policies from the 'Policies' folder...
if exist "LGPO.exe" ( if exist "Policies" ( LGPO.exe /g .\\Policies && echo     - Group policies applied successfully. ) else ( echo     [!] WARNING: 'Policies' folder not found. ) ) else ( echo     [!] WARNING: LGPO.exe not found. )
echo [+] Checking for and installing Windows Updates (this may take a while)...
(
echo Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue
echo Install-Module -Name PSWindowsUpdate -Force -SkipPublisherCheck -ErrorAction SilentlyContinue
echo Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
echo Get-WindowsUpdate -Install -AcceptAll -AutoReboot ^| Out-File -FilePath Windows_Update_Log.txt
) > temp_update_script.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\\temp_update_script.ps1
del temp_update_script.ps1
echo     - Windows Update process initiated. See Windows_Update_Log.txt for details.
echo [--- Security Hardening Complete ---]

:: ============================================================================
:: COMPLETION
:: ============================================================================
echo.
echo ##############################################################
echo # Script Finished!                                           #
echo #                                                            #
echo # - New passwords have been saved to: %LOG_FILE%             #
echo # - A reboot may be required for all changes to take effect. #
echo ##############################################################
echo.
pause
goto :eof

:: ############################################################################
:: #                          SUBROUTINES                                     #
:: ############################################################################

:GeneratePassword
set "ALPHANUM=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
set "NEW_PASS="
for /l %%N in (1,1,14) do (
    set /a "RAND_NUM=!RANDOM! %% 62"
    for %%R in (!RAND_NUM!) do set "NEW_PASS=!NEW_PASS!!ALPHANUM:~%%R,1!"
)
goto :eof
