@echo off
setlocal enabledelayedexpansion

:: #############################################################################
:: #                                                                           #
:: #                    CyberPatriot Security Script                           #
:: #                                                                           #
:: #             Manages users, admins, and security settings.                 #
:: #                   MUST BE RUN AS ADMINISTRATOR.                           #
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
set "LOG_FILE=Security_Script.log"

:: Clear previous log file and write header
echo Script run on %date% at %time% > %LOG_FILE%
echo ------------------------------------------ >> %LOG_FILE%
echo. >> %LOG_FILE%
echo PASSWORD CHANGES >> %LOG_FILE%
echo ---------------- >> %LOG_FILE%

:: ============================================================================
:: SECTION 1: USER AND ADMINISTRATOR MANAGEMENT
:: ============================================================================
echo.
echo [--- Starting User and Administrator Management ---]
:: Run external scripts to get current system users and admins
call get_all_users.bat
call get_all_admins.bat

:: --------------------------------------------------
:: 1a. Remove Unauthorized Users
:: --------------------------------------------------
echo [+] Checking for and removing unauthorized user accounts...
for /f "usebackq" %%U in ("system_users.txt") do (
    set "user=%%U"
    if /i not "!user!"=="%USERNAME%" (
        echo !IGNORE_USERS! | findstr /i /c:"!user!" >nul
        if !errorlevel! neq 0 (
            findstr /i /x /c:"!user!" users.txt >nul
            if !errorlevel! neq 0 (
                echo     - Unauthorized user '!user!' found. DELETING account and profile...
                net user "!user!" /delete
                echo DELETED Unauthorized User: !user! >> %LOG_FILE%
            )
        )
    )
)

:: --------------------------------------------------
:: 1b. Remove Unauthorized Admins (Demote to Standard User)
:: --------------------------------------------------
echo [+] Checking for and removing unauthorized administrators...
for /f "usebackq" %%U in ("system_admins.txt") do (
    set "admin_user=%%U"
    echo !IGNORE_USERS! | findstr /i /c:"!admin_user!" >nul
    if !errorlevel! neq 0 (
        findstr /i /x /c:"!admin_user!" admins.txt >nul
        if !errorlevel! neq 0 (
            echo     - Unauthorized admin '!admin_user!' found. Removing from Administrators group...
            net localgroup Administrators "!admin_user!" /delete >nul
            echo DEMOTED Unauthorized Admin: !admin_user! >> %LOG_FILE%
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
        echo CREATED Authorized User: !user! >> %LOG_FILE%
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
for /f %%A in (admins.txt) do (
    echo     - Verifying admin rights for '%%A'...
    net localgroup Administrators "%%A" /add >nul
)
echo [--- User and Administrator Management Complete ---]

:: ============================================================================
:: SECTION 2: SECURITY MANAGEMENT
:: ============================================================================
echo.
echo [--- Starting Security Hardening ---]

:: --------------------------------------------------
:: 2a. Enable Windows Security Features
:: --------------------------------------------------
echo [+] Enabling Windows Security features via PowerShell...
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false" >nul
echo     - Real-time Virus ^& Threat Protection: ENABLED
powershell -Command "Set-MpPreference -DisableBehaviorMonitoring $false" >nul
echo     - Behavior Monitoring: ENABLED

echo [+] Enabling Windows Firewall for all network profiles...
netsh advfirewall set allprofiles state on
echo     - Firewall: ENABLED

:: --------------------------------------------------
:: 2b. Apply Local Group Policy
:: --------------------------------------------------
echo [+] Applying Local Group Policies from the 'Policies' folder...
if exist "LGPO.exe" (
    if exist "Policies" (
        LGPO.exe /g .\\Policies
        echo     - Group policies applied successfully.
    ) else (
        echo     [!] WARNING: 'Policies' folder not found. Skipping GPO application.
    )
) else (
    echo     [!] WARNING: LGPO.exe not found. Skipping GPO application.
)

:: --------------------------------------------------
:: 2c. Check for and Install Windows Updates
:: --------------------------------------------------
echo [+] Checking for and installing Windows Updates (this may take a while)...
echo Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue > temp_update_script.ps1
echo Install-Module -Name PSWindowsUpdate -Force -SkipPublisherCheck -ErrorAction SilentlyContinue >> temp_update_script.ps1
echo Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue >> temp_update_script.ps1
echo Get-WindowsUpdate -Install -AcceptAll -AutoReboot ^| Out-File -FilePath Windows_Update_Log.txt >> temp_update_script.ps1

powershell -NoProfile -ExecutionPolicy Bypass -File .\\temp_update_script.ps1
del temp_update_script.ps1

echo     - Windows Update process initiated. See Windows_Update_Log.txt for details.

:: --------------------------------------------------
:: 2d. Disable Unnecessary Services
:: --------------------------------------------------
echo [+] Disabling unnecessary services...
sc stop SMTPSVC >nul 2>&1
sc config SMTPSVC start= disabled >nul 2>&1
echo     - Simple Mail Transfer Protocol (SMTP): DISABLED
sc stop FTPSVC >nul 2>&1
sc config FTPSVC start= disabled >nul 2>&1
echo     - FTP Service: DISABLED

:: --------------------------------------------------
:: 2e. Manage Remote Desktop
:: --------------------------------------------------
echo [+] Managing Remote Desktop settings...
set "disableRDP="
set /p "disableRDP=Do you want to disable Remote Desktop? (Y/N): "
if /i "!disableRDP!"=="Y" (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f >nul
    echo     - Remote Desktop has been DISABLED.
    echo DISABLED Remote Desktop >> %LOG_FILE%
) else (
    echo     - Remote Desktop settings remain unchanged.
)

:: --------------------------------------------------
:: 2f. Manage Default Accounts
:: --------------------------------------------------
echo [+] Managing default accounts...
set "disableDefaults="
set /p "disableDefaults=Do you want to disable the default Administrator and Guest accounts? (Y/N): "
if /i "!disableDefaults!"=="Y" (
    net user Administrator /active:no >nul
    echo     - Default 'Administrator' account has been DISABLED.
    echo DISABLED Default Administrator Account >> %LOG_FILE%
    net user Guest /active:no >nul
    echo     - Default 'Guest' account has been DISABLED.
    echo DISABLED Default Guest Account >> %LOG_FILE%
) else (
    echo     - Default account settings remain unchanged.
)

:: --------------------------------------------------
:: 2g. Manage User Files
:: --------------------------------------------------
echo [+] Scanning user files for potential deletion...
echo. >> %LOG_FILE%
echo FILE DELETIONS >> %LOG_FILE%
echo -------------- >> %LOG_FILE%
for /d %%D in ("%SystemDrive%\Users\*") do (
    set "userName=%%~nxD"
    if /i not "!userName!"=="Public" if /i not "!userName!"=="Default" if /i not "!userName!"=="All Users" (
        if exist "%%D\Documents" (
            echo --- Scanning files for user: !userName! ---
            call :ScanAndDelete "%%D\Documents"
            call :ScanAndDelete "%%D\Pictures"
            call :ScanAndDelete "%%D\Music"
            call :ScanAndDelete "%%D\Videos"
        )
    )
)

echo [--- Security Hardening Complete ---]

:: ============================================================================
:: COMPLETION
:: ============================================================================
echo.
echo ##############################################################
echo # Script Finished!                                           #
echo #                                                            #
echo # - All actions have been logged to: %LOG_FILE% #
echo # - A reboot may be required for all changes to take effect. #
echo ##############################################################
echo.

set "restartPC="
set /p "restartPC=Would you like to restart the computer now? (Y/N): "
if /i "!restartPC!"=="Y" (
    echo Restarting computer in 5 seconds...
    shutdown /r /t 5
) else (
    echo Please restart the computer later to apply all changes.
    pause
)

goto :eof

:: ############################################################################
:: #                                                                          #
:: #                          SUBROUTINES                                     #
:: #                                                                          #
:: ############################################################################

:GeneratePassword
:: A secure password will be generated for each user.
:: This function generates a 14-character alphanumeric password.
set "ALPHANUM=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
set "NEW_PASS="
for /l %%N in (1,1,14) do (
    set /a "RAND_NUM=!RANDOM! %% 62"
    for %%R in (!RAND_NUM!) do set "NEW_PASS=!NEW_PASS!!ALPHANUM:~%%R,1!"
)
goto :eof

:ScanAndDelete
set "folder=%~1"
if not exist "%folder%\" goto :eof
for /r "%folder%" %%F in (*) do (
    echo   File: %%F
    set "deleteFile="
    set /p "deleteFile=  -> Delete this file? (Y/N): "
    if /i "!deleteFile!"=="Y" (
        del "%%F"
        echo      ...DELETED.
        echo DELETED file: %%F >> %LOG_FILE%
    ) else (
        echo      ...SKIPPED.
    )
)
goto :eof
