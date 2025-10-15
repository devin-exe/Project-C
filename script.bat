@echo off
setlocal enabledelayedexpansion

:: #############################################################################
:: #                                                                           #
:: #                  CyberPatriot Security Script                             #
:: #                                                                           #
:: #                Manages users, admins, and security settings.              #
:: #                MUST BE RUN AS ADMINISTRATOR.                              #
:: #                                                                           #
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
echo     ...Success. Privileges confirmed.

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
:: NOTE: We only ignore 'DefaultAccount' and 'WDAGUtilityAccount' here.
:: 'Administrator' and 'Guest' are handled separately in the new 1e section.
set "IGNORE_USERS=DefaultAccount WDAGUtilityAccount"
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

:: --------------------------------------------------
:: 1a. Remove Unauthorized Users
:: --------------------------------------------------
echo [+] Checking for and removing unauthorized user accounts...
for /f "skip=4 tokens=*" %%L in ('net user') do (
    set "line=%%L"
    
    :: Ignore the successful completion line
    if /i not "!line!"=="The command completed successfully." (
        
        :: Iterate over each user token (%%U) found on the captured line (%%L)
        for %%U in (%%L) do (
            set "user=%%U"
            
            :: 1. Check if the user is the currently logged-in user (skip)
            if /i not "!user!"=="%USERNAME%" (
                
                :: 2. Check if the user is in the IGNORE_USERS list (system accounts) OR the built-in accounts
                echo !IGNORE_USERS! Administrator Guest | findstr /i /c:"!user!" >nul
                if !errorlevel! neq 0 (
                    
                    :: 3. Check if user is NOT in the authorized list (users.txt)
                    findstr /i /c:"!user!" users.txt >nul
                    if !errorlevel! neq 0 (
                        echo      - Unauthorized user '!user!' found. DELETING account and profile...
                        net user "!user!" /delete 2>nul
                    )
                )
            )
        )
    )
)

:: --------------------------------------------------
:: 1b. Remove Unauthorized Admins (Demote to Standard User)
:: --------------------------------------------------
echo [+] Checking for and removing unauthorized administrators...
for /f "tokens=*" %%A in ('net localgroup Administrators') do (
    set "line=%%A"
    if "!line:~0,4!"=="----" (
        set "start_processing=true"
    ) else if defined start_processing (
        if not "!line!"=="" if not "!line!"=="The command completed successfully." (
            for %%U in (!line!) do (
                :: Ignore system accounts including built-in Administrator
                echo !IGNORE_USERS! Administrator | findstr /i /c:"%%U" >nul
                if !errorlevel! neq 0 (
                    findstr /i /c:"%%U" admins.txt >nul
                    if !errorlevel! neq 0 (
                        echo     - Unauthorized admin '%%U' found. Removing from Administrators group...
                        net localgroup Administrators "%%U" /delete >nul
                    )
                )
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
        echo     - User '!user!' does not exist. CREATING account...
        net user "!user!" /add /comment:"Account created by CyberPatriot script." >nul
    )
    
    if /i not "!user!"=="%USERNAME%" (
        call :GeneratePassword
        echo     - Setting new secure password for user '!user!'...
        net user "!user!" "!NEW_PASS!" >nul
        echo User: !user! --^> New Password: !NEW_PASS! >> %LOG_FILE%
    ) else (
        echo     - Skipping password reset for current user: !user!
    )
)

:: --------------------------------------------------
:: 1d. Ensure Authorized Admins Have Admin Rights
:: --------------------------------------------------
echo [+] Ensuring all authorized admins are in the Administrators group...
for /f %%A in (admins.txt) do (
    echo     - Verifying admin rights for '%%A'...
    net localgroup Administrators "%%A" /add >nul
)

:: --------------------------------------------------
:: 1e. Default Account Management (NEW)
:: --------------------------------------------------
echo.
echo [+] **Default Account Management**
:DisableAccountsPrompt
set /p "DisableDefaults=     -> Disable the built-in 'Administrator' and 'Guest' accounts? (Y/N): "

if /i "%DisableDefaults%"=="Y" (
    echo     - Disabling built-in 'Administrator' account...
    net user Administrator /active:no >nul 2>&1
    echo     - Disabling built-in 'Guest' account...
    net user Guest /active:no >nul 2>&1
) else if /i not "%DisableDefaults%"=="N" (
    echo [!] Invalid choice. Please enter Y or N.
    goto DisableAccountsPrompt
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
echo     - Real-time Virus ^& Threat Protection: ENABLED
powershell -Command "Set-MpPreference -DisableBehaviorMonitoring $false" >nul
echo     - Behavior Monitoring: ENABLED

echo [+] Enabling Windows Firewall for all network profiles...
netsh advfirewall set allprofiles state on
echo     - Firewall: ENABLED

:: --------------------------------------------------
:: 2b. Disable Unnecessary Services (NEW)
:: --------------------------------------------------
echo.
echo [+] **Disabling Unnecessary Services** (SMTP, FTP, Telnet, SNMP)
:: Set to 'disabled' (4) to prevent them from starting even if the VM is rebooted.
echo     - Attempting to disable SMTP (Simple Mail Transfer Protocol)...
sc config smtpsvc start= disabled >nul 2>&1
net stop smtpsvc >nul 2>&1
echo     - Attempting to disable FTP (File Transfer Protocol)...
sc config ftpsvc start= disabled >nul 2>&1
net stop ftpsvc >nul 2>&1
echo     - Attempting to disable Telnet Service...
sc config TlntSvr start= disabled >nul 2>&1
net stop TlntSvr >nul 2>&1
echo     - Attempting to disable SNMP Trap Service...
sc config SNMPTRAP start= disabled >nul 2>&1
net stop SNMPTRAP >nul 2>&1
echo     ...Unnecessary services disabled.

:: --------------------------------------------------
:: 2c. Scan and Manage Unallowed Files (NEW)
:: --------------------------------------------------
echo.
echo [+] **Scanning for Unallowed File Types** (.mp3, .avi, .torrent, .vbs)
set "UNALLOWED_EXTENSIONS=*.mp3 *.avi *.torrent *.vbs"
set "SCAN_ROOTS=C:\Users C:\ProgramData"
set "FOUND_COUNT=0"

for %%R in (%SCAN_ROOTS%) do (
    if exist "%%R" (
        for %%E in (%UNALLOWED_EXTENSIONS%) do (
            for /r "%%R" %%F in (%%E) do (
                set /a "FOUND_COUNT+=1"
                echo.
                echo [!] Unallowed file found: "%%F"
                
                :FileManagementPrompt
                set /p "ACTION=     -> Delete this file? (Y/N): "
                
                if /i "!ACTION!"=="Y" (
                    del "%%F"
                    echo     - DELETED "%%F"
                ) else if /i "!ACTION!"=="N" (
                    echo     - KEPT "%%F"
                ) else (
                    echo [!] Invalid choice. Please enter Y or N.
                    goto FileManagementPrompt
                )
            )
        )
    ) else (
        echo     [!] WARNING: Scan root "%%R" not found or inaccessible.
    )
)

if !FOUND_COUNT! equ 0 (
    echo     - No unallowed files found in the specified locations.
)

:: --------------------------------------------------
:: 2d. Apply Local Group Policy (Original 2b)
:: --------------------------------------------------
echo.
echo [+] Applying Local Group Policies from the 'Policies' folder...
if exist "LGPO.exe" (
    if exist "Policies" (
        LGPO.exe /g .\\Policies
        echo     - Group policies applied successfully.
    ) else (
        echo     [!] WARNING: 'Policies' folder not found. Skipping GPO application.
    )
) else (
    echo     [!] WARNING: LGPO.exe not found. Skipping GPO application.
)

:: --------------------------------------------------
:: 2e. Check for and Install Windows Updates (Original 2c)
:: --------------------------------------------------
echo.
echo [+] Checking for and installing Windows Updates (this may take a while)...
echo Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue > temp_update_script.ps1
echo Install-Module -Name PSWindowsUpdate -Force -SkipPublisherCheck -ErrorAction SilentlyContinue >> temp_update_script.ps1
echo Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue >> temp_update_script.ps1
echo Get-WindowsUpdate -Install -AcceptAll -AutoReboot ^| Out-File -FilePath Windows_Update_Log.txt >> temp_update_script.ps1

powershell -NoProfile -ExecutionPolicy Bypass -File .\\temp_update_script.ps1
del temp_update_script.ps1

echo     - Windows Update process initiated. See Windows_Update_Log.txt for details.

echo [--- Security Hardening Complete ---]

:: ============================================================================
:: COMPLETION
:: ============================================================================
echo.
echo ##############################################################
echo # Script Finished!                                           #
echo #                                                            #
echo # - New passwords have been saved to: %LOG_FILE%             #
echo # - A reboot may be required for all changes to take effect. #
echo ##############################################################
echo.
pause

goto :eof

:: ############################################################################
:: #                                                                          #
:: #                          SUBROUTINES                                     #
:: #                                                                          #
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
