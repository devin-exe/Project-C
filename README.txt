Made by Devin Kelley (NPHS)
Catharsis is a group of scripts designed to secure a virtual machine for the CyberPatriot competition. The following README is a step by step guide to running the script on your virtual machine.

--- Setting Up The Script ---
To use this script on a competition/training round VM, you must first download the zipped folder from this repository, and extract it to create a non-zipped file. 
Next, you will need to copy over the entire unzipped folder onto the VM's file system. I personally prefer dragging it from my file system to the VM desktop.

--- User Management Preparation ---
Before running the script, you MUST first edit the list of approved admins and users. Failing to do this will result in unnecessary user deletion.
In each text file (admins.txt, users.txt), copy & paste the names of approved users and admins found in the VM README file, with each username being on a different line.
Example:
user1
user2
user3

It is also important to copy over the list of approved admins to the list of approved users to avoid approved admins having their entire accounts deleted.
There is a built-in failsafe to prevent the deletion of the current user, as this would negatively impact the state of the VM.
Other accounts built into Windows by default are handled separately and left to your descretion when running the script.

--- Running The Script ---
To run the script, select script.bat and run it as an administator.
The script will not fully run without administrative privileges, so it is important to remember this.

--- User Management ---
In this section of the script, it will automatically remove unauthorized users, and demote unauthorized admins.
In addition, each user is configured to have a secure password, which is ensured to expire by force.
You can find each users new password in an automatically generated file in the same folder as the script.
As another failsafe, the current user's password is not changed to prevent a potential lockout.
You can find the current user's password in the README file of the VM.

--- Security Hardening ---
In this section of the script, many settings are changed to ensure the security of the system and its users.
The script begins this section by ensuring that Windows Defender and the Firewall are enabled.

Next, the system modifies the group policy using the Microsoft Local Group Policy Editor (LGPO.exe).
The script retrieves a list of group policies to modify from the "Policies" folder, which are then applied to your system.
It is critical to ensure that both the .exe file and the Policies folder are preserved for the competition, as this is where most of your points will be acheived.

In the part of the security hardening section, the script automatically stops multiple unsecure services, and scans for unauthorized file types on the system.
You will be required to manually approve each file that is deleted from the system.
It is important to ensure that you do not delete any files contained in the "Catharsis" folder, as they will be automatically flagged.
If you DO delete any files contained in Catharsis, the script could potentially cease functioning, so don't do that. That would be pretty stupid.

The script will lastly automatically install updates for Windows. This section is mostly left up to you for the following reasons:
  The VM might not require the newest updates.
  Some VMs ask you not to install updates at all.
For this reason, the script will still attempt to install updates, but if you wish not to, you can stop the script and delete the Powershell script it utilizes.
If you do decide to go ahead with the download/install process, a text will be generated to show you the status of which updates have been downloaded and installed.

Overall, this script is very robust, and I highly reccomend you analyze it in depth to ensure you understand it to the fullest extent. In any case, the whole script is here for you to use. Good luck, you'll need it.
