# Dynamic Minimal Services

## How It Works
By comparing required services from safemode with networking with normal boot services a slimmed down list can be created with minimal impact to normal Windows functionality 

Idea From: [GamingPCSetup](https://github.com/djdallmann/GamingPCSetup/blob/master/CONTENT/SCRIPTS/SafeMode.ps1)

### Improvements
Unlike the script above, this script will automate the whole process for you while also excluding important services for normal OS functionality

## How To Use
1. Download the `ServicesMinDynamic.ps1` script
2. If you have not already allow PowerShell scripts to run
   
   ```PowerShell
   Set-executionpolicy bypass -Force
   ```
3. Choose Option `1` to Collect Services in Safemode with Networking
4. Once Rebooted to Safemode run the script and it will create a service query with required services
5. When booted back to normal mode run the script and choose option `2` to collect services and disable
6. Revert Changes if needed
   
   ![{26667D4A-F125-4DEE-9063-928353291FD8}](https://github.com/user-attachments/assets/dc639e4a-07d7-44d0-bd1a-b0803525b1d7)

## Warnings

If you use a microsoft account this script is not for you

Things like Store, Updates, Xbox features will likely NOT work

DO NOT! delete the result log created in `[C:\Users\Username]` or you will NOT be able to revert the changes
