<span style="color:red">⚠️ Attention!</span>
# Attention
New version 2.1 is now able to decrypt local databases from the new WEBVIEW2 ARCH.

Since 9th December 2025, Meta changed WhatsApp Desktop platform from UWP (Universal Windows Platform) to WebView2 (Windows Services + Browser Services).

Another possible method to extract data is restart WEBVIEW2 application with developer tools activated, and use ZAPiXWEB technique <https://github.com/kraftdenker/ZAPiXWEB>:

-Kill active WhatsApp.Root process using taskmanager or using command line:
```
Stop-Process -Name "WhatsApp.Root" -Force
Start-Sleep -Milliseconds 300
```
And restart it passing the following argument:
```
C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2587.9.0_x64__cv1g1gvanyjgm>WhatsApp.Root.exe --auto-open-devtools-for-tabs
```

# ZAPiXDESK
WhatsApp Desktop Live Forensiscs - Decryption and Extraction Technique

```
______  ___  ______ ___   _______ _____ _____ _   __
|___  / / _ \ | ___ (_) \ / /  _  \  ___/  ___| | / /
   / / / /_\ \| |_/ /_ \ V /| | | | |__ \ ---.| |/ /
  / /  |  _  ||  __/| |/   \| | | |  __| ---. \    \  
./ /___| | | || |   | / /^\ \ |/ /| |___/\__/ / |\  \
\_____/\_| |_/\_|   |_\/   \/___/ \____/\____/\_| \_/
                                       ZAPiXDESK
```
                                       
Copyrights: 2025 Alberto Magno <alberto.magno@gmail.com> 
LICENSE GNU General Public License v3.0

# Description: 
A script that extracts DBKeys and decrypts all SQLITE3 database files (including db and write-ahead-logfiles ). 
On completion a ZIP file containing all WhatsApp decrypted LocalState db's and a MD5 is calculated.
Some information also in: https://medium.com/@alberto.magno/whatsapp-desktop-and-web-live-forensics-4n6-233f640e9fb3

Techinique for WEBVIEW2 is full based on reverse-engineering-fu passing over WEB, CLR and NATIVE layers of the architecture.

Technique for UWP is based on reverse-engineering-fu (yes! you do not need to use SQLite3 SEE to decrypt) and some info contained in following paper:
Giyoon Kim, Uk Hur, Soojin Kang, Jongsung Kim,Analyzing the Web and UWP versions of WhatsApp for digital forensics,
Forensic Science International: Digital Investigation,Volume 52,2025,301861,ISSN 2666-2817,
https://doi.org/10.1016/j.fsidi.2024.301861.
(https://www.sciencedirect.com/science/article/pii/S2666281724001884)

# WEBVIEW2 ARCH Operation:
- First, it obtains the OfflineDeviceUniqueID, indicating the method used (TPM, REGISTRY, etc...), used in keys derivations linked to the machine.
- The tool copies the WhatsApp localstate files (where SQLite3 DB files are located) to operate them
- It generates the first decryption key to session.db based on staticKey protect by DPAPI-NG than recovers clientKey from WAL file as database is configured to secure-deletion PRAGMA.
- With clientKey, it is able to derives encryption key using OOUID and statickey to decrypt nativeSettings database, where all other keys were stored and are recovered from WAL file.
- DbKeys are used to decrypt the others databases.
- All decrypted files and the other content of LocalState are zipped.
- MD5 HASH file is generates for chain-of-custody purposes.

# UWP ARCH Operation:
- First, it obtains the OfflineDeviceUniqueID, indicating the method used (TPM, REGISTRY, etc...), used in keys derivation linked to the machine.
- The tool copies the WhatsApp localstate files (where SQLite3 DB files are located) to operate them
- It generates the userKey to generate the dbKey for decrypting the files.
- DbKey is used to decrypt DB and WAL files.
- All decrypted files and the other content of LocalState are zipped.
- MD5 HASH file is generates for chain-of-custody purposes.

This script uses Bouncy Castle (BC) for C# .NET (MIT License).
https://www.bouncycastle.org/
OBS: this version needs that target machine be on to have access to the unique device id. Its not possible to decrypt without this ID.

You can just collect this ID and LocalState contents to decrypt on another machine.

# Usage:
FIRST OF ALL!
- It is necessary to unblock BouncyCastle.Cryptography.dll in Windows. BouncyCastle.Cryptography.dll must be in the same directory of the ZAPiXDESK.ps1 file.
- It may also be necessary to enable set the execution policy to Unrestricted or Bypass in PowerShell to execute the script. This can be done with the following command in PS console:
  
  `Set-ExecutionPolicy Unrestricted` or `Set-ExecutionPolicy Bypass`
- Open PowerShell on target computer (it will attempt to claim administrative rights).
run script:

  `.\ZAPiXDESK.ps1` with selected arguments. If no arguments are supplied, defaults will be used.

This script will take the following arguments:
```
-WhatsAppPath  
```
- This should be the full file path to the location of the WhatsApp LocalState directory. If not provided, it will be derived from the running machine's
  installation of WhatsApp.

```
-OutputPath
```
- Allows you to select the OutputPath. If not chosen, it will output into the directory from where the script is executed.

```
-Offline  
```
- This will allow you to run the script offline against an extracted WhatsApp directory, provided you have the ODUID. To get this, you can either:
  - Run the script simply with the `-GetID` flag
  - Use the binary in the `binaries` folder to run on the live system containing the desired WhatsApp installation;
  - Check the registry of the running system at `HKLM\SYSTEM\CurrentControlSet\Services\TPM\ODUID` for a value named `RandomSeed`. Using this, you can 
    convert the value "cv1g1gv" to UTF-16 bytes, then make sure the RandomSeed is in bytes, concatenate the "cvgv1gv" bytes and RandomSeed bytes, then 
    get the byte value of performing a SHA256 of those bytes.; or
  - Reboot the computer and boot into UEFI shell, and run the command `dmpstore -b OfflineUniqueIDRandomSeed` and perform the same byte conversion, concat
    and SHA256 as in the previous step

```
-ID
```
- When using Offline mode, provide the OfflineDeviceUniqueID (ODUID) value as a standard hex string to be used to decrypt database contents on a system other
  than the original live system

```
-GetID
```
- This will get only the ODUID as a hex string for use in offline decryption.


Have a nice 4N6!






