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
A script that extracts DBKey and decrypt all SQLITE3 database files (including db and write-ahead-logfiles ). 
At final a ZIP file containing all WhatsAppDesk local state decripted and a SHA512 is calculated.
Some information also in: https://medium.com/@alberto.magno/whatsapp-desktop-and-web-live-forensics-4n6-233f640e9fb3

Technique based on reverse-engineering-fu (yes! you do not need to use SQLITE3 SEE to decrypt) and some infos contained in following paper:
Giyoon Kim, Uk Hur, Soojin Kang, Jongsung Kim,Analyzing the Web and UWP versions of WhatsApp for digital forensics,
Forensic Science International: Digital Investigation,Volume 52,2025,301861,ISSN 2666-2817,
https://doi.org/10.1016/j.fsidi.2024.301861.
(https://www.sciencedirect.com/science/article/pii/S2666281724001884)

# Operation:
- First, it obtains the OfflineDeviceUniqueID, indicating the method used (TPM, REGISTRY, etc...), used in keys derivation linked to the machine.
- The tool start copying WhatsApp localstate files (where SQLITE3 DB files are located) to operate them
- It generates the userKey to generate the dbKey for decryption files.
- DbKey is used to decript DB and WAL files.
- All files decripted and the other in localstate are compacted.
- HASH file is generates for chain-of-custody purposes.

This script uses Bouncy Castle (BC) for C# .NET (MIT License).
https://www.bouncycastle.org/
OBS: this version needs that target machine be on to have access to the unique device id. Its not possible to decript without this ID.
You can just collect this ID and DB and nodb files to decrypt in other machine.

# Usage:
FIRST OF ALL!
- It is necessary to unblock BC`s DLL in windows. BouncyCastle.Cryptography.dll must be in the same directory of the ZAPiXWEB.ps1 file.
  Similar process as decribed for other DLL in https://simpledns.plus/kb/206-how-to-unblock-downloaded-plug-in-dll-file
- It also necessary to enable unrestricted execution in powershell with the following command typed on PS console:
  
  `Set-ExecutionPolicy Unrestricted`
- Open PowerShell on target computer (it will claim administrative rights).
run script:

  `.\ZAPiXDESK.ps1`

Have a nice 4N6!






