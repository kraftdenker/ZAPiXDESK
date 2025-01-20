clear
Write-Output "______  ___  ______ ___   _______ _____ _____ _   __
|___  / / _ \ | ___ (_) \ / /  _  \  ___/  ___| | / /
   / / / /_\ \| |_/ /_ \ V /| | | | |__ \ `--.| |/ / 
  / /  |  _  ||  __/| |/   \| | | |  __| `--. \    \ 
./ /___| | | || |   | / /^\ \ |/ /| |___/\__/ / |\  \
\_____/\_| |_/\_|   |_\/   \/___/ \____/\____/\_| \_/
                                       ZAPiXDESK         
# Copyright: 2025 Alberto Magno <alberto.magno@gmail.com> 
# URL: https://github.com/kraftdenker/ZAPiXDESK"                                      

# Windows WhatsApp Desktop
# Script Name: SPIZAPIXWEB.js
# Version: 1.0
# Revised Date: 01/01/25

# Copyright: 2025 Alberto Magno <alberto.magno@gmail.com> 
# URL: https://github.com/kraftdenker/ZAPiXDESK

# Description: A script that extracts DBKey and decrypt all SQLITE3 database files (including db and write-ahead-logfiles ). At final a ZIP file containing all WhatsAppDesk localstate decripted.

# Technique based on reverse-engineering-fu (yes! you do not need to use SQLITE3 SEE to decrypt) and infos contained in following paper:
# Giyoon Kim, Uk Hur, Soojin Kang, Jongsung Kim,Analyzing the Web and UWP versions of WhatsApp for digital forensics,
# Forensic Science International: Digital Investigation,Volume 52,2025,301861,ISSN 2666-2817,
# https://doi.org/10.1016/j.fsidi.2024.301861.
# (https://www.sciencedirect.com/science/article/pii/S2666281724001884)

# Verify Administrator rights 
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 
{ 
	# Elevate to power user
	$arguments = "& '" + $myInvocation.MyCommand.Definition + "'" 
	Start-Process powershell -Verb runAs -ArgumentList $arguments 
	Exit 
}
Set-ExecutionPolicy Unrestricted

$currentDirectory = Get-Location

function Get-AppLocalStatePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppName
    )

    $appPackage = Get-AppxPackage | Where-Object {$_.Name -like "*$AppName*"}

    if ($appPackage) {
        # Verify if does it use PackageFamilyName or not
        if ($appPackage.Name -like "*WhatsApp*") {
            $packageId = $appPackage.PackageFamilyName
        } else {
            $packageId = $appPackage.PackageFullName
        }

        $localStatePath = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Packages\$packageId\LocalState"

        if (!(Test-Path -Path $localStatePath -PathType Container)) {
            Write-Warning "Dir LocalState not found to '$AppName'. PackageId: $packageId"
            return $null
        }

        return $localStatePath
    } else {
        Write-Warning "WindowsApp '$AppName' not found."
        return $null
    }
}

$zapLocalStatePath = Get-AppLocalStatePath -AppName "WhatsApp"
Write-Verbose $zapLocalStatePath

# Function to copy the contents of a directory to a destination,
# creating or clearing the destination if it exists, waiting for completion,
# and handling individual file copy errors.
function Copy-Directory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    try {
        # Check if the source directory exists
        if (!(Test-Path -Path $Source -PathType Container)) {
            throw "Source directory '$Source' not found."
        }

        # Create the destination directory if it doesn't exist
        if (!(Test-Path -Path $Destination -PathType Container)) {
            New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        } else {
            # Clear the destination directory if it already exists
            Write-Verbose "Clearing destination directory: $Destination"
            Get-ChildItem -Path $Destination -Force | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        }

        # Copy the contents of the source directory to the destination
        Get-ChildItem -Path $Source -Force -Recurse | ForEach-Object {
            $targetPath = Join-Path -Path $Destination -ChildPath ($_.FullName.Substring($Source.Length + 1))
            if ($_.PSIsContainer) {
                Write-Verbose "Creating directory: $targetPath"
                New-Item -ItemType Directory -Path $targetPath -Force | Out-Null
            } else {
                try {
                    Write-Verbose "Copying file: $($_.FullName) to $targetPath"
                    Copy-Item -Path $_.FullName -Destination $targetPath -Force -ErrorAction Stop # Stop on error for each file
                    #Write-Verbose "Copied: $($_.FullName)" # Visual feedback
                }
                catch {
                    Write-Warning "Failed to copy '$($_.FullName)': $($_.Exception.Message)"
                }
            }
        }

        Write-Verbose "Copy completed."

    } catch {
        Write-Error "Error during copy operation: $($_.Exception.Message)"
    }
}
# Global UserKey
$userKey = [byte[]]::new(32)
# ZAPiXDESK Metadata file
$metaDataFileName = "ZAPiXDESK.mtd.txt"

# Copies zap directory (creates/clears the destination and ignores errors)
$reverseDate = Get-Date -Format "yyyyMMddHHmmss"
$targetOutput="$currentDirectory\ZAPiXDESK_$reverseDate"
Copy-Directory -Source $zapLocalStatePath -Destination $targetOutput

"ZAPiXDESK DATE:$reverseDate"| Out-File -FilePath "$targetOutput\$metaDataFileName" -Append

# enum RETRIEVAL_METHOD used to getOfflineDeviceUniqueID (live)
enum RETRIEVAL_METHOD {
    ODUID_DEFAULT = 0
    ODUID_TPM_EK
    ODUID_UEFI_VARIABLE_TPM
    ODUID_UEFI_VARIABLE_RANDOMSEED
    ODUID_UEFI_DEV_LOCK_UNLOCK
    ODUID_XBOX_CONSOLE_ID
    ODUID_REGISTRY_ENTRY
}

# Import function GetOfflineDeviceUniqueID (ODUID)
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ClipcWrapper {
    [DllImport("clipc.dll")]
    public static extern int GetOfflineDeviceUniqueID(uint cbSalt, byte[] pbSalt, out uint oMethod, ref uint pcbSystemId, byte[] rgbSystemId, uint unk1, uint unk2);
}
"@

function ConvertTo-HexString {
    param(
        [byte[]]$ByteArray
    )

    if (-not $ByteArray) { return "" } # nul array 

    $hexString = ""
    foreach ($byte in $ByteArray) {
        $hexString += $byte.ToString("x2")
    }
    return $hexString
}
# function to get ODUID
function Get-OfflineDeviceUniqueID {
    param(
        [string]$Salt
    )

    $rm = [RETRIEVAL_METHOD]::ODUID_DEFAULT
    $cbSalt = 0
    $pbSalt = [byte[]]::new(0)

    if ($Salt) {
        if ($Salt.StartsWith("0x") -and ($Salt.Length % 2 -eq 0)) {
            $pbSalt = [byte[]]::new(($Salt.Length - 2) / 2)
            for ($i = 2; $i -lt $Salt.Length; $i += 2) {
                $pbSalt[($i / 2) - 1] = [Convert]::ToByte($Salt.Substring($i, 2), 16)
            }
        } else {
            $pbSalt = [System.Text.Encoding]::ASCII.GetBytes($Salt)
        }
        $cbSalt = [System.UInt32]$pbSalt.Length
    }

    $cbSystemId = [System.UInt32]32
    $rgbSystemId = [byte[]]::new(32)

    $res = [ClipcWrapper]::GetOfflineDeviceUniqueID($cbSalt, $pbSalt, ([ref]$rm), ([ref]$cbSystemId), $rgbSystemId, 0, 0) 

    if ($res -lt 0) {
        throw [System.ComponentModel.Win32Exception]::new($res)
    }

    Write-Verbose "Got device-unique ID"
    #Write-Verbose "ID: $($rgbSystemId[2] -join '')" 
    return @{Method = $rm; ID = $rgbSystemId}
}
# OFFLINEDEVICEUNIQUEID Stuff
$result = Get-OfflineDeviceUniqueID -Salt "0x6300760031006700310067007600"
$mtd = [RETRIEVAL_METHOD]$result.Method
"ODUID Extraction Method:$mtd"| Out-File -FilePath "$targetOutput\$metaDataFileName" -Append
Write-Host "Method: $($mtd)"
#Write-Verbose "ID: $($result.ID -join '')"
$WhatsAppAppUID = $result.ID #ConvertTo-HexString($result.ID)
$hexaWhatsAppAppUID = ConvertTo-HexString $WhatsAppAppUID 
"ODUID:$hexaWhatsAppAppUID"| Out-File -FilePath "$targetOutput\$metaDataFileName" 
# WhatsApp.DLL Passphrase (in WhatsApp.dll)
Set-Variable -Name "whatsappDll_passphrase" -Value "5303b14c0984e9b13fe75770cd25aaf7" -Option Constant

Add-Type -AssemblyName System.Security

#Load BoucyCastle for cryptography operations
$bouncecastleDllPath = "$PSScriptRoot\BouncyCastle.Cryptography.dll"
Add-Type -Path $bouncecastleDllPath
# VErify if did DLL loaded successfuly 
if ([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.FullName -like "*BouncyCastle*" }) {
    Write-Verbose "BouncyCastle assembly present."
} else {
    Write-Verbose "Erro: BouncyCastle assembly not loaded."
}

function Read-Bytes {
    param (
        [string]$filePath,
        [int]$offset,
        [int]$length
    )
    
    $fileStream = [System.IO.File]::OpenRead($filePath)
    $fileStream.Seek($offset, [System.IO.SeekOrigin]::Begin) | Out-Null
    $buffer = New-Object byte[] $length
    $fileStream.Read($buffer, 0, $length) | Out-Null
    $fileStream.Close()
    return $buffer
}

function Convert-HexStringToByteArray {
    param (
        [string]$hexString
    )

    # Remove any spaces or dashes from the hex string
    $hexString = $hexString -replace '[-\s]', ''

    # Ensure the hex string length is even
    if ($hexString.Length % 2 -ne 0) {
        throw "The hex string must have an even length."
    }

    # Convert the hex string to a byte array
    $byteArray = @()
    for ($i = 0; $i -lt $hexString.Length; $i += 2) {
        $byteValue = [Convert]::ToByte($hexString.Substring($i, 2), 16)
        $byteArray += $byteValue
    }

    return ,$byteArray
}
function Convert-HexStringToByteArray {
    param (
        [string]$HexString
    )

    # Remove any non-hexadecimal characters (if necessary)
    $HexString = $HexString -replace '[^0-9A-Fa-f]', ''

    # Split the string into pairs of hexadecimal digits
    $byteArray = @()
    for ($i = 0; $i -lt $HexString.Length; $i += 2) {
        $byte = $HexString.Substring($i, 2)
        $byteArray += [Convert]::ToByte($byte, 16)
    }

    return $byteArray
}



# Função para desembrulhar a chave AES usando Bouncy Castle
function Unwrap-AesKeyBC {
    param(
        [Parameter(Mandatory = $true)]
        [System.Byte[]]$wrappedKey,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Byte[]]$kek
    )

    try {
        # Import necessary namespaces 
        $null = [System.Reflection.Assembly]::LoadWithPartialName("BouncyCastle.Crypto") 
        $null = [System.Reflection.Assembly]::LoadWithPartialName("BouncyCastle.Security") 
        # Create the cipher 
        $cipher = [Org.BouncyCastle.Crypto.Engines.AesWrapEngine]::new() 
        $cipher.Init($false, [Org.BouncyCastle.Crypto.Parameters.KeyParameter]::new($kek)) 
        # Unwrap the key 
        $unwrappedKey = $cipher.Unwrap($wrappedKey, 0, $wrappedKey.Length)

        return $unwrappedKey
    }
    catch {
        Write-Error "Error unwrapping key (Bouncy Castle): $($_.Exception.Message)"
        Write-Error $_.Exception | Format-List * # Mostra detalhes da exceção
        return $null
    }
}

function nsDecrypt{
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Byte[]]$dpapi_blob,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Byte[]]$wrapped_key,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Byte[]]$nonce,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Byte[]]$cipher_text,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Byte[]]$gcmTag,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Byte[]]$passphrase,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [boolean]$hasPadding
    )
	# Decrypt blob DPAPI with Windows API 
	$kek = [System.Security.Cryptography.ProtectedData]::Unprotect($dpapi_blob, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    Write-Verbose "kek: $( [BitConverter]::ToString($kek).Replace('-', '') )"
    
    # Decript wrappedKey
	# Unwrap AES key using AesKeyUnwrap
    $gcm_key = Unwrap-AesKeyBC -WrappedKey $wrapped_key -KEK $kek

    $gcm_key_hex = $( [BitConverter]::ToString($gcm_key).Replace('-', '') )
	Write-Verbose "gcm_key: $gcm_key_hex"
	# Algorithm definition - AES256GCM 
    # Create the cipher 
    $cipher = [Org.BouncyCastle.Crypto.Engines.AesEngine]::new() 
    $gcmBlockCipher = [Org.BouncyCastle.Crypto.Modes.GcmBlockCipher]::new($cipher) 
    $parameters = [Org.BouncyCastle.Crypto.Parameters.AeadParameters]::new([Org.BouncyCastle.Crypto.Parameters.KeyParameter]::new($gcm_key), 128, $nonce) 
    $cipher_text_tagged = $cipher_text + $gcmTag
    # Initialize the cipher for decryption 
    $null = $gcmBlockCipher.Init($false, $parameters) 
    # Decrypt the bytes 
    $second_cipher_text = [byte[]]::new($gcmBlockCipher.GetOutputSize($cipher_text_tagged.Length)) 
    $len = $gcmBlockCipher.ProcessBytes($cipher_text_tagged, 0, $cipher_text_tagged.Length, $second_cipher_text, 0) 
    $null = $gcmBlockCipher.DoFinal($second_cipher_text, $len)

    Write-Verbose "Decrypted-BC nsCipherText(padded): $( [BitConverter]::ToString($second_cipher_text).Replace('-', '') )"
       
    $iterations = 10000
    
    # Generate encryption key (encKey) throught PBKDF2
    $digest= [Org.BouncyCastle.Crypto.Digests.Sha256Digest]::new()
    $generator = [Org.BouncyCastle.Crypto.Generators.Pkcs5S2ParametersGenerator]::new($digest) 
    $generator.Init($passphrase, $WhatsAppAppUID, $iterations) 
    $keyParameter = $generator.GenerateDerivedMacParameters(256) 
    $encKey = $keyParameter.GetKey()
    Write-Verbose "EncryptionKey-BC (encKey): $( [BitConverter]::ToString($encKey).Replace('-', '') )"
    
    $generator.Init($encKey, $WhatsAppAppUID, $iterations) 
    $keyParameter = $generator.GenerateDerivedMacParameters(128) 
    $IV = $keyParameter.GetKey()
	Write-Verbose "(IV-BC): $( [BitConverter]::ToString($IV).Replace('-', '') )"
    

    # Create the AES object (.NET implementation is simpler to use than bouncycastle`s one)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $encKey
    $aes.IV = $IV
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    if ($hasPadding){
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    } else {
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
        
    }
    # Create a decryptor
    $decryptor = $aes.CreateDecryptor($aes.Key, $aes.IV)

    # Decrypt the data
    $decryptedBytes = $decryptor.TransformFinalBlock($second_cipher_text, 0, $second_cipher_text.Length) 
    $aes.Dispose()
    return [byte[]]$decryptedBytes
    
}

function ns16 {
    
    $ns16_filePath = "$zapLocalStatePath\nondb_settings16.dat"
    Write-Verbose "##################### NS16 #####################"

    # Read dpapiBlob
	$byteArray = [byte[]](Read-Bytes -filePath $ns16_filePath -offset 0x33 -length 2)
	[Array]::Reverse($byteArray)
    $dpapi_blob_size = [BitConverter]::ToInt16( $byteArray, 0)
    Write-Verbose "dpapi_blob_size: $dpapi_blob_size"
    
    $dpapi_blob = Read-Bytes -filePath $ns16_filePath -offset 0x35 -length $dpapi_blob_size
    Write-Verbose "dpapi_blob: $( [BitConverter]::ToString($dpapi_blob).Replace('-', '') )"

    # Read wrappedKey
    $wrapped_key_size = (Read-Bytes -filePath $ns16_filePath -offset 0x177 -length 1)[0]
    Write-Verbose "wrapped_key_size: $wrapped_key_size"
    
    $wrapped_key = Read-Bytes -filePath $ns16_filePath -offset 0x178 -length $wrapped_key_size
    Write-Verbose "wrapped_key: $( [BitConverter]::ToString($wrapped_key).Replace('-', '') )"

    # Read nonce
    $nonce_size = (Read-Bytes -filePath $ns16_filePath -offset 0x1bd -length 1)[0]
    Write-Verbose "nonce_size: $nonce_size"
    
    $nonce = Read-Bytes -filePath $ns16_filePath -offset 0x1be -length $nonce_size
    Write-Verbose "nonce: $( [BitConverter]::ToString($nonce).Replace('-', '') )"
    
    # Read cipherText
    $cipher_text_size = (Read-Bytes -filePath $ns16_filePath -offset 0x1ce -length 1)[0] - 16
    Write-Verbose "cipher_text_size: $cipher_text_size"
    
    $cipher_text = Read-Bytes -filePath $ns16_filePath -offset 0x1cf -length $cipher_text_size
    Write-Verbose "cipher_text: $( [BitConverter]::ToString($cipher_text).Replace('-', '') )"
    
    # Read gcmTag
    $gcmTag = Read-Bytes -filePath $ns16_filePath -offset (0x1cf + $cipher_text_size) -length 16
    Write-Verbose "gcmTag: $( [BitConverter]::ToString($gcmTag).Replace('-', '') )"
	
    $whatsappDll_passphrase_bc = Convert-HexStringToByteArray $whatsappDll_passphrase

    return nsDecrypt $dpapi_blob $wrapped_key $nonce $cipher_text $gcmTag $whatsappDll_passphrase_bc $true

}

function ns18 {
    Write-Verbose "##################### NS18 #####################"
    $n18_filePath = "$zapLocalStatePath\nondb_settings18.dat"
    
    # Read dpapiBlob
	
	$byteArray = [byte[]](Read-Bytes -filePath $n18_filePath -offset 0x33 -length 2)
	[Array]::Reverse($byteArray)
    $dpapi_blob_size = [BitConverter]::ToInt16( $byteArray, 0)
    Write-Verbose "dpapi_blob_size: $dpapi_blob_size"
    
    $dpapi_blob = Read-Bytes -filePath $n18_filePath -offset 0x35 -length $dpapi_blob_size
    Write-Verbose "dpapi_blob: $( [BitConverter]::ToString($dpapi_blob).Replace('-', '') )"

    # Read wrappedKey
    $wrapped_key_size = (Read-Bytes -filePath $n18_filePath -offset 0x177 -length 1)[0]
    Write-Verbose "wrapped_key_size: $wrapped_key_size"
    
    $wrapped_key = Read-Bytes -filePath $n18_filePath -offset 0x178 -length $wrapped_key_size
    Write-Verbose "wrapped_key: $( [BitConverter]::ToString($wrapped_key).Replace('-', '') )"

    # Read nonce
    $nonce_size = (Read-Bytes -filePath $n18_filePath -offset 0x1bf -length 1)[0]
    Write-Verbose "nonce_size: $nonce_size"
    
    $nonce = Read-Bytes -filePath $n18_filePath -offset 0x1c0 -length $nonce_size
    Write-Verbose "nonce: $( [BitConverter]::ToString($nonce).Replace('-', '') )"
    
    # Read cipherText
	$byteArray = [byte[]](Read-Bytes -filePath $n18_filePath -offset 0x1d1 -length 2)
	[Array]::Reverse($byteArray)
    $cipher_text_size =  [BitConverter]::ToInt16( $byteArray, 0) - 16
    Write-Verbose "cipher_text_size: $cipher_text_size"
    
    $cipher_text = Read-Bytes -filePath $n18_filePath -offset 0x1d3 -length $cipher_text_size
    Write-Verbose "cipher_text: $( [BitConverter]::ToString($cipher_text).Replace('-', '') )"
    
    # Read gcmTag
    $gcmTag = Read-Bytes -filePath $n18_filePath -offset (0x1d3 + $cipher_text_size) -length 16
    Write-Verbose "gcmTag: $( [BitConverter]::ToString($gcmTag).Replace('-', '') )"

    $whatsappDll_passphrase_bc = Convert-HexStringToByteArray $whatsappDll_passphrase
    return nsDecrypt $dpapi_blob $wrapped_key $nonce $cipher_text $gcmTag $whatsappDll_passphrase_bc $true
}

function decNS18 {
	param ([byte[]]$userKey, [string]$n18_filePath)
    Write-Verbose "##################### DECNS18 #####################"
    
    # Read dpapiBlob
	$byteArray = [byte[]](Read-Bytes -filePath $n18_filePath -offset 0x2B -length 2)
	[Array]::Reverse($byteArray)
    $dpapi_blob_size = [BitConverter]::ToInt16( $byteArray, 0)
    Write-Verbose "dpapi_blob_size: $dpapi_blob_size"
    
    $dpapi_blob = (Read-Bytes -filePath $n18_filePath -offset 0x2D -length $dpapi_blob_size)
    Write-Verbose "dpapi_blob: $( [BitConverter]::ToString($dpapi_blob).Replace('-', '') )"

    # Read wrappedKey
    $wrapped_key_size = (Read-Bytes -filePath $n18_filePath -offset 0x16f -length 1)[0]
    Write-Verbose "wrapped_key_size: $wrapped_key_size"
    
    $wrapped_key = Read-Bytes -filePath $n18_filePath -offset 0x170 -length $wrapped_key_size
    Write-Verbose "wrapped_key: $( [BitConverter]::ToString($wrapped_key).Replace('-', '') )"

    # Read nonce
    $nonce_size = (Read-Bytes -filePath $n18_filePath -offset 0x1b5 -length 1)[0]
    Write-Verbose "nonce_size: $nonce_size"
    
    $nonce = Read-Bytes -filePath $n18_filePath -offset 0x1b6 -length $nonce_size
    Write-Verbose "nonce: $( [BitConverter]::ToString($nonce).Replace('-', '') )"
    
    # Read cipherText
    $cipher_text_size =  (Read-Bytes -filePath $n18_filePath -offset 0x1c6 -length $dpapi_blob_size)[0] -16
    Write-Verbose "cipher_text_size: $cipher_text_size"
    
    $cipher_text = Read-Bytes -filePath $n18_filePath -offset 0x1c7 -length $cipher_text_size 
    Write-Verbose "cipher_text: $( [BitConverter]::ToString($cipher_text).Replace('-', '') )"
    
    # Read gcmTag
    $gcmTag = Read-Bytes -filePath $n18_filePath -offset (0x1c7 + $cipher_text_size) -length 16
    Write-Verbose "gcmTag: $( [BitConverter]::ToString($gcmTag).Replace('-', '') )"

    return nsDecrypt $dpapi_blob $wrapped_key $nonce $cipher_text $gcmTag $userKey $false
}

# Decrypt database page
function Decrypt-Page ($blockCipher, $keyParameter, $pageNumber, $pageData) {
    $IV = [byte[]]::new(16)
    $null = [BitConverter]::GetBytes([int]$pageNumber).CopyTo($IV, 0)
    $pageData[-12..-1].CopyTo($IV, 4)
    
    $cipherParameters = [Org.BouncyCastle.Crypto.Parameters.ParametersWithIV]::new($keyParameter, $IV)

    $null = $blockCipher.Init($true, $cipherParameters) 
    # UJsing BufferedBlockCipher to be able to call ProcessBytes
    $bufferedCipher = [Org.BouncyCastle.Crypto.BufferedBlockCipher]::new($blockCipher)
    # Create buffer
    $decryptedBytes = [byte[]]::new($pageData.Length)
    # DEcrypt block bytes
    $null = $bufferedCipher.ProcessBytes($pageData, 0, $pageData.Length, $decryptedBytes, 0)
    $null = $bufferedCipher.DoFinal($decryptedBytes, $bufferedCipher.GetUpdateOutputSize($pageData.Length))
    return $decryptedBytes
}

# DEcrypt DB file
function Decrypt-DBFile ($dbKey, $inputFile, $outputFile) {
    #$key = HexStringToByteArray $keyHex
    $cipher = [Org.BouncyCastle.Crypto.Engines.AesEngine]::new() 
    $blockCipher = [Org.BouncyCastle.Crypto.Modes.OfbBlockCipher]::new($cipher, 128) 
    $keyParameter = [Org.BouncyCastle.Crypto.Parameters.KeyParameter]::new($dbKey)
    
  
    $pageSize = 4096
    $inputBytes = [System.IO.File]::ReadAllBytes($inputFile)
    
    # Create a file stream to write the output bytes
    $fileStream = [System.IO.File]::OpenWrite($outputFile)
    
    # Copy bytes from 0x10 to 0x17 (from target file)
    $copiedBytes = $inputBytes[0x10..0x17]
    
    for ($i = 0; $i -lt $inputBytes.Length; $i += $pageSize) {
        $pageData = $inputBytes[$i..($i + $pageSize - 1)]
        $decryptedPage = Decrypt-Page $blockCipher $keyParameter ($i / $pageSize + 1) $pageData
        $null = $fileStream.Write($decryptedPage, 0, $decryptedPage.Length)
    }
    
    # Swap bytes from 0x10 to 0x17 in decrypted file by bytes copied from target file
    $null = $fileStream.Seek(0x10, [System.IO.SeekOrigin]::Begin)
    $null = $fileStream.Write($copiedBytes, 0, $copiedBytes.Length)
    
    # Close the file stream
    $null = $fileStream.Close()
    
    # Delete the input file
    Remove-Item $inputFile
    
    Write-Verbose "DB file successfully decrypted and input file deleted: $outputFile"
}

function Decrypt-DBWALFile ($dbKey, $inputFile, $outputFile) {
    #$key = HexStringToByteArray $keyHex
    $cipher = [Org.BouncyCastle.Crypto.Engines.AesEngine]::new() 
    $blockCipher = [Org.BouncyCastle.Crypto.Modes.OfbBlockCipher]::new($cipher, 128) 
    $keyParameter = [Org.BouncyCastle.Crypto.Parameters.KeyParameter]::new($dbKey)
    $pageSize = 4096
    $headerSize = 32
    $pageHeaderSize = 24
    $inputBytes = [System.IO.File]::ReadAllBytes($inputFile)
    
    $fileHeader = [byte[]]::new($headerSize)
    [Array]::Copy($inputBytes,0,$fileHeader,0,$headerSize)
    
    # Create a file stream to write the output bytes
    $fileStream = [System.IO.File]::OpenWrite($outputFile)
    
    # Write the file header to the output file
    $fileStream.Write($fileHeader, 0, $fileHeader.Length)
    
    for ($i = $headerSize; $i -lt $inputBytes.Length; $i += $pageSize+$pageHeaderSize) {
        $pageHeaderData = $inputBytes[$i..($i + $pageHeaderSize - 1)]
        $pageData = $inputBytes[($i+$pageHeaderSize)..($i + $pageHeaderSize+ $pageSize - 1)]
        $pageIndex = [byte[]]::new(4)
        [Array]::Copy($pageHeaderData,0,$pageIndex,0,4)
        [Array]::Reverse($pageIndex)
        $pageIndex = [System.BitConverter]::ToInt32($pageIndex, 0)
        #Write-Output "pageIndex: $pageIndex"
        
        $IV = [byte[]]::new(16)
        [BitConverter]::GetBytes([int]$pageIndex).CopyTo($IV, 0)
        $pageData[-12..-1].CopyTo($IV, 4)
        $ivHex = [BitConverter]::ToString($IV).Replace("-", "")
        #Write-Output "IV: $ivHex"
        
        $decryptedPage = Decrypt-Page $blockCipher $keyParameter $pageIndex $pageData
        $fileStream.Write($pageHeaderData, 0, $pageHeaderData.Length)
        $fileStream.Write($decryptedPage, 0, $decryptedPage.Length)
    }
    
    # Close the file stream
    $fileStream.Close()
    
    # Delete the input file
    Remove-Item $inputFile
    
    Write-Verbose "DBWAL file successfully decrypted and input file deleted: $outputFile"
}

# Decrypt all files in current directory 
function Decrypt-AllFiles ($dbKey, $targetDirectory) { 
    #delete previous decriptions
    Get-ChildItem -Filter "*.dec.*" -Force | Remove-Item -Force
    $dbFiles = Get-ChildItem -Path $targetDirectory -Filter *.db 
    $walFiles = Get-ChildItem -Path $targetDirectory -Filter *.db-wal 
    $files = @() #empty array
    if ($dbFiles) { $files += $dbFiles } 
    if ($walFiles) {$files += $walFiles} 
    foreach ($file in $files) { 
        if ($file.Extension -eq ".db" -or $file.Extension -eq ".db-wal") { 
            $outputFile = [System.IO.Path]::ChangeExtension($file.FullName, ".dec" + $file.Extension) 
            if (-not (Test-Path $outputFile)) { 
                try{
                    if ($file.Extension -eq ".db") {
                        Write-Output "Decrypting DB: $file"
                        Decrypt-DBFile $dbKey $file.FullName $outputFile
                    } else {
                            if ($file.Extension -eq ".db-wal") {
                                Write-Output "Decrypting DB-WAL: $file"
                                Decrypt-DBWALFile $dbKey $file.FullName $outputFile
                            }
                    }
                } catch{
                    Write-Output "Error decrypting $file."
                }
            } 
        } 
    } 
}
# Function to compress the content of a directory to a zip file and delete the source directory.
function Compress-Directory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [string]$DestinationZipFile
    )

    try {
        # Check if the source directory exists
        if (!(Test-Path -Path $Source -PathType Container)) {
            throw "Source directory '$Source' not found."
        }

        # Remove the destination zip file if it already exists
        if (Test-Path -Path $DestinationZipFile) {
            Remove-Item -Path $DestinationZipFile -Force -ErrorAction SilentlyContinue
        }

        # Get the content of the source directory
        $sourceContent = Get-ChildItem -Path $Source

        # Compress the content of the directory
        Compress-Archive -Path $sourceContent.FullName -DestinationPath $DestinationZipFile -Force

        # Delete the source directory
        Remove-Item -Path $Source -Force -Recurse -ErrorAction SilentlyContinue

        Write-Verbose "Content of directory '$Source' compressed to '$DestinationZipFile' and deleted successfully."

    } catch {
        Write-Error "Error during compression operation: $($_.Exception.Message)"
    }
}

# Function to generate a SHA512 checksum of a file, save it to a text file, and copy it to the clipboard.
function Generate-SHA512Checksum {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    try {
        # Check if the file exists
        if (!(Test-Path -Path $FilePath -PathType Leaf)) {
            throw "File '$FilePath' not found."
        }

        # Calculate the SHA512 hash
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA512

        # Create the output file path. Replace ".zip" with ".sha512.txt" only if it ends with ".zip".
        # If the file doesn't end with ".zip", simply append ".sha512.txt".
        if ($FilePath -like "*.zip") {
            $outputFilePath = $FilePath -replace "\.zip$", ".sha512.txt"
        } else {
            $outputFilePath = $FilePath + ".sha512.txt"
        }

        # Write the hash to the output file using UTF8 encoding
        $hash.Hash | Out-File -FilePath $outputFilePath -Encoding UTF8

        # Copy the hash to the clipboard
        Set-Clipboard -Value $hash.Hash

        Write-Verbose "SHA512 checksum for '$FilePath' written to '$outputFilePath' and copied to clipboard."
        return $outputFilePath # Return the checksum file path
    }
    catch {
        Write-Error "Error generating SHA512 checksum for '$FilePath': $($_.Exception.Message)"
        return $null # Return $null in case of error
    }
}


#########################################################################################################
# Main 
$userKey = ns16
$hexaUserKey = ConvertTo-HexString $userKey 
Write-Host "UserKey: $hexaUserKey"

$ns18Output = ns18 
$tmp_dec_nondb_settings18 = Join-Path -Path $currentDirectory -ChildPath 'dec_nondb_settings18.dat'
[System.IO.File]::WriteAllBytes($tmp_dec_nondb_settings18, $ns18Output)
Write-Verbose "Ns18:$ns18Output"

$dbKey = decNS18 -userKey $userKey $tmp_dec_nondb_settings18
#Write-Output "DBKey: $dbKey"
Write-Host "DBKey calculated."
$hexaDBKey = ConvertTo-HexString $dbKey 
Write-Output "DBKey: $hexaDBKey"
"DBKEY:$hexaDBKey"| Out-File -FilePath "$targetOutput\$metaDataFileName" -Append
Remove-Item $tmp_dec_nondb_settings18

# Decript all-files
Write-Output "Decripting databases..."
Decrypt-AllFiles $dbKey $targetOutput

# Compresses a directory to a zip file and deletes the source
$zipTarget="$currentDirectory\ZAPiXDESK_$reverseDate.zip"
Compress-Directory -Source $targetOutput -DestinationZipFile $zipTarget
Write-Output "Compressed file (ZIP) generated: $zipTarget"
# Generate integrity HASH
$checksumFileZip = Generate-SHA512Checksum -FilePath $zipTarget
if ($checksumFileZip) {
    Write-Verbose "Checksum file (ZIP): $checksumFileZip"
}
Write-Output "HASH (SHA512): $checksumFileZip (hash also copied to clipboard)"
