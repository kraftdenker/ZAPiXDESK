param (
    [Parameter(Mandatory = $false)]
    [string]$WhatsAppPath,
    [Parameter(Mandatory = $false)]
    [switch]$Offline,
    [Parameter(Mandatory = $false)]
    [string]$ID,
    [Parameter(Mandatory = $false)]
    [switch]$GetID,
    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

# Windows WhatsApp Desktop
# Version: 2.1
# Revised Date: 20/01/26
# Revised by: Alberto Magno (kraftdenker)


# Copyright: 2026 Alberto Magno <alberto.magno@gmail.com> 
# URL: https://github.com/kraftdenker/ZAPiXDESK

# Description: A script that extracts DBKey and decrypt all SQLite3 database files (including db and write-ahead-logfiles ). At final a ZIP file containing all WhatsAppDesk localstate decripted.

# First technique based on reverse-engineering-fu (yes! you do not need to use SQLite3 SEE to decrypt) and infos contained in following paper:
# Giyoon Kim, Uk Hur, Soojin Kang, Jongsung Kim,Analyzing the Web and UWP versions of WhatsApp for digital forensics,
# Forensic Science International: Digital Investigation,Volume 52,2025,301861,ISSN 2666-2817,
# https://doi.org/10.1016/j.fsidi.2024.301861.
# (https://www.sciencedirect.com/science/article/pii/S2666281724001884)



# Updates: 
# 20 January 2026 - Alberto Magno @kraftdenker
# After M3t4 changes in 09/12/25, it has been added new strategie to address the new WEBVIEW2 architecture using reverse-fu techniques.
# Recover of clientKey from session database to derive other database (nativeSettings) witch cares other encryptions keys to decode the 
# other databases.
# New DPAPI-NG method to protect bytes and an raw DB-WAL recovery method to get securited managed registers.
# Important key ideas:
# - Session.db and session.db-wal stores all sessions clientKeys from the current userKey
# - It creates a subdir named with sha1 from clientKey
# - Inside this subdir, it is stored nativeSettings.db with other types of keys (1 ,2 ,3 )
# - Keys type 1, used to decrypt genericStorageDB (Messages), type 2 to decrypt the other ones.

# 12 April 2025 - Corey Forman @digitalsleuth
# The following signatures were observed before each of the values during analysis of multiple
# nondb_settings dat files
# dpapi_blob signature: 02010430. If the next byte is not 81 or 82, Then skip that and 2 more bytes and read the right nibble of the 4th byte to 
# determine the number of bytes to read next for the size of the dpapi_blob.
# If it is 81 or 82, the right nibble tells you how many bytes come after it, after those it's a 0x04, then the size byte for the num of bytes in the
# dpapi_blob size. So if it's 81, then 1 byte follows (skip it), then 04 after that (skip it) then the third byte is the byte count for size.
# If it's 82, then 2 bytes follow (skip them) then 04, then the fourth byte is the byte count for size.
# Could use the 01 00 00 00 signature, however that could appear more frequently than expected.

# The byte after the dpapi_blob signature (rather, the right nibble) indicates how many bytes are in the size of the entire block from 0x04 until
# the entry: 0x30 0B 06 09 60 86 48 01 65 03 04 01 2D 04
# For now, I'm just using the last 4 bytes for the wrapped_key signature:
# wrapped_key signature: 04012D04
# The next byte is typically 28 (40)

# The next 30 bytes for the nondb_settings16.dat seem to be: 30 6D 06 09 2A 86 48 86 F7 0D 01 07 01 30 1E 06 09 60 86 48 01 65 03 04 01 2E 30 11 04 0C
# And for the nondb_settings18.dat the next 32 seem to be:   30 82 01 EF 06 09 2A 86 48 86 F7 0D 01 07 01 30 1E 06 09 60 86 48 01 65 03 04 01 2E 30 11 04 0C
# The 0C is the size for the nonce, but since both values have 2E 30 11 04 before the size, I'm using that as the signature.
# nonce signature: 2E301104

# Immediately after the nonce should be 02 01 10 80. If the following byte is 81 or 82, we read the right
# nibble to determine how many bytes following this next byte to read for the size.
# Otherwise, the next byte is the size of the cipher_text AND the gcm
# This seems to go all the way to the end of the file, with the exception of the last 5 bytes.
# cipher_text: 02011080
# gcm is last 16 bytes of cipher_text
# The last 5 bytes of each file are different for each file, except that the last byte is always 01.

$global:metaDataFileName = "ZAPiXDESK.mtd.txt"
$global:whatsappDll_passphrase = "5303b14c0984e9b13fe75770cd25aaf7"
$global:ZDVersion = "2.1.0"
$global:webview2_staticBytes = "23a7f19c11e5bd784235c96f85d24913"
$global:getOUID_salt = "0x6300760031006700310067007600"
$global:pbkdf_iterations = 10000

function Convert-HexStringToByteArray {
    param (
        [string]$hexString
    )

    # Remove espaços extras no início e fim
    $hexString = $hexString.Trim()

    # Remove qualquer caractere que não seja válido em hexadecimal (0-9, A-F, a-f)
    $hexString = $hexString -replace '[^0-9A-Fa-f]', ''

    # Verifica se o comprimento é par
    if ($hexString.Length % 2 -ne 0) {
        throw "The hex string must have an even length. Actual length: $($hexString.Length)"
    }

    # Converte a string em array de bytes
    $byteArray = @()
    for ($i = 0; $i -lt $hexString.Length; $i += 2) {
        $byteValue = [Convert]::ToByte($hexString.Substring($i, 2), 16)
        $byteArray += $byteValue
    }

    return ,$byteArray
}

$global:whatsappDll_passphrase_bc = (Convert-HexStringToByteArray $whatsappDll_passphrase)

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
            $targetPath = Join-Path -Path $Destination -ChildPath ($_.FullName.Substring($Source.Length))
            if ($_.PSIsContainer) {
                Write-Verbose "Creating directory: $targetPath"
                New-Item -ItemType Directory -Path $targetPath -Force | Out-Null
            } else {
                try {
                    Write-Verbose "Copying file: $($_.FullName) to $targetPath"
                    Copy-Item -Path $_.FullName -Destination $targetPath -Force -ErrorAction Stop # Stop on error for each file
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

    Write-Verbose "Got Offline Device Unique ID"
    $devID = ConvertTo-HexString $rgbSystemId
    Write-Verbose "ID: $devID"
    return @{Method = [RETRIEVAL_METHOD]$rm; ID = $rgbSystemId}
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

# Function to unwrap AES key using Bouncy Castle
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
        Write-Error $_.Exception | Format-List *
        [Windows.Forms.MessageBox]::Show("Error unwrapping key (Bouncy Castle): $($_.Exception.Message)", "Acquisition Failed","Ok","Error") | Out-Null
        exit
    }
}

function Decrypt-NS{
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
	try {
	$kek = [System.Security.Cryptography.ProtectedData]::Unprotect($dpapi_blob, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
	} catch {
	    Write-Output "Generation of KEK failed - this may occur if the ODUID provided is incorrect"
        [Windows.Forms.MessageBox]::Show("Generation of KEK failed - this may occur if the ODUID provided is incorrect", "Acquisition Failed","Ok","Error") | Out-Null
		exit
	}
    Write-Verbose "kek: $( [BitConverter]::ToString($kek).Replace('-', '') )"
    
    # Decrypt wrappedKey
	# Unwrap AES key using AesKeyUnwrap
    $gcm_key = Unwrap-AesKeyBC -WrappedKey $wrapped_key -KEK $kek

    $gcm_key_hex = $( [BitConverter]::ToString($gcm_key).Replace('-', '') )
	Write-Verbose "gcm_key: $gcm_key_hex"
	# Algorithm definition - AES256GCM 
    # Create the cipher 
    try {
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
       
        # Generate encryption key (encKey) throught PBKDF2
        $digest= [Org.BouncyCastle.Crypto.Digests.Sha256Digest]::new()
        $generator = [Org.BouncyCastle.Crypto.Generators.Pkcs5S2ParametersGenerator]::new($digest) 
        $generator.Init($passphrase, $WhatsAppAppUID, $global:pbkdf_iterations) 
        $keyParameter = $generator.GenerateDerivedMacParameters(256) 
        $encKey = $keyParameter.GetKey()
        Write-Verbose "EncryptionKey-BC (encKey): $( [BitConverter]::ToString($encKey).Replace('-', '') )"
    
        $generator.Init($encKey, $WhatsAppAppUID, $global:pbkdf_iterations) 
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
    } catch {
        Write-Output "Unable to decrypt the data - $($_.Exception.Message)"
        [Windows.Forms.MessageBox]::Show("Unable to decrypt the data: $($_.Exception.Message)", "Acquisition Failed","Ok","Error") | Out-Null
        exit
    }
}

function Get-Key {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [byte[]]$UserKey,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [boolean]$HasPadding
    )
   
    Write-Verbose "--- Extracting key from $FilePath ---"
    $byteArray = [System.IO.File]::ReadAllBytes($FilePath)
    $dpapi_blob_size, $dpapi_blob, $dpapi_hex = Find-Signature $byteArray ([byte[]](0x02,0x01,0x04,0x30)) 0 $false
    Write-Verbose "dpapi_blob_size: $dpapi_blob_size"
    Write-Verbose "dpapi_blob: $dpapi_hex"
    "--- $FilePath ---" | Out-File -FilePath "$targetOutput\$metaDataFileName" -Append
    "dpapi_blob: $dpapi_hex" | Out-File -FilePath "$targetOutput\$metaDataFileName" -Append

    $wrapped_key_size, $wrapped_key, $wrapped_key_hex = Find-Signature $byteArray ([byte[]](0x04,0x01,0x2D,0x04)) 0 $false
    Write-Verbose "wrapped_key_size: $wrapped_key_size"
    Write-Verbose "wrapped_key: $wrapped_key_hex"
    "wrapped_key: $wrapped_key_hex" | Out-File -FilePath "$targetOutput\$metaDataFileName" -Append

    $nonce_size, $nonce, $nonce_hex = Find-Signature $byteArray ([byte[]](0x2E,0x30,0x11,0x04)) 0 $false
    Write-Verbose "nonce_size: $nonce_size"
    Write-Verbose "nonce: $nonce_hex"
    "nonce: $nonce_hex" | Out-File -FilePath "$targetOutput\$metaDataFileName" -Append

    $cipher_text_and_gcm_size, $cipher_text_and_gcm, $cipher_text_and_gcm_hex = Find-Signature $byteArray ([byte[]](0x02,0x01,0x10,0x80)) 0 $false
    $cipher_text_size = $cipher_text_and_gcm_size - 16
    $cipher_text = $cipher_text_and_gcm[0..($cipher_text_size -1)]
    $cipher_text_hex = $cipher_text_and_gcm_hex.Substring(0, ($cipher_text_size * 2))
    Write-Verbose "cipher_text_size: $cipher_text_size"
    Write-Verbose "cipher_text: $cipher_text_hex"
    "cipher_text: $cipher_text_hex" | Out-File -FilePath "$targetOutput\$metaDataFileName" -Append

    $gcm_tag = $cipher_text_and_gcm[($cipher_text_and_gcm_size - 16)..$cipher_text_and_gcm_size]
    $gcm_tag_hex = [BitConverter]::ToString($gcm_tag).Replace('-', '')
    Write-Verbose "gcm_tag: $gcm_tag_hex"
    "gcm_tag: $gcm_tag_hex" | Out-File -FilePath "$targetOutput\$metaDataFileName" -Append
    Write-Verbose "--- End key extraction from $FilePath ---"
    "--- End $FilePath ---" | Out-File -FilePath "$targetOutput\$metaDataFileName" -Append
    if ($PSBoundParameters.ContainsKey('UserKey'))
    {
        return Decrypt-NS $dpapi_blob $wrapped_key $nonce $cipher_text $gcm_tag $UserKey $HasPadding
    }
    else
    {
        return Decrypt-NS $dpapi_blob $wrapped_key $nonce $cipher_text $gcm_tag $whatsappDll_passphrase_bc $HasPadding
    }
}

# Decrypt database page
function Decrypt-Page ($blockCipher, $keyParameter, $pageNumber, $pageData) {
    $IV = [byte[]]::new(16)
    $null = [BitConverter]::GetBytes([int]$pageNumber).CopyTo($IV, 0)
    $pageData[-12..-1].CopyTo($IV, 4)
    
    $cipherParameters = [Org.BouncyCastle.Crypto.Parameters.ParametersWithIV]::new($keyParameter, $IV)

    $null = $blockCipher.Init($true, $cipherParameters) 
    # Using BufferedBlockCipher to be able to call ProcessBytes
    $bufferedCipher = [Org.BouncyCastle.Crypto.BufferedBlockCipher]::new($blockCipher)
    # Create buffer
    $decryptedBytes = [byte[]]::new($pageData.Length)
    # Decrypt block bytes
    $null = $bufferedCipher.ProcessBytes($pageData, 0, $pageData.Length, $decryptedBytes, 0)
    $null = $bufferedCipher.DoFinal($decryptedBytes, $bufferedCipher.GetUpdateOutputSize($pageData.Length))
    return $decryptedBytes
}

# Decrypt DB file
function Decrypt-DBFile ($dbKey, $inputFile, $outputFile) {
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
        Write-Verbose "pageIndex: $pageIndex"
        
        $IV = [byte[]]::new(16)
        [BitConverter]::GetBytes([int]$pageIndex).CopyTo($IV, 0)
        $pageData[-12..-1].CopyTo($IV, 4)
        $ivHex = [BitConverter]::ToString($IV).Replace("-", "")
        Write-Verbose "IV: $ivHex"
        
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
                try {
                    if ($file.Extension -eq ".db") {
                        Write-Output "Decrypting DB: $file"
                        Decrypt-DBFile $dbKey $file.FullName $outputFile
                    } else {
                            if ($file.Extension -eq ".db-wal") {
                                Write-Output "Decrypting DB-WAL: $file"
                                Decrypt-DBWALFile $dbKey $file.FullName $outputFile
                            }
                    }
                } catch {
                    if ($_.Exception.Message -like "*Source array was not long enough*"){
                        Write-Output "Error decrypting $file - File is $($file.Length) bytes."
                    }
                    else {
                        Write-Output "Error decrypting $file - $($_.Exception.Message)"
                    }
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
function Get-SHA512Checksum {
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
        "$($hash.Hash) - $FilePath" | Out-File -FilePath $outputFilePath -Encoding UTF8

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

function Get-MD5Checksum {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    try {
        # Check if the file exists
        if (!(Test-Path -Path $FilePath -PathType Leaf)) {
            throw "File '$FilePath' not found."
        }

        # Calculate the MD5
        $hash = Get-FileHash -Path $FilePath -Algorithm MD5
        # Create the output file path. Replace ".zip" with ".md5.txt" only if it ends with ".zip".
        # If the file doesn't end with ".zip", simply append ".md5.txt".
        if ($FilePath -like "*.zip") {
            $outputFilePath = $FilePath -replace "\.zip$", ".md5.txt"
        } else {
            $outputFilePath = $FilePath + ".md5.txt"
        }
        # Write the hash to the output file using UTF8 encoding
        "$($hash.Hash) - $FilePath" | Out-File -FilePath $outputFilePath -Encoding UTF8

        # Copy the hash to the clipboard
        Set-Clipboard -Value $hash.Hash
        Write-Verbose "MD5 checksum for '$FilePath' written to '$outputFilePath' and copied to clipboard."
        return $outputFilePath # Return the checksum file path
    }
    catch {
        Write-Error "Error generating MD5 checksum for '$FilePath': $($_.Exception.Message)"
        return $null # Return $null in case of error
    }
}

function Find-Signature {
    param (
        [byte[]]$ByteArray,
        [byte[]]$Signature,
        [int]$BytesToSkip,
        [bool]$UseNibble = $true
    )

    $sigLength = $Signature.Length
    $index = 0
    $maxIndex = $ByteArray.Length - $sigLength

    while ($index -le $maxIndex) {
        $match = $true
        for ($i = 0; $i -lt $sigLength; $i++) {
            if ($ByteArray[$index + $i] -ne $Signature[$i]) {
                $match = $false
                break
            }
        }

        if ($match) {
            $sizeIndicatorIndex = $index + $sigLength + $BytesToSkip
            if ($sizeIndicatorIndex -ge $ByteArray.Length) {
                Write-Verbose "Not enough data to read size indicator byte."
                return
            }

            $sizeIndicatorByte = $ByteArray[$sizeIndicatorIndex]
            if ($Signature -join ',' -eq '2,1,4,48' -and $sizeIndicatorByte -in @(0x81, 0x82)) {
                $firstRightNibble = $sizeIndicatorByte -band 0x0F

                if ($firstRightNibble -eq 1) {
                    $sizeIndicatorIndex += 3 # Skips the single byte and the 0x04 after
                } elseif ($firstRightNibble -eq 2) {
                    $sizeIndicatorIndex += 4 # Skips the two bytes and the 0x04 after
                } else {
                    Write-Verbose "Unexpected nibble value after signature."
                    return
                }

                if ($sizeIndicatorIndex -ge $ByteArray.Length) {
                    Write-Verbose "Reached end of array before actual size indicator byte."
                    return
                }

                $sizeIndicatorByte = $ByteArray[$sizeIndicatorIndex]
                $UseNibble = $true
            }
            elseif (-not ($Signature -join ',' -eq '2,1,4,48') -and $sizeIndicatorByte -in @(0x81, 0x82)){
                $UseNibble = $true
            }
            if ($UseNibble) {
                # Use right nibble to get number of size bytes. This is founded in research only, experimental.
                $rightNibble = $sizeIndicatorByte -band 0x0F
                $sizeBytesStart = $sizeIndicatorIndex + 1
                $sizeBytesEnd = $sizeBytesStart + $rightNibble - 1
                if ($sizeBytesEnd -ge $ByteArray.Length) {
                    Write-Verbose "Not enough data to read size field."
                    return
                }
                $sizeBytes = $ByteArray[$sizeBytesStart..$sizeBytesEnd]
                $sizeValue = 0
                foreach ($b in $sizeBytes) {
                    $sizeValue = ($sizeValue -shl 8) -bor $b
                }

                $dataStart = $sizeBytesEnd + 1
            }
            else {
                $sizeValue = $sizeIndicatorByte
                $dataStart = $sizeIndicatorIndex + 1
                $rightNibble = $null
                $sizeBytes = @()
            }

            $dataEnd = $dataStart + $sizeValue - 1
            if ($dataEnd -ge $ByteArray.Length) {
                Write-Verbose "Not enough data to read full blob."
                return
            }

            $dataBlob = $ByteArray[$dataStart..$dataEnd]
            $dataHex = ($dataBlob | ForEach-Object { $_.ToString("X2") }) -join ''
            return $sizeValue, $dataBlob, $dataHex
        }

        $index++
    }
    Write-Verbose "Signature $Signature not found."
}

function Get-WalSettingsData {
    param (
        [string]$FilePath
    )

    if (-not (Test-Path $FilePath)) { 
        Write-Error "File not found: $FilePath"
        return $null 
    }

    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    } catch {
        Write-Error "Error reading file: $($_.Exception.Message)"
        return $null
    }

    $pageSize = [System.Net.IPAddress]::NetworkToHostOrder([BitConverter]::ToInt32($bytes, 8))
    $offset = 32
    $results = New-Object System.Collections.Generic.List[PSObject]

    while ($offset + 24 + $pageSize -le $bytes.Length) {
        $pStart = $offset + 24
        $pEnd = $pStart + $pageSize
        
        # scan byte per byte
        for ($cursor = $pStart; $cursor -lt ($pEnd - 3); $cursor++) {
            
            # Header Size 3  (Key, Value)
            if ($bytes[$cursor] -eq 0x03) {
                $kType = $bytes[$cursor+1]
                $vType = $bytes[$cursor+2]
                
                $kVal = $null
                $kLen = 0
                $dataStart = $cursor + 3

                # Identify Key
                if ($kType -eq 8) { $kVal = 0; $kLen = 0 }
                elseif ($kType -eq 9) { $kVal = 1; $kLen = 0 }
                elseif ($kType -eq 1) { 
                    $kVal = [int][sbyte]$bytes[$dataStart]
                    $kLen = 1 
                }

                # Filter keys (0 to 10)
                if ($null -ne $kVal -and ($kVal -ge 0 -and $kVal -le 10)) {
                    $blobHex = ""
                    $status = ""

                    # Case A: Value is BLOB of 32 bytes (Type 76 / 0x4C)
                    if ($vType -eq 0x4C) {
                        if (($dataStart + $kLen + 32) -le $pEnd) {
                            $blob = New-Object byte[] 32
                            [Buffer]::BlockCopy($bytes, ($dataStart + $kLen), $blob, 0, 32)
                            $blobHex = [BitConverter]::ToString($blob).Replace("-","")
                            $status = "32 bytes"
                        }
                    }
                    # Caso B: Value é NULL (Tipo 0)
                    elseif ($vType -eq 0) {
                        $blobHex = "[NULL]"
                        $status = "Null"
                    }

                    if ($status -ne "") {
                        $results.Add([PSCustomObject]@{
                            Frame    = "F" + [Math]::Floor(($offset-32)/($pageSize+24))
                            Key      = $kVal
                            Status   = $status
                            HexBlob  = $blobHex
                            DBPage   = [System.Net.IPAddress]::NetworkToHostOrder([BitConverter]::ToInt32($bytes, $offset))
                        })
                    }
                }
            }
        }
        $offset += 24 + $pageSize
    }

    return $results
}

function Protect-WebView2Secret {
    param (
        [Parameter(Mandatory=$true)]
        [string]$HexInput,
        
        [Parameter(Mandatory=$false)]
        [string]$Descriptor = "LOCAL=user"
    )

    # 1. Definir e Adicionar o tipo C# (apenas se não existir)
    if (-not ([System.Management.Automation.PSTypeName]'DpapiNgInteropV2').Type) {
        $code = @"
        using System;
        using System.Runtime.InteropServices;

        public static class DpapiNgInteropV2 {
            [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
            public static extern int NCryptCreateProtectionDescriptor(string descriptorString, uint flags, out IntPtr phDescriptor);

            [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
            public static extern int NCryptCloseProtectionDescriptor(IntPtr hDescriptor);

            [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
            public static extern int NCryptProtectSecret(IntPtr hDescriptor, uint dwFlags, byte[] pbData, int cbData, IntPtr pMemPara, IntPtr hWnd, out IntPtr ppbProtectedBlob, out int pcbProtectedBlob);

            [DllImport("kernel32.dll")]
            public static extern IntPtr LocalFree(IntPtr hMem);
        }
"@
        Add-Type -TypeDefinition $code
    }

    # 2. Convert Hex String to Byte Array
    $cleanHex = $HexInput.Trim() -replace '[^0-9A-Fa-f]', ''
    if ($cleanHex.Length % 2 -ne 0) { throw "String Hexadecimal inválida." }
    
    $inputBytes = New-Object byte[] ($cleanHex.Length / 2)
    for ($i = 0; $i -lt $cleanHex.Length; $i += 2) {
        $inputBytes[$i/2] = [Convert]::ToByte($cleanHex.Substring($i, 2), 16)
    }

    # 3. Protection DPAPI-NG
    $hDescriptor = [IntPtr]::Zero
    $res = [DpapiNgInteropV2]::NCryptCreateProtectionDescriptor($Descriptor, 0, [ref]$hDescriptor)
    
    if ($res -ne 0) {
        Write-Error "Error creating descriptor: $res"
        return $null
    }

    try {
        $ptrOut = [IntPtr]::Zero
        $sizeOut = 0
        $resProtect = [DpapiNgInteropV2]::NCryptProtectSecret($hDescriptor, 0, $inputBytes, $inputBytes.Length, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$ptrOut, [ref]$sizeOut)

        if ($resProtect -eq 0) {
            $protected = New-Object byte[] $sizeOut
            [Runtime.InteropServices.Marshal]::Copy($ptrOut, $protected, 0, $sizeOut)
            
            # Extract first 32 bytes
            $sessionDBSecret = $protected[0..31]
            
            # Return data
            return [PSCustomObject]@{
                FullBlob    = $protected
                Secret32    = $sessionDBSecret
                HexSecret32 = [BitConverter]::ToString($sessionDBSecret).Replace('-', '')
            }
        } else {
            Write-Error "Error protecting bytes: code $resProtect"
            return $null
        }
    }
    finally {
        # Memory cleaning
        if ($ptrOut -ne [IntPtr]::Zero) { [DpapiNgInteropV2]::LocalFree($ptrOut) | Out-Null }
        if ($hDescriptor -ne [IntPtr]::Zero) { [DpapiNgInteropV2]::NCryptCloseProtectionDescriptor($hDescriptor) | Out-Null }
    }
}

#########################################################################################################
# Main 

function Start-ZapixDesk {
    param(
        [Parameter(Mandatory = $false)]
        [string]$WhatsAppPath,
        [Parameter(Mandatory = $false)]
        [switch]$Offline,
        [Parameter(Mandatory = $false)]
        [string]$ID,
        [Parameter(Mandatory = $false)]
        [string]$OutputPath
    )
    Clear-Host
    Write-Output "
______  ___  ______ ___   _______ _____ _____ _   __
|___  / / _ \ | ___ (_) \ / /  _  \  ___/  ___| | / /
   / / / /_\ \| |_/ /_ \ V /| | | | |__ \ ---.| |/ /
  / /  |  _  ||  __/| |/   \| | | |  __| ---. \    \
./ /___| | | || |   | / /^\ \ |/ /| |___/\__/ / |\  \
\_____/\_| |_/\_|   |_\/   \/___/ \____/\____/\_| \_/
                                       ZAPiXDESK         
# Copyright: 2025 Alberto Magno <alberto.magno@gmail.com> 
# URL: https://github.com/kraftdenker/ZAPiXDESK
# Version: $ZDVersion
# Source Path: $($WhatsAppPath)
# Output Path: $($OutputDirectory)"

    # Verify Administrator rights 

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 
    { 
        try {
            $script_file = $MyInvocation.MyCommand.ScriptBlock.File
            $script_path = Split-Path -Path $script_file -Parent
            $argList = foreach ($key in $PSBoundParameters.Keys) {
                $value = $PSBoundParameters[$key]
                if ($value -is [switch]) {
                    "-$key"
                } elseif ($value -match '\s') {
                    "-$key `"$value`""
                } else {
                    "-$key $value"
                }
            }
            $arguments = $argList -join ' '
            Start-Process powershell -Verb RunAs -WorkingDirectory $script_path -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$script_file`" $arguments"
            Exit
        }
        catch {
            Write-Output "Unable to elevate to Administrator. Exiting."
            Exit
        }
    }

    Add-Type -AssemblyName System.Security
    Add-Type -AssemblyName System.Windows.Forms
    try {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ClipcWrapper {
    [DllImport("clipc.dll")]
    public static extern int GetOfflineDeviceUniqueID(uint cbSalt, byte[] pbSalt, out uint oMethod, ref uint pcbSystemId, byte[] rgbSystemId, uint unk1, uint unk2);
}
"@ } catch {
        Write-Warning "Unable to add the Clipcwrapper to utilize GetOfflineDeviceUniqueID - Unless ODUID can be extracted by other means, decryption may not be successful."
    }
    try {
        Add-Type -Path "$PSScriptRoot\BouncyCastle.Cryptography.dll"
        Write-Verbose "BouncyCastle Assembly loaded."
    } catch {
        Write-Error "Error: BouncyCastle assembly not loaded. Make sure the BouncyCastle.Cryptography.dll is located in $PSScriptRoot."
        exit
    }
    if (-not $PSBoundParameters.ContainsKey('WhatsAppPath'))
    {
        $WhatsAppPath = Get-AppLocalStatePath -AppName "WhatsApp"
        if ($null -eq $WhatsAppPath)
        {
            Write-Output "WhatsApp installation path not found on this PC. If you are attempting to process a standalone directory structure, please use the -WhatsApp argument."
            exit
        }
    }
    Set-Variable -Name reverseDate -Value $(Get-Date -Format "yyyyMMddHHmmss") -Scope Global
    Set-Variable -Name targetOutput -Value "$OutputPath\ZAPiXDESK_$reverseDate" -Scope Global
    Write-Verbose $WhatsAppPath
    Write-Verbose "Copying $WhatsAppPath to $targetOutput"
    Copy-Directory -Source $WhatsAppPath -Destination $targetOutput
    "ZAPiXDESK DATE: $reverseDate"| Out-File -FilePath "$targetOutput\$metaDataFileName" -Append
    if (-not $PSBoundParameters.ContainsKey('Offline'))
    {
        $ODUID = Get-OfflineDeviceUniqueID -Salt $global:getOUID_salt
        "ODUID Extraction Method: $($ODUID.Method)"| Out-File -FilePath "$targetOutput\$metaDataFileName" -Append
        Write-Output "Method: $($ODUID.Method)"
        $WhatsAppAppUID = $ODUID.ID
        $hexaWhatsAppAppUID = ConvertTo-HexString $WhatsAppAppUID
        "ODUID: $hexaWhatsAppAppUID"| Out-File -FilePath "$targetOutput\$metaDataFileName" -Append
        Write-Output "ODUID: $hexaWhatsAppAppUID"
    }
    else {
        $whatsAppAppUID = Convert-HexStringToByteArray $ID
        $hexaWhatsAppAppUID = $ID
        "ODUID: $hexaWhatsAppAppUID"| Out-File -FilePath "$targetOutput\$metaDataFileName" -Append
        Write-Output "ODUID: $hexaWhatsAppAppUID"
     }
     
     # Detect WhatsApp Desktop architecture
    $sessionDBFileExists = Test-Path -Path "$WhatsAppPath\session.db" -PathType Leaf
    $sessionsDirExists = Test-Path -Path "$WhatsAppPath\sessions" -PathType Container

    if ($sessionDBFileExists -and $sessionsDirExists) {
        $staticKeyBytes = Convert-HexStringToByteArray $global:webview2_staticBytes
        Write-Output "(staticKeyBytes): $( [BitConverter]::ToString($staticKeyBytes).Replace('-', '') )"
       
        
        $sessionDBSecretData = Protect-WebView2Secret $global:webview2_staticBytes
        $sessionDBSecret = $sessionDBSecretData.Secret32 
        Write-Output "(sessionDBSecret): $( [BitConverter]::ToString($sessionDBSecret).Replace('-', ''))"
        Write-Output "Decrypting session.db-wal"
        Decrypt-DBWALFile $sessionDBSecret "$targetOutput\session.db-wal" "$targetOutput\session.dec.db-wal"
        Write-Output "Decrypting session.db"
        Decrypt-DBFile $sessionDBSecret "$targetOutput\session.db" "$targetOutput\session.dec.db"
        
        #Decrypt-AllFiles $sessionDBSecret ($targetOutput)
        Write-Output $targetOutput"\session.dec.db-wal"
        $clientKeyList = Get-WalSettingsData $targetOutput"\session.dec.db-wal"
        $clientKey = Convert-HexStringToByteArray $clientKeyList[-1].HexBlob
        Write-Output "(clientKey): $( [BitConverter]::ToString($clientKey).Replace('-', '') )"
        #Write-Output $clientKey
        
        #Session dir
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        $hashBytes = $sha1.ComputeHash($clientKey)
        $targetSession = [BitConverter]::ToString($hashBytes).Replace('-', '') 
        Write-Output "(SessionDirectory Name): $targetSession"
        
        #DB files
        $publisherKey = $ODUID.ID 
        Write-Output "(publisherKey): $( [BitConverter]::ToString($publisherKey).Replace('-', '') )"
        
        # Generate encryption key (auxKey2) throught PBKDF2
        $digest= [Org.BouncyCastle.Crypto.Digests.Sha256Digest]::new()
        $generator = [Org.BouncyCastle.Crypto.Generators.Pkcs5S2ParametersGenerator]::new($digest) 
        $generator.Init($clientKey, $publisherKey, $global:pbkdf_iterations) 
        $keyParameter = $generator.GenerateDerivedMacParameters(256) 
        $auxKey = $keyParameter.GetKey()
        Write-Output "EncryptionKey-BC (encKey): $( [BitConverter]::ToString($auxKey).Replace('-', '') )"
        # Generate IV throught PBKDF2
        $generator.Init($auxKey, $publisherKey, $global:pbkdf_iterations) 
        $keyParameter = $generator.GenerateDerivedMacParameters(128) 
        $IV = $keyParameter.GetKey()
        Write-Output "(IV-BC): $( [BitConverter]::ToString($IV).Replace('-', '') )"
        
        # Create the AES object 
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $auxKey
        $aes.IV = $IV
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7 #None
        # Create a encryptor
        $encryptor = $aes.CreateEncryptor($aes.Key, $aes.IV)
        # Encrypt the key
        $dbKey = $encryptor.TransformFinalBlock($staticKeyBytes, 0, $staticKeyBytes.Length) 
        $aes.Dispose()
        
        #Crop first (32 bytes)
        $dbKey = $dbKey[0..63] 

        Write-Output "(DBKEY): $( [BitConverter]::ToString($dbKey).Replace('-', '') )"
        $workingDir = "$targetOutput\sessions\$targetSession"
        
        Write-Output "Decrypting nativeSettings.db-wal"
        Decrypt-DBWALFile $dbKey ("$workingDir\nativeSettings.db-wal") ("$workingDir\nativeSettings.dec.db-wal")
        Write-Output "Decrypting nativeSettings.db"
        Decrypt-DBFile $dbKey ("$workingDir\nativeSettings.db") ("$workingDir\nativeSettings.dec.db")

        
        $databaseKeyList = Get-WalSettingsData "$workingDir\nativeSettings.dec.db-wal"
        #Write-Verbose $databaseKeyList
        

        if ($databaseKeyList) {
            # 2. grup Keys filter keys types 1, 2 e 3
            $keyGroup = $databaseKeyList | Where-Object { $_.Key -in 1, 2, 3 } | Group-Object Key

            foreach ($keyType in $keyGroup) {
                # get latest key from keytype
                $lastFromThisType = $keyType.Group | Select-Object -Last 1
                
                $currentKey = $lastFromThisType.Key
                $dbKey = Convert-HexStringToByteArray $lastFromThisType.HexBlob
                switch ($currentKey) {
                    1 {
                        Write-Output "Decrypting genericStorage.db-wal"
                        Decrypt-DBWALFile $dbKey ("$workingDir\genericStorage.db-wal") ("$workingDir\genericStorage.dec.db-wal")
                        Write-Output "Decrypting genericStorage.db"
                        Decrypt-DBFile $dbKey ("$workingDir\genericStorage.db") ("$workingDir\genericStorage.dec.db")
                    }
                    2 {
                        Write-Output "Decrypting abprops.db-wal"
                        Decrypt-DBWALFile $dbKey ("$workingDir\abprops.db-wal") ("$workingDir\abprops.dec.db-wal")
                        Write-Output "Decrypting abprops.db"
                        Decrypt-DBFile $dbKey ("$workingDir\abprops.db") ("$workingDir\abprops.dec.db")
                        Write-Output "Decrypting contacts.db-wal"
                        Decrypt-DBWALFile $dbKey ("$workingDir\contacts.db-wal") ("$workingDir\contacts.dec.db-wal")
                        Write-Output "Decrypting contacts.db"
                        Decrypt-DBFile $dbKey ("$workingDir\contacts.db") ("$workingDir\contacts.dec.db")
                        Write-Output "Decrypting contactsState.db-wal"
                        Decrypt-DBWALFile $dbKey ("$workingDir\contactsState.db-wal") ("$workingDir\contactsState.dec.db-wal")
                        Write-Output "Decrypting contactsState.db"
                        Decrypt-DBFile $dbKey ("$workingDir\contactsState.db") ("$workingDir\contactsState.dec.db")
                        Write-Output "Decrypting mediaDownloads.db-wal"
                        Decrypt-DBWALFile $dbKey ("$workingDir\mediaDownloads.db-wal") ("$workingDir\mediaDownloads.dec.db-wal")
                        Write-Output "Decrypting mediaDownloads.db"
                        Decrypt-DBFile $dbKey ("$workingDir\mediaDownloads.db") ("$workingDir\mediaDownloads.dec.db")
                    }
                    3 {
                        #Write-Warning "NOP"
                    }
                    Default {
                        #Write-Warning "NOP"
                    }  
                }
            }
        } else {
            Write-Warning "Error processing nativeSettings WAL file."
        }
        
    } else {
        $userKey = Get-Key -FilePath "$WhatsAppPath\nondb_settings16.dat" -HasPadding $true
        $hexaUserKey = ConvertTo-HexString $userKey 
        Write-Output "UserKey: $hexaUserKey"
        
        $ns18Output = Get-Key -FilePath "$WhatsAppPath\nondb_settings18.dat" -HasPadding $true
        $tmp_dec_nondb_settings18 = Join-Path -Path $OutputDirectory -ChildPath 'dec_nondb_settings18.dat'
        [System.IO.File]::WriteAllBytes($tmp_dec_nondb_settings18, $ns18Output)
        Write-Verbose "NS18: $(ConvertTo-HexString($ns18Output))"
        
        $dbKey = Get-Key -FilePath $tmp_dec_nondb_settings18 -UserKey $userKey -HasPadding $false
        $hexaDBKey = ConvertTo-HexString $dbKey 
        Write-Output "DBKey: $hexaDBKey"
        "DBKEY: $hexaDBKey"| Out-File -FilePath "$targetOutput\$metaDataFileName" -Append
        Remove-Item $tmp_dec_nondb_settings18

        # Decrypt all-files
        Write-Output "Decrypting databases..."
        Decrypt-AllFiles $dbKey $targetOutput
    }     

    # Compresses a directory to a zip file and deletes the source
    $zipTarget="$OutputDirectory\ZAPiXDESK_$reverseDate.zip"
    Compress-Directory -Source $targetOutput -DestinationZipFile $zipTarget
    Write-Output "Compressed file (ZIP) generated: $zipTarget"
    # Generate integrity HASH - Changed to MD5 as computation time for higher algorithms for large files can be minutes instead of seconds.
    $checksumFileZip = Get-MD5Checksum -FilePath $zipTarget
    if ($checksumFileZip) {
        Write-Verbose "Checksum file (ZIP): $checksumFileZip"
    }
    Write-Output "MD5 Hash: $checksumFileZip (hash also copied to clipboard)"
    [Windows.Forms.MessageBox]::Show("WhatsApp acquisition and decryption completed. Results save in $zipTarget", "Acquisition Complete","Ok","Information") | Out-Null
}

if ($PSBoundParameters.ContainsKey('Offline'))
{
    if (-not $PSBoundParameters.ContainsKey('WhatsAppPath'))
    {
        $WhatsAppPath = Get-AppLocalStatePath -AppName "WhatsApp"
        if ($null -eq $WhatsAppPath)
        {
            Write-Output "WhatsApp installation path not found on this PC. If you are attempting to process a standalone directory structure, please use the -WhatsApp argument."
            exit
        }
    }
    else {
        $WhatsAppPath = (Resolve-Path $WhatsAppPath).Path
    }
    if (-not $PSBoundParameters.ContainsKey('ID')){
        Write-Output "The 'ID' argument is required when using this script in Offline mode"
        exit
    }
    if (-not $PSBoundParameters.ContainsKey('OutputPath'))
    {
        Set-Variable -Name OutputDirectory -Value $PWD.Path -Scope Global
    } else {
        Set-Variable -Name OutputDirectory -Value $OutputPath -Scope Global
    }
    Start-ZapixDesk -WhatsAppPath $WhatsAppPath -Offline -ID $ID -OutputPath $OutputDirectory
} elseif ($PSBoundParameters.ContainsKey('GetID')){
    $ODUID = Get-OfflineDeviceUniqueID -Salt $global:getOUID_salt
    $ODUID_HEX = ConvertTo-HexString $ODUID.ID
    Write-Output "ODUID: $ODUID_HEX"
}
else {
    if (-not $PSBoundParameters.ContainsKey('WhatsAppPath'))
    {
        $WhatsAppPath = Get-AppLocalStatePath -AppName "WhatsApp"
        if ($null -eq $WhatsAppPath)
        {
            Write-Output "WhatsApp installation path not found on this PC. If you are attempting to process a standalone directory structure, please use the -WhatsApp argument."
            exit
        }
    }
    else {
        $WhatsAppPath = (Resolve-Path $WhatsAppPath).Path
    }
    if (-not $PSBoundParameters.ContainsKey('OutputPath'))
    {
        Set-Variable -Name OutputDirectory -Value $PWD.Path -Scope Global
    } else {
        Set-Variable -Name OutputDirectory -Value $OutputPath -Scope Global
    }
    Start-ZapixDesk -WhatsAppPath $WhatsAppPath -OutputPath $OutputDirectory
}
