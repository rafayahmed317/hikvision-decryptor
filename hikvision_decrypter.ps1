[CmdletBinding()]
param (
    [Parameter()]
    [String]
    $FilePath
)
function decryptXOR([byte[]] $bytes, [byte[]] $key){
    # Get the length of the key array
    $keyLength = $key.Length

    # Perform the XOR operation
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = $bytes[$i] -bxor $key[$i % $keyLength]
    }

    # Output the modified bytes array
    return $bytes
}
function Invoke-AESDecrypt {
    param (
        [byte[]] $InputBytes,
        [byte[]] $KeyBytes
    )

    # Create AES instance
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $KeyBytes
    $aes.Mode = [System.Security.Cryptography.CipherMode]::ECB
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None  # No automatic padding

    # Create decryptor
    $decryptor = $aes.CreateDecryptor()

    # Decrypt in blocks
    $DecryptedBytes = New-Object byte[] $InputBytes.Length
    for ($i = 0; $i -lt $InputBytes.Length; $i += 16) {
        $Block = $InputBytes[$i..($i + 15)]
        $DecryptedBlock = $decryptor.TransformFinalBlock($Block, 0, $Block.Length)
        [Array]::Copy($DecryptedBlock, 0, $DecryptedBytes, $i, $DecryptedBlock.Length)
    }

    return $DecryptedBytes
}

function Get-PaddedBytes($fileBytes){
    # Ensure input is padded to 16 bytes
    $paddingNeeded = 16 - ($fileBytes.Length % 16)
    if ($paddingNeeded -ne 16) {
        $paddedBytes = New-Object byte[] ($fileBytes.Length + $paddingNeeded)
        [Array]::Copy($fileBytes, $paddedBytes, $fileBytes.Length)
    } else {
        $paddedBytes = $fileBytes
    }
    return $paddedBytes
}

try{
    $file = Get-Item $FilePath
}catch{
    Write-Host "Make sure a file exists at path: $FilePath !" -ForegroundColor Red 
    Exit
}

# Read bytes 
$fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
$paddedBytes = Get-PaddedBytes -fileBytes $fileBytes

try{
    Write-Host "Decrypting AES" -ForegroundColor Yellow
    $aesDecrypted = Invoke-AESDecrypt -InputBytes $paddedBytes -KeyBytes $aesKey
    Write-Host "Successfully decrypted AES" -ForegroundColor Green
}catch{
    Write-Host "Could not decrypt AES!" -ForegroundColor Red
    Exit
}

try{
    Write-Host "Decrypting XOR" -ForegroundColor Yellow
    $finalDecrypted = decryptXOR -bytes $aesDecrypted -key $xorKey
    Write-Host "Successfully decrypted XOR" -ForegroundColor Green
}catch{
    Write-Host "Could not decrypt XOR!" -ForegroundColor Red
    Exit
}

$outputPath = $file.DirectoryName + "\" + $file.BaseName + "_decrypted" + $file.Extension
Write-Host "Writing decrypted config file to: $outputPath" -ForegroundColor Yellow
[System.IO.File]::WriteAllBytes($outputPath, $finalDecrypted)