$creds = Get-Credential

# Here, we'll randomly generate a 32-byte encryption key.  You would load this up from secure storage somewhere, ideally.

$key = New-Object byte[](32)

$rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
$rng.GetBytes($key)

$exportObject = New-Object psobject -Property @{
    UserName = $creds.UserName
    Password = ConvertFrom-SecureString -SecureString $creds.Password -Key $key
}

$exportObject | Export-Clixml -Path .\savedCreds.xml

# To read these back in later, reverse this process (using the same key):

$importObject = Import-Clixml -Path .\savedCreds.xml

$secureString = ConvertTo-SecureString -String $importObject.Password -Key $key

$savedCreds = New-Object System.Management.Automation.PSCredential($importObject.UserName, $secureString)