$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\packaging\windows\security.ps1"
function Assert($Condition, $Message) { if (!$Condition) { throw $Message } }
function Rejects([scriptblock]$Action, [string]$Reason) {
    # Match the reason so a different check failing cannot mask a missing one.
    $rejected = $false
    try { & $Action } catch {
        Assert ("$_" -like "*$Reason*") "Expected rejection '$Reason', got: $_"
        $rejected = $true
    }
    Assert $rejected "Unsafe input was accepted (expected '$Reason')"
}
foreach ($directory in @($true, $false)) {
    $acl = New-PrivateAcl $directory
    Assert $acl.AreAccessRulesProtected 'DACL must be protected'
    Assert ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-544') 'Unexpected owner'
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    Assert ($rules.Count -eq 2) 'DACL must contain exactly two grants'
    foreach ($rule in $rules) {
        Assert ($rule.IdentityReference.Value -in @('S-1-5-18','S-1-5-32-544')) 'Untrusted grant'
        Assert ($rule.FileSystemRights -eq 'FullControl') 'Wrong access rights'
    }
}
# Exercise trust policy using actual Windows ACL objects, without elevation.
$script:FixtureAcl = New-PrivateAcl $true
function Get-Acl { param($LiteralPath) return $script:FixtureAcl }
$item = [pscustomobject]@{FullName='fixture'; Attributes=[IO.FileAttributes]::Directory}
Assert-TrustedItem $item
$read = New-Object Security.AccessControl.FileSystemAccessRule([Security.Principal.SecurityIdentifier]'S-1-1-0','ReadAndExecute','Allow')
$script:FixtureAcl.AddAccessRule($read)
Assert-TrustedItem $item
$write = New-Object Security.AccessControl.FileSystemAccessRule([Security.Principal.SecurityIdentifier]'S-1-1-0','Write','Allow')
$script:FixtureAcl.AddAccessRule($write)
Rejects { Assert-TrustedItem $item } 'Untrusted write permission'
# Generic rights on inherit-only ACEs have no FileSystemRights name.
foreach ($generic in @('GW', 'GA')) {
    $script:FixtureAcl = New-PrivateAcl $true
    $script:FixtureAcl.SetSecurityDescriptorSddlForm("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;$generic;;;BU)")
    Rejects { Assert-TrustedItem $item } 'Untrusted write permission'
}
$script:FixtureAcl = New-PrivateAcl $true
$script:FixtureAcl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-1-0')
Rejects { Assert-TrustedItem $item } 'Untrusted owner'
# The account running setup is a trusted owner only with an unfiltered admin token.
Assert ((Test-UnfilteredAdminToken) -is [bool]) 'Token elevation type must be readable'
$script:FixtureAcl = New-PrivateAcl $true
$script:FixtureAcl.SetOwner([Security.Principal.WindowsIdentity]::GetCurrent().User)
function Test-UnfilteredAdminToken { return $true }
Assert-TrustedItem $item
# An elevated UAC admin's own account may also run reduced-rights programs.
function Test-UnfilteredAdminToken { return $false }
Rejects { Assert-TrustedItem $item } 'Untrusted owner'
Remove-Item Function:\Test-UnfilteredAdminToken
. "$PSScriptRoot\..\packaging\windows\security.ps1"
$script:FixtureAcl = New-PrivateAcl $true
$item.Attributes = [IO.FileAttributes]::ReparsePoint
Rejects { Assert-TrustedItem $item } 'Reparse points are not permitted'
Remove-Item Function:\Get-Acl
$tempFile = Join-Path ([IO.Path]::GetTempPath()) ('lighthouse-security-test-' + [guid]::NewGuid().ToString('N'))
try {
    [IO.File]::WriteAllText($tempFile, 'trusted payload')
    $expected = (Get-FileHash $tempFile -Algorithm SHA256).Hash
    Assert-FileHash $tempFile $expected
    Assert-FileHash $tempFile $expected $expected
    [IO.File]::WriteAllText($tempFile, 'modified payload')
    Rejects { Assert-FileHash $tempFile $expected } 'SHA256 mismatch'
    Rejects { Assert-FileHash $tempFile '' } 'Missing trusted SHA256'
    Rejects { Assert-Publisher $tempFile @('Microsoft Corporation') } 'Invalid Authenticode signature'
    # A Sysmon archive must carry a signed Sysmon64.exe; staging is always removed.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archiveSource = "$tempFile-src"
    New-Item -ItemType Directory $archiveSource | Out-Null
    [IO.File]::WriteAllText("$archiveSource\Sysmon64.exe", 'unsigned')
    [IO.Compression.ZipFile]::CreateFromDirectory($archiveSource, "$tempFile.zip")
    Rejects { Assert-SysmonArchive "$tempFile.zip" "$tempFile-staging" } 'Invalid Authenticode signature'
    Assert (!(Test-Path "$tempFile-staging")) 'Sysmon staging directory was left behind'
    [IO.File]::WriteAllText("$tempFile.zip", '<html>captive portal</html>')
    Rejects { Assert-SysmonArchive "$tempFile.zip" "$tempFile-staging" } 'Central Directory'
} finally {
    Remove-Item -LiteralPath $tempFile, "$tempFile.zip", "$tempFile-src" -Recurse -Force -ErrorAction SilentlyContinue
}
# Verify both trust-chain status and the expected signing identity are required.
$cert = New-Object PSObject
$cert | Add-Member ScriptMethod GetNameInfo { param($Type,$Issuer) return 'Expected Publisher' }
$script:Signature = [pscustomobject]@{Status='Valid'; SignerCertificate=$cert}
function Get-AuthenticodeSignature { param($LiteralPath) return $script:Signature }
Assert-Publisher 'fixture.exe' @('Expected Publisher')
Rejects { Assert-Publisher 'fixture.exe' @('Another Publisher') } 'Unexpected signing publisher'
$script:Signature.Status = 'HashMismatch'
Rejects { Assert-Publisher 'fixture.exe' @('Expected Publisher') } 'Invalid Authenticode signature'
Remove-Item Function:\Get-AuthenticodeSignature
# The program folder: Administrators and SYSTEM change it, Users only read and run it.
foreach ($directory in @($true, $false)) {
    $acl = New-AppAcl $directory
    Assert $acl.AreAccessRulesProtected 'Program DACL must be protected'
    Assert ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-544') 'Program folder owner must be Administrators'
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    Assert ($rules.Count -eq 3) 'Program DACL must contain exactly three grants'
    $users = @($rules | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-32-545' })
    Assert ($users.Count -eq 1 -and $users[0].FileSystemRights -eq 'ReadAndExecute, Synchronize') "Users must only read and run: $($users.FileSystemRights)"
}
$script:FixtureAcl = New-AppAcl $true
function Get-Acl { param($LiteralPath) return $script:FixtureAcl }
Assert-TrustedItem ([pscustomobject]@{FullName='app'; Attributes=[IO.FileAttributes]::Directory})
Remove-Item Function:\Get-Acl
# Only an internal NTFS/ReFS drive, and never a drive root.
function Get-InstallVolume { param($Path) return $script:Volume }
foreach ($case in @(@('Network', '', 'internal drive'), @('Removable', 'NTFS', 'internal drive'), @('CDRom', 'UDF', 'internal drive'),
                    @('Fixed', 'FAT32', 'cannot protect'), @('Fixed', 'exFAT', 'cannot protect'))) {
    $script:Volume = [pscustomobject]@{ Root = 'E:\'; DriveType = $case[0]; DriveFormat = $case[1] }
    Rejects { Assert-InstallVolume 'E:\LightHouse' } $case[2]
}
foreach ($format in @('NTFS', 'ReFS')) {
    $script:Volume = [pscustomobject]@{ Root = 'D:\'; DriveType = 'Fixed'; DriveFormat = $format }
    Assert-InstallVolume 'D:\LightHouse'
}
Rejects { Assert-InstallVolume 'D:\' } 'not the root'
Remove-Item Function:\Get-InstallVolume
. "$PSScriptRoot\..\packaging\windows\security.ps1"
Assert ((Get-InstallVolume '\\server\share\LightHouse').DriveType -eq 'Network') 'UNC paths must count as network drives'
Rejects { Assert-FreeSpace ([IO.Path]::GetTempPath()) ([int64]::MaxValue) } 'Not enough free space'
# Moving an earlier install's data keeps every file and leaves nothing behind.
$moveRoot = Join-Path ([IO.Path]::GetTempPath()) ('lighthouse-move-test-' + [guid]::NewGuid().ToString('N'))
try {
    $source = "$moveRoot\legacy"; $target = "$moveRoot\new\data"
    New-Item -ItemType Directory -Force "$source\models", "$source\config", "$target" | Out-Null
    [IO.File]::WriteAllText("$source\lighthouse.db", 'database')
    [IO.File]::WriteAllText("$source\models\model.gguf", 'weights')
    [IO.File]::WriteAllText("$source\config\windows.json", '{}')
    Assert ((Get-TreeSize $source) -eq 17) "Unexpected tree size $(Get-TreeSize $source)"
    Move-DataTree $source $target
    Assert (!(Test-Path $source)) 'The old data folder must be gone after a move'
    Assert ([IO.File]::ReadAllText("$target\models\model.gguf") -eq 'weights') 'Model was not moved'
    Assert ([IO.File]::ReadAllText("$target\lighthouse.db") -eq 'database') 'Database was not moved'
    Assert (Test-Path "$target\config\windows.json") 'Configuration was not moved'
} finally {
    Remove-Item -LiteralPath $moveRoot -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Output 'Windows installer security regression checks passed'
