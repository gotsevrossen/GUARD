# Shared, side-effect-free definitions used by setup and regression tests.
function New-PrivateAcl([bool]$Directory) {
    $acl = if ($Directory) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $inheritance = if ($Directory) { 'ContainerInherit,ObjectInherit' } else { 'None' }
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            [Security.Principal.SecurityIdentifier]$sid, 'FullControl', $inheritance, 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    return $acl
}
function Test-UnfilteredAdminToken {
    # True for an administrator without a split UAC token (built-in Administrator,
    # UAC off). Such an account never runs anything with reduced rights.
    if (!('LightHouse.Token' -as [type])) {
        Add-Type -Namespace LightHouse -Name Token -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool GetTokenInformation(IntPtr token, int infoClass, out int info, int length, out int returned);
'@
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return $false }
        $elevationType = 0; $returned = 0
        # TokenElevationType (18): 1 = default (no split token), 2 = full, 3 = limited.
        if (![LightHouse.Token]::GetTokenInformation($identity.Token, 18, [ref]$elevationType, 4, [ref]$returned)) {
            throw 'Unable to read the setup token elevation type.'
        }
        return $elevationType -eq 1
    } finally { $identity.Dispose() }
}
function Get-TrustedSids {
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    # An unfiltered admin token makes the account itself, not Administrators, the
    # owner of what it creates, including earlier installs. Trusting it adds no
    # risk because that account has no reduced-rights programs to plant files.
    # Elevated UAC admins already create Administrators-owned files.
    if (Test-UnfilteredAdminToken) { $trusted += [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
    return $trusted
}
function Assert-TrustedItem($Item) {
    if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse points are not permitted: $($Item.FullName)" }
    $acl = Get-Acl -LiteralPath $Item.FullName
    $trusted = Get-TrustedSids
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
        throw "Untrusted owner on $($Item.FullName). Move the existing directory aside and reinstall; do not reuse untrusted configuration or cached files."
    }
    # Inherit-only ACEs often carry generic rights (GENERIC_WRITE 0x40000000,
    # GENERIC_ALL 0x10000000), which have no FileSystemRights name.
    $writeMask = [int][Security.AccessControl.FileSystemRights]'WriteData,AppendData,WriteExtendedAttributes,WriteAttributes,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership' -bor 0x50000000
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $trusted -and ($rule.FileSystemRights -band $writeMask)) {
            throw "Untrusted write permission on $($Item.FullName). Refusing to consume potentially modified installation data."
        }
    }
}
function Set-PrivateTree([string]$Path, [bool]$Verify) {
    $queue = New-Object 'Collections.Generic.Queue[IO.FileSystemInfo]'
    $queue.Enqueue((Get-Item -LiteralPath $Path -Force))
    while ($queue.Count) {
        $item = $queue.Dequeue()
        if ($Verify) { Assert-TrustedItem $item }
        elseif ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse points are not permitted: $($item.FullName)" }
        try {
            # Replace the entire DACL, including explicit grants, and the owner.
            Set-Acl -LiteralPath $item.FullName -AclObject (New-PrivateAcl $item.PSIsContainer)
            $children = if ($item.PSIsContainer) { @(Get-ChildItem -LiteralPath $item.FullName -Force) } else { @() }
        } catch {
            # Running services may rotate logs or drop SQLite journals meanwhile.
            if ($Verify -or (Test-Path -LiteralPath $item.FullName)) { throw }
            continue
        }
        foreach ($child in $children) { $queue.Enqueue($child) }
    }
}
function Protect-DataDirectory([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    # Reject junctions in the path before creating or following any children.
    $ancestor = [IO.DirectoryInfo]$full
    while ($null -ne $ancestor) {
        if ($ancestor.Exists -and ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Reparse point in data path: $($ancestor.FullName)" }
        $ancestor = $ancestor.Parent
    }
    if (!(Test-Path -LiteralPath $full)) {
        [IO.Directory]::CreateDirectory($full, (New-PrivateAcl $true)) | Out-Null
    }
    Set-PrivateTree $full $true
}
function Restore-DataOwnership([string]$Path) {
    # Only administrators and SYSTEM can write below a protected tree, so what
    # this run created is trusted; hand it to Administrators so a later repair
    # by any administrator accepts it.
    Set-PrivateTree ([IO.Path]::GetFullPath($Path)) $false
}
function New-AppAcl([bool]$Directory) {
    # The program tree: SYSTEM and Administrators change it, Users may only read and
    # run it. Every LightHouse service runs from here as LocalSystem, so anyone who
    # could replace a file here could run code as SYSTEM. Program Files gives this by
    # default; any other folder (C:\LightHouse, another drive) must be made so.
    $acl = if ($Directory) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
    $inheritance = if ($Directory) { 'ContainerInherit,ObjectInherit' } else { 'None' }
    foreach ($grant in @(@('S-1-5-18', 'FullControl'), @('S-1-5-32-544', 'FullControl'), @('S-1-5-32-545', 'ReadAndExecute'))) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            [Security.Principal.SecurityIdentifier]$grant[0], $grant[1], $inheritance, 'None', 'Allow')))
    }
    return $acl
}
function Get-InstallVolume([string]$Path) {
    # Separate so tests can describe a drive without needing one.
    $root = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Path))
    if ($root.StartsWith('\\')) { return [pscustomobject]@{ Root = $root; DriveType = 'Network'; DriveFormat = '' } }
    $drive = New-Object IO.DriveInfo $root
    return [pscustomobject]@{ Root = $root; DriveType = [string]$drive.DriveType; DriveFormat = [string]$drive.DriveFormat }
}
function Assert-InstallVolume([string]$Path) {
    # Permissions are the security boundary for both the program and its data, so
    # the drive must support them (FAT32/exFAT do not), and it must be there when
    # the services start at boot (a USB or network drive may not be, or may come
    # back under another letter).
    $volume = Get-InstallVolume $Path
    if ($volume.DriveType -ne 'Fixed') { throw "LightHouse must be installed on an internal drive, not a $($volume.DriveType.ToLower()) drive ($($volume.Root)). Choose a folder on an internal NTFS drive." }
    if ($volume.DriveFormat -notin @('NTFS', 'ReFS')) { throw "The drive $($volume.Root) uses $($volume.DriveFormat), which cannot protect LightHouse's files. Choose a folder on an NTFS drive." }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ($full.Length -le 2) { throw "Choose a folder for LightHouse, not the root of drive $($volume.Root)" }
}
function Protect-AppDirectory([string]$Path, [string[]]$Except = @()) {
    # Lock the root, then make everything below it inherit from it, replacing any
    # explicit grant (an older install, or a folder someone prepared in advance).
    # Subfolders named in $Except (the private data folder) are left to their own
    # stricter protection.
    $full = [IO.Path]::GetFullPath($Path)
    $ancestor = [IO.DirectoryInfo]$full
    while ($null -ne $ancestor) {
        if ($ancestor.Exists -and ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Reparse point in program path: $($ancestor.FullName)" }
        $ancestor = $ancestor.Parent
    }
    Set-Acl -LiteralPath $full -AclObject (New-AppAcl $true)
    foreach ($child in @(Get-ChildItem -LiteralPath $full -Force)) {
        if ($child.Name -in $Except) { continue }
        if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse points are not permitted: $($child.FullName)" }
        & icacls.exe $child.FullName /reset /T /C /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not reset permissions on $($child.FullName) (icacls $LASTEXITCODE)" }
    }
    Assert-TrustedItem (Get-Item -LiteralPath $full -Force)
}
function Get-TreeSize([string]$Path) {
    $sum = (Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    if ($sum) { return [int64]$sum } else { return [int64]0 }
}
function Assert-FreeSpace([string]$Path, [int64]$Bytes) {
    $root = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Path))
    $free = (New-Object IO.DriveInfo $root).AvailableFreeSpace
    if ($free -lt $Bytes) { throw ("Not enough free space on {0}: {1:N1} GB needed, {2:N1} GB free." -f $root, ($Bytes / 1GB), ($free / 1GB)) }
}
function Move-DataTree([string]$Source, [string]$Target) {
    # Moves an earlier install's data (database, settings, the 2.5 GB model) into
    # the new data folder; robocopy because Move-Item cannot move a folder across
    # drives. The caller verifies the source is trusted first. Copied files take
    # the target's private permissions; the caller re-protects the tree afterwards.
    & robocopy.exe $Source $Target /E /MOVE /XJ /COPY:DAT /DCOPY:T /R:2 /W:2 /NFL /NDL /NJH /NJS /NP | Out-Null
    # robocopy: 0-7 are success variants, 8 and above mean files were not moved.
    # /MOVE deletes a source file only after copying it, so nothing is lost either way.
    if ($LASTEXITCODE -ge 8) { throw "Could not move all LightHouse data from $Source to $Target (robocopy $LASTEXITCODE). What was not moved is still in $Source; run setup again." }
    if (Test-Path -LiteralPath $Source) {
        if (@(Get-ChildItem -LiteralPath $Source -Recurse -Force -File).Count) { throw "Some LightHouse data could not be moved out of $Source. Close anything using it and run setup again." }
        Remove-Item -LiteralPath $Source -Recurse -Force
    }
}
function Assert-FileHash([string]$Path, [string]$Expected, [string]$Actual) {
    if ($Expected -notmatch '^[0-9a-fA-F]{64}$') { throw "Missing trusted SHA256 for $Path" }
    if (!$Actual) { $Actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
    if ($Actual -ne $Expected) { throw "SHA256 mismatch: $Path. Dependency will not be executed." }
}
function Assert-Publisher([string]$Path, [string[]]$Publishers) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or !$signature.SignerCertificate) { throw "Invalid Authenticode signature: $Path" }
    $publisher = $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    if ($publisher -notin $Publishers) { throw "Unexpected signing publisher '$publisher': $Path" }
}
function Assert-SysmonArchive([string]$Path, [string]$Staging) {
    # Sysinternals serves only the latest release at a fixed URL, so a pinned
    # hash would break on every release. Pin the signer and product instead.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (Test-Path -LiteralPath $Staging) { Remove-Item -LiteralPath $Staging -Recurse -Force }
    try {
        [IO.Compression.ZipFile]::ExtractToDirectory($Path, $Staging)
        $sysmon = Join-Path $Staging 'Sysmon64.exe'
        Assert-Publisher $sysmon @('Microsoft Windows Publisher', 'Microsoft Corporation')
        $product = (Get-Item -LiteralPath $sysmon).VersionInfo.ProductName
        if ($product -ne 'Sysinternals Sysmon') { throw "Unexpected Sysmon product '$product': $Path" }
    } finally {
        Remove-Item -LiteralPath $Staging -Recurse -Force -ErrorAction SilentlyContinue
    }
}
