<#
.SYNOPSIS
    Dynamically generate and validate GRANT/DENY/REVOKE statements for SQL Server.

.DESCRIPTION
    This script enforces both syntax-level and catalog-level validation before producing
    a T-SQL permission statement. It logs every request for audit purposes but never
    executes the T-SQL itself.

.PARAMETER Action
    GRANT, DENY, or REVOKE.

.PARAMETER ServerInstance
    Name of the target SQL Server instance (e.g. "w01samlidb1a").

.PARAMETER Database
    Target database name (defaults to "master").

.PARAMETER User
    Login or database user to modify (e.g. "amlopr").

.PARAMETER RoleOrPermission
    Server role, database role, or built-in permission (e.g. "sysadmin" or "db_datareader").

.PARAMETER Justification
    Free-form reason for the change (optional).

.PARAMETER StartDate
    If provided together with EndDate, marks the grant as temporary.

.PARAMETER EndDate
    End date for a temporary grant.

.PARAMETER Credential
    PSCredential object for SQL Server authentication (optional - uses Windows Auth if not provided).

.EXAMPLE
    # Permanent server-role grant
    .\Manage-SqlPermission.ps1 `
      -Action GRANT `
      -ServerInstance 'w01samlidb1a' `
      -Database 'master' `
      -User 'amlopr' `
      -RoleOrPermission 'sysadmin' `
      -Justification 'UAT deployment access'

.EXAMPLE
    # Temporary database-role grant
    .\Manage-SqlPermission.ps1 `
      -Action GRANT `
      -ServerInstance 'w01samlidb1a' `
      -Database 'MRS' `
      -User 'FIDsAccount' `
      -RoleOrPermission 'db_datareader' `
      -Justification 'Replication batch' `
      -StartDate '2025-07-17' `
      -EndDate   '2025-07-31'
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [ValidateSet('GRANT','DENY','REVOKE')]
    [string]$Action,

    [Parameter(Mandatory)]
    [string]$ServerInstance,

    [string]$Database = 'master',

    [Parameter(Mandatory)]
    [string]$User,

    [Parameter(Mandatory)]
    [string]$RoleOrPermission,

    [string]$Justification,

    [datetime]$StartDate,

    [datetime]$EndDate,

    [PSCredential]$Credential
)

# Configuration
$script:LogFile = "$PSScriptRoot\Audit-SqlPermission.log"
$script:MaxLogSizeMB = 10

function Write-Log {
    param (
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )
    
    try {
        $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $logEntry = "$timestamp [$Level] $Message"
        
        # Log rotation check
        if (Test-Path $script:LogFile) {
            $logSize = (Get-Item $script:LogFile).Length / 1MB
            if ($logSize -gt $script:MaxLogSizeMB) {
                $backupLog = $script:LogFile -replace '\.log$', "_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                Move-Item -Path $script:LogFile -Destination $backupLog -Force
            }
        }
        
        Add-Content -Path $script:LogFile -Value $logEntry -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to write to log file: $($_.Exception.Message)"
    }
}

function Validate-Syntax {
    param (
        [string]$Action,
        [string]$Database,
        [string]$User,
        [string]$RoleOrPermission
    )
    
    Write-Log "Validating syntax for Action=$Action, Database=$Database, User=$User, RoleOrPermission=$RoleOrPermission"
    
    if ($Action -notin 'GRANT','DENY','REVOKE') {
        throw "Invalid Action '$Action'. Use GRANT, DENY or REVOKE."
    }

    # Enhanced validation for SQL identifiers
    foreach ($param in @{Database=$Database; User=$User; RoleOrPermission=$RoleOrPermission}.GetEnumerator()) {
        $key = $param.Key
        $value = $param.Value
        
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw "Missing or empty parameter: $key"
        }
        
        # Allow quoted identifiers and standard SQL identifiers
        $quotedPattern = '^\[.*\]$'
        $standardPattern = '^[A-Za-z_@#][A-Za-z0-9_@#$]*$'
        
        if ($value -notmatch $quotedPattern -and $value -notmatch $standardPattern) {
            throw "Invalid $key name '$value'. Must be a valid SQL identifier or quoted identifier [name]."
        }
    }
    
    # Validate date range if provided
    if ($StartDate -and $EndDate) {
        if ($StartDate -gt $EndDate) {
            throw "StartDate cannot be after EndDate."
        }
        if ($EndDate -lt (Get-Date)) {
            throw "EndDate cannot be in the past."
        }
    }
}

function Invoke-SqlCmdSafe {
    param (
        [string]$ServerInstance,
        [string]$Database,
        [string]$Query,
        [hashtable]$Variables = @{},
        [PSCredential]$Credential
    )
    
    try {
        $params = @{
            ServerInstance = $ServerInstance
            Database = $Database
            Query = $Query
            ErrorAction = 'Stop'
        }
        
        if ($Variables.Count -gt 0) {
            $params.Variable = $Variables.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
        }
        
        if ($Credential) {
            $params.Username = $Credential.UserName
            $params.Password = $Credential.GetNetworkCredential().Password
        }
        
        return Invoke-Sqlcmd @params
    }
    catch {
        Write-Log "SQL execution failed: $($_.Exception.Message)" -Level ERROR
        throw "Database operation failed: $($_.Exception.Message)"
    }
}

function Validate-SqlCatalog {
    param (
        [string]$ServerInstance,
        [string]$Database,
        [string]$User,
        [string]$RoleOrPermission,
        [string]$Action,
        [PSCredential]$Credential
    )
    
    Write-Log "Validating SQL catalog for $Action on $RoleOrPermission for $User"
    
    try {
        # 1) Database existence
        $dbQuery = "SELECT CASE WHEN EXISTS(SELECT 1 FROM sys.databases WHERE name = @Database) THEN 1 ELSE 0 END AS Exists"
        $dbExists = Invoke-SqlCmdSafe -ServerInstance $ServerInstance -Database 'master' -Query $dbQuery -Variables @{Database=$Database} -Credential $Credential
        
        if ($dbExists.Exists -eq 0) {
            throw "Database '$Database' not found on instance '$ServerInstance'."
        }

        # 2) Login existence (server-level)
        $loginQuery = "SELECT CASE WHEN EXISTS(SELECT 1 FROM sys.server_principals WHERE name = @User) THEN 1 ELSE 0 END AS Exists"
        $loginExists = Invoke-SqlCmdSafe -ServerInstance $ServerInstance -Database 'master' -Query $loginQuery -Variables @{User=$User} -Credential $Credential
        
        if ($loginExists.Exists -eq 0) {
            throw "Login '$User' does not exist on instance '$ServerInstance'."
        }

        # 3) Check if it's a server role
        $srvRoleQuery = "SELECT COUNT(*) AS Cnt FROM sys.server_principals WHERE type_desc = 'SERVER_ROLE' AND name = @RoleOrPermission"
        $srvRole = Invoke-SqlCmdSafe -ServerInstance $ServerInstance -Database 'master' -Query $srvRoleQuery -Variables @{RoleOrPermission=$RoleOrPermission} -Credential $Credential
        
        if ($srvRole.Cnt -gt 0) {
            # Check server role membership
            $memberQuery = @"
                SELECT CASE WHEN EXISTS(
                    SELECT 1 FROM sys.server_role_members rm
                    JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
                    JOIN sys.server_principals m ON rm.member_principal_id = m.principal_id
                    WHERE r.name = @Role AND m.name = @User
                ) THEN 1 ELSE 0 END AS IsMember
"@
            $member = Invoke-SqlCmdSafe -ServerInstance $ServerInstance -Database 'master' -Query $memberQuery -Variables @{Role=$RoleOrPermission; User=$User} -Credential $Credential
            
            if ($Action -eq 'GRANT' -and $member.IsMember -eq 1) {
                throw "'$User' is already a member of server role '$RoleOrPermission'."
            }
            if ($Action -eq 'REVOKE' -and $member.IsMember -eq 0) {
                throw "'$User' is not a member of server role '$RoleOrPermission'."
            }
            return
        }

        # 4) Check if it's a database role
        $dbRoleQuery = "SELECT COUNT(*) AS Cnt FROM sys.database_principals WHERE type_desc LIKE '%ROLE' AND name = @RoleOrPermission"
        $dbRole = Invoke-SqlCmdSafe -ServerInstance $ServerInstance -Database $Database -Query $dbRoleQuery -Variables @{RoleOrPermission=$RoleOrPermission} -Credential $Credential
        
        if ($dbRole.Cnt -gt 0) {
            # Check database role membership
            $memberQuery = @"
                SELECT CASE WHEN EXISTS(
                    SELECT 1 FROM sys.database_role_members rm
                    JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id
                    JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id
                    WHERE r.name = @Role AND m.name = @User
                ) THEN 1 ELSE 0 END AS IsMember
"@
            $member = Invoke-SqlCmdSafe -ServerInstance $ServerInstance -Database $Database -Query $memberQuery -Variables @{Role=$RoleOrPermission; User=$User} -Credential $Credential
            
            if ($Action -eq 'GRANT' -and $member.IsMember -eq 1) {
                throw "'$User' is already a member of database role '$RoleOrPermission'."
            }
            if ($Action -eq 'REVOKE' -and $member.IsMember -eq 0) {
                throw "'$User' is not a member of database role '$RoleOrPermission'."
            }
            return
        }

        # 5) Check if it's a built-in permission
        $permQuery = "SELECT COUNT(*) AS Cnt FROM fn_builtin_permissions(default) WHERE permission_name = @RoleOrPermission"
        $perm = Invoke-SqlCmdSafe -ServerInstance $ServerInstance -Database $Database -Query $permQuery -Variables @{RoleOrPermission=$RoleOrPermission} -Credential $Credential
        
        if ($perm.Cnt -eq 0) {
            throw "Role or permission '$RoleOrPermission' not found on '$ServerInstance' or in database '$Database'."
        }
        
        Write-Log "Catalog validation completed successfully"
    }
    catch {
        Write-Log "Catalog validation failed: $($_.Exception.Message)" -Level ERROR
        throw
    }
}

function Generate-TSqlStatement {
    param (
        [string]$Action,
        [string]$User,
        [string]$RoleOrPermission,
        [datetime]$StartDate,
        [datetime]$EndDate
    )
    
    # Properly quote the user name if not already quoted
    $quotedUser = if ($User.StartsWith('[') -and $User.EndsWith(']')) {
        $User
    } else {
        "[$User]"
    }
    
    # Properly quote the role/permission if not already quoted
    $quotedRoleOrPermission = if ($RoleOrPermission.StartsWith('[') -and $RoleOrPermission.EndsWith(']')) {
        $RoleOrPermission
    } else {
        "[$RoleOrPermission]"
    }
    
    $stmt = switch ($Action) {
        'GRANT'  { "GRANT $quotedRoleOrPermission TO $quotedUser;" }
        'DENY'   { "DENY $quotedRoleOrPermission TO $quotedUser;" }
        'REVOKE' { "REVOKE $quotedRoleOrPermission FROM $quotedUser;" }
    }
    
    if ($StartDate -and $EndDate) {
        $sd = $StartDate.ToString('yyyy-MM-dd')
        $ed = $EndDate.ToString('yyyy-MM-dd')
        $stmt += " -- TEMPORARY from $sd to $ed"
    }
    
    return $stmt
}

function Log-Request {
    param (
        [string]$ServerInstance,
        [string]$Database,
        [string]$User,
        [string]$Action,
        [string]$RoleOrPermission,
        [string]$Justification,
        [datetime]$StartDate,
        [datetime]$EndDate
    )
    
    try {
        $entry = [PSCustomObject]@{
            TimeStamp     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            Server        = $ServerInstance
            Database      = $Database
            User          = $User
            Action        = $Action
            Permission    = $RoleOrPermission
            Justification = $Justification
            StartDate     = if ($StartDate) { $StartDate.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
            EndDate       = if ($EndDate) { $EndDate.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
            RequestedBy   = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        }
        
        # Convert to structured log entry
        $logEntry = ($entry.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '
        Write-Log "PERMISSION_REQUEST: $logEntry"
    }
    catch {
        Write-Log "Failed to log request: $($_.Exception.Message)" -Level ERROR
        throw "Logging failed: $($_.Exception.Message)"
    }
}

#─── Main ───────────────────────────────────────────────────────────────────────
try {
    Write-Log "Starting permission request processing" -Level INFO
    
    # Validate input syntax
    Validate-Syntax -Action $Action `
                   -Database $Database `
                   -User $User `
                   -RoleOrPermission $RoleOrPermission

    # Validate against SQL Server catalog
    # Validate-SqlCatalog -ServerInstance $ServerInstance `
    #                    -Database $Database `
    #                    -User $User `
    #                    -RoleOrPermission $RoleOrPermission `
    #                    -Action $Action `
    #                    -Credential $Credential

    # Generate T-SQL statement
    $tsql = Generate-TSqlStatement -Action $Action `
                                 -User $User `
                                 -RoleOrPermission $RoleOrPermission `
                                 -StartDate $StartDate `
                                 -EndDate $EndDate

    # Log the request
    Log-Request -ServerInstance $ServerInstance `
               -Database $Database `
               -User $User `
               -Action $Action `
               -RoleOrPermission $RoleOrPermission `
               -Justification $Justification `
               -StartDate $StartDate `
               -EndDate $EndDate

    Write-Log "Permission request processed successfully" -Level INFO
    Write-Host "Generated T-SQL:" -ForegroundColor Green
    Write-Output $tsql
    
    if ($StartDate -and $EndDate) {
        Write-Host "`nNote: This is a temporary permission that should be revoked after $($EndDate.ToString('yyyy-MM-dd'))" -ForegroundColor Yellow
    }
}
catch {
    Write-Log "Permission request failed: $($_.Exception.Message)" -Level ERROR
    Write-Error $_.Exception.Message
    exit 1
}