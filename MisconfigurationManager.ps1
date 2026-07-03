<#
.SYNOPSIS
Collect information from an SMS Provider and remote site systems to identify the issues described in Misconfiguration Manager

.DESCRIPTION
Author: Chris Thompson (@_Mayyhem)
Version: 1.0

Requirements:
  - Run on an SMS Provider or target one using the -SMSProvider parameter
  - Any SCCM Security Role (e.g., Read-only Analyst or higher)
  - Use the -Verbose option to display the results of checks as they occur

Recommended to improve accuracy and reduce false positives:
  - Local Administrators group privileges on site systems
  - RPC and SMB connectivity to site systems

.PARAMETER SMSProvider
Specify a remote SMS Provider to run the script against.

.PARAMETER Timeout
Increase or decrease the connection timeout for remote site system checks (default: 5 seconds)

.PARAMETER Verbose
Enable verbose logging of script execution events and display check results as they occur.

.EXAMPLE
.\MisconfigurationManager.ps1 -Help
# Display help text

.EXAMPLE
.\MisconfigurationManager.ps1
# Collect information from a local SMS Provider and print only the final results after analysis.

.EXAMPLE
.\MisconfigurationManager.ps1 -SMSProvider <SMS_PROVIDER> -Timeout 2 -Verbose
# Collect information from a remote SMS Provider, give up on failed connections after 2 seconds, and print results as they occur.

.LINK
https://misconfigurationmanager.com

#>

[CmdletBinding()]
param(
    [switch]$Help,
    [string]$SMSProvider,
    [int]$Timeout = 5
)

if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path
    exit
}

if (-not $SMSProvider) {
    $SMSProvider = $env:COMPUTERNAME
}

# Save settings
$originalVerbosePreference = $VerbosePreference
$originalWarningPreference = $WarningPreference


# Determine if the host is the console or ISE
if ($Host.Name -eq 'ConsoleHost') {
    # For the standard console, we use ConsoleColor enum values
    $originalVerboseColor = $Host.PrivateData.VerboseForegroundColor
    $originalVerboseBackgroundColor = $Host.PrivateData.VerboseBackgroundColor
    $originalWarningColor = $Host.PrivateData.WarningForegroundColor
    $originalWarningBackgroundColor = $Host.PrivateData.WarningBackgroundColor
    # Set the foreground colors and set the background colors to match the console's background
    $Host.PrivateData.VerboseForegroundColor = 'Cyan'
    $Host.PrivateData.WarningForegroundColor = 'DarkYellow'
    $Host.PrivateData.VerboseBackgroundColor = $Host.UI.RawUI.BackgroundColor
    $Host.PrivateData.WarningBackgroundColor = $Host.UI.RawUI.BackgroundColor
} elseif ($Host.Name -eq 'Windows PowerShell ISE Host') {
    # For ISE, we use System.Windows.Media.Color values
    $originalVerboseColor = $psISE.Options.VerboseForegroundColor
    $originalWarningColor = $psISE.Options.WarningForegroundColor
    $psISE.Options.VerboseForegroundColor = [System.Windows.Media.Colors]::Cyan
    $psISE.Options.WarningForegroundColor = [System.Windows.Media.Colors]::DarkOrange
}



# Set output preferences
if ($VerbosePreference) {
    $VerbosePreference = 'Continue'
    $WarningPreference = 'Continue'
}
else {
    $VerbosePreference = 'SilentlyContinue'
    $WarningPreference = 'SilentlyContinue'    
}

# Display help text
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path
    exit
}

function Check-AccountIsLocalAdmin {
    param (
        [Parameter(Mandatory = $true)]
        [string]$AccountName,
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    Write-Verbose "    Checking local Administrators group on $ComputerName for account: $AccountName"

    try {
        $scriptBlock = {
            param($AccountName, $ComputerName)
            Get-WmiObject Win32_GroupUser -ComputerName $ComputerName |
            Where-Object { $_.GroupComponent -like '*"Administrators"' } |
            Where-Object { $_.PartComponent -like "*`"$AccountName`"*" } |
            ForEach-Object { $_.PartComponent } |
            ForEach-Object { $_.Split('=')[2].Trim('"') }
        }

        $matchingAdminAccounts = Run-Script -ScriptBlock $scriptBlock -ArgumentList $AccountName, $ComputerName -TimeoutSeconds $Timeout

        # Check succeeded and found a matching account in local Administrators group
        if ($matchingAdminAccounts) {
            return $true
        }

        # Check timed out
        elseif ($matchingAdminAccounts -like "*timed out*") {
            return "Check for local Administrators group members timed out after $Timeout seconds"
        } 

        # Check succeeded but no matches
        else {
            return $false
        }
    }
    catch {
        return "Failed to check local Administrators group members: $($_.ToString())"
    }
}

function Check-IssueStatus {
    param (
        [string]$Issue,
        [bool]$LikelyCondition,
        [bool]$PreventingCondition,
        [string]$LikelyMessage,
        [string]$FailedCheckMessage,
        [string]$PreventingMessage,
        [string]$RolePrefix,
        [ref]$System
    )

    if ($System.Value.IssuesToCheck -contains $Issue) {

        $message = 
        if ($PreventingCondition) { 
            $PreventingMessage
            $System.Value.IssuesToCheck = $System.Value.IssuesToCheck | Where-Object { $_ -ne $Issue }
        }
        elseif ($LikelyCondition) {
            $LikelyMessage
        } 
        else { 
            $FailedCheckMessage
        }
        $System.Value.Output += "$RolePrefix    $message`n"
    }
}

# Function converted to string to load in scriptblock to reduce connection timeouts
$getRegistrySubkeyValueFunction = @'
    function Get-RegistrySubkeyValue {
        param (
            [string]$ComputerName,
            [string]$Hive,
            [string]$SubKeyPath,
            [string]$ValueName
        )

        # Define the registry hive, subkey, and value name you want to read
        $registryHive = if ($Hive) { $Hive } else { [Microsoft.Win32.RegistryHive]::LocalMachine }

        try {
            # Open the remote registry key
            $remoteRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($registryHive, $ComputerName)
            $subKey = $remoteRegistry.OpenSubKey($SubKeyPath)

            # Read the value
            if ($subKey -ne $null) {
                $value = $subKey.GetValue($ValueName)
                # Value not set in registry means default applies (e.g., SMB signing not required = 0)
                if ($value -eq $null) { return 0 }
                return $value
            } else {
                return "Subkey $SubKeyPath not found on $ComputerName"
            }
        } catch {
            return "Failed to read registry on ${ComputerName}: $_"
        } finally {
            if ($subKey -ne $null) {
                $subKey.Close()
            }
            if ($remoteRegistry -ne $null) {
                $remoteRegistry.Close()
            }
        }
    }
'@


function Get-SiteDatabaseEPA {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    # Combine namespace enumeration and EPA query in a single job to avoid double startup overhead
    $scriptBlock = {
        param($computerName)
        try {
            $serverNamespaceRoot = "root\Microsoft\SqlServer"
            $namespaces = Get-WmiObject -ComputerName $computerName -Namespace $serverNamespaceRoot -Class "__NAMESPACE" -ErrorAction Stop
            $cmNamespaces = $namespaces | Where-Object { $_.Name -match "^ComputerManagement\d+$" }

            if ($cmNamespaces) {
                foreach ($namespace in $cmNamespaces) {
                    $fullNamespace = "$serverNamespaceRoot\$($namespace.Name)"
                    $wmiQuery = "SELECT * FROM ServerSettingsExtendedProtection"
                    $extendedProtectionSettings = Get-WmiObject -ComputerName $computerName -Namespace $fullNamespace -Query $wmiQuery -ErrorAction Stop
                    return $extendedProtectionSettings.ExtendedProtection
                }
            }
            else {
                return "No SQL Server ComputerManagement namespace found on $computerName"
            }
        }
        catch {
            if ($_.Exception.Message -match "Access is denied|UnauthorizedAccess") {
                return "Access denied querying WMI on $computerName (local admin required)"
            }
            return "Failed to check EPA on ${computerName}: $($_.Exception.Message)"
        }
    }

    $result = Run-Script -ScriptBlock $scriptBlock -ArgumentList $ComputerName -TimeoutSeconds $Timeout
    if (-not $result -and $result -ne 0) {
        return "Failed to check EPA requirements on $ComputerName"
    }
    if ("$result" -like "*timed out*") {
        return "Check for EPA requirements timed out after $Timeout seconds"
    }
    return $result
}

function Get-SiteSecuritySettings {
    param (
        [string]$Namespace,
        [ref]$Site,
        [string]$SMSProvider
    )

    # Check for Network Access Account (CRED-2, CRED-3, CRED-4)
    Write-Verbose "Checking for Network Access Account configuration in $($Site.Value.SiteCode)"
    try {
        $queryNAA = "SELECT * FROM SMS_SCI_SCPropertyList WHERE SiteCode='$($Site.Value.SiteCode)' AND PropertyListName='Network Access User Names' AND ItemType='SMS_SOFTWARE_DISTRIBUTION_COMPONENT_CONFIG'"
        $naaResult = Get-WmiObject -Namespace $Namespace -Query $queryNAA -ComputerName $SMSProvider -ErrorAction Stop
        if ($naaResult -and $naaResult.Values) {
            $Site.Value.NAAConfigured = $true
            Write-Warning "    Network Access Account is configured (CRED-2, CRED-3, CRED-4 possible)"
            foreach ($account in $naaResult.Values) {
                Write-Warning "        NAA: $account"
            }
        }
        else {
            $Site.Value.NAAConfigured = $false
            Write-Verbose "    Network Access Account is not configured"
        }
    }
    catch {
        Write-Warning "    Failed to check Network Access Account: $($_.Exception.Message)"
    }

    # Check for Enhanced HTTP (CRED-2, PREVENT-4)
    Write-Verbose "Checking Enhanced HTTP configuration in $($Site.Value.SiteCode)"
    try {
        $queryEHTTP = "SELECT * FROM SMS_SCI_SCProperty WHERE SiteCode='$($Site.Value.SiteCode)' AND PropertyName='IsEnhancedHTTPEnabled' AND ItemType='SMS_SCI_SiteDefinition'"
        $ehttpResult = Get-WmiObject -Namespace $Namespace -Query $queryEHTTP -ComputerName $SMSProvider -ErrorAction Stop
        if ($ehttpResult -and $ehttpResult.Value -eq 1) {
            $Site.Value.EnhancedHTTPEnabled = $true
            Write-Verbose "    Enhanced HTTP is enabled"
        }
        else {
            $Site.Value.EnhancedHTTPEnabled = $false
            Write-Warning "    Enhanced HTTP is not enabled (CRED-2 more likely)"
        }
    }
    catch {
        Write-Warning "    Failed to check Enhanced HTTP: $($_.Exception.Message)"
    }

    # Check PKI client certificate requirement (CRED-2, PREVENT-8)
    Write-Verbose "Checking PKI client certificate requirements in $($Site.Value.SiteCode)"
    try {
        $queryPKI = "SELECT * FROM SMS_SCI_SCProperty WHERE SiteCode='$($Site.Value.SiteCode)' AND PropertyName='Certificate' AND ItemType='SMS_SCI_SiteDefinition'"
        $pkiResult = Get-WmiObject -Namespace $Namespace -Query $queryPKI -ComputerName $SMSProvider -ErrorAction Stop
        if ($pkiResult -and $pkiResult.Value1 -eq "Required") {
            $Site.Value.PKIRequired = $true
            Write-Verbose "    PKI client certificates are required"
        }
        else {
            $Site.Value.PKIRequired = $false
            Write-Warning "    PKI client certificates are not required (CRED-2 more likely)"
        }
    }
    catch {
        Write-Warning "    Failed to check PKI requirements: $($_.Exception.Message)"
    }
}

function Get-SiteHierarchy {
    param (
        [string]$Namespace,
        [string]$ParentSiteCode = $null,
        [string]$SMSProvider
    )

    # Initialize output variable, a list of sites in the hierarchy
    $siteHierarchy = @()

    # Query the top level site first
    $filter = if ($ParentSiteCode) { "ParentSiteCode = '$ParentSiteCode'" } else { "ParentSiteCode = ''" }
    Write-Verbose "Querying $($Namespace).SMS_SCI_SiteDefinition for the list of sites with parent: $ParentSiteCode"

    $scriptBlock = { 
        param($Namespace, $Filter, $SMSProvider)
        return Get-WmiObject -Namespace $Namespace -Class SMS_SCI_SiteDefinition -Filter $Filter -ComputerName $SMSProvider
    }

    $sites = Run-Script -ScriptBlock $scriptBlock -ArgumentList $Namespace, $filter, $SMSProvider -TimeoutSeconds $Timeout
        
    # Exit loop if job times out or isn't completed
    if ($sites) {
        if ($sites -like "*timed out*") {
            Write-Warning "Query timed out: $ParentSiteCode doesn't have any child sites or the site database is offline"
            return
        }
        elseif ($sites[0].ToString() -like "*PSRemotingJob") {
            Write-Warning "The timeout is too short for jobs to finish"
            return
        }
    }

    foreach ($site in $sites) {
        
        Write-Verbose ("Gathering data for site: {0} ({1})" -f $site.SiteName, $site.SiteCode)

        $currentSite = @{
            "AutomaticClientPush"      = $null
            "ClearClientInstalledFlag" = $null
            "ClientPushAccounts"       = @()
            "ClientPushTargets"        = $null
            "EnhancedHTTPEnabled"      = $null
            "FallbackToNTLM"           = $null
            "NAAConfigured"            = $null
            "ParentSiteCode"           = $site.ParentSiteCode
            "PKIRequired"              = $null
            "SiteCode"                 = $site.SiteCode
            "SiteName"                 = $site.SiteName
            "SiteServerName"           = $site.SiteServerName
            "SiteSystems"              = @()
            "Type"                     = $site.SiteType
            "TypeDepth"                = $null
            "TypeName"                 = $null
        }

        # Get the hierarchy level
        $currentSite = Get-SiteType -Site $([ref]$currentSite)
        Write-Verbose ("{0} is a {1}" -f $currentSite.SiteName, $currentSite.TypeName)

        # Indent based on the hierarchy level
        $indent = " " * ($currentSite.TypeDepth * 4)

        # Query other site system roles
        Get-SiteSystems -Namespace $Namespace -Site $([ref]$currentSite) -Indent ($Indent + "   ") -SMSProvider $SMSProvider

        # Get site-level security settings for primary sites
        if ($currentSite.Type -eq 2) {
            Get-SiteSecuritySettings -Namespace $namespace -Site $([ref]$currentSite) -SMSProvider $SMSProvider
            Get-SitePushSettings -Namespace $namespace -Site $currentSite -ComputerName $SMSProvider
        }
        
        # Add the site to the list of sites
        $siteHierarchy += $currentSite

        # Recursive call for child sites excluding secondary sites
        Get-SiteHierarchy -Namespace $Namespace -ParentSiteCode $site.SiteCode -SMSProvider $SMSProvider
    }
    return $siteHierarchy
}

function Get-SiteNamespace {
    param (
        [string]$SMSProvider
    )

    # Query WMI to get all SMS namespaces
    Write-Verbose "Looking for site namespace in root\SMS on $SMSProvider"
    try {
        $namespaces = Get-WmiObject -Namespace "root\SMS" -Class "__NAMESPACE" -ComputerName $SMSProvider -ErrorAction Stop
    } 
    
    catch {
        Write-Warning "Could not find root\SMS namespace. Is $SMSProvider an SMS Provider?"
        exit
    }

    $foundNamespace = $null

    foreach ($ns in $namespaces) {
        # Check if the namespace is like SMS_<SiteCode>
        if ($ns.Name -match '^site_') {
            $foundNamespace = "root\SMS\" + $ns.Name
            break
        }
    }
    Write-Verbose "Found $foundNamespace on $SMSProvider"
    return $foundNamespace
}

function Get-SitePushSettings {
    param (
        [string]$ComputerName,
        [string]$Namespace,
        $Site
    )

    Write-Verbose "Querying client push installation settings for $($Site.SiteCode)"

    $queryAutomaticClientPush = "SELECT PropertyName, Value, Value1 FROM SMS_SCI_SCProperty WHERE SiteCode='$($Site.SiteCode)' AND ItemType='SMS_DISCOVERY_DATA_MANAGER' AND PropertyName='SETTINGS'"
    try {
        $result = Get-WmiObject -Namespace $Namespace -Query $queryAutomaticClientPush -ComputerName $ComputerName
        if ($result) {
            if ($result.Value1 -eq "Active") {
                Write-Warning "    Automatic site-wide client push installation is enabled"
                $Site.AutomaticClientPush = $true
            }
            elseif ($result.Value1 -eq "INACTIVE") {
                Write-Verbose "    Automatic site-wide client push installation is not enabled"
                $Site.AutomaticClientPush = $false
            }
            else {
                Write-Warning "    Check for automatic site-wide client push installation settings failed"
            }
        }
    }
    catch {
        Write-Warning "    An error occurred while querying client push settings for site $($siteCode.SiteCode): $($_.Exception.Message)" -ErrorAction 'Continue'
    }


    $queryFallbackToNTLM = "SELECT PropertyName, Value, Value1 FROM SMS_SCI_SCProperty WHERE SiteCode='$($Site.SiteCode)' AND ItemType='SMS_DISCOVERY_DATA_MANAGER' AND PropertyName='ENABLEKERBEROSCHECK'"
    try {
        $result = Get-WmiObject -Namespace $Namespace -Query $queryFallbackToNTLM -ComputerName $ComputerName
        if ($result) {
            if ($result.Value -eq 3) {
                Write-Warning "    Fallback to NTLM is enabled"
                $Site.FallbackToNTLM = $true
            }
            elseif ($result.Value -eq 2) {
                Write-Verbose "    Fallback to NTLM is not enabled"
                $Site.FallbackToNTLM = $false
            }
            else {
                Write-Warning "    Check for fallback to NTLM setting failed"
            }
        }
    }
    catch {
        Write-Warning "    An error occurred while querying client push settings for site $($siteCode.SiteCode): $($_.Exception.Message)" -ErrorAction 'Continue'
    }

    if ($Site.AutomaticClientPush -and $Site.FallbackToNTLM) {
        $queryClientPushTargets = "SELECT PropertyName, Value, Value1 FROM SMS_SCI_SCProperty WHERE SiteCode='$($Site.SiteCode)' AND ItemType='SMS_DISCOVERY_DATA_MANAGER' AND PropertyName='FILTERS'"
        try {
            $result = Get-WmiObject -Namespace $Namespace -Query $queryClientPushTargets -ComputerName $ComputerName
            if ($result) {
                Write-Warning "    Install client software on the following computers:"
                $Site.ClientPushTargets =
                switch ($result.Value) {
                    0 { "Workstations and Servers (including domain controllers)" }
                    1 { "Servers only (including domain controllers)" }
                    2 { "Workstations and Servers (excluding domain controllers)" }
                    3 { "Servers only (excluding domain controllers)" }
                    4 { "Workstations and domain controllers only (excluding other servers)" }
                    5 { "Domain controllers only" }
                    6 { "Workstations only" }
                    7 { "No computers" }
                }
                Write-Warning $Site.ClientPushTargets
            }
            else {
                Write-Warning "    Check for client push targets failed"
            }

            $queryAccounts = "SELECT Values FROM SMS_SCI_SCPropertyList WHERE PropertyListName='Reserved2' AND SiteCode='$($Site.SiteCode)'"
            $accounts = Get-WmiObject -Namespace $Namespace -Query $queryAccounts -ComputerName $ComputerName
            if ($accounts.Values) {
                $uniqueAccounts = $accounts.Values | Select-Object -Unique
                foreach ($value in $uniqueAccounts) {
                    Write-Warning "    Discovered client push installation account: $value"
                    $Site.ClientPushAccounts += $value
                }
            }
            else {
                Write-Warning "    No client push installation accounts were configured, but the server may still use its machine account"

            }

            # Always add the site server computer account to client installation accounts
            $Site.ClientPushAccounts += "$($Site.SiteServerName.Split('.')[0])$"

            $queryTask = "SELECT * FROM SMS_SCI_SQLTask WHERE ItemName='Clear Undiscovered Clients'"
            $task = Get-WmiObject -Namespace $Namespace -Query $queryTask -ComputerName $ComputerName
            if ($task.Enabled -eq $true) {
                Write-Warning "    The client installed flag is automatically cleared on inactive clients after $($task.DeleteOlderThan) days, resulting in automatic client push for reinstallation"
                $Site.ClearClientInstalledFlag = $true
            }
            elseif ($task.Enabled -eq $false) {
                Write-Verbose "    The client installed flag is not automatically cleared on inactive clients, preventing automatic reinstallation"
                $Site.ClearClientInstalledFlag = $false
            }
            else {
                Write-Verbose "    Check for clear client installed flag failed"
            }
        }
        catch {
            Write-Warning "    An error occurred while querying client push settings for site $($siteCode.SiteCode): $($_.Exception.Message)" -ErrorAction 'Continue'
        }
    }
}

function Get-SiteSystems {
    param (
        [string]$Namespace,
        [ref]$Site,
        [string]$SMSProvider
    )

    # Query SMS_SCI_SysResUse class for site system roles
    Write-Verbose "Querying the list of systems in $($Site.Value.SiteCode)"
    $siteSystemRoles = Get-WmiObject -Namespace $Namespace -Class SMS_SCI_SysResUse -Filter "SiteCode = '$($Site.Value.SiteCode)'" -ComputerName $SMSProvider

    # Group roles by NetworkOSPath
    $siteSystems = $siteSystemRoles | Group-Object -Property NetworkOSPath

    foreach ($siteSystem in $siteSystems) {

        $siteSystemName = $siteSystem.Name.TrimStart('\')
        Write-Verbose "Collecting data for $siteSystemName"
        $isRemote = $siteSystemName -ne $Site.Value.SiteServerName

        $currentSiteSystem = @{
            # Check whether the role is on a remote server (not the site server), making NTLM relay possible
            "Name"               = $siteSystemName
            "EPARequired"        = $null
            "IsRemote"           = $isRemote
            "IssuesToCheck"      = @()
            "Output"             = $null
            "PXEEnabled"         = $null
            "SiteCode"           = $Site.Value.SiteCode
            "SiteSystemRoles"    = @()
            "SMBSigningRequired" = $null
            "WebClientStatus"    = $null
        }

        foreach ($role in $siteSystem.Group) {                       
            $currentSiteSystem.SiteSystemRoles += $role.RoleName
            Write-Verbose "    $($role.RoleName)"
        }

        # Check SMB signing requirements for TAKEOVER-2, TAKEOVER-4, TAKEOVER-6, TAKEOVER-7, and ELEVATE-1
        Write-Verbose "    Collecting SMB signing requirements"
        $currentSiteSystem.SMBSigningRequired = Get-SMBSigningRequirement -ComputerName $currentSiteSystem.Name

        if ($currentSiteSystem.IsRemote) {

            foreach ($role in $siteSystem.Group) {   

                if ($role.RoleName -eq "SMS SQL Server" -and $Site.Type -ne 1) {
                    $currentSiteSystem.IssuesToCheck += "TAKEOVER-1", "TAKEOVER-2"

                    # TAKEOVER-2
                    Print-SMBSigningStatus -CurrentSiteSystem $currentSiteSystem -Issue "TAKEOVER-2"

                    # TAKEOVER-1
                    Write-Verbose "    Collecting EPA requirements"
                    $currentSiteSystem.EPARequired = Get-SiteDatabaseEPA -ComputerName $currentSiteSystem.Name

                    if ($currentSiteSystem.EPARequired -eq 2) {
                        Write-Verbose "        EPA required: True" 
                    }
                    elseif ($currentSiteSystem.EPARequired -lt 2) {
                        Write-Warning "        EPA required: False (TAKEOVER-1 likely!)" 
                    }
                    else { 
                        Write-Warning "        $($currentSiteSystem.EPARequired) (check TAKEOVER-1 manually)"
                    }
                }
                
                elseif ($role.RoleName -eq "SMS Provider") {
                    $currentSiteSystem.IssuesToCheck += "TAKEOVER-5", "TAKEOVER-6"
                    # CRED-7: AdminService on remote SMS Provider exposes credential retrieval API
                    $currentSiteSystem.IssuesToCheck += "CRED-7"

                    # TAKEOVER-5 cannot be prevented on the relay target because AdminService does not support EPA

                    # TAKEOVER-6
                    if ($currentSiteSystem.SMBSigningRequired -eq 1) {
                        $currentSiteSystem.IssuesToCheck = $currentSiteSystem.IssuesToCheck | Where-Object { $_ -ne "TAKEOVER-6" }
                    }
                    Print-SMBSigningStatus -CurrentSiteSystem $currentSiteSystem -Issue "TAKEOVER-6"
                }

                elseif ($role.RoleName -eq "SMS Distribution Point") {
                    # CRED-6: DP shares may expose content with credentials
                    $currentSiteSystem.IssuesToCheck += "CRED-6"

                    # Check PXE status for CRED-1 and ELEVATE-4
                    $pxeProp = $role.Props | Where-Object { $_.PropertyName -eq "IsPXE" }
                    if ($pxeProp -and $pxeProp.Value -eq 1) {
                        $currentSiteSystem.PXEEnabled = $true
                        $currentSiteSystem.IssuesToCheck += "CRED-1", "ELEVATE-4", "ELEVATE-5"
                        Write-Warning "    PXE is enabled (CRED-1 and ELEVATE-4 likely!)"
                    }
                    else {
                        $currentSiteSystem.PXEEnabled = $false
                        Write-Verbose "    PXE is not enabled"
                        # ELEVATE-5 is still possible via OSD media on any DP
                        $currentSiteSystem.IssuesToCheck += "ELEVATE-5"
                    }
                }

                elseif ($role.RoleName -eq "SMS Management Point") {
                    # CRED-8: If MP is remote from DB, relay attack is possible
                    $currentSiteSystem.IssuesToCheck += "CRED-8"
                    Write-Verbose "    Remote management point detected (check CRED-8: MP relay to site DB)"
                }

                # Add ELEVATE-1 if no TAKEOVER techniques are present
                elseif ($currentSiteSystem.IssuesToCheck -notcontains "ELEVATE-1" -and ($currentSiteSystem.IssuesToCheck -match '^TAKEOVER.*').Count -eq 0) {
                    $currentSiteSystem.IssuesToCheck += "ELEVATE-1"
                    Print-SMBSigningStatus -CurrentSiteSystem $currentSiteSystem -Issue "ELEVATE-1"
                }
            }

            # This is a site server
        }
        else {

            # Don't add TAKEOVERs to secondary site servers
            if ($Site.Value.Type -ne 1) {

                # TAKEOVER-3 is applicable if AD CS is in use (check manually)
                $currentSiteSystem.IssuesToCheck += "TAKEOVER-3"

                # TAKEOVER-7 is applicable to sites with passive site servers
                if ($currentSiteSystem.Name -ne $Site.Value.SiteServerName) {
                    $currentSiteSystem.IssuesToCheck += "TAKEOVER-7"
                    Write-Verbose "    This system is a passive site server"
                    Print-SMBSigningStatus -CurrentSiteSystem $currentSiteSystem -Issue "TAKEOVER-7"
                } 
                
                # Print the SMB signing status even if no attack techniques are detected
                else {
                    if ($currentSiteSystem.SMBSigningRequired -eq 1) {
                        Write-Verbose "        SMB signing required: True"
                    }
                    elseif ($currentSiteSystem.SMBSigningRequired -eq 0) {
                        Write-Warning "        SMB signing required: False"
                    }
                    else {
                        Write-Warning "        SMB signing required: $($CurrentSiteSystem.SMBSigningRequired)"
                    }
                }

                # CRED-5: Site database credentials are recoverable from the site server
                $currentSiteSystem.IssuesToCheck += "CRED-5"

                # COERCE-1: CMPivot can coerce NTLM auth from clients
                $currentSiteSystem.IssuesToCheck += "COERCE-1"

                # Check for colocated DP with PXE on site server
                foreach ($role in $siteSystem.Group) {
                    if ($role.RoleName -eq "SMS Distribution Point") {
                        $currentSiteSystem.IssuesToCheck += "CRED-6"
                        $pxeProp = $role.Props | Where-Object { $_.PropertyName -eq "IsPXE" }
                        if ($pxeProp -and $pxeProp.Value -eq 1) {
                            $currentSiteSystem.PXEEnabled = $true
                            $currentSiteSystem.IssuesToCheck += "CRED-1", "ELEVATE-4", "ELEVATE-5"
                            Write-Warning "    PXE is enabled on colocated DP (CRED-1 and ELEVATE-4 likely!)"
                        }
                        else {
                            $currentSiteSystem.PXEEnabled = $false
                            $currentSiteSystem.IssuesToCheck += "ELEVATE-5"
                        }
                    }
                }

                # TAKEOVER-8 is applicable if WebClient is running on the site server
                $currentSiteSystem.IssuesToCheck += "TAKEOVER-8"
                Write-Verbose "    Collecting WebClient service status"
                $currentSiteSystem.WebClientStatus = Get-WebClientService -ComputerName $siteSystemName

                if ($currentSiteSystem.WebClientStatus -eq "Not installed") {
                    Write-Verbose "        WebClient: Not installed, preventing TAKEOVER-8"
                }
                elseif ($currentSiteSystem.WebClientStatus -eq "Running") {
                    Write-Warning "        WebClient: Running (TAKEOVER-8 likely!)"
                }
                elseif ($currentSiteSystem.WebClientStatus -eq "Installed") {
                    Write-Warning "        WebClient: Installed (TAKEOVER-8 possible if it ever starts!)"
                }
                else {
                    Write-Warning "        WebClient check failed, validate TAKEOVER-8 manually"
                }
            }

            # Add ELEVATE-1 to secondary site servers
            else {
                $currentSiteSystem.IssuesToCheck += "ELEVATE-1"
                Print-SMBSigningStatus -CurrentSiteSystem $currentSiteSystem -Issue "ELEVATE-1"
            }
            
            # Get site server computer account name from CAS, which should be processed first
            if ($Site.Value.Type -eq 4) { 
                $Global:casComputerAccount = "$($Site.Value.SiteServerName.Split('.')[0])$"
            }
            
            # TAKEOVER-4 Check whether the CAS computer account is a local admin on primary site servers
            elseif ($Site.Value.Type -eq 2 -and $Global:casComputerAccount) {
                $currentSiteSystem.IssuesToCheck += "TAKEOVER-4"
                $isLocalAdmin = Check-AccountIsLocalAdmin -AccountName $casComputerAccount -ComputerName $currentSiteSystem.Name
                if ($casComputerAccount -eq $isLocalAdmin) {
                    Write-Warning "        $casComputerAccount is a local admin on $currentSiteSystem.Name (TAKEOVER-4 possible)"
                    Print-SMBSigningStatus -CurrentSiteSystem $currentSiteSystem -Issue "TAKEOVER-4"
                }
                elseif ($isLocalAdmin -contains "Failed") {
                    Write-Warning "        Failed to check whether $casComputerAccount is a local admin on $($currentSiteSystem.Name) (check TAKEOVER-4 manually)"
                    Print-SMBSigningStatus -CurrentSiteSystem $currentSiteSystem -Issue "TAKEOVER-4"
                }
                else {
                    Write-Verbose "        $casComputerAccount is not a local admin on $($currentSiteSystem.Name)"
                }
            }
        }

        # Add the current site system to the site
        $Site.Value.SiteSystems += $currentSiteSystem
    }
}

function Get-SiteType {
    param (
        [Parameter(Mandatory = $true)]
        [ref]$Site
    )

    if ($Site.Value.Type -eq 1) {
        $Site.Value.TypeName = "secondary site"
        $Site.Value.TypeDepth = 3
    }
    elseif ($Site.Value.Type -eq 2) {
        $Site.Value.TypeName = "primary site"
        $Site.Value.TypeDepth = 2
    }
    elseif ($Site.Value.Type -eq 4) {
        $Site.Value.TypeName = "central administration site"
        $Site.Value.TypeDepth = 1
    }
    return $Site.Value
}

function Get-SMBSigningRequirement {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    $subKeyPath = "System\CurrentControlSet\Services\LanManServer\Parameters"
    $valueName = "RequireSecuritySignature"

    # Try direct remote registry access first (avoids ~2-3s job startup overhead)
    try {
        $remoteRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $ComputerName)
        $subKey = $remoteRegistry.OpenSubKey($subKeyPath)
        if ($subKey -ne $null) {
            $value = $subKey.GetValue($valueName)
            $subKey.Close()
            $remoteRegistry.Close()
            # Value not set in registry means SMB signing is not required (default: 0)
            if ($value -eq $null) { return 0 }
            return $value
        }
        else {
            if ($remoteRegistry) { $remoteRegistry.Close() }
            return "Registry subkey not found on $ComputerName"
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        if ($errorMessage -match "access is not allowed|Access is denied|UnauthorizedAccess") {
            return "Access denied reading registry on $ComputerName (local admin required)"
        }
        Write-Verbose "    Direct registry access failed for $ComputerName, falling back to job-based approach"
    }

    # Fall back to job-based approach with timeout for unreachable/slow hosts
    $scriptBlock = {
        param($functionString, $computerName, $subKeyPath, $valueName)
        try {
            Invoke-Expression $functionString
            $requireSecuritySignature = Get-RegistrySubkeyValue -ComputerName $computerName -SubKeyPath $subKeyPath -ValueName $valueName
            # Value not set in registry means SMB signing is not required (default: 0)
            if ($requireSecuritySignature -eq $null) { return 0 }
            return $requireSecuritySignature
        }
        catch {
            return "Failed to read registry on ${computerName}: $($_.Exception.Message)"
        }
    }

    try {
        $requireSecuritySignature = Run-Script -ScriptBlock $scriptBlock -ArgumentList $getRegistrySubkeyValueFunction, $ComputerName, $subKeyPath, $valueName -TimeoutSeconds $Timeout
        if ($requireSecuritySignature -like "*timed out*") {
            return "Check for SMB signing requirements timed out after $Timeout seconds"
        }
        return $requireSecuritySignature
    }
    catch {
        return "Failed to check SMB signing requirements: $($_.ToString())"
    }
}

function Get-WebClientService {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    try {
        # Check if the remote computer is accessible within 3 seconds
        $ping = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet
        if ($ping) {
            $service = Get-Service -Name WebClient -ComputerName $ComputerName -ErrorAction Stop
            return $service.Status
        }
        else {
            return "Failed to connect to $ComputerName to check for WebClient"
        }
    }
    catch {
        return "Failed to connect or an unexpected error occurred while checking for WebClient"
    }
}

function Print-SiteStructure {
    param (
        [Parameter(Mandatory = $true)]
        $Site,
        [string]$Indent = "",
        [array]$AllSites
    )

    try {
        # Determine if there are any child sites for this site
        $childSites = $AllSites | Where-Object { $_.ParentSiteCode -eq $Site.SiteCode }
        $hasChildSites = $childSites.Count -gt 0

        # Display the current site details
        $siteDetails = "Site Code: $($Site.SiteCode), Name: $($Site.SiteName), Site Server: $($Site.SiteServerName)"
        if ($Site.ParentSiteCode) {
            $siteDetails += ", Reporting to: $($Site.ParentSiteCode)"
        }

        # Link site to parent in tree and add space between items
        $siteIndent = if ($Site.ParentSiteCode -and $hasChildSites) { $Indent.Substring(0, $Indent.Length - 4) + "├───" }
        elseif ($Site.ParentSiteCode) { $Indent.Substring(0, $Indent.Length - 4) + "└───" }
        else { $Indent }

        $afterDetailsSpace =
        # This site has child sites
        if ($hasChildSites) {
            " │   " * $Site.TypeDepth
        }
        # This is a standalone primary site
        elseif ($Indent.Length -eq 0) {
            " │   "
        }
        # This is a descendent site
        else {
            $Indent.Substring(0, $Indent.Length - 4) + "     │" 
        }

        Write-Host "$siteIndent$siteDetails`n$afterDetailsSpace"
    
        # Print client push settings for primary sites
        if ($Site.Type -eq 2) {
            if ($Site.AutomaticClientPush -eq $true) {
                Write-Host "$Indent ├───Automatic site-wide client push installation is enabled"

                # Print relevant settings if automatic push is enabled
                if ($Site.FallbackToNTLM -eq $true) {
                    Write-Host "$Indent │       Fallback to NTLM is enabled (ELEVATE-2 and ELEVATE-3 likely!)"
                }
                elseif ($Site.FallbackToNTLM -eq $false) {
                    Write-Host "$Indent │       Fallback to NTLM is not enabled"
                }
                else {
                    Write-Host "$Indent │       Check for fallback to NTLM setting failed"
                }

                Write-Host "$Indent │       Install client software on the following computers:"
                Write-Host "$Indent │           $($Site.ClientPushTargets)"
                Write-Host "$Indent │       Discovered client push installation accounts:"
                if ($Site.ClientPushAccounts.Count -gt 0) {
                    foreach ($value in $Site.ClientPushAccounts) {
                        Write-Host "$Indent │           $value"
                    }
                }
                else {
                    Write-Host "$Indent │           No client push installation accounts were configured, but the server may still use its machine account"
                }

                if ($Site.ClearClientInstalledFlag -eq $true) {
                    Write-Host "$Indent │       The client installed flag is automatically cleared on inactive clients, resulting in automatic client push for reinstallation"
                }
                else {
                    Write-Host "$Indent │       The client installed flag is not automatically cleared on inactive clients, preventing automatic reinstallation"
                }
            }
            elseif ($Site.AutomaticClientPush -eq $false) {
                Write-Host "$Indent ├───Automatic site-wide client push installation is not enabled"
            }
            else {
                Write-Host "$Indent ├───Check for automatic site-wide client push installation settings failed"
            }
            Write-Host "$Indent │"
        }

        # Get primary site server object
        $primarySiteServer = $Site.SiteSystems | Where-Object { $_.Name.TrimStart('\') -eq $Site.SiteServerName }

        # Display site systems
        $siteSystemCount = $Site.SiteSystems.Count

        foreach ($system in $Site.SiteSystems) {

            # Remove ELEVATE-1 if any TAKEOVER is present
            if ($system.IssuesToCheck -contains "ELEVATE-1" -and ($system.IssuesToCheck -match '^TAKEOVER.*').Count -gt 0) {
                $system.IssuesToCheck = $system.IssuesToCheck | Where-Object { $_ -ne "ELEVATE-1" }
            }

            # Do not continue tree structure if on the last system in the site
            $siteSystemCount--
            $isLastSystem = $siteSystemCount -eq 0

            if ($isLastSystem -and -not $hasChildSites) { 
                # This is a standalone primary site    
                if ($Indent.Length -eq 0) {
                    $systemPrefix = " └───"
                }
                # This is a descendent site
                else {
                    $systemPrefix = $Indent.Substring(0, $Indent.Length - 4) + "     └───"
                }
            }
            # This site has child sites
            else {
                $systemPrefix = "$Indent ├───"
            }

            $remoteText = if ($system.IsRemote) { " (Remote: True)" } else { "" }
            $system.Output = "$systemPrefix$($system.Name)$remoteText`n"

            # Do not continue tree structure if on the last role in the site
            $roleCount = $system.SiteSystemRoles.Count
            foreach ($role in $system.SiteSystemRoles) {
                $roleCount--

                if ($isLastSystem -and -not $hasChildSites) {
                    # This is a standalone primary site 
                    if ($Indent.Length -eq 0) {
                        $rolePrefix = "        "
                    }
                    # This is a descendent site
                    else {
                        $rolePrefix = $Indent.Substring(0, $Indent.Length - 4) + "            "
                    }
                } 
                else {
                    $rolePrefix = "$Indent │     "
                }

                $system.Output += "$rolePrefix $role`n"

                # Issue details
                if ($role -eq "SMS SQL Server") {
                
                    # TAKEOVER-1
                    Check-IssueStatus -Issue "TAKEOVER-1" `
                        -FailedCheckMessage "EPA check failed, validate TAKEOVER-1 manually" `
                        -LikelyCondition ($system.EPARequired -lt 2) `
                        -LikelyMessage "EPA not required, TAKEOVER-1 likely!" `
                        -PreventingCondition ($system.EPARequired -eq 2) `
                        -PreventingMessage "EPA required, preventing TAKEOVER-1" `
                        -RolePrefix $rolePrefix `
                        -System $([ref]$system)

                    # TAKEOVER-2
                    Check-IssueStatus -Issue "TAKEOVER-2" `
                        -FailedCheckMessage "SMB signing check failed, validate TAKEOVER-2 manually" `
                        -LikelyCondition ($system.SMBSigningRequired -eq 0) `
                        -LikelyMessage "SMB signing not required, TAKEOVER-2 likely!" `
                        -PreventingCondition ($system.SMBSigningRequired -eq 1) `
                        -PreventingMessage "SMB signing required, preventing TAKEOVER-2" `
                        -RolePrefix $rolePrefix `
                        -System $([ref]$system)

                    # TAKEOVER-9: Check manually for SQL Server linked servers with DBA privileges
                    if ($system.IssuesToCheck -notcontains "TAKEOVER-9") {
                        $system.IssuesToCheck += "TAKEOVER-9"
                    }
                    $system.Output += "$rolePrefix    TAKEOVER-9: Check for SQL linked servers with DBA privileges manually`n"
                }

                elseif ($role -eq "SMS Distribution Point") {

                    # CRED-1
                    Check-IssueStatus -Issue "CRED-1" `
                        -FailedCheckMessage "PXE check inconclusive, validate CRED-1 manually" `
                        -LikelyCondition ($system.PXEEnabled -eq $true) `
                        -LikelyMessage "PXE enabled, CRED-1 likely!" `
                        -PreventingCondition ($system.PXEEnabled -eq $false) `
                        -PreventingMessage "PXE not enabled, preventing CRED-1" `
                        -RolePrefix $rolePrefix `
                        -System $([ref]$system)

                    # CRED-6
                    if ($system.IssuesToCheck -contains "CRED-6") {
                        $system.Output += "$rolePrefix    CRED-6: DP shares may expose content with hardcoded credentials`n"
                    }

                    # ELEVATE-4
                    Check-IssueStatus -Issue "ELEVATE-4" `
                        -FailedCheckMessage "PXE PKI check inconclusive, validate ELEVATE-4 manually" `
                        -LikelyCondition ($system.PXEEnabled -eq $true) `
                        -LikelyMessage "PXE enabled, ELEVATE-4 possible if PKI certs are in use!" `
                        -PreventingCondition ($system.PXEEnabled -eq $false) `
                        -PreventingMessage "PXE not enabled, preventing ELEVATE-4" `
                        -RolePrefix $rolePrefix `
                        -System $([ref]$system)

                    # ELEVATE-5
                    if ($system.IssuesToCheck -contains "ELEVATE-5") {
                        $system.Output += "$rolePrefix    ELEVATE-5: OSD media on this DP may contain recoverable PKI certificates`n"
                    }
                }

                elseif ($role -eq "SMS Site Server") {

                    # CRED-5
                    if ($system.IssuesToCheck -contains "CRED-5") {
                        $system.Output += "$rolePrefix    CRED-5: Site server access allows recovery of encrypted credentials from site DB`n"
                    }

                    # COERCE-1
                    if ($system.IssuesToCheck -contains "COERCE-1") {
                        $system.Output += "$rolePrefix    COERCE-1: CMPivot can coerce NTLM authentication from managed clients`n"
                    }

                    # TAKEOVER-3

                    # TAKEOVER-4
                    Check-IssueStatus -Issue "TAKEOVER-4" `
                        -FailedCheckMessage "SMB signing check failed, validate TAKEOVER-4 manually" `
                        -LikelyCondition ($system.SMBSigningRequired -eq 0) `
                        -LikelyMessage "SMB signing not required, TAKEOVER-4 likely!" `
                        -PreventingCondition ($system.SMBSigningRequired -eq 1) `
                        -PreventingMessage "SMB signing required, preventing TAKEOVER-4" `
                        -RolePrefix $rolePrefix `
                        -System $([ref]$system)

                    # TAKEOVER-7 check on both active and passive site servers
                    if ($system.IssuesToCheck -contains "TAKEOVER-7" -and $primarySiteServer.IssuesToCheck -notcontains "TAKEOVER-7") {
                        $primarySiteServer.IssuesToCheck += "TAKEOVER-7"
                    }

                    # Active site server
                    Check-IssueStatus -Issue "TAKEOVER-7" `
                        -FailedCheckMessage "SMB signing check failed, validate TAKEOVER-7 manually" `
                        -LikelyCondition ($primarySiteServer.SMBSigningRequired -eq 0) `
                        -LikelyMessage "SMB signing not required, TAKEOVER-7 likely!" `
                        -PreventingCondition ($primarySiteServer.SMBSigningRequired -eq 1) `
                        -PreventingMessage "SMB signing required, preventing TAKEOVER-7" `
                        -RolePrefix $rolePrefix `
                        -System $([ref]$primarySiteServer)

                    # Passive site servers
                    Check-IssueStatus -Issue "TAKEOVER-7" `
                        -FailedCheckMessage "SMB signing check failed, validate TAKEOVER-7 manually" `
                        -LikelyCondition ($system.SMBSigningRequired -eq 0) `
                        -LikelyMessage "SMB signing not required, TAKEOVER-7 likely!" `
                        -PreventingCondition ($system.SMBSigningRequired -eq 1) `
                        -PreventingMessage "SMB signing required, preventing TAKEOVER-7" `
                        -RolePrefix $rolePrefix `
                        -System $([ref]$system)
                
                    # TAKEOVER-8
                    if ($system.IssuesToCheck -contains "TAKEOVER-8") {
                        $message = 
                        if ($system.WebClientStatus -eq "Not installed") {
                            "WebClient not installed, preventing TAKEOVER-8"
                            $system.IssuesToCheck = $system.IssuesToCheck | Where-Object { $_ -ne "TAKEOVER-8" }
                        } 
                        elseif ($system.WebClientStatus -eq "Running") {
                            "WebClient running, TAKEOVER-8 likely!"
                        } 
                        elseif ($system.WebClientStatus -eq "Installed") {
                            "WebClient installed, TAKEOVER-8 possible if it ever starts!"
                        } 
                        else {
                            "WebClient check failed, validate TAKEOVER-8 manually"
                        }
                        $system.Output += "$rolePrefix    $message`n"
                    }
                }
            
                elseif ($role -eq "SMS Management Point") {

                    # CRED-8
                    if ($system.IssuesToCheck -contains "CRED-8") {
                        $system.Output += "$rolePrefix    CRED-8: Remote MP can be relayed to site DB for credential extraction`n"
                    }
                }

                elseif ($role -eq "SMS Provider") {

                    # CRED-7: AdminService API credential extraction
                    if ($system.IssuesToCheck -contains "CRED-7") {
                        $system.Output += "$rolePrefix    CRED-7: AdminService API may expose encrypted credential blobs`n"
                    }

                    # TAKEOVER-5 is not possible to completely prevent on remote SMS Providers (EPA is not supported by AdminService)

                    # TAKEOVER-6
                    Check-IssueStatus -Issue "TAKEOVER-6" `
                        -FailedCheckMessage "SMB signing check failed, validate TAKEOVER-6 manually" `
                        -LikelyCondition ($system.SMBSigningRequired -eq 0) `
                        -LikelyMessage "SMB signing not required, TAKEOVER-6 likely!" `
                        -PreventingCondition ($system.SMBSigningRequired -eq 1) `
                        -PreventingMessage "SMB signing required, preventing TAKEOVER-6" `
                        -RolePrefix $rolePrefix `
                        -System $([ref]$system)
                } 
            }
        
            # ELEVATE-1 (if no TAKEOVERs exist)
            if ($system.IssuesToCheck -contains "ELEVATE-1" -and ($system.IssuesToCheck -match '^TAKEOVER.*').Count -eq 0) {

                Check-IssueStatus -Issue "ELEVATE-1" `
                    -FailedCheckMessage "SMB signing check failed, validate ELEVATE-1 manually" `
                    -LikelyCondition ($system.SMBSigningRequired -eq 0) `
                    -LikelyMessage "SMB signing not required, ELEVATE-1 likely!" `
                    -PreventingCondition ($system.SMBSigningRequired -eq 1) `
                    -PreventingMessage "SMB signing required, preventing ELEVATE-1" `
                    -RolePrefix $rolePrefix `
                    -System $([ref]$system)
            }

            # Create some space between sites
            if ($roleCount -eq 0) {
                $system.Output += "$rolePrefix"
            }

            # Add possible issues to header for system
            $issueText = if ($system.IssuesToCheck.Count -gt 0) { " (Possible Issues: $($system.IssuesToCheck -join ', '))" }
            $systemOutputLines = $system.Output -split "`n"
            $systemOutputLines[0] += $issueText
            $systemOutput = $systemOutputLines -join "`n" # Match the line ending style used in split

            Write-Host $systemOutput
        }

        # Process child sites
        $childSiteCount = $childSites.Count
        foreach ($childSite in $childSites) {
            $childSiteCount--
            $newIndent = if ($childSiteCount -eq 0 -and -not ($AllSites | Where-Object { $_.ParentSiteCode -eq $childSite.SiteCode }).Count) { "$Indent     " } else { "$Indent │   " }
            Print-SiteStructure -Site $childSite -Indent $newIndent -AllSites $AllSites
        }
    }

    catch {
        Write-Error "Encountered an unexpected error at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
    }

}

function Print-SMBSigningStatus {
    param(
        $CurrentSiteSystem,
        [string]$Issue
    )
    if ($CurrentSiteSystem.SMBSigningRequired -eq 1) {
        Write-Verbose "        SMB signing required: True"
    }
    elseif ($CurrentSiteSystem.SMBSigningRequired -eq 0) {
        Write-Warning "        SMB signing required: False ($($Issue) likely!)"
    } 
    else {
        Write-Warning "        SMB signing required: $($CurrentSiteSystem.SMBSigningRequired) (check $($Issue) manually)"
    }
}


function Run-Script {
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [array]$ArgumentList,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds
    )

    try {
        # Start the script block as a job with the arguments
        $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList

        # Wait for the job to finish with the specified timeout
        if ($TimeoutSeconds) {
            $finished = Wait-Job -Job $job -Timeout $TimeoutSeconds
            if (-not $finished) {
                throw
            }
        } 
        else {
            Wait-Job -Job $job
        }

        # Get the result from the job
        $result = Receive-Job -Job $job
        Remove-Job -Job $job
        return $result
    } 
    catch {
        return "The operation timed out after $TimeoutSeconds seconds:`n`t$ScriptBlock"
    }
}

# Main
if ($VerbosePreference -eq "SilentlyContinue") {
    Write-Host "`nCollecting data... this may take a while. Add -Verbose option to show details as they are collected..."
}

# Catch and log unexpected execution error messages
try {
    # Start the hierarchy output from the CAS
    $namespace = Get-SiteNamespace -SMSProvider $SMSProvider
    $Global:casComputerAccount = $null
    $sites = @()
    $sites = Get-SiteHierarchy -Namespace $namespace -SMSProvider $SMSProvider

    if ($sites) {
        # Begin output
        Write-Host "`nHierarchy Tree:`n"

        # Start with top-level site
        $topLevelSites = $sites | Where-Object { -not $_.ParentSiteCode }  

        foreach ($site in $topLevelSites) {
            Print-SiteStructure -Site $site -AllSites $sites
        }

        # Print site-level security findings
        foreach ($site in $sites) {
            if ($site.Type -eq 2) {
                Write-Host "`nSite-Level Security Settings ($($site.SiteCode)):`n"

                # NAA status (CRED-2, CRED-3, CRED-4)
                if ($site.NAAConfigured -eq $true) {
                    Write-Host "  [!] Network Access Account is configured"
                    Write-Host "      CRED-2: Clients can request and deobfuscate NAA policy credentials"
                    Write-Host "      CRED-3: NAA credentials recoverable via DPAPI on any managed client"
                    Write-Host "      CRED-4: Legacy NAA credentials may persist in CIM repository"
                }
                elseif ($site.NAAConfigured -eq $false) {
                    Write-Host "  [+] Network Access Account is not configured"
                }
                else {
                    Write-Host "  [?] Network Access Account check failed, validate CRED-2/3/4 manually"
                }

                # Enhanced HTTP (CRED-2, PREVENT-4)
                if ($site.EnhancedHTTPEnabled -eq $true) {
                    Write-Host "  [+] Enhanced HTTP is enabled (PREVENT-4)"
                }
                elseif ($site.EnhancedHTTPEnabled -eq $false) {
                    Write-Host "  [!] Enhanced HTTP is not enabled"
                }
                else {
                    Write-Host "  [?] Enhanced HTTP check failed"
                }

                # PKI (CRED-2, PREVENT-8)
                if ($site.PKIRequired -eq $true) {
                    Write-Host "  [+] PKI client certificates are required (PREVENT-8)"
                }
                elseif ($site.PKIRequired -eq $false) {
                    Write-Host "  [!] PKI client certificates are not required"
                }
                else {
                    Write-Host "  [?] PKI requirement check failed"
                }

                # Client push (ELEVATE-2, ELEVATE-3)
                if ($site.AutomaticClientPush -eq $true -and $site.FallbackToNTLM -eq $true) {
                    Write-Host "  [!] Automatic client push with NTLM fallback (ELEVATE-2, ELEVATE-3 likely!)"
                }
                elseif ($site.AutomaticClientPush -eq $true) {
                    Write-Host "  [+] Automatic client push enabled but NTLM fallback disabled"
                }
                elseif ($site.AutomaticClientPush -eq $false) {
                    Write-Host "  [+] Automatic client push is not enabled (PREVENT-5)"
                }

                # ELEVATE-6 informational
                Write-Host "  [?] ELEVATE-6: Verify ccmcache directory permissions on managed clients manually"

                # COERCE-2 informational
                Write-Host "  [?] COERCE-2: SCNotification AppDomainManager injection requires client-side validation"
            }
        }

        # Print technique coverage summary
        Write-Host "`n"
        Write-Host "Technique Coverage Summary:"
        Write-Host "====================================================================================================================="
        Write-Host ("{0,-14} {1,-45} {2,-12} {3}" -f "Technique", "Description", "Check", "Result")
        Write-Host "---------------------------------------------------------------------------------------------------------------------"

        # Collect all issues found across all site systems
        $allIssues = @()
        foreach ($site in $sites) {
            foreach ($system in $site.SiteSystems) {
                $allIssues += $system.IssuesToCheck
            }
        }
        $allIssues = $allIssues | Select-Object -Unique

        # Site-level conditions
        $naaConfigured = ($sites | Where-Object { $_.NAAConfigured -eq $true }).Count -gt 0
        $naaCheckFailed = ($sites | Where-Object { $_.Type -eq 2 -and $_.NAAConfigured -eq $null }).Count -gt 0
        $ehttpEnabled = ($sites | Where-Object { $_.EnhancedHTTPEnabled -eq $true }).Count -gt 0
        $pkiRequired = ($sites | Where-Object { $_.PKIRequired -eq $true }).Count -gt 0
        $autoPushNTLM = ($sites | Where-Object { $_.AutomaticClientPush -eq $true -and $_.FallbackToNTLM -eq $true }).Count -gt 0
        $hasPXEDP = $allIssues -contains "CRED-1"
        $hasDP = $allIssues -contains "CRED-6"

        # Helper to print a row
        function Print-Row {
            param([string]$Id, [string]$Desc, [string]$Check, [string]$Result)
            Write-Host ("{0,-14} {1,-45} {2,-12} {3}" -f $Id, $Desc, $Check, $Result)
        }

        # CRED techniques
        # CRED-1
        if ($hasDP) {
            $c1Check = "Auto"
            $c1Result = if ($hasPXEDP) { "LIKELY - PXE-enabled DP found" } else { "Mitigated - no PXE-enabled DPs" }
        } else { $c1Check = "N/A"; $c1Result = "No DPs in hierarchy" }
        Print-Row "CRED-1" "PXE boot media secrets" $c1Check $c1Result

        # CRED-2
        if ($naaCheckFailed) { $c2Check = "Failed"; $c2Result = "Validate manually" }
        elseif ($naaConfigured -and -not $pkiRequired -and -not $ehttpEnabled) { $c2Check = "Auto"; $c2Result = "LIKELY - NAA set, no PKI/eHTTP" }
        elseif ($naaConfigured -and -not $pkiRequired) { $c2Check = "Auto"; $c2Result = "Reduced - NAA set but eHTTP enabled" }
        elseif ($naaConfigured) { $c2Check = "Auto"; $c2Result = "Reduced - NAA set but PKI required" }
        else { $c2Check = "Auto"; $c2Result = "Mitigated - NAA not configured" }
        Print-Row "CRED-2" "Policy request credential deobfuscation" $c2Check $c2Result

        # CRED-3
        if ($naaCheckFailed) { $c3Check = "Failed"; $c3Result = "Validate manually" }
        elseif ($naaConfigured) { $c3Check = "Auto"; $c3Result = "LIKELY - NAA set, DPAPI recovery possible" }
        else { $c3Check = "Auto"; $c3Result = "Mitigated - NAA not configured" }
        Print-Row "CRED-3" "DPAPI credential recovery on clients" $c3Check $c3Result

        # CRED-4
        if ($naaCheckFailed) { $c4Check = "Failed"; $c4Result = "Validate manually" }
        elseif ($naaConfigured) { $c4Check = "Auto"; $c4Result = "Possible - NAA set, legacy CIM data may exist" }
        else { $c4Check = "Auto"; $c4Result = "Mitigated - NAA not configured" }
        Print-Row "CRED-4" "Legacy CIM repository credential recovery" $c4Check $c4Result

        # CRED-5
        $c5Check = if ($allIssues -contains "CRED-5") { "Auto" } else { "N/A" }
        $c5Result = if ($allIssues -contains "CRED-5") { "LIKELY - site server access enables DB cred recovery" } else { "No primary site servers found" }
        Print-Row "CRED-5" "Site database credential extraction" $c5Check $c5Result

        # CRED-6
        $c6Check = if ($hasDP) { "Auto" } else { "N/A" }
        $c6Result = if ($hasDP) { "Possible - DP shares may contain sensitive content" } else { "No DPs found" }
        Print-Row "CRED-6" "Distribution point share looting" $c6Check $c6Result

        # CRED-7
        $c7Check = if ($allIssues -contains "CRED-7") { "Auto" } else { "Auto" }
        $c7Result = if ($allIssues -contains "CRED-7") { "LIKELY - remote SMS Provider exposes AdminService" } else { "Mitigated - no remote SMS Providers" }
        Print-Row "CRED-7" "AdminService API credential extraction" $c7Check $c7Result

        # CRED-8
        $c8Check = if ($allIssues -contains "CRED-8") { "Auto" } else { "Auto" }
        $c8Result = if ($allIssues -contains "CRED-8") { "Possible - remote MP can relay to site DB" } else { "Mitigated - no remote MPs detected" }
        Print-Row "CRED-8" "MP relay to site database" $c8Check $c8Result

        Write-Host "---------------------------------------------------------------------------------------------------------------------"

        # ELEVATE techniques
        $e1Check = "Auto"
        $e1Result = if ($allIssues -contains "ELEVATE-1") { "LIKELY - SMB signing not required on remote system" } else { "Mitigated - SMB signing required or no remote systems" }
        Print-Row "ELEVATE-1" "NTLM relay to site system (SMB)" $e1Check $e1Result

        $e2Check = "Auto"
        $e2Result = if ($autoPushNTLM) { "LIKELY - auto push + NTLM fallback enabled" } else { "Mitigated - auto push disabled or NTLM fallback off" }
        Print-Row "ELEVATE-2" "NTLM relay via client push" $e2Check $e2Result
        Print-Row "ELEVATE-3" "NTLM relay via push + AD discovery" $e2Check $e2Result

        $e4Check = if ($hasDP) { "Auto" } else { "N/A" }
        $e4Result = if ($hasPXEDP) { "Possible - PXE-enabled DP may have PKI certs" } elseif ($hasDP) { "Mitigated - no PXE-enabled DPs" } else { "No DPs found" }
        Print-Row "ELEVATE-4" "PXE boot PKI certificate abuse" $e4Check $e4Result

        $e5Check = if ($hasDP) { "Auto" } else { "N/A" }
        $e5Result = if ($hasDP) { "Possible - OSD media on DPs may contain PKI certs" } else { "No DPs found" }
        Print-Row "ELEVATE-5" "OSD media PKI certificate recovery" $e5Check $e5Result

        Print-Row "ELEVATE-6" "LPE via writable ccmcache" "Manual" "Verify ccmcache ACLs on managed clients"

        Write-Host "---------------------------------------------------------------------------------------------------------------------"

        # EXEC techniques
        Print-Row "EXEC-1" "Application deployment" "Manual" "Review SMS_Admin RBAC role assignments"
        Print-Row "EXEC-2" "Script deployment" "Manual" "Review SMS_Admin RBAC role assignments"

        Write-Host "---------------------------------------------------------------------------------------------------------------------"

        # RECON techniques
        Print-Row "RECON-1" "LDAP site information enumeration" "N/A" "Always possible with domain credentials"
        Print-Row "RECON-2" "SMB share enumeration" "N/A" "Always possible with domain credentials"
        Print-Row "RECON-3" "HTTP endpoint probing" "N/A" "Always possible with domain credentials"
        Print-Row "RECON-4" "CMPivot reconnaissance" "Manual" "Review SMS_Admin RBAC role assignments"
        Print-Row "RECON-5" "SMS Provider enumeration" "N/A" "Always possible with read access"
        Print-Row "RECON-6" "Remote registry enumeration" "N/A" "Always possible with domain credentials"
        Print-Row "RECON-7" "Local file site enumeration" "N/A" "Possible with client file system access"

        Write-Host "---------------------------------------------------------------------------------------------------------------------"

        # TAKEOVER techniques
        # TAKEOVER-1
        $t1Check = if ($allIssues -contains "TAKEOVER-1") { "Auto" } else { "N/A" }
        $t1Systems = @()
        foreach ($site in $sites) { foreach ($sys in $site.SiteSystems) { if ($sys.IssuesToCheck -contains "TAKEOVER-1") { $t1Systems += $sys } } }
        if ($t1Systems.Count -gt 0) {
            $epaVuln = $t1Systems | Where-Object { $_.EPARequired -is [int] -and $_.EPARequired -lt 2 }
            $epaOk = $t1Systems | Where-Object { $_.EPARequired -eq 2 }
            $epaAccessDenied = $t1Systems | Where-Object { "$($_.EPARequired)" -match "Access denied" }
            if ($epaVuln.Count -gt 0) { $t1Result = "LIKELY - EPA not required on remote site DB" }
            elseif ($epaOk.Count -gt 0) { $t1Result = "Mitigated - EPA required" }
            elseif ($epaAccessDenied.Count -gt 0) { $t1Check = "Denied"; $t1Result = "Local admin required on site DB server" }
            else { $t1Result = "Unknown - EPA check failed" }
        } else { $t1Result = "N/A - site DB colocated with site server" }
        Print-Row "TAKEOVER-1" "NTLM relay to site database (MSSQL)" $t1Check $t1Result

        # TAKEOVER-2
        $t2Check = if ($allIssues -contains "TAKEOVER-2") { "Auto" } else { "N/A" }
        $t2Systems = @()
        foreach ($site in $sites) { foreach ($sys in $site.SiteSystems) { if ($sys.IssuesToCheck -contains "TAKEOVER-2") { $t2Systems += $sys } } }
        if ($t2Systems.Count -gt 0) {
            $smbVuln = $t2Systems | Where-Object { $_.SMBSigningRequired -eq 0 }
            $smbOk = $t2Systems | Where-Object { $_.SMBSigningRequired -eq 1 }
            $smbAccessDenied = $t2Systems | Where-Object { "$($_.SMBSigningRequired)" -match "Access denied" }
            if ($smbVuln.Count -gt 0) { $t2Result = "LIKELY - SMB signing not required on remote site DB" }
            elseif ($smbOk.Count -gt 0) { $t2Result = "Mitigated - SMB signing required" }
            elseif ($smbAccessDenied.Count -gt 0) { $t2Check = "Denied"; $t2Result = "Local admin required on site DB server" }
            else { $t2Result = "Unknown - SMB signing check failed" }
        } else { $t2Result = "N/A - site DB colocated with site server" }
        Print-Row "TAKEOVER-2" "NTLM relay to site database (SMB)" $t2Check $t2Result

        # TAKEOVER-3
        $t3Check = if ($allIssues -contains "TAKEOVER-3") { "Manual" } else { "N/A" }
        $t3Result = if ($allIssues -contains "TAKEOVER-3") { "Validate AD CS relay manually" } else { "No applicable site servers" }
        Print-Row "TAKEOVER-3" "NTLM relay to AD CS" $t3Check $t3Result

        # TAKEOVER-4
        $t4Check = if ($allIssues -contains "TAKEOVER-4") { "Auto" } else { "N/A" }
        $t4Systems = @()
        foreach ($site in $sites) { foreach ($sys in $site.SiteSystems) { if ($sys.IssuesToCheck -contains "TAKEOVER-4") { $t4Systems += $sys } } }
        if ($t4Systems.Count -gt 0) {
            $smbVuln = $t4Systems | Where-Object { $_.SMBSigningRequired -eq 0 }
            if ($smbVuln.Count -gt 0) { $t4Result = "LIKELY - CAS account is local admin, SMB signing off" }
            else { $t4Result = "Reduced - CAS account found but SMB signing required" }
        } else { $t4Result = "N/A - no CAS or CAS account not local admin" }
        Print-Row "TAKEOVER-4" "NTLM relay CAS to child primary" $t4Check $t4Result

        # TAKEOVER-5
        $t5Check = if ($allIssues -contains "TAKEOVER-5") { "Auto" } else { "N/A" }
        $t5Result = if ($allIssues -contains "TAKEOVER-5") { "LIKELY - remote SMS Provider, AdminService has no EPA" } else { "N/A - no remote SMS Providers" }
        Print-Row "TAKEOVER-5" "NTLM relay to AdminService" $t5Check $t5Result

        # TAKEOVER-6
        $t6Check = if ($allIssues -contains "TAKEOVER-6") { "Auto" } else { "Auto" }
        $t6Systems = @()
        foreach ($site in $sites) { foreach ($sys in $site.SiteSystems) { if ($sys.IssuesToCheck -contains "TAKEOVER-6") { $t6Systems += $sys } } }
        if ($t6Systems.Count -gt 0) {
            $smbVuln = $t6Systems | Where-Object { $_.SMBSigningRequired -eq 0 }
            if ($smbVuln.Count -gt 0) { $t6Result = "LIKELY - SMB signing not required on remote SMS Provider" }
            else { $t6Result = "Unknown - SMB signing check inconclusive" }
        } else { $t6Result = "Mitigated - SMB signing required or no remote SMS Provider" }
        Print-Row "TAKEOVER-6" "NTLM relay to SMS Provider (SMB)" $t6Check $t6Result

        # TAKEOVER-7
        $t7Check = if ($allIssues -contains "TAKEOVER-7") { "Auto" } else { "N/A" }
        $t7Systems = @()
        foreach ($site in $sites) { foreach ($sys in $site.SiteSystems) { if ($sys.IssuesToCheck -contains "TAKEOVER-7") { $t7Systems += $sys } } }
        if ($t7Systems.Count -gt 0) {
            $smbVuln = $t7Systems | Where-Object { $_.SMBSigningRequired -eq 0 }
            if ($smbVuln.Count -gt 0) { $t7Result = "LIKELY - SMB signing not required between HA servers" }
            else { $t7Result = "Reduced - passive server found but SMB signing required" }
        } else { $t7Result = "N/A - no passive site server detected" }
        Print-Row "TAKEOVER-7" "NTLM relay between HA site servers" $t7Check $t7Result

        # TAKEOVER-8
        $t8Check = if ($allIssues -contains "TAKEOVER-8") { "Auto" } else { "Auto" }
        $t8Systems = @()
        foreach ($site in $sites) { foreach ($sys in $site.SiteSystems) { if ($sys.IssuesToCheck -contains "TAKEOVER-8") { $t8Systems += $sys } } }
        if ($t8Systems.Count -gt 0) {
            $wcRunning = $t8Systems | Where-Object { $_.WebClientStatus -eq "Running" }
            $wcInstalled = $t8Systems | Where-Object { $_.WebClientStatus -eq "Installed" }
            if ($wcRunning.Count -gt 0) { $t8Result = "LIKELY - WebClient running on site server" }
            elseif ($wcInstalled.Count -gt 0) { $t8Result = "Possible - WebClient installed but not running" }
            else { $t8Result = "Mitigated - WebClient not installed" }
        } else { $t8Result = "Mitigated - WebClient not present on site servers" }
        Print-Row "TAKEOVER-8" "NTLM relay to LDAP via WebClient" $t8Check $t8Result

        # TAKEOVER-9
        $t9Check = if ($allIssues -contains "TAKEOVER-9") { "Manual" } else { "N/A" }
        $t9Result = if ($allIssues -contains "TAKEOVER-9") { "Check SQL linked servers with DBA privileges" } else { "No remote site DB detected" }
        Print-Row "TAKEOVER-9" "SQL linked server with DBA privileges" $t9Check $t9Result

        Write-Host "---------------------------------------------------------------------------------------------------------------------"

        # COERCE techniques
        $co1Check = if ($allIssues -contains "COERCE-1") { "Auto" } else { "N/A" }
        $co1Result = if ($allIssues -contains "COERCE-1") { "Possible - CMPivot can coerce client NTLM auth" } else { "No site servers detected" }
        Print-Row "COERCE-1" "CMPivot UNC path NTLM coercion" $co1Check $co1Result
        Print-Row "COERCE-2" "SCNotification AppDomainManager injection" "Manual" "Requires client-side validation"

        Write-Host "====================================================================================================================="
        Write-Host ""
        Write-Host "Legend:  Check: Auto = automated check | Manual = requires manual validation | Denied = access denied (needs local admin)"
        Write-Host "                N/A = not applicable to this environment"
        Write-Host "        Result: LIKELY = conditions met for exploitation | Possible = some conditions met | Reduced = partially mitigated"
        Write-Host "                Mitigated = key conditions not met | N/A = prerequisite architecture not present"
        Write-Host ""
    }
    else {
        Write-Warning "No sites were found. Add -Verbose option to debug"
    }
} 

catch {
    Write-Error "Encountered an unexpected error at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
} 

finally {
    # Set preferences back to original values
    $VerbosePreference = $originalVerbosePreference
    $WarningPreference = $originalWarningPreference

    if ($Host.Name -eq 'ConsoleHost') {
        # For the standard console, we use ConsoleColor enum values
        $Host.PrivateData.VerboseForegroundColor = $originalVerboseColor
        $Host.PrivateData.WarningForegroundColor = $originalWarningColor
        $Host.PrivateData.VerboseBackgroundColor = $originalVerboseBackgroundColor
        $Host.PrivateData.WarningBackgroundColor = $originalWarningBackgroundColor
    } elseif ($Host.Name -eq 'Windows PowerShell ISE Host') {
        # For ISE, we use System.Windows.Media.Color values
        $psISE.Options.VerboseForegroundColor = $originalVerboseColor
        $psISE.Options.WarningForegroundColor = $originalWarningColor
    }
}