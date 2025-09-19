#Requires -Modules PnP.PowerShell

<#
.SYNOPSIS
    SharePoint Online Permissions and External Links Audit Script
.DESCRIPTION
    This script audits all SharePoint sites in your tenant for:
    - File and folder permissions
    - External sharing links
    - Site collection permissions
.NOTES
    Prerequisites:
    - Install PnP PowerShell: Install-Module -Name PnP.PowerShell -Force
    - Global Admin or SharePoint Admin permissions
    - Modern authentication enabled
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$TenantUrl,  # e.g., "https://contoso-admin.sharepoint.com"
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\SharePointAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeInheritedPermissions,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExternalLinksOnly
)

# Initialize results array
$AuditResults = @()

function Write-LogMessage {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $(
        switch($Level) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            default { "White" }
        }
    )
}

function Get-SharePointSites {
    try {
        Write-LogMessage "Retrieving all SharePoint sites..."
        $sites = Get-PnPTenantSite -Detailed | Where-Object { $_.Template -notlike "*REDIRECTSITE*" }
        Write-LogMessage "Found $($sites.Count) SharePoint sites" -Level "SUCCESS"
        return $sites
    }
    catch {
        Write-LogMessage "Error retrieving sites: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

function Get-SitePermissions {
    param([string]$SiteUrl)
    
    try {
        Connect-PnPOnline -Url $SiteUrl -Interactive
        
        # Get site collection permissions
        $siteGroups = Get-PnPGroup
        $siteUsers = Get-PnPUser
        
        foreach ($group in $siteGroups) {
            $groupUsers = Get-PnPGroupMember -Identity $group.Id -ErrorAction SilentlyContinue
            
            foreach ($user in $groupUsers) {
                $AuditResults += [PSCustomObject]@{
                    SiteUrl = $SiteUrl
                    ItemType = "Site"
                    ItemPath = "/"
                    PrincipalType = "Group"
                    PrincipalName = $group.Title
                    UserName = $user.Title
                    UserEmail = $user.Email
                    Permission = $group.Title
                    IsExternal = $user.Email -like "*#ext#*" -or $user.PrincipalType -eq "SecurityGroup"
                    HasExternalLinks = $false
                    LinkType = ""
                    Inherited = $false
                }
            }
        }
        
        # Get direct site users
        foreach ($user in $siteUsers) {
            if ($user.PrincipalType -eq "User" -and $user.Email) {
                $AuditResults += [PSCustomObject]@{
                    SiteUrl = $SiteUrl
                    ItemType = "Site"
                    ItemPath = "/"
                    PrincipalType = "User"
                    PrincipalName = $user.Title
                    UserName = $user.Title
                    UserEmail = $user.Email
                    Permission = "Direct Access"
                    IsExternal = $user.Email -like "*#ext#*"
                    HasExternalLinks = $false
                    LinkType = ""
                    Inherited = $false
                }
            }
        }
        
        Write-LogMessage "Retrieved site-level permissions for: $SiteUrl" -Level "SUCCESS"
    }
    catch {
        Write-LogMessage "Error getting site permissions for $SiteUrl : $($_.Exception.Message)" -Level "ERROR"
    }
}

function Get-LibraryPermissions {
    param([string]$SiteUrl)
    
    try {
        Connect-PnPOnline -Url $SiteUrl -Interactive
        
        # Get all document libraries
        $libraries = Get-PnPList | Where-Object { $_.BaseType -eq "DocumentLibrary" -and $_.Hidden -eq $false }
        
        foreach ($library in $libraries) {
            Write-LogMessage "Scanning library: $($library.Title)"
            
            # Get unique permissions on library level
            $libraryPermissions = Get-PnPListPermissions -Identity $library.Id
            
            foreach ($permission in $libraryPermissions) {
                $AuditResults += [PSCustomObject]@{
                    SiteUrl = $SiteUrl
                    ItemType = "Library"
                    ItemPath = $library.Title
                    PrincipalType = $permission.Member.PrincipalType
                    PrincipalName = $permission.Member.Title
                    UserName = $permission.Member.Title
                    UserEmail = if($permission.Member.Email) { $permission.Member.Email } else { "" }
                    Permission = ($permission.RoleDefinitionBindings | ForEach-Object { $_.Name }) -join ", "
                    IsExternal = if($permission.Member.Email) { $permission.Member.Email -like "*#ext#*" } else { $false }
                    HasExternalLinks = $false
                    LinkType = ""
                    Inherited = $false
                }
            }
            
            # Get all items in library
            try {
                $items = Get-PnPListItem -List $library.Id -PageSize 1000
                
                foreach ($item in $items) {
                    # Check for unique permissions
                    if ($item.HasUniqueRoleAssignments) {
                        $itemPermissions = Get-PnPListItemPermissions -List $library.Id -Identity $item.Id
                        
                        foreach ($permission in $itemPermissions) {
                            $AuditResults += [PSCustomObject]@{
                                SiteUrl = $SiteUrl
                                ItemType = if($item.FileSystemObjectType -eq "File") { "File" } else { "Folder" }
                                ItemPath = "$($library.Title)$($item['FileRef'])"
                                PrincipalType = $permission.Member.PrincipalType
                                PrincipalName = $permission.Member.Title
                                UserName = $permission.Member.Title
                                UserEmail = if($permission.Member.Email) { $permission.Member.Email } else { "" }
                                Permission = ($permission.RoleDefinitionBindings | ForEach-Object { $_.Name }) -join ", "
                                IsExternal = if($permission.Member.Email) { $permission.Member.Email -like "*#ext#*" } else { $false }
                                HasExternalLinks = $false
                                LinkType = ""
                                Inherited = $false
                            }
                        }
                    }
                    
                    # Check for sharing links (external links)
                    try {
                        if ($item.FileSystemObjectType -eq "File") {
                            $sharingInfo = Get-PnPFileSharingInformation -Identity $item['FileRef'] -ErrorAction SilentlyContinue
                            
                            if ($sharingInfo.SharingLinks.Count -gt 0) {
                                foreach ($link in $sharingInfo.SharingLinks) {
                                    $AuditResults += [PSCustomObject]@{
                                        SiteUrl = $SiteUrl
                                        ItemType = "File"
                                        ItemPath = "$($library.Title)$($item['FileRef'])"
                                        PrincipalType = "SharingLink"
                                        PrincipalName = "Anonymous/External Link"
                                        UserName = "External Link"
                                        UserEmail = ""
                                        Permission = $link.LinkKind
                                        IsExternal = $true
                                        HasExternalLinks = $true
                                        LinkType = $link.LinkKind
                                        Inherited = $false
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        # Sharing info might not be available for all files
                    }
                }
            }
            catch {
                Write-LogMessage "Error scanning items in library $($library.Title): $($_.Exception.Message)" -Level "WARNING"
            }
        }
        
        Write-LogMessage "Completed library scan for: $SiteUrl" -Level "SUCCESS"
    }
    catch {
        Write-LogMessage "Error scanning libraries for $SiteUrl : $($_.Exception.Message)" -Level "ERROR"
    }
}

function Export-Results {
    param([array]$Results, [string]$Path)
    
    try {
        if ($Results.Count -gt 0) {
            $Results | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
            Write-LogMessage "Results exported to: $Path" -Level "SUCCESS"
            Write-LogMessage "Total records: $($Results.Count)" -Level "SUCCESS"
        } else {
            Write-LogMessage "No results to export" -Level "WARNING"
        }
    }
    catch {
        Write-LogMessage "Error exporting results: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Main execution
try {
    Write-LogMessage "Starting SharePoint permissions audit..." -Level "SUCCESS"
    Write-LogMessage "Tenant URL: $TenantUrl"
    Write-LogMessage "Output Path: $OutputPath"
    
    # Connect to SharePoint Admin Center
    Write-LogMessage "Connecting to SharePoint Admin Center..."
    Connect-PnPOnline -Url $TenantUrl -Interactive
    
    # Get all sites
    $sites = Get-SharePointSites
    
    if ($sites.Count -eq 0) {
        Write-LogMessage "No sites found or unable to retrieve sites" -Level "ERROR"
        exit
    }
    
    # Process each site
    $siteCount = 0
    foreach ($site in $sites) {
        $siteCount++
        Write-LogMessage "Processing site $siteCount of $($sites.Count): $($site.Url)"
        
        try {
            # Get site-level permissions
            if (-not $ExternalLinksOnly) {
                Get-SitePermissions -SiteUrl $site.Url
            }
            
            # Get library and item permissions
            Get-LibraryPermissions -SiteUrl $site.Url
            
            Write-LogMessage "Completed site: $($site.Url)" -Level "SUCCESS"
        }
        catch {
            Write-LogMessage "Error processing site $($site.Url): $($_.Exception.Message)" -Level "ERROR"
        }
        
        # Disconnect to avoid connection limits
        Disconnect-PnPOnline
    }
    
    # Filter results if needed
    if ($ExternalLinksOnly) {
        $AuditResults = $AuditResults | Where-Object { $_.IsExternal -eq $true -or $_.HasExternalLinks -eq $true }
    }
    
    # Export results
    Export-Results -Results $AuditResults -Path $OutputPath
    
    Write-LogMessage "Audit completed successfully!" -Level "SUCCESS"
    Write-LogMessage "Summary:"
    Write-LogMessage "- Sites processed: $($sites.Count)"
    Write-LogMessage "- Total permission records: $($AuditResults.Count)"
    Write-LogMessage "- External users/links: $(($AuditResults | Where-Object { $_.IsExternal -eq $true -or $_.HasExternalLinks -eq $true }).Count)"
    
}
catch {
    Write-LogMessage "Critical error during execution: $($_.Exception.Message)" -Level "ERROR"
}
finally {
    # Ensure we disconnect
    try { Disconnect-PnPOnline } catch { }
}
