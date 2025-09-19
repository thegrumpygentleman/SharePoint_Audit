Prerequisites

Install PnP PowerShell module (one-time setup):

powershell   Install-Module -Name PnP.PowerShell -Force

Required permissions: Global Admin or SharePoint Admin rights

Usage Examples
powershell# Basic audit of all sites
.\SharePointAudit.ps1 -TenantUrl "https://contoso-admin.sharepoint.com"

# Only check for external links and users
.\SharePointAudit.ps1 -TenantUrl "https://contoso-admin.sharepoint.com" -ExternalLinksOnly

# Specify custom output path
.\SharePointAudit.ps1 -TenantUrl "https://contoso-admin.sharepoint.com" -OutputPath "C:\Audit\SPAudit.csv"
What the Script Does
Permissions Audit:

Site collection permissions
Document library permissions
Individual file/folder unique permissions
Group memberships and direct user access

External Sharing Detection:

External users (identified by #ext# in email)
Anonymous sharing links
External sharing links with various permission levels
Guest user access

Output Information:

Site URL and item path
Permission type and level
User/group information
External user identification
Sharing link details

Key Features

Minimal setup: Uses PnP PowerShell (Microsoft's recommended module)
Comprehensive: Covers all permission levels from site to individual files
External focus: Specifically identifies external users and sharing links
Progress tracking: Real-time logging of progress
Error handling: Continues processing even if individual sites fail
CSV export: Results in easily readable format

The script will create a detailed CSV file with all permissions and external links, making it easy to analyze your SharePoint security posture and identify potential over-sharing issues.
