<#
.SYNOPSIS
    Configures Microsoft Sentinel settings (UEBA, data connectors, Azure Activity,
    and playbook permissions) for a Conosco-managed client workspace.

.DESCRIPTION
    Run this interactively, signed in as the dedicated global admin used for the
    client onboarding, AFTER deploying the infrastructure template (azuredeploy.json).

    Connector enablement and the tenant-level settings this applies require Microsoft
    Entra directory roles (Security Administrator / Global Administrator) that a
    deployment-script managed identity does not hold. That is why this work runs in
    your own signed-in context rather than inside the ARM template.

    Supports -WhatIf for a safe dry run. Writes a timestamped audit log per run.

    Prerequisites:
      - Connect-AzAccount, signed in to the client tenant
      - Security Administrator or Global Administrator (for the tenant connectors)
      - Owner or User Access Administrator on the resource group (for the playbook
        permission grant only; omit with -SkipPlaybookPermissions if not held)

.PARAMETER ClientName
    Short client identifier. Resource group and workspace are both cns-<ClientName>-sentinel.

.PARAMETER EnabledConnectors
    Connector IDs to enable. Defaults to the full Conosco standard set. Remove any
    connector for which the client lacks the required licence.

.PARAMETER SubscriptionId
    Optional. Target subscription. Defaults to the current Az context subscription.

.PARAMETER SkipUeba
    Skip UEBA configuration.

.PARAMETER SkipPlaybookPermissions
    Skip granting Logic App Contributor to the Azure Security Insights service principal.

.EXAMPLE
    .\Configure-SentinelSettings.ps1 -ClientName contoso -WhatIf

.EXAMPLE
    .\Configure-SentinelSettings.ps1 -ClientName contoso -EnabledConnectors AzureActivity,Office365,AzureActiveDirectory
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9][a-z0-9-]{0,18}[a-z0-9]$')]
    [string]$ClientName,

    [string[]]$EnabledConnectors = @(
        'AzureActivity', 'Office365', 'OfficeIRM', 'MicrosoftCloudAppSecurity',
        'MicrosoftDefenderAdvancedThreatProtection', 'AzureAdvancedThreatProtection',
        'OfficeATP', 'MicrosoftThreatIntelligence', 'MicrosoftThreatProtection',
        'AzureActiveDirectory', 'AzureActiveDirectoryIdentityProtection'
    ),

    [string]$SubscriptionId,

    [switch]$SkipUeba,

    [switch]$SkipPlaybookPermissions
)

$ErrorActionPreference = 'Stop'

# --- Resolve names (RG and workspace share the cns-<client>-sentinel convention) ---
$workspaceName = "cns-$ClientName-sentinel"
$resourceGroup = "cns-$ClientName-sentinel"

# --- Audit log (one file per run) ---
$timestamp        = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:logFile   = Join-Path (Get-Location) "$workspaceName-config-$timestamp.log"
$script:apiVersion = '2023-02-01-preview'

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')][string]$Level = 'Info'
    )
    $line = '{0}  [{1}]  {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level.ToUpper().PadRight(7), $Message
    switch ($Level) {
        'Success' { Write-Host $line -ForegroundColor Green }
        'Warning' { Write-Host $line -ForegroundColor Yellow }
        'Error'   { Write-Host $line -ForegroundColor Red }
        default   { Write-Host $line }
    }
    Add-Content -Path $script:logFile -Value $line
}

function Set-SentinelConfig {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Path, $Body, [string]$Description)
    $uri = $script:siBase + $Path + '?api-version=' + $script:apiVersion
    if ($PSCmdlet.ShouldProcess($Description, 'Configure Sentinel')) {
        try {
            $null = Invoke-RestMethod -Uri $uri -Method Put -Headers $script:headers -Body ($Body | ConvertTo-Json -Depth 10)
            Write-Log "[OK]   $Description" 'Success'
        } catch {
            $detail = $_.ErrorDetails.Message
            Write-Log "[FAIL] $Description | $($_.Exception.Message)$(if ($detail) { " | $detail" })" 'Warning'
        }
    }
}

# --- Context ---
$ctx = Get-AzContext
if (-not $ctx) { throw 'Not signed in. Run Connect-AzAccount first.' }
if ($SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    $ctx = Get-AzContext
}
$subId    = $ctx.Subscription.Id
$tenantId = $ctx.Tenant.Id

Write-Log "Configuring $workspaceName | subscription $subId | tenant $tenantId"
Write-Log "Signed in as: $($ctx.Account.Id)"
if ($WhatIfPreference) { Write-Log 'WHATIF MODE - no changes will be made' 'Warning' }

# --- Verify the workspace exists (template must have run first) ---
$ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $resourceGroup -Name $workspaceName -ErrorAction SilentlyContinue
if (-not $ws) {
    throw "Workspace $workspaceName not found in resource group $resourceGroup. Deploy azuredeploy.json first."
}

# --- Management token (version-safe: Az 14+ returns a SecureString) ---
$tokenResult = Get-AzAccessToken -ResourceUrl 'https://management.azure.com'
if ($tokenResult.Token -is [System.Security.SecureString]) {
    $mgmtToken = [System.Net.NetworkCredential]::new('', $tokenResult.Token).Password
} else {
    $mgmtToken = $tokenResult.Token
}
$script:headers = @{ Authorization = "Bearer $mgmtToken"; 'Content-Type' = 'application/json' }
$script:siBase  = 'https://management.azure.com/subscriptions/' + $subId +
                  '/resourceGroups/' + $resourceGroup +
                  '/providers/Microsoft.OperationalInsights/workspaces/' + $workspaceName +
                  '/providers/Microsoft.SecurityInsights'

# ------------------------------------------------------------------
# 1. UEBA
# ------------------------------------------------------------------
if (-not $SkipUeba) {
    Write-Log '--- UEBA ---'
    Set-SentinelConfig -Path '/settings/Ueba' `
        -Description 'UEBA (AuditLogs, AzureActivity, SigninLogs, SecurityEvent)' `
        -Body @{
            kind = 'Ueba'; etag = '*'
            properties = @{ dataSources = @('AuditLogs', 'AzureActivity', 'SigninLogs', 'SecurityEvent') }
        }
} else {
    Write-Log '--- UEBA: skipped ---'
}

# ------------------------------------------------------------------
# 2. Data connectors (filtered to the selected list)
# ------------------------------------------------------------------
Write-Log '--- Data connectors ---'
$connectors = @(
    @{ id = 'Office365'
       body = @{ kind = 'Office365'; properties = @{ dataTypes = @{
           exchange = @{ state = 'enabled' }; sharePoint = @{ state = 'enabled' }; teams = @{ state = 'enabled' } } } } },
    @{ id = 'OfficeIRM'
       body = @{ kind = 'OfficeIRM'; properties = @{ tenantId = $tenantId
           dataTypes = @{ alerts = @{ state = 'enabled' } } } } },
    @{ id = 'MicrosoftCloudAppSecurity'
       body = @{ kind = 'MicrosoftCloudAppSecurity'; properties = @{ tenantId = $tenantId
           dataTypes = @{ alerts = @{ state = 'enabled' }; discoveryLogs = @{ state = 'enabled' } } } } },
    @{ id = 'MicrosoftDefenderAdvancedThreatProtection'
       body = @{ kind = 'MicrosoftDefenderAdvancedThreatProtection'; properties = @{ tenantId = $tenantId
           dataTypes = @{ alerts = @{ state = 'enabled' } } } } },
    @{ id = 'AzureAdvancedThreatProtection'
       body = @{ kind = 'AzureAdvancedThreatProtection'; properties = @{ tenantId = $tenantId
           dataTypes = @{ alerts = @{ state = 'enabled' } } } } },
    @{ id = 'OfficeATP'
       body = @{ kind = 'OfficeATP'; properties = @{ tenantId = $tenantId
           dataTypes = @{ alerts = @{ state = 'enabled' } } } } },
    @{ id = 'MicrosoftThreatIntelligence'
       body = @{ kind = 'MicrosoftThreatIntelligence'; properties = @{ tenantId = $tenantId
           dataTypes = @{ microsoftEmergingThreatFeed = @{ state = 'enabled'; lookbackPeriod = '2024-01-01T00:00:00.000Z' } } } } },
    @{ id = 'MicrosoftThreatProtection'
       body = @{ kind = 'MicrosoftThreatProtection'; properties = @{ tenantId = $tenantId
           dataTypes = @{ alerts = @{ state = 'enabled' }; incidents = @{ state = 'enabled' } } } } },
    @{ id = 'AzureActiveDirectory'
       body = @{ kind = 'AzureActiveDirectory'; properties = @{ tenantId = $tenantId
           dataTypes = @{
               signinLogs                   = @{ state = 'enabled' }
               auditLogs                    = @{ state = 'enabled' }
               nonInteractiveUserSignInLogs = @{ state = 'enabled' }
               serviceAccountSignInLogs     = @{ state = 'enabled' }
               aadRiskyUsers                = @{ state = 'enabled' }
               userRiskEvents               = @{ state = 'enabled' }
           } } } },
    @{ id = 'AzureActiveDirectoryIdentityProtection'
       body = @{ kind = 'AzureActiveDirectoryIdentityProtection'; properties = @{ tenantId = $tenantId
           dataTypes = @{ alerts = @{ state = 'enabled' } } } } }
)

foreach ($c in $connectors) {
    if ($c.id -notin $EnabledConnectors) {
        Write-Log "[SKIP] $($c.id)"
        continue
    }
    Set-SentinelConfig -Path "/dataConnectors/$($c.id)" -Description "Connector: $($c.id)" -Body $c.body
}

# Azure Activity - subscription-level diagnostic setting
if ('AzureActivity' -in $EnabledConnectors) {
    $actUri = 'https://management.azure.com/subscriptions/' + $subId +
              '/providers/microsoft.insights/diagnosticSettings/cns-sentinel-activity?api-version=2021-05-01-preview'
    $actBody = @{
        properties = @{
            workspaceId = $ws.ResourceId
            logs = @(
                @{ category = 'Administrative'; enabled = $true }
                @{ category = 'Security';       enabled = $true }
                @{ category = 'ServiceHealth';  enabled = $true }
                @{ category = 'Alert';          enabled = $true }
                @{ category = 'Recommendation'; enabled = $true }
                @{ category = 'Policy';         enabled = $true }
                @{ category = 'Autoscale';      enabled = $true }
                @{ category = 'ResourceHealth'; enabled = $true }
            )
        }
    }
    if ($PSCmdlet.ShouldProcess('Azure Activity diagnostic setting', 'Configure')) {
        try {
            $null = Invoke-RestMethod -Uri $actUri -Method Put -Headers $script:headers -Body ($actBody | ConvertTo-Json -Depth 10)
            Write-Log '[OK]   AzureActivity diagnostic setting' 'Success'
        } catch {
            $detail = $_.ErrorDetails.Message
            Write-Log "[FAIL] AzureActivity | $($_.Exception.Message)$(if ($detail) { " | $detail" })" 'Warning'
        }
    }
} else {
    Write-Log '[SKIP] AzureActivity'
}

# ------------------------------------------------------------------
# 3. Playbook permissions
#    Grants Logic App Contributor to the Azure Security Insights service
#    principal so Sentinel can trigger Logic App playbooks. Requires the
#    signed-in account to hold Owner or User Access Administrator on the RG.
# ------------------------------------------------------------------
if (-not $SkipPlaybookPermissions) {
    Write-Log '--- Playbook permissions ---'
    $sp = Get-AzADServicePrincipal -DisplayName 'Azure Security Insights' -ErrorAction SilentlyContinue
    if (-not $sp) {
        Write-Log '[WARN] Azure Security Insights SP not found - grant manually via Sentinel > Settings > Playbook permissions' 'Warning'
    } else {
        $lacRoleId = '87a39d53-fc1b-424a-814c-f7e04687dc9e'   # Logic App Contributor
        $rgScope   = "/subscriptions/$subId/resourceGroups/$resourceGroup"
        $existing  = Get-AzRoleAssignment -ObjectId $sp.Id -RoleDefinitionId $lacRoleId -Scope $rgScope -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Log '[OK]   Logic App Contributor already assigned' 'Success'
        } elseif ($PSCmdlet.ShouldProcess("Azure Security Insights SP on $rgScope", 'Grant Logic App Contributor')) {
            try {
                $null = New-AzRoleAssignment -ObjectId $sp.Id -RoleDefinitionId $lacRoleId -Scope $rgScope -ErrorAction Stop
                Write-Log '[OK]   Logic App Contributor granted to Azure Security Insights SP' 'Success'
            } catch {
                Write-Log "[FAIL] Logic App Contributor | $($_.Exception.Message) | Needs Owner or User Access Administrator on the RG; otherwise grant via the Sentinel portal." 'Warning'
            }
        }
    }
} else {
    Write-Log '--- Playbook permissions: skipped ---'
}

Write-Log "=== Complete. Audit log written to $script:logFile ==="
