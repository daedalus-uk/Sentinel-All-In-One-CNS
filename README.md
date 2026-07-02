# Conosco Sentinel Deployment Package

Standardised Microsoft Sentinel onboarding for Conosco-managed client tenants.

Deployment is two steps by design: an ARM template provisions the infrastructure, then a
PowerShell script run by the onboarding administrator configures the Sentinel settings that
require Entra directory roles. See "Why two steps" below.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fdaedalus-uk%2FSentinel-All-In-One-CNS%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fdaedalus-uk%2FSentinel-All-In-One-CNS%2Fmain%2FcreateUiDefinition.json)

The button runs Step 1 only (the infrastructure template with the portal wizard). It requires the
repository to be public and the two files to sit at the repo root on `main`. After it completes,
continue with Step 2 below. See "Deploy to Azure button" for pinning to a release tag.

---

## Package structure

```
conosco-sentinel/
├── azuredeploy.json                        # Step 1: infrastructure (workspace, Sentinel, onboarding)
├── createUiDefinition.json                 # Portal wizard for the template
├── generate-deploy-link.py                 # Builds the Deploy to Azure button link
├── scripts/
│   └── Configure-SentinelSettings.ps1      # Step 2: UEBA, connectors, playbook permissions (run as admin)
├── automation/
│   └── azuredeploy-automation.json         # Automation rules + local playbooks (deploy after Step 2)
└── lighthouse/
    └── azuredeploy-lighthouse.json         # Reference Lighthouse delegation (Conosco uses its own)
```

---

## Why two steps

Enabling the tenant-based connectors (Microsoft 365, the Defender suite, Entra ID) and granting
playbook permissions require Microsoft Entra directory roles (Security Administrator or Global
Administrator) and, for the playbook role assignment, Owner or User Access Administrator on the
resource group. An ARM deployment script runs under a managed identity, which cannot hold those
directory roles, so that work cannot be done reliably from inside the template. Running it as the
signed-in onboarding administrator means it executes with the right roles and reports per-item
results instead of failing silently.

A side benefit: the template no longer uses a deployment script, so there is no Azure Container
Instance dependency and none of the resource-provider registration delays that come with it.

---

## Step 1: deploy the infrastructure (azuredeploy.json)

Creates, in UK South:

| Resource | Notes |
|----------|-------|
| Log Analytics Workspace | Named `cns-<client>-sentinel`, 90-day retention, pay-as-you-go, no daily cap |
| Microsoft Sentinel solution | Installed on the workspace |
| Sentinel onboarding state | Formally onboards the workspace (required, in addition to the solution) |

Only parameter is `clientName`. Resource group and workspace are both `cns-<clientName>-sentinel`.

### Prerequisites

- An Azure subscription in the client tenant
- Permission to create the resources above (Contributor on the target resource group, or Owner)
- These resource providers registered on the subscription (one-time, harmless to re-run):

```bash
az provider register --namespace Microsoft.OperationalInsights
az provider register --namespace Microsoft.OperationsManagement
az provider register --namespace Microsoft.SecurityInsights
az provider register --namespace Microsoft.Insights

for rp in Microsoft.OperationalInsights Microsoft.OperationsManagement Microsoft.SecurityInsights Microsoft.Insights; do
  echo "$rp: $(az provider show -n $rp --query registrationState -o tsv)"
done
```

### Deploy by CLI

```bash
az login --tenant <CLIENT-TENANT-ID>
az account set --subscription <SUBSCRIPTION-ID>

CLIENT="contoso"
az group create --name "cns-${CLIENT}-sentinel" --location uksouth

az deployment group create \
  --resource-group "cns-${CLIENT}-sentinel" \
  --template-file azuredeploy.json \
  --parameters clientName="${CLIENT}"
```

### Deploy by portal

Use the Deploy to Azure button (see below) or "Deploy a custom template" and upload
`azuredeploy.json`. The resource group must already exist; name it `cns-<client>-sentinel`.

---

## Step 2: configure Sentinel settings (Configure-SentinelSettings.ps1)

Run interactively, signed in as the dedicated onboarding administrator, after Step 1 completes.
Applies UEBA, the selected data connectors, the Azure Activity diagnostic setting, and the
playbook permission grant. Supports `-WhatIf` and writes a timestamped audit log per run.

```powershell
Connect-AzAccount -Tenant <CLIENT-TENANT-ID>

# Dry run first
.\scripts\Configure-SentinelSettings.ps1 -ClientName contoso -WhatIf

# Apply
.\scripts\Configure-SentinelSettings.ps1 -ClientName contoso
```

Drop any connector the client is not licensed for:

```powershell
.\scripts\Configure-SentinelSettings.ps1 -ClientName contoso `
  -EnabledConnectors AzureActivity,Office365,AzureActiveDirectory,MicrosoftThreatProtection
```

### Permissions for Step 2

| Action | Required role |
|--------|---------------|
| Tenant connectors (M365, Defender, Entra ID) | Security Administrator or Global Administrator on the client tenant |
| Azure Activity diagnostic setting | Monitoring Contributor (or Contributor) at subscription scope |
| Playbook permission grant | Owner or User Access Administrator on the resource group |

The playbook grant is the only step needing Owner/UAA. If the onboarding account does not hold it,
run with `-SkipPlaybookPermissions` and grant it afterwards via Sentinel > Settings > Playbook
permissions, or have an account with UAA run that step.

### Connectors configured

- Azure Activity
- Microsoft 365 (Exchange, SharePoint, Teams)
- Microsoft 365 Insider Risk Management
- Microsoft Defender for Cloud Apps (alerts + discovery logs)
- Microsoft Defender for Endpoint
- Microsoft Defender for Identity
- Microsoft Defender for Office 365
- Microsoft Defender Threat Intelligence
- Microsoft Defender XDR (alerts + incidents)
- Microsoft Entra ID (sign-in, audit, non-interactive, service account, risky users, risk events)
- Microsoft Entra ID Protection

Connectors for unlicensed products will log a failure and be skipped; this is expected. Check the
audit log the script writes for the per-connector result.

---

## Step 3 (per client): Lighthouse delegation

Conosco deploys its own Lighthouse offering to delegate client resources to the SOC team. The
reference template under `lighthouse/` is illustrative only.

If you use the managing-tenant automation rules (see below), the Lighthouse setup must also grant
the Azure Security Insights app the **Microsoft Sentinel Automation Contributor** role
(`f4c81013-99ee-4d62-a7ee-b3f1f648599a`) on the Conosco resource group holding the central
playbooks. This is what allows a client-tenant automation rule to trigger a playbook in the Conosco
tenant, and it must be in place before those rules are deployed, or rule creation fails.

---

## Step 4: automation rules and playbooks (automation/azuredeploy-automation.json)

Deploy after Step 2, once connectors have started populating their tables (typically 15-30 minutes),
so analytics and automation rules validate against existing data.

This template deploys the two local playbooks (into the client resource group) and the automation
rules. Rules that call central playbooks in the Conosco tenant are gated behind the
`deployManagingTenantRules` parameter; leave it at the default once the Lighthouse Automation
Contributor grant is in place, or set it false to deploy only the local rules.

```bash
az deployment group create \
  --resource-group "cns-${CLIENT}-sentinel" \
  --template-file automation/azuredeploy-automation.json \
  --parameters clientName="${CLIENT}" tenantId="<CLIENT-TENANT-ID>" \
               clientDisplayName="Contoso Ltd" \
               primaryContact="..." secondaryContact="..." \
               accountManager="..." headOfSupport="..."
```

After deployment, authorise the API connections (Office365, Teams, Azureblob) for the two local
playbooks in the portal. ARM creates the connection resources but cannot complete their OAuth; the
Sentinel connections use managed identity and need no action.

---

## Deploy to Azure button

The button covers Step 1 only. It requires the template and wizard to be reachable anonymously over
HTTPS, so the repository holding them must be public. These files contain no secrets. Generate the
link with:

```bash
python3 generate-deploy-link.py daedalus-uk Sentinel-All-In-One-CNS main
```

The raw URLs the button points at must resolve:
`https://raw.githubusercontent.com/daedalus-uk/Sentinel-All-In-One-CNS/main/azuredeploy.json` and
the matching `createUiDefinition.json`. To pin deployments to a known-good version, point the link
at a release tag instead of `main`.

---

## Post-deployment checklist

- [ ] Step 1 deployment shows Succeeded; Sentinel opens on the workspace without an onboarding error
- [ ] Step 2 audit log reviewed; UEBA on, expected connectors enabled, playbook permission granted
- [ ] Connectors show Connected in Sentinel > Data connectors (allow time for first data)
- [ ] Step 4 deployed; local playbook connections authorised in the portal
- [ ] If using managing-tenant rules: Automation Contributor grant confirmed before deploying them

---

## Offboarding note (future)

Deleting the `cns-<client>-sentinel` resource group does not remove the subscription-scope Azure
Activity diagnostic setting (`cns-sentinel-activity`) or the tenant-scope Entra ID diagnostic
settings, because both live outside the resource group. Remove these as part of client offboarding
to avoid orphaned settings and to free an Entra diagnostic-setting slot. A dedicated offboarding
script is a planned addition.

---

*Maintained by Conosco Security Engineering.*
