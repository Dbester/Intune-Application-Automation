<#
.SYNOPSIS
    Create an Azure AD App Registration
    
.DESCRIPTION
    Create an Azure AD App Registration with HomePage, ReplyURLs and a Key valid for 1 year
     
.EXAMPLE

    C:\PS> AppRegistration.ps1
    
.NOTES
    Edited by : Dirk
    From     : Blogpost Creating Azure AD App Registration with PowerShell – Part 1 & 2
    Date    : 23.10.2020
    Version    : 1.4
#>
Connect-AzureAD


$appName = "Intune App Registration"
$appURI = "https://MWPIntuneApp.azurewebsites.com"
$appHomePageUrl = "https://MWPIntuneApp.Contentandcloud.com"
$appReplyURLs = @($appURI, $appHomePageURL, "https://localhost:12345")
$tenantDetails = Get-AzureADTenantDetail


if(!($myApp = Get-AzureADApplication -Filter "DisplayName eq '$($appName)'"  -ErrorAction SilentlyContinue))
{
    $Guid = New-Guid
    $startDate = Get-Date
    
    $PasswordCredential                 = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordCredential
    $PasswordCredential.StartDate         = $startDate
    $PasswordCredential.EndDate         = $startDate.AddYears(5)
    $PasswordCredential.KeyId             = $Guid
    $PasswordCredential.Value             = ([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($Guid))))+"="


#Microsoft Graph Permissions
    $svcprincipal = Get-AzureADServicePrincipal -All $true | ? { $_.DisplayName -eq "Microsoft Graph" }


    ### Microsoft Graph
    $reqGraph = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
    $reqGraph.ResourceAppId = $svcprincipal.AppId


    ##Delegated Permissions
    $delPermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "0e263e50-5827-48a4-b97c-d940288653c7","Scope" #Access Directory as the signed in user
    $delPermission2 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "c79f8feb-a9db-4090-85f9-90d820caa0eb","Scope" #Read applications
    $delPermission3 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "af2819c9-df71-4dd3-ade7-4d7c9dc653b7","Scope" #Read all terms of use agreements
    $delPermission4 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "0e263e50-5827-48a4-b97c-d940288653c7","Scope" #Access directory as the signed in user
    $delPermission5 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "06da0dbc-49e2-44d2-8312-53f166ab848a","Scope" #Read directory data
    $delPermission6 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "572fea84-0151-49b2-9301-11cb16974376","Scope" #Read your organization's policies
    $delPermission7 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "ad902697-1014-4ef5-81ef-2b4301988e8c","Scope" #Read and write your organization's conditional access policies


    ##Application Permissions
    $appPermission1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "62a82d76-70ea-41e2-9197-370581804d09","Role" #Read and Write All Groups
    $appPermission2 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "19dbc75e-c2e2-444c-a770-ec69d8559fc7","Role" #Read and Write directory data
    $appPermission3 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "1138cb37-bd11-4084-a2b7-9f71582aeddb","Role" #Read and Write Devices
    $appPermission4 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "243333ab-4d21-40cb-a475-36241daa0842","Role" #Read and Write Intune Devices
    $appPermission5 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "9241abd9-d0e6-425a-bd4f-47ba86e767a4","Role" #Read and write Microsoft Intune device configuration and policies
    $appPermission6 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "78145de6-330d-4800-a6ce-494ff2d33d07","Role" #Read and write Microsoft Intune apps
    $appPermission7 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "5ac13192-7ace-4fcf-b828-1a26f28068ee","Role" #Read and write Microsoft Intune configuration
    $appPermission8 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "e330c4f0-4170-414e-a55a-2f022ec2b57b","Role" #Read and write Microsoft Intune RBAC settings
    $appPermission9 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "498476ce-e0fe-48b0-b801-37ba7e2685c6","Role" #Read organization information
    $appPermission10 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "246dd0d5-5bd0-4def-940b-0421030a5b68","Role" #Read your organization's policies
    $appPermission11 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "01c0a623-fc9b-48e9-b794-0756f8e8f067","Role" #Read and write your organization's conditional access policies
    $appPermission12 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "79a677f7-b79d-40d0-a36a-3e6f8688dd7a","Role" #Read and write your organization's trust framework policies


    $reqGraph.ResourceAccess = $delPermission1, $delPermission2, $delPermission3, $delPermission4, $delPermission5, $delPermission6, $delPermission7, $appPermission1, $appPermission2, $appPermission3, $appPermission4, $appPermission5, $appPermission6, $appPermission7, $appPermission8, $appPermission9, $appPermission10, $appPermission11, $appPermission12
    
    $myApp = New-AzureADApplication -DisplayName $appName -IdentifierUris $appURI -Homepage $appHomePageUrl -ReplyUrls $appReplyURLs -PasswordCredentials $PasswordCredential -RequiredResourceAccess $reqGraph


    $AppDetailsOutput = "Application Details for the $AADApplicationName application:
=========================================================
Application Name:     $appName
Application Id:       $($myApp.AppId)
Secret Key:           $($PasswordCredential.Value)
Tenant Id:            $($tenantDetails.ObjectId)
"


    Write-Host
    Write-Host $AppDetailsOutput
}
else
{
    Write-Host
    Write-Host -f Yellow Azure AD Application $appName already exists.
}


Write-Host
Write-Host -f Green "Finished"
Write-Host


#You will receive a popup on your default browser. Sign in with the admin account and click Accept

$tenant = $tenantDetails.ObjectId
$clientid = $myApp.AppId
$URI = "https://localhost:12345"
$Resource = "https://graph.microsoft.com"

Start-Process -FilePath  "https://login.microsoftonline.com/$tenant/oauth2/authorize?client_id=$clientid&response_type=code&redirect_uri=$URI&response_mode=query&resource=$Resource&state=12345&prompt=admin_consent"
