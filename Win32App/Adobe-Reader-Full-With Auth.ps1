<#
    .SYNOPSIS
        Download Latest version of Adobe, pacakge it as .Intunewin. 
        Connect to Microsoft Intune Graph to retrieve an authentication token required for some functions.
    .DESCRIPTION
        Require 7-Zip to be installed locally for .exe extraction.
        Run the script from your local machine or clients server in a PS session.
        The app packages will be downloaded from Adobe and Packaged automatically.
        Local folder will be created in C:\Temp\
        Authenticate with your GA account.
    .NOTES
        Author:      Dirk Bester
        Contact:     Dirk.Bester@Contentandcloud.com
        Created:     2021-08-09
        Updated:     2021-08-09
        Version history:
        1.0.0
#>

#####################################################

$sleep = 10
$SourceFile = "C:\Temp\Adobe\AcroRead.intunewin"

#####################################################
# Authentication Token #
#####################################################

function Get-AuthToken {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthToken
    Authenticates you with the Graph API interface
    .NOTES
    NAME: Get-AuthToken
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory=$true)]
        $User
    )
    
    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
    
    $tenant = $userUpn.Host
    
    Write-Host "Checking for AzureAD module..."
    
        $AadModule = Get-Module -Name "AzureAD" -ListAvailable
    
        if ($AadModule -eq $null) {
    
            Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
            $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    
        }
    
        if ($AadModule -eq $null) {
            write-host
            write-host "AzureAD Powershell module not installed..." -f Red
            write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
            write-host "Script can't continue..." -f Red
            write-host
            exit
        }
    
    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    
        if($AadModule.count -gt 1){
    
            $Latest_Version = ($AadModule | select version | Sort-Object)[-1]
    
            $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }
    
                # Checking if there are multiple versions of the same module found
    
                if($AadModule.count -gt 1){
    
                $aadModule = $AadModule | select -Unique
    
                }
    
            $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
        }
    
        else {
    
            $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
        }
    
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    
    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    
    $resourceAppIdURI = "https://graph.microsoft.com"
    
    $authority = "https://login.microsoftonline.com/$Tenant"
    
        try {
    
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    
        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
    
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
    
        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
    
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result
    
            # If the accesstoken is valid then create the authentication header
    
            if($authResult.AccessToken){
    
            # Creating header for Authorization token
    
            $authHeader = @{
                'Content-Type'='application/json'
                'Authorization'="Bearer " + $authResult.AccessToken
                'ExpiresOn'=$authResult.ExpiresOn
                }
    
            return $authHeader
    
            }
    
            else {
    
            Write-Host
            Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
            Write-Host
            break
    
            }
    
        }
    
        catch {
    
        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
        break
    
        }
    
    }

#region Authentication

write-host

# Checking if authToken exists before running authentication
if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){

        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        write-host

            # Defining User Principal Name if not present

            if($User -eq $null -or $User -eq ""){

            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

            }

        $global:authToken = Get-AuthToken -User $User

        }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if($User -eq $null -or $User -eq ""){

    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host

    }

# Getting the authorization token
$global:authToken = Get-AuthToken -User $User

}

#endregion

#####################################################
# Just some functions to execute the script #
#####################################################


function CloneObject($object){

	$stream = New-Object IO.MemoryStream;
	$formatter = New-Object Runtime.Serialization.Formatters.Binary.BinaryFormatter;
	$formatter.Serialize($stream, $object);
	$stream.Position = 0;
	$formatter.Deserialize($stream);
}

function WriteHeaders($authToken){

	foreach ($header in $authToken.GetEnumerator())
	{
		if ($header.Name.ToLower() -eq "authorization")
		{
			continue;
		}

		Write-Output -ForegroundColor Gray "$($header.Name): $($header.Value)";
	}
}

function MakeGetRequest($collectionPath){

	$uri = "$baseUrl$collectionPath";
	$request = "GET $uri";
	
	if ($logRequestUris) { Write-Output $request; }
	if ($logHeaders) { WriteHeaders $authToken; }

	try
	{
		#Test-AuthToken
		$response = Invoke-RestMethod $uri -Method Get -Headers $authToken;
		$response;
	}
	catch
	{
		Write-Output -ForegroundColor Red $request;
		Write-Output -ForegroundColor Red $_.Exception.Message;
		throw;
	}
}

function MakePatchRequest($collectionPath, $body){

	MakeRequest "PATCH" $collectionPath $body;

}

function MakePostRequest($collectionPath, $body){

	MakeRequest "POST" $collectionPath $body;

}

function MakeRequest($verb, $collectionPath, $body){

	$uri = "$baseUrl$collectionPath";
	$request = "$verb $uri";
	
	$clonedHeaders = CloneObject $authToken;
	$clonedHeaders["content-length"] = $body.Length;
	$clonedHeaders["content-type"] = "application/json";

	if ($logRequestUris) { Write-Output $request; }
	if ($logHeaders) { WriteHeaders $clonedHeaders; }
	if ($logContent) { Write-Output -ForegroundColor Gray $body; }

	try
	{
		#Test-AuthToken
		$response = Invoke-RestMethod $uri -Method $verb -Headers $clonedHeaders -Body $body;
		$response;
	}
	catch
	{
		Write-Output -ForegroundColor Red $request;
		Write-Output -ForegroundColor Red $_.Exception.Message;
		throw;
	}
}

function UploadAzureStorageChunk($sasUri, $id, $body){

	$uri = "$sasUri&comp=block&blockid=$id";
	$request = "PUT $uri";

	$iso = [System.Text.Encoding]::GetEncoding("iso-8859-1");
	$encodedBody = $iso.GetString($body);
	$headers = @{
		"x-ms-blob-type" = "BlockBlob"
	};

	if ($logRequestUris) { Write-Output $request; }
	if ($logHeaders) { WriteHeaders $headers; }

	try
	{
		$response = Invoke-WebRequest $uri -Method Put -Headers $headers -Body $encodedBody;
	}
	catch
	{
		Write-Output -ForegroundColor Red $request;
		Write-Output -ForegroundColor Red $_.Exception.Message;
		throw;
	}

}

function FinalizeAzureStorageUpload($sasUri, $ids){

	$uri = "$sasUri&comp=blocklist";
	$request = "PUT $uri";

	$xml = '<?xml version="1.0" encoding="utf-8"?><BlockList>';
	foreach ($id in $ids)
	{
		$xml += "<Latest>$id</Latest>";
	}
	$xml += '</BlockList>';

	if ($logRequestUris) { Write-Output $request; }
	if ($logContent) { Write-Output -ForegroundColor Gray $xml; }

	try
	{
		Invoke-RestMethod $uri -Method Put -Body $xml;
	}
	catch
	{
		Write-Output -ForegroundColor Red $request;
		Write-Output -ForegroundColor Red $_.Exception.Message;
		throw;
	}
}

function UploadFileToAzureStorage($sasUri, $filepath, $fileUri){

	try {

        $chunkSizeInBytes = 1024l * 1024l * $azureStorageUploadChunkSizeInMb;
		
		# Start the timer for SAS URI renewal.
		$sasRenewalTimer = [System.Diagnostics.Stopwatch]::StartNew()
		
		# Find the file size and open the file.
		$fileSize = (Get-Item $filepath).length;
		$chunks = [Math]::Ceiling($fileSize / $chunkSizeInBytes);
		$reader = New-Object System.IO.BinaryReader([System.IO.File]::Open($filepath, [System.IO.FileMode]::Open));
		$position = $reader.BaseStream.Seek(0, [System.IO.SeekOrigin]::Begin);
		
		# Upload each chunk. Check whether a SAS URI renewal is required after each chunk is uploaded and renew if needed.
		$ids = @();

		for ($chunk = 0; $chunk -lt $chunks; $chunk++){

			$id = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($chunk.ToString("0000")));
			$ids += $id;

			$start = $chunk * $chunkSizeInBytes;
			$length = [Math]::Min($chunkSizeInBytes, $fileSize - $start);
			$bytes = $reader.ReadBytes($length);
			
			$currentChunk = $chunk + 1;			

            Write-Progress -Activity "Uploading File to Azure Storage" -status "Uploading chunk $currentChunk of $chunks" `
            -percentComplete ($currentChunk / $chunks*100)

            $uploadResponse = UploadAzureStorageChunk $sasUri $id $bytes;
			
			# Renew the SAS URI if 7 minutes have elapsed since the upload started or was renewed last.
			if ($currentChunk -lt $chunks -and $sasRenewalTimer.ElapsedMilliseconds -ge 450000){

				$renewalResponse = RenewAzureStorageUpload $fileUri;
				$sasRenewalTimer.Restart();
			
            }

		}

        Write-Progress -Completed -Activity "Uploading File to Azure Storage"

		$reader.Close();

	}

	finally {

		if ($reader -ne $null) { $reader.Dispose(); }
	
    }
	
	# Finalize the upload.
	$uploadResponse = FinalizeAzureStorageUpload $sasUri $ids;

}

function RenewAzureStorageUpload($fileUri){

	$renewalUri = "$fileUri/renewUpload";
	$actionBody = "";
	$rewnewUriResult = MakePostRequest $renewalUri $actionBody;
	
	$file = WaitForFileProcessing $fileUri "AzureStorageUriRenewal" $azureStorageRenewSasUriBackOffTimeInSeconds;

}

function WaitForFileProcessing($fileUri, $stage){

	$attempts= 600;
	$waitTimeInSeconds = 10;

	$successState = "$($stage)Success";
	$pendingState = "$($stage)Pending";
	$failedState = "$($stage)Failed";
	$timedOutState = "$($stage)TimedOut";

	$file = $null;
	while ($attempts -gt 0)
	{
		$file = MakeGetRequest $fileUri;

		if ($file.uploadState -eq $successState)
		{
			break;
		}
		elseif ($file.uploadState -ne $pendingState)
		{
			Write-Output -ForegroundColor Red $_.Exception.Message;
            throw "File upload state is not success: $($file.uploadState)";
		}

		Start-Sleep $waitTimeInSeconds;
		$attempts--;
	}

	if ($file -eq $null -or $file.uploadState -ne $successState)
	{
		throw "File request did not complete in the allotted time.";
	}

	$file;
}

function GetWin32AppBody(){

param
(

[parameter(Mandatory=$true,ParameterSetName = "MSI",Position=1)]
[Switch]$MSI,

[parameter(Mandatory=$true,ParameterSetName = "EXE",Position=1)]
[Switch]$EXE,

[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
[string]$displayName,

[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
[string]$publisher,

[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
[string]$description,

[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
[string]$filename,

[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
[string]$SetupFileName,

[parameter(Mandatory=$true)]
[ValidateSet('system','user')]
$installExperience = "system",

[parameter(Mandatory=$true,ParameterSetName = "EXE")]
[ValidateNotNullOrEmpty()]
$installCommandLine,

[parameter(Mandatory=$true,ParameterSetName = "EXE")]
[ValidateNotNullOrEmpty()]
$uninstallCommandLine,

[parameter(Mandatory=$true,ParameterSetName = "MSI")]
[ValidateNotNullOrEmpty()]
$MsiPackageType,

[parameter(Mandatory=$true,ParameterSetName = "MSI")]
[ValidateNotNullOrEmpty()]
$MsiProductCode,

[parameter(Mandatory=$false,ParameterSetName = "MSI")]
$MsiProductName,

[parameter(Mandatory=$true,ParameterSetName = "MSI")]
[ValidateNotNullOrEmpty()]
$MsiProductVersion,

[parameter(Mandatory=$false,ParameterSetName = "MSI")]
$MsiPublisher,

[parameter(Mandatory=$true,ParameterSetName = "MSI")]
[ValidateNotNullOrEmpty()]
$MsiRequiresReboot,

[parameter(Mandatory=$true,ParameterSetName = "MSI")]
[ValidateNotNullOrEmpty()]
$MsiUpgradeCode

)

    if($MSI){

	    $body = @{ "@odata.type" = "#microsoft.graph.win32LobApp" };
        $body.applicableArchitectures = "x64,x86";
        $body.description = $description;
	    $body.developer = "";
	    $body.displayName = $displayName;
	    $body.fileName = $filename;
        $body.installCommandLine = "msiexec /i `"$SetupFileName`""
        $body.installExperience = @{"runAsAccount" = "$installExperience"};
	    $body.informationUrl = $null;
	    $body.isFeatured = $false;
        $body.minimumSupportedOperatingSystem = @{"v10_1607" = $true};
        $body.msiInformation = @{
            "packageType" = "$MsiPackageType";
            "productCode" = "$MsiProductCode";
            "productName" = "$MsiProductName";
            "productVersion" = "$MsiProductVersion";
            "publisher" = "$MsiPublisher";
            "requiresReboot" = "$MsiRequiresReboot";
            "upgradeCode" = "$MsiUpgradeCode"
        };
	    $body.notes = "";
	    $body.owner = "";
	    $body.privacyInformationUrl = $null;
	    $body.publisher = $publisher;
        $body.runAs32bit = $false;
        $body.setupFilePath = $SetupFileName;
        $body.uninstallCommandLine = "msiexec /x `"$MsiProductCode`""

    }

    elseif($EXE){

        $body = @{ "@odata.type" = "#microsoft.graph.win32LobApp" };
        $body.description = $description;
	    $body.developer = "";
	    $body.displayName = $displayName;
	    $body.fileName = $filename;
        $body.installCommandLine = "$installCommandLine"
        $body.installExperience = @{"runAsAccount" = "$installExperience"};
	    $body.informationUrl = $null;
	    $body.isFeatured = $false;
        $body.minimumSupportedOperatingSystem = @{"v10_1607" = $true};
        $body.msiInformation = $null;
	    $body.notes = "";
	    $body.owner = "";
	    $body.privacyInformationUrl = $null;
	    $body.publisher = $publisher;
        $body.runAs32bit = $false;
        $body.setupFilePath = $SetupFileName;
        $body.uninstallCommandLine = "$uninstallCommandLine"

    }

	$body;
}

function GetAppFileBody($name, $size, $sizeEncrypted, $manifest){

	$body = @{ "@odata.type" = "#microsoft.graph.mobileAppContentFile" };
	$body.name = $name;
	$body.size = $size;
	$body.sizeEncrypted = $sizeEncrypted;
	$body.manifest = $manifest;
    $body.isDependency = $false;

	$body;
}

function GetAppCommitBody($contentVersionId, $LobType){

	$body = @{ "@odata.type" = "#$LobType" };
	$body.committedContentVersion = $contentVersionId;

	$body;

}

Function Test-SourceFile(){

param
(
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $SourceFile
)

    try {

            if(!(test-path "$SourceFile")){

            Write-Output "Source File '$sourceFile' doesn't exist..." -ForegroundColor Red
            throw

            }

        }

    catch {

		Write-Output -ForegroundColor Red $_.Exception.Message;
		break

    }

}

Function New-DetectionRule(){

[cmdletbinding()]

param
(
 [parameter(Mandatory=$true,ParameterSetName = "PowerShell",Position=1)]
 [Switch]$PowerShell,

 [parameter(Mandatory=$true,ParameterSetName = "MSI",Position=1)]
 [Switch]$MSI,

 [parameter(Mandatory=$true,ParameterSetName = "File",Position=1)]
 [Switch]$File,

 [parameter(Mandatory=$true,ParameterSetName = "Registry",Position=1)]
 [Switch]$Registry,

 [parameter(Mandatory=$true,ParameterSetName = "PowerShell")]
 [ValidateNotNullOrEmpty()]
 [String]$ScriptFile,

 [parameter(Mandatory=$true,ParameterSetName = "PowerShell")]
 [ValidateNotNullOrEmpty()]
 $enforceSignatureCheck,

 [parameter(Mandatory=$true,ParameterSetName = "PowerShell")]
 [ValidateNotNullOrEmpty()]
 $runAs32Bit,

 [parameter(Mandatory=$true,ParameterSetName = "MSI")]
 [ValidateNotNullOrEmpty()]
 [String]$MSIproductCode,
   
 [parameter(Mandatory=$true,ParameterSetName = "File")]
 [ValidateNotNullOrEmpty()]
 [String]$Path,
 
 [parameter(Mandatory=$true,ParameterSetName = "File")]
 [ValidateNotNullOrEmpty()]
 [string]$FileOrFolderName,

 [parameter(Mandatory=$true,ParameterSetName = "File")]
 [ValidateSet("notConfigured","exists","modifiedDate","createdDate","version","sizeInMB")]
 [string]$FileDetectionType,

 [parameter(Mandatory=$false,ParameterSetName = "File")]
 $FileDetectionValue = $null,

 [parameter(Mandatory=$true,ParameterSetName = "File")]
 [ValidateSet("True","False")]
 [string]$check32BitOn64System = "False",

 [parameter(Mandatory=$true,ParameterSetName = "Registry")]
 [ValidateNotNullOrEmpty()]
 [String]$RegistryKeyPath,

 [parameter(Mandatory=$true,ParameterSetName = "Registry")]
 [ValidateSet("notConfigured","exists","doesNotExist","string","integer","version")]
 [string]$RegistryDetectionType,

 [parameter(Mandatory=$false,ParameterSetName = "Registry")]
 [ValidateNotNullOrEmpty()]
 [String]$RegistryValue,

 [parameter(Mandatory=$true,ParameterSetName = "Registry")]
 [ValidateSet("True","False")]
 [string]$check32BitRegOn64System = "False"

)

    if($PowerShell){

        if(!(Test-Path "$ScriptFile")){
            
            Write-Output "Could not find file '$ScriptFile'..." -ForegroundColor Red
            Write-Output "Script can't continue..." -ForegroundColor Red
            break

        }
        
        $ScriptContent = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$ScriptFile"));
        
        $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppPowerShellScriptDetection" }
        $DR.enforceSignatureCheck = $false;
        $DR.runAs32Bit = $false;
        $DR.scriptContent =  "$ScriptContent";

    }
    
    elseif($MSI){
    
        $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppProductCodeDetection" }
        $DR.productVersionOperator = "notConfigured";
        $DR.productCode = "$MsiProductCode";
        $DR.productVersion =  $null;

    }

    elseif($File){
    
        $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppFileSystemDetection" }
        $DR.check32BitOn64System = "$check32BitOn64System";
        $DR.detectionType = "$FileDetectionType";
        $DR.detectionValue = $FileDetectionValue;
        $DR.fileOrFolderName = "$FileOrFolderName";
        $DR.operator =  "notConfigured";
        $DR.path = "$Path"

    }

    elseif($Registry){
    
        $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppRegistryDetection" }
        $DR.check32BitOn64System = "$check32BitRegOn64System";
        $DR.detectionType = "$RegistryDetectionType";
        $DR.detectionValue = "";
        $DR.keyPath = "$RegistryKeyPath";
        $DR.operator = "notConfigured";
        $DR.valueName = "$RegistryValue"

    }

    return $DR

}

function Get-DefaultReturnCodes(){

@{"returnCode" = 0;"type" = "success"}, `
@{"returnCode" = 1707;"type" = "success"}, `
@{"returnCode" = 3010;"type" = "softReboot"}, `
@{"returnCode" = 1641;"type" = "hardReboot"}, `
@{"returnCode" = 1618;"type" = "retry"}

}

function New-ReturnCode(){

param
(
[parameter(Mandatory=$true)]
[int]$returnCode,
[parameter(Mandatory=$true)]
[ValidateSet('success','softReboot','hardReboot','retry')]
$type
)

    @{"returnCode" = $returnCode;"type" = "$type"}

}

Function Get-IntuneWinXML(){

param
(
[Parameter(Mandatory=$true)]
$SourceFile,

[Parameter(Mandatory=$true)]
$fileName,

[Parameter(Mandatory=$false)]
[ValidateSet("false","true")]
[string]$removeitem = "true"
)

Test-SourceFile "$SourceFile"

$Directory = [System.IO.Path]::GetDirectoryName("$SourceFile")

Add-Type -Assembly System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead("$SourceFile")

    $zip.Entries | where {$_.Name -like "$filename" } | foreach {

    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$filename", $true)

    }

$zip.Dispose()

[xml]$IntuneWinXML = gc "$Directory\$filename"

return $IntuneWinXML

if($removeitem -eq "true"){ remove-item "$Directory\$filename" }

}

Function Get-IntuneWinFile(){

param
(
[Parameter(Mandatory=$true)]
$SourceFile,

[Parameter(Mandatory=$true)]
$fileName,

[Parameter(Mandatory=$false)]
[string]$Folder = "win32"
)

    $Directory = [System.IO.Path]::GetDirectoryName("$SourceFile")

    if(!(Test-Path "$Directory\$folder")){

        New-Item -ItemType Directory -Path "$Directory" -Name "$folder" | Out-Null

    }

    Add-Type -Assembly System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead("$SourceFile")

        $zip.Entries | where {$_.Name -like "$filename" } | foreach {

        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$folder\$filename", $true)

        }

    $zip.Dispose()

    return "$Directory\$folder\$filename"

    if($removeitem -eq "true"){ remove-item "$Directory\$filename" }

}

function Upload-Win32Lob(){

<#
.SYNOPSIS
This function is used to upload a Win32 Application to the Intune Service
.DESCRIPTION
This function is used to upload a Win32 Application to the Intune Service
.EXAMPLE
Upload-Win32Lob "C:\Packages\package.intunewin" -publisher "Microsoft" -description "Package"
This example uses all parameters required to add an intunewin File into the Intune Service
.NOTES
NAME: Upload-Win32LOB
#>

[cmdletbinding()]

param
(
    [parameter(Mandatory=$true,Position=1)]
    [ValidateNotNullOrEmpty()]
    [string]$SourceFile,

    [parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$displayName,

    [parameter(Mandatory=$true,Position=2)]
    [ValidateNotNullOrEmpty()]
    [string]$publisher,

    [parameter(Mandatory=$true,Position=3)]
    [ValidateNotNullOrEmpty()]
    [string]$description,

    [parameter(Mandatory=$true,Position=4)]
    [ValidateNotNullOrEmpty()]
    $detectionRules,

    [parameter(Mandatory=$true,Position=5)]
    [ValidateNotNullOrEmpty()]
    $returnCodes,

    [parameter(Mandatory=$false,Position=6)]
    [ValidateNotNullOrEmpty()]
    [string]$installCmdLine,

    [parameter(Mandatory=$false,Position=7)]
    [ValidateNotNullOrEmpty()]
    [string]$uninstallCmdLine,

    [parameter(Mandatory=$false,Position=8)]
    [ValidateSet('system','user')]
    $installExperience = "system"
)

	try	{

        $LOBType = "microsoft.graph.win32LobApp"

        Write-Output "Testing if SourceFile '$SourceFile' Path is valid..." -ForegroundColor Yellow
        Test-SourceFile "$SourceFile"

        $Win32Path = "$SourceFile"

        Write-Output "Creating JSON data to pass to the service..." -ForegroundColor Yellow

        # Funciton to read Win32LOB file
        $DetectionXML = Get-IntuneWinXML "$SourceFile" -fileName "detection.xml"

        # If displayName input don't use Name from detection.xml file
        if($displayName){ $DisplayName = $displayName }
        else { $DisplayName = $DetectionXML.ApplicationInfo.Name }
        
        $FileName = $DetectionXML.ApplicationInfo.FileName

        $SetupFileName = $DetectionXML.ApplicationInfo.SetupFile

        $Ext = [System.IO.Path]::GetExtension($SetupFileName)

        if((($Ext).contains("msi") -or ($Ext).contains("Msi")) -and (!$installCmdLine -or !$uninstallCmdLine)){

		    # MSI
            $MsiExecutionContext = $DetectionXML.ApplicationInfo.MsiInfo.MsiExecutionContext
            $MsiPackageType = "DualPurpose";
            if($MsiExecutionContext -eq "System") { $MsiPackageType = "PerMachine" }
            elseif($MsiExecutionContext -eq "User") { $MsiPackageType = "PerUser" }

            $MsiProductCode = $DetectionXML.ApplicationInfo.MsiInfo.MsiProductCode
            $MsiProductVersion = $DetectionXML.ApplicationInfo.MsiInfo.MsiProductVersion
            $MsiPublisher = $DetectionXML.ApplicationInfo.MsiInfo.MsiPublisher
            $MsiRequiresReboot = $DetectionXML.ApplicationInfo.MsiInfo.MsiRequiresReboot
            $MsiUpgradeCode = $DetectionXML.ApplicationInfo.MsiInfo.MsiUpgradeCode
            
            if($MsiRequiresReboot -eq "false"){ $MsiRequiresReboot = $false }
            elseif($MsiRequiresReboot -eq "true"){ $MsiRequiresReboot = $true }

            $mobileAppBody = GetWin32AppBody `
                -MSI `
                -displayName "$DisplayName" `
                -publisher "$publisher" `
                -description $description `
                -filename $FileName `
                -SetupFileName "$SetupFileName" `
                -installExperience $installExperience `
                -MsiPackageType $MsiPackageType `
                -MsiProductCode $MsiProductCode `
                -MsiProductName $displayName `
                -MsiProductVersion $MsiProductVersion `
                -MsiPublisher $MsiPublisher `
                -MsiRequiresReboot $MsiRequiresReboot `
                -MsiUpgradeCode $MsiUpgradeCode

        }

        else {

            $mobileAppBody = GetWin32AppBody -EXE -displayName "$DisplayName" -publisher "$publisher" `
            -description $description -filename $FileName -SetupFileName "$SetupFileName" `
            -installExperience $installExperience -installCommandLine $installCmdLine `
            -uninstallCommandLine $uninstallcmdline

        }

        if($DetectionRules.'@odata.type' -contains "#microsoft.graph.win32LobAppPowerShellScriptDetection" -and @($DetectionRules).'@odata.type'.Count -gt 1){

            Write-Warning "A Detection Rule can either be 'Manually configure detection rules' or 'Use a custom detection script'"
            Write-Warning "It can't include both..."
            break

        }

        else {

        $mobileAppBody | Add-Member -MemberType NoteProperty -Name 'detectionRules' -Value $detectionRules

        }

        #ReturnCodes

        if($returnCodes){
        
        $mobileAppBody | Add-Member -MemberType NoteProperty -Name 'returnCodes' -Value @($returnCodes)

        }

        else {

            Write-Warning "Intunewin file requires ReturnCodes to be specified"
            Write-Warning "If you want to use the default ReturnCode run 'Get-DefaultReturnCodes'"
            break

        }

        Write-Output "Creating application in Intune..." -ForegroundColor Yellow
		$mobileApp = MakePostRequest "mobileApps" ($mobileAppBody | ConvertTo-Json);

		# Get the content version for the new app (this will always be 1 until the new app is committed).
        Write-Output "Creating Content Version in the service for the application..." -ForegroundColor Yellow
		$appId = $mobileApp.id;
		$contentVersionUri = "mobileApps/$appId/$LOBType/contentVersions";
		$contentVersion = MakePostRequest $contentVersionUri "{}";

        # Encrypt file and Get File Information
        Write-Output "Getting Encryption Information for '$SourceFile'..." -ForegroundColor Yellow

        $encryptionInfo = @{};
        $encryptionInfo.encryptionKey = $DetectionXML.ApplicationInfo.EncryptionInfo.EncryptionKey
        $encryptionInfo.macKey = $DetectionXML.ApplicationInfo.EncryptionInfo.macKey
        $encryptionInfo.initializationVector = $DetectionXML.ApplicationInfo.EncryptionInfo.initializationVector
        $encryptionInfo.mac = $DetectionXML.ApplicationInfo.EncryptionInfo.mac
        $encryptionInfo.profileIdentifier = "ProfileVersion1";
        $encryptionInfo.fileDigest = $DetectionXML.ApplicationInfo.EncryptionInfo.fileDigest
        $encryptionInfo.fileDigestAlgorithm = $DetectionXML.ApplicationInfo.EncryptionInfo.fileDigestAlgorithm

        $fileEncryptionInfo = @{};
        $fileEncryptionInfo.fileEncryptionInfo = $encryptionInfo;

        # Extracting encrypted file
        $IntuneWinFile = Get-IntuneWinFile "$SourceFile" -fileName "$filename"

        [int64]$Size = $DetectionXML.ApplicationInfo.UnencryptedContentSize
        $EncrySize = (Get-Item "$IntuneWinFile").Length

		# Create a new file for the app.
        Write-Output "Creating a new file entry in Azure for the upload..." -ForegroundColor Yellow
		$contentVersionId = $contentVersion.id;
		$fileBody = GetAppFileBody "$FileName" $Size $EncrySize $null;
		$filesUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files";
		$file = MakePostRequest $filesUri ($fileBody | ConvertTo-Json);
	
		# Wait for the service to process the new file request.
        Write-Output "Waiting for the file entry URI to be created..." -ForegroundColor Yellow
		$fileId = $file.id;
		$fileUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId";
		$file = WaitForFileProcessing $fileUri "AzureStorageUriRequest";

		# Upload the content to Azure Storage.
        Write-Output "Uploading file to Azure Storage..." -f Yellow

		$sasUri = $file.azureStorageUri;
		UploadFileToAzureStorage $file.azureStorageUri "$IntuneWinFile" $fileUri;

        # Need to Add removal of IntuneWin file
        $IntuneWinFolder = [System.IO.Path]::GetDirectoryName("$IntuneWinFile")
        Remove-Item "$IntuneWinFile" -Force

		# Commit the file.
        Write-Output "Committing the file into Azure Storage..." -ForegroundColor Yellow
		$commitFileUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId/commit";
		MakePostRequest $commitFileUri ($fileEncryptionInfo | ConvertTo-Json);

		# Wait for the service to process the commit file request.
        Write-Output "Waiting for the service to process the commit file request..." -ForegroundColor Yellow
		$file = WaitForFileProcessing $fileUri "CommitFile";

		# Commit the app.
        Write-Output "Committing the file into Azure Storage..." -ForegroundColor Yellow
		$commitAppUri = "mobileApps/$appId";
		$commitAppBody = GetAppCommitBody $contentVersionId $LOBType;
		MakePatchRequest $commitAppUri ($commitAppBody | ConvertTo-Json);

        Write-Output "Sleeping for $sleep seconds to allow patch completion..." -f Magenta
        Start-Sleep $sleep
    
    }
	
    catch {

		Write-Output -ForegroundColor Red "Aborting with exception: $($_.Exception.ToString())";
	
    }
}

function New-IntuneWin32AppPackage {
       
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the full path of the source folder where the setup file and all of it's potential dependency files reside.")]
        [ValidateNotNullOrEmpty()]
        [string]$SourceFolder,

        [parameter(Mandatory = $true, HelpMessage = "Specify the complete setup file name including it's file extension, e.g. Setup.exe or Installer.msi.")]
        [ValidateNotNullOrEmpty()]
        [string]$SetupFile,

        [parameter(Mandatory = $true, HelpMessage = "Specify the full path of the output folder where the packaged .intunewin file will be exported to.")]
        [ValidateNotNullOrEmpty()]
        [string]$OutputFolder,

        [parameter(Mandatory = $false, HelpMessage = "Specify the full path to the IntuneWinAppUtil.exe file.")]
        [ValidateNotNullOrEmpty()]
        [string]$IntuneWinAppUtilPath = (Join-Path -Path $env:TEMP -ChildPath "IntuneWinAppUtil.exe")
    )
    Process {
        # Trim trailing backslashes from input paths
        $SourceFolder = $SourceFolder.TrimEnd("\")
        $OutputFolder = $OutputFolder.TrimEnd("\")

        if (Test-Path -Path $SourceFolder) {
            Write-Verbose -Message "Successfully detected specified source folder: $($SourceFolder)"

            if (Test-Path -Path (Join-Path -Path $SourceFolder -ChildPath $SetupFile)) {
                Write-Verbose -Message "Successfully detected specified setup file '$($SetupFile)' in source folder"

                if (Test-Path -Path $OutputFolder) {
                    Write-Verbose -Message "Successfully detected specified output folder: $($OutputFolder)"

                    if (-not(Test-Path -Path $IntuneWinAppUtilPath)) {                      
                        if (-not($PSBoundParameters["IntuneWinAppUtilPath"])) {
                            # Download IntuneWinAppUtil.exe if not present in context temporary folder
                            Write-Verbose -Message "Unable to detect IntuneWinAppUtil.exe in specified location, attempting to download to: $($env:TEMP)"
                            Start-DownloadFile -URL "https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/raw/master/IntuneWinAppUtil.exe" -Path $env:TEMP -Name "IntuneWinAppUtil.exe"

                            # Override path for IntuneWinApputil.exe if custom path was passed as a parameter, but was not found and downloaded to temporary location
                            $IntuneWinAppUtilPath = Join-Path -Path $env:TEMP -ChildPath "IntuneWinAppUtil.exe"
                        }
                    }

                    if (Test-Path -Path $IntuneWinAppUtilPath) {
                        Write-Verbose -Message "Successfully detected IntuneWinAppUtil.exe in: $($IntuneWinAppUtilPath)"

                        # Invoke IntuneWinAppUtil.exe with parameter inputs
                        $PackageInvocation = Invoke-Executable -FilePath $IntuneWinAppUtilPath -Arguments "-c ""$($SourceFolder)"" -s ""$($SetupFile)"" -o ""$($OutPutFolder)""" # -q
                        if ($PackageInvocation -eq 0) {
                            $IntuneWinAppPackage = Join-Path -Path $OutputFolder -ChildPath "$([System.IO.Path]::GetFileNameWithoutExtension($SetupFile)).intunewin"
                            if (Test-Path -Path $IntuneWinAppPackage) {
                                Write-Verbose -Message "Successfully created Win32 app package object"

                                # Retrieve Win32 app package meta data
                                $IntuneWinAppMetaData = Get-IntuneWin32AppMetaData -FilePath $IntuneWinAppPackage

                                # Construct output object with package details
                                $PSObject = [PSCustomObject]@{
                                    "Name" = $IntuneWinAppMetaData.ApplicationInfo.Name
                                    "FileName" = $IntuneWinAppMetaData.ApplicationInfo.FileName
                                    "SetupFile" = $IntuneWinAppMetaData.ApplicationInfo.SetupFile
                                    "UnencryptedContentSize" = $IntuneWinAppMetaData.ApplicationInfo.UnencryptedContentSize
                                    "Path" = $IntuneWinAppPackage
                                }
                                Write-Output -InputObject $PSObject
                            }
                            else {
                                Write-Warning -Message "Unable to detect expected '$($SetupFile).intunewin' file after IntuneWinAppUtil.exe invocation"
                            }
                        }
                        else {
                            Write-Warning -Message "Unexpect error occurred while packaging Win32 app. Return code from invocation: $($PackageInvocation)"
                        }
                    }
                    else {
                        Write-Warning -Message "Unable to detect IntuneWinAppUtil.exe in: $($IntuneWinAppUtilPath)"
                    }
                }
                else {
                    Write-Warning -Message "Unable to detect specified output folder: $($OutputFolder)"
                }
            }
            else {
                Write-Warning -Message "Unable to detect specified setup file '$($SetupFile)' in source folder: $($SourceFolder)"
            }
        }
        else {
            Write-Warning -Message "Unable to detect specified source folder: $($SourceFolder)"
        }
    }
}

function Get-IntuneWin32AppMetaData {
    <#
    .SYNOPSIS
        Retrieves meta data from the detection.xml file inside the packaged Win32 application .intunewin file.
 
    .DESCRIPTION
        Retrieves meta data from the detection.xml file inside the packaged Win32 application .intunewin file.
 
    .PARAMETER FilePath
        Specify an existing local path to where the Win32 app .intunewin file is located.
 
    .NOTES
        Author: Nickolaj Andersen
        Contact: @NickolajA
        Created: 2020-01-04
        Updated: 2020-06-10
 
        Version history:
        1.0.0 - (2020-01-04) Function created
        1.0.1 - (2020-06-10) Amended the pattern validation for FilePath parameter to only require a single folder instead of two-level folder structure
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify an existing local path to where the win32 app .intunewin file is located.")]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^[A-Za-z]{1}:\\\w+")]
        [ValidateScript({
            # Check if path contains any invalid characters
            if ((Split-Path -Path $_ -Leaf).IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
                Write-Warning -Message "$(Split-Path -Path $_ -Leaf) contains invalid characters"; break
            }
            else {
            # Check if file extension is intunewin
                if ([System.IO.Path]::GetExtension((Split-Path -Path $_ -Leaf)) -like ".intunewin") {
                    return $true
                }
                else {
                    Write-Warning -Message "$(Split-Path -Path $_ -Leaf) contains unsupported file extension. Supported extension is '.intunewin'"; break
                }
            }
        })]
        [string]$FilePath
    )
    Begin {
        # Load System.IO.Compression assembly for managing compressed files
        try {
            $ClassImport = Add-Type -AssemblyName "System.IO.Compression.FileSystem" -ErrorAction Stop -Verbose:$false
        }
        catch [System.Exception] {
            Write-Warning -Message "An error occurred while loading System.IO.Compression.FileSystem assembly. Error message: $($_.Exception.Message)"; break
        }
    }
    Process {
        try {
            # Attemp to open compressed .intunewin archive file from parameter input
            $IntuneWin32AppFile = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
    
            # Attempt to extract meta data from .intunewin file
            try {
                if ($IntuneWin32AppFile -ne $null) {
                    # Determine the detection.xml file inside zip archive
                    $DetectionXMLFile = $IntuneWin32AppFile.Entries | Where-Object { $_.Name -like "detection.xml" }
                    
                    # Open the detection.xml file
                    $FileStream = $DetectionXMLFile.Open()
    
                    # Construct new stream reader, pass file stream and read XML content to the end of the file
                    $StreamReader = New-Object -TypeName "System.IO.StreamReader" -ArgumentList $FileStream -ErrorAction Stop
                    $DetectionXMLContent = [xml]($StreamReader.ReadToEnd())
                    
                    # Close and dispose objects to preserve memory usage
                    $FileStream.Close()
                    $StreamReader.Close()
                    $IntuneWin32AppFile.Dispose()
    
                    # Handle return value with XML content from detection.xml
                    return $DetectionXMLContent
                }
            }
            catch [System.Exception] {
                Write-Warning -Message "An error occurred while reading application information from detection.xml file. Error message: $($_.Exception.Message)"
            }
        }
        catch [System.Exception] {
            Write-Warning -Message "An error occurred while attempting to open compressed '$($FilePath)' file. Error message: $($_.Exception.Message)"
        }
    }
}

function Start-DownloadFile {
         
    param(
        [parameter(Mandatory = $true, HelpMessage = "URL for the file to be downloaded.")]
        [ValidateNotNullOrEmpty()]
        [string]$URL,

        [parameter(Mandatory = $true, HelpMessage = "Folder where the file will be downloaded.")]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [parameter(Mandatory = $true, HelpMessage = "Name of the file including file extension.")]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
    Begin {
        # Set global variable
        $ErrorActionPreference = "Stop"

        # Construct WebClient object
        $WebClient = New-Object -TypeName System.Net.WebClient
    }
    Process {
        # Create path if it doesn't exist
        if (-not(Test-Path -Path $Path)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }

        # Register events for tracking download progress
        $Global:DownloadComplete = $false
        $EventDataComplete = Register-ObjectEvent $WebClient DownloadFileCompleted -SourceIdentifier WebClient.DownloadFileComplete -Action {$Global:DownloadComplete = $true}
        $EventDataProgress = Register-ObjectEvent $WebClient DownloadProgressChanged -SourceIdentifier WebClient.DownloadProgressChanged -Action { $Global:DPCEventArgs = $EventArgs }                

        # Start download of file
        $WebClient.DownloadFileAsync($URL, (Join-Path -Path $Path -ChildPath $Name))

        # Track the download progress
        do {
            $PercentComplete = $Global:DPCEventArgs.ProgressPercentage
            $DownloadedBytes = $Global:DPCEventArgs.BytesReceived
            if ($DownloadedBytes -ne $null) {
                Write-Progress -Activity "Downloading file: $($Name)" -Id 1 -Status "Downloaded bytes: $($DownloadedBytes)" -PercentComplete $PercentComplete
            }
        }
        until ($Global:DownloadComplete)
    }
    End {
        # Dispose of the WebClient object
        $WebClient.Dispose()

        # Unregister events used for tracking download progress
        Unregister-Event -SourceIdentifier WebClient.DownloadProgressChanged
        Unregister-Event -SourceIdentifier WebClient.DownloadFileComplete
    }
}

function Invoke-Executable {
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the file name or path of the executable to be invoked, including the extension.")]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [parameter(Mandatory = $false, HelpMessage = "Specify arguments that will be passed to the executable.")]
        [ValidateNotNull()]
        [string]$Arguments
    )

    # Construct a hash-table for default parameter splatting
    $SplatArgs = @{
        FilePath = $FilePath
        NoNewWindow = $true
        Passthru = $true
        ErrorAction = "Stop"
    }

    # Add ArgumentList param if present
    if (-not([System.String]::IsNullOrEmpty($Arguments))) {
        $SplatArgs.Add("ArgumentList", $Arguments)
    }

    # Invoke executable and wait for process to exit
    try {
        $Invocation = Start-Process @SplatArgs
        $Handle = $Invocation.Handle
        $Invocation.WaitForExit()
    }
    catch [System.Exception] {
        Write-Warning -Message $_.Exception.Message; break
    }

    return $Invocation.ExitCode
}

#####################################################

$OutputFolder = "C:\Temp\Adobe"
if (-not(Test-Path -Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

# Download latest Adobe reader #
$web = Invoke-WebRequest -Uri 'https://get.adobe.com/reader/?loc=en' -UseBasicParsing
$version = [regex]::match($web.Content,'Version ([\d\.]+)').Groups[1].Value.Substring(2).replace('.','')
$URI = "http://ardownload.adobe.com/pub/adobe/reader/win/AcrobatDC/$Version/AcroRdrDC$($Version)_en_US.exe"
$AdobeOutFile = "C:\Temp\Adobe\AcroRdrDC$($Version)_en_US.exe"
Invoke-WebRequest -Uri $URI -OutFile $AdobeOutFile -Verbose

# 7-Zip extract exe files #
$7zipPath = "C:\PROGRA~1\7-Zip\7z.exe"
$zipFile = $AdobeOutFile
$extractPath = "C:\Temp\Adobe"
Invoke-Expression "$7zipPath e -o$extractPath -y $zipFile"

$DownloadDestinationFolderPath = "C:\Temp\Adobe"

# Remove Exe file before Packaging
Remove-Item -Path $AdobeOutFile -Force

# Package new Intunewin file.
New-IntuneWin32AppPackage -SourceFolder $DownloadDestinationFolderPath -SetupFile "AcroRead.msi" -OutputFolder $OutputFolder -Verbose

Start-Sleep $sleep

$DetectionXML = Get-IntuneWinXML "$SourceFile" -fileName "detection.xml"

Start-Sleep $sleep

#####################################################
# Variables #
#####################################################

$SourceFile = "C:\Temp\Adobe\AcroRead.intunewin"
$DisplayName = "$($DetectionXML.ApplicationInfo.Name) $($DetectionXML.ApplicationInfo.MsiInfo.MsiProductVersion)"
$Publisher = "$($DetectionXML.ApplicationInfo.MsiInfo.MsiPublisher)"
$Description = "Adobe $($DetectionXML.ApplicationInfo.MsiInfo.MsiProductVersion)"
$InstallCMDLine = "msiexec /i '$($DetectionXML.ApplicationInfo.SetupFile)' /q"
$UninstallCMDLine = "MsiExec.exe /X $($DetectionXML.ApplicationInfo.MsiInfo.MsiProductCode) /q"


#####################################################
# Script exectution (cheer) #
#####################################################

$baseUrl = "https://graph.microsoft.com/beta/deviceAppManagement/"
$logRequestUris = $true;
$logHeaders = $false;
$logContent = $true;
$azureStorageUploadChunkSizeInMb = 6l;
$DetectionXML = Get-IntuneWinXML "$SourceFile" -fileName "detection.xml"

# Change the file -path and -FileorFolderName entries for detection #

$MSIRule = New-DetectionRule -MSI -MSIproductCode $DetectionXML.ApplicationInfo.MsiInfo.MsiProductCode

# Creating Array for detection Rule
$DetectionRule = @($MSIRule)
$ReturnCodes = Get-DefaultReturnCodes
$ReturnCodes += New-ReturnCode -returnCode 302 -type softReboot
$ReturnCodes += New-ReturnCode -returnCode 145 -type hardReboot

# Win32 Application Upload
# Change your Publisher, description, install and uninstall lines as required.
Upload-Win32Lob -SourceFile "$SourceFile" -publisher "$Publisher" `
-description "$Description" -detectionRules $DetectionRule -returnCodes $ReturnCodes `
-displayName "$DisplayName" `
-installCmdLine "$InstallCMDLine" `
-uninstallCmdLine "$UninstallCMDLine"

####################################################

# Delete old files #

Get-ChildItem -Path $OutputFolder -Include *.* -Recurse | foreach { $_.Delete()}
