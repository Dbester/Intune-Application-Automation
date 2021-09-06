# Install application Module #
function Load-Module ($m) {

    # If module is imported say that and do nothing
    if (Get-Module | Where-Object {$_.Name -eq $m}) {
        write-host "Module $m is already imported."
    }
    else {

        # If module is not imported, but available on disk then import
        if (Get-Module -ListAvailable | Where-Object {$_.Name -eq $m}) {
            Import-Module $m -Verbose
        }
        else {

            # If module is not imported, not available on disk, but is in online gallery then install and import
            if (Find-Module -Name $m | Where-Object {$_.Name -eq $m}) {
                Install-Module -Name $m -Force -Verbose -Scope CurrentUser
                Import-Module $m -Verbose
            }
            else {

                # If module is not imported, not available and not in online gallery then abort
                write-host "Module $m not imported, not available and not in online gallery, exiting."
                EXIT 1
            }
        }
    }
}

Load-Module "Evergreen" 

# Function to write to Storage table #
function Add-StorageTableRow
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        $table,
        
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [String]$partitionKey,

        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [String]$rowKey,

        [Parameter(Mandatory=$false)]
        [hashtable]$property
    )
    
    # Creates the table entity with mandatory partitionKey and rowKey arguments
    $entity = New-Object -TypeName "Microsoft.WindowsAzure.Storage.Table.DynamicTableEntity" -ArgumentList $partitionKey, $rowKey
    
    # Adding the additional columns to the table entity
    foreach ($prop in $property.Keys)
    {
        if ($prop -ne "TableTimestamp")
        {
            $entity.Properties.Add($prop, $property.Item($prop))
        }
    }
    
     return ($table.CloudTable.ExecuteAsync((invoke-expression "[Microsoft.WindowsAzure.Storage.Table.TableOperation]::insert(`$entity)")))
 
}

# Upload data to Storage Table #
$storageAccountName = ''
$tableName = ''
$sasToken = ''
$dateTime = get-date
$partitionKey = 'Adobe'
$Adobe = @()

# Step 2, Connect to Azure Table Storage
$storageCtx = New-AzureStorageContext -StorageAccountName $storageAccountName -SasToken $sasToken
$table = Get-AzureStorageTable -Name $tableName -Context $storageCtx

# Step 3, get the data 
$Adobe = Get-EvergreenApp -Name AdobeAcrobatReaderDC | Where-Object { $_.Architecture -eq "x64" -and $_.Language -eq "English" }

foreach ($Adob in $Adobe) {
    Add-StorageTableRow -table $table -partitionKey $partitionKey -rowKey ([guid]::NewGuid().tostring()) -property @{
    'Time' = $dateTime.ToString("yyyymmdd:hhmmss")
    'Architecture' = $Adob.Architecture
    'Platform' = "Windows"
    'Type' = "exe"
    'Version' = $Adob.Version
    'URI' = $Adobe.URI
    } | Out-Null
}