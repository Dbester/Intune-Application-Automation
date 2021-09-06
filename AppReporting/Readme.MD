# Win32 Application Reporting

These scripts utilize the Evergreen model and send the latest package details to your Storage Account Table.

You will have to get the following infromation from your Azure Storage account.
 - storageAccountName
 - tableName
 - sasToken 

You can put these scripts into a Azure Automation Account to run on a scheduled time and view the application update status as you wish on your Azure Table.
Feel free to change the logic to report to another desired location.
