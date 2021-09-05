# Webhook Registration
Run the AppRegistration.ps1 to create a new App Registration on your Azure Tenant that will allow you to access services using Graph API.
It will require a Global Admin to connect to Azure AD.
Once you've authenticated it will complete the creation and give you a output for the: 
  Application Name
  Application ID
  Secret Key
  Tenant ID
Save this output as the Secret key will not be obtainable once you close the PowerShell session.

The session will redirect you to a Webpage to sign-in and grant admin consent for the API permissions, use the same credentials that you used to Connect-AzureAD.
Second redirect will be to a blank page, close this as it's just to https://localhost:12345

The following permissions will be added:

Agreement.Read.All - Delegated
	
Application.Read.All - Delegated
	
Device.ReadWrite.All - Application

DeviceManagementApps.ReadWrite.All - Application

DeviceManagementConfiguration.ReadWrite.All - Application

DeviceManagementManagedDevices.ReadWrite.All - Application

DeviceManagementRBAC.ReadWrite.All - Application

DeviceManagementServiceConfig.ReadWrite.All - Application

Directory.AccessAsUser.All - Delegated

Directory.AccessAsUser.All - Delegated

Directory.Read.All - Delegated

Directory.ReadWrite.All - Application

Group.ReadWrite.All - Application

Organization.Read.All - Application

Policy.Read.All - Delegated

Policy.Read.All - Application

Policy.ReadWrite.ConditionalAccess - Delegated

Policy.ReadWrite.ConditionalAccess - Application

Policy.ReadWrite.TrustFramework - Application
