# Win32 Application Deployment

These scripts utilize the Evergreen model to download the latest version of an application to your C:\Temp then packages it as a .Intunewin file and uploads to your authenticated tenant.

You must have 7-Zip installed on the machine you are executing the script from to extract .msi files from .exe during the Adobe script.

Run one of the application.ps1 files, enter your admin credentials and let it complete it's tasks.
Once it's completed, you can access it on your Intune tenant and complete the assignment to push out the application.
