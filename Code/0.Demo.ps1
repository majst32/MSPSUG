cd C:\Github\Live360\PKIDSC\Code

code .\PKIDeploy.ps1
code .\PKIDeploy.psd1

code .\WaitFor.ps1

code .\IssueIssuing.ps1


#Create folders to hold the cert public key
Invoke-Command -ComputerName S1,WIN-CC3ILGK5OR6 -ScriptBlock {new-item C:\Cert2 -ItemType Directory}

#Need the DSC certificate's public key...

#Export-PFXCertificate is being cranky... can export it through GUI
invoke-command -ComputerName S1 -ScriptBlock {Get-ChildItem Cert:\LocalMachine\My | `
    where-object {($_.EnhancedKeyUsageList -like "*Document Encryption*") -and `
        ($_.Subject -like "CN=S1.Company.pri")} | `
    Export-PfxCertificate -filePath "C:\Cert2\S1.cer"}

#Copy public key to authoring box
Copy-Item '\\s1\C$\Cert2\*' 'C:\Cert2' -force

#Config needs the public key defined in the config data to encrypt!
code .\ConfigService.ps1

notepad C:\DSC\Configs\S1.mof

#LCM needs the certificate thumbprint in the CertificateID 
Enter-PSSession s1
Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -like "CN=S1.Company.pri"} | `
    Select-Object Thumbprint

code .\S1_LCMConfig.ps1
Set-DscLocalConfigurationManager -ComputerName S1 -Path C:\DSC\LCM -Verbose

#And.... run the config
Start-DscConfiguration -ComputerName S1 -Path C:\DSC\Configs -Verbose -wait
