cd C:\Github\MSPSUG\Code

code .\PKIDeploy.ps1
code .\PKIDeploy.psd1

code .\WaitFor.ps1

code .\IssueIssuing.ps1


#Create folders to hold the cert public key
Invoke-Command -ComputerName S1,Auth -ScriptBlock {new-item C:\Cert2 -ItemType Directory}

#Need the DSC certificate's public key...

#Export-PFXCertificate no longer does just the public key, use export-certificate!
invoke-command -ComputerName S1 -ScriptBlock {Get-ChildItem Cert:\LocalMachine\My | `
    where-object {($_.EnhancedKeyUsageList -like "*Document Encryption*") -and `
        ($_.Subject -like "CN=S1.Company.pri")} | `
    Export-Certificate -filePath "C:\Cert2\S1.cer"}

#Copy public key to authoring box
Copy-Item '\\s1\C$\Cert2\*' 'C:\Cert2' -force

#Config needs the public key defined in the config data to encrypt!
code .\ConfigService.ps1

notepad C:\DSC\Configs\S1.mof

#LCM needs the certificate thumbprint in the CertificateID 
Enter-PSSession s1
Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -like "CN=S1.Company.pri"} | Select-Object Thumbprint
Exit-PSSession

code .\S1_LCMConfig.ps1
Set-DscLocalConfigurationManager -ComputerName S1 -Path C:\DSC\LCM -Verbose

#And.... run the config
Start-DscConfiguration -ComputerName S1 -Path C:\DSC\Configs -Verbose -wait

#New Fun Stuff!
find-module ADCSTemplateForPSEncryption
code "C:\Program Files\WindowsPowerShell\Modules\ADCSTemplateForPSEncryption\1.0.0\ADCSTemplateForPSEncryption.psm1"
#Article and Youtube video too!
#https://blogs.technet.microsoft.com/ashleymcglone/2017/08/29/function-to-create-certificate-template-in-active-directory-certificate-services-for-powershell-dsc-and-cms-encryption/
#https://www.youtube.com/watch?v=1qWF44Plbrk
