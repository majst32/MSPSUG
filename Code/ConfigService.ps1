$ConfigData = @{
        AllNodes = @(
            @{
                NodeName='*'
              }
            @{
                NodeName = 'S1' 
                PSDscAllowDomainUser=$true
                CertificateFile = 'c:\cert2\S1.cer'
                #ThumbPrint = Invoke-Command -ComputerName s1 {Get-ChildItem -Path cert:\localMachine\my | Where-Object {$_.EnhancedKeyUsageList -like "*Document Encryption*"} | Select-Object -ExpandProperty ThumbPrint}        
            }

        )
}

Configuration ConfigService {
    param (
        [pscredential]$DACredential
        )

    Import-DscResource -ModuleName xActiveDirectory -ModuleVersion 2.16.0.0

    Node S1 {
        
        Service BITSService {
            Name = 'Bits'
            StartupType = 'Automatic'
            State = 'Running'
            PsDscRunAsCredential = $DACredential
            }
    }
}

ConfigService -DACredential (get-credential) -OutputPath C:\DSC\Configs -ConfigurationData $ConfigData