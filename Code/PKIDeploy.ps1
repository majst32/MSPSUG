Configuration PKIDeploy {

        Import-DSCresource -ModuleName PSDesiredStateConfiguration,
            @{ModuleName="xADCSDeployment";ModuleVersion="1.1.0.0"},
            @{ModuleName="xSMBShare";ModuleVersion="2.0.0.0"},
            @{ModuleName="xDNSServer";ModuleVersion="1.7.0.0"},
            @{ModuleName="xWebAdministration";ModuleVersion="1.17.0.0"},
            @{ModuleName="xPendingReboot";ModuleVersion="0.3.0.0"}

    Node $AllNodes.Where{$_.Role -eq "ADCSRoot"}.NodeName {

        #Set up all the variables
        $ADCSRoot = $ConfigurationData.ADCSRoot
        $ADCSSub = $ConfigurationData.ADCSSub
        
        #This should be changed to an input parameter and not in config data
        $Secure = ConvertTo-SecureString -String "$($Node.Password)" -AsPlainText -Force 
        $Credential = New-Object -typename Pscredential -ArgumentList Administrator, $secure 
        $DACredential = new-Object -typeName pscredential -ArgumentList "Company.pri\administrator", $secure

        #Install Windows Features
        foreach ($Feature in $ADCSRoot.Features) {

            WindowsFeature $Feature {
                Name = $Feature
                Ensure = 'Present'
                }
                
        }

        #Configure Root CA         
            xAdcsCertificationAuthority ADCSConfig {
                CAType = $ADCSRoot.CAType
                Credential = $Credential
                CryptoProviderName = $Node.ADCSCryptoProviderName
                HashAlgorithmName = $Node.ADCSHashAlgorithmName
                KeyLength = $Node.ADCSKeyLength
                CACommonName = $ADCSRoot.CACN
                CADistinguishedNameSuffix = $ADCSRoot.CADNSuffix
                DatabaseDirectory = $Node.CADatabasePath
                LogDirectory = $Node.CALogPath
                ValidityPeriod = $Node.ADCSValidityPeriod
                ValidityPeriodUnits = $Node.ADCSValidityPeriodUnits
                Ensure = 'Present'
                DependsOn = '[WindowsFeature]ADCS-Cert-Authority'
                }
        
        #Configure Root CA settings:  CRL and Cert publication URLs
        #Changed from registry resource to script resource

        script SetCRLCDP {
            TestScript = {
                if ((Get-CACrlDistributionPoint).count -ne 2) {Return $False}
                else {Return $True}
                }
            SetScript = {
               $crllist = Get-CACrlDistributionPoint; foreach ($crl in $crllist) {Remove-CACrlDistributionPoint $crl.uri -Force}
               Add-CACRLDistributionPoint -Uri C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl -PublishToServer -Force
               $CRLURL = $using:ADCSRoot.CRLURL
               Add-CACRLDistributionPoint -Uri "http://$($CRLURL)/pki/%3%8.crl" -AddToCertificateCDP -Force
               }
            getScript = {
               return @{Result=(Get-CACrlDistributionPoint).Count}
               }
            DependsOn = '[xADCSCertificationAuthority]ADCSConfig'
            }

        #Changed from registry resource to script resource
        script ClearAIAList {
            TestScript = {
                if ((Get-CAAuthorityInformationAccess).Count -ne 0) {return $False}
                else {Return $True}
                }
            SetScript = {
                $aialist = Get-CAAuthorityInformationAccess; foreach ($aia in $aialist) {Remove-CAAuthorityInformationAccess $aia.uri -Force}
                }
            GetScript = {
                return @{Result=(Get-CAAuthorityInformationAccess).Count}
                }
            DependsOn = '[xADCSCertificationAuthority]ADCSConfig'
            }

        #Other registry settings that can be set using registry resource

        $Key = "HKEY_Local_Machine\System\CurrentControlSet\Services\CertSvc\Configuration\$($ADCSRoot.CACN)"
        foreach ($Setting in $ADCSRoot.RegistrySettings) {

            Registry $Setting.Name  {
                Ensure = 'Present'
                Key = "$Key"
                ValueName = "$($Setting.Name)"
                ValueType = "$($Setting.Type)"
                ValueData = "$($Setting.Value)"
                DependsOn = '[xADCSCertificationAuthority]ADCSConfig'
                }
            }

            #publish CRL

            script PublishCRL {
                testScript = {
                    try {
                        $CACN=$Using:ADCSRoot.CACN
                        get-childitem -Path "C:\Windows\System32\certsrv\certenroll\$($CACN).crl" -erroraction stop
                        return $True
                        }
                    catch {
                        return $False
                        }
                    }
                setscript = {
                    certutil -crl
                    }
                getscript = {
                    Return @{Result = "None"}
                    }
                DependsOn = '[Registry]DSConfigDN'
            }

            #Copy the root certificate into a temp directory so don't have to get it from the admin share
            File CopyRootCert {
                Type = 'Directory'
                DestinationPath = "C:\temp"
                SourcePath = "C:\Windows\System32\certsrv\certenroll"
                Recurse = $true
                MatchSource = $true
                Ensure = 'Present'
                DependsOn = '[Script]PublishCRL'
                }
            
            #Share folder so subCA and dc can get to the certificate
            xSMBShare RootShare {
                Name = "RootShare"
                Path = "C:\temp"
                DependsOn = '[File]CopyRootCert'
                }   

            #Now wait until the subCA is complete
            WaitForAll WFADCSSub {
                NodeName = 'ENTSUB'
                ResourceName = '[xADCSCertificationAuthority]ADCSSub'
                RetryIntervalSec = 60
                RetryCount = 30
                DependsOn = '[xSMBShare]RootShare'
                }

            #After subordinate is installed, copy the cert request to the root.
            File ADCSCertReq {
                Ensure = 'Present'
                SourcePath = "\\ENTSub\C$\ENTSub.$($node.DNSSuffix)_IssuingCA-$($ADCSRoot.CACN).req"
                DestinationPath = "C:\ENTSub.$($node.DNSSuffix)_IssuingCA-$($ADCSRoot.CACN).req"
                #Contents =  "$($Node.Nodename).$($node.DNSSuffix)_IssuingCA-$($ADCSRoot.CompanyRoot).req"
                MatchSource = $True
                Type = 'File'
                Force = $True
                Credential = $DACredential
                }

            File IssuingCertFolder {
                Ensure = 'Present'
                DestinationPath = "C:\ForIssuing"
                Type = 'Directory'
                }

            xSMBShare IssuingCertShare {
                Name = "IssuingShare"
                Path = "C:\ForIssuing"
                DependsOn = '[File]IssuingCertFolder'
                }
             
            Script IssueIssuingCert {
                PsDscRunAsCredential = $Credential
                TestScript = {
                    $CACN = $Using:ADCSRoot.CACN
                    $IssuingName = $Using:ADCSSub.Name
                    $DNSSuffix = $Using:Node.DNSSuffix
                    if (!(Test-Path "C:\ForIssuing\$($IssuingName).$($DNSSuffix)_IssuingCA-$($CACN).crt")) {
                        return $False
                        }
                    else {return $True}
                    }
                SetScript = {
                    Write-Verbose "Starting set..."
                    #remove-item "C:\ForIssuing\*.*" -Recurse
                    $CACN = $Using:ADCSRoot.CACN
                    $IssuingName = $Using:ADCSSub.Name
                    $DNSSuffix = $Using:Node.DNSSuffix
                    #write-verbose "Submitting request..."
                    #$req = certreq -config "localhost\$($CACN)" -submit "C:\$($IssuingName).$($DNSSuffix)_IssuingCA-$($CACN).req"
                    #$ReqSplit = $Req -split("RequestID: ",2)
                    #$ReqSplit = $ReqSplit[1]
                    #write-verbose $ReqSplit[1]
                    write-verbose "Issuing request..."
                    certutil -resubmit 2
                    write-verbose "Retrieving certificate..."
                    $Null = certreq -config "localhost\$($CACN)" -retrieve 2 "C:\ForIssuing\$($IssuingName).$($DNSSuffix)_IssuingCA-$($CACN).crt"
                    }
                GetScript = {
                    $CACN = $Using:ADCSRoot.CACN
                    $IssuingName = $Using:ADCSSub.Name
                    $DNSSuffix = $Using:Node.DNSSuffix
                    $Result = test-path "C:\ForIssuing\$($IssuingName).$($DNSSuffix)_IssuingCA-$($CACN).crt"
                    return @{Result = $Result}
                    }
                }

 
        }  #End ADCSRoot

    Node $AllNodes.Where({$_.Role -eq "DC"}).NodeName {

    $Secure = ConvertTo-SecureString -String "$($Node.Password)" -AsPlainText -Force 
    $Credential = New-Object -typename Pscredential -ArgumentList Administrator, $secure 
    $OLRoot = $AllNodes.Where({$_.Role -eq "ADCSRoot"}).NodeName
    $DCData = $ConfigurationData.DomainData
        
        #Create a DNS record for www.company.pri
        xDnsRecord PKIRecord {
            Name = "www"
            Zone = $Node.DNSSuffix
            PsDscRunAsCredential = $DACredential
            Ensure = 'Present'
            Type = 'ARecord'
            Target = $Node.ENTSubIP
        }
        
        
        #Wait for share with root certificate to be available
        WaitForAll WaitForRoot {
            NodeName = 'OLRoot.company.pri'
            ResourceName = '[xSMBShare]RootShare'
            Retryintervalsec = 60
            RetryCount = 30
        }

          File RootCerttoDC {
            SourcePath = "\\$OLRoot\RootShare"
            DestinationPath = "C:\temp"
            Type = 'Directory'
            MatchSource = $True
            Recurse = $True
            Ensure = 'Present'
            Credential = $Credential
            DependsOn = '[WaitForAll]WaitForRoot'
            }

        #publish root certificate to AD
        Script DSPublish {
                Credential = $DACredential
                TestScript = {
                    try {
                        Get-ADObject -Identity "CN=CompanyRoot,CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=Company,DC=Pri"
                        Return $True
                    }
                    Catch {
                        Return $False
                        }
                    }
                SetScript = {
                    certutil -dspublish -f "C:\Temp\OLROOT_CompanyRoot.crt" RootCA
                    }
                GetScript = {
                    Return @{Result = (Get-ADObject -Identity "CN=CompanyRoot,CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=Company,DC=Pri").Name}
                    }
                }

        WaitForAll WaitForCAReady {
                NodeName = 'EntSub'
                ResourceName = '[Script]PublishCRLIssuing'
                Retryintervalsec = 60
                RetryCount = 30
            }
            
        
        #Add GPO for PKI AutoEnroll
        script CreatePKIAEGpo
        {
            Credential = $DACredential
            TestScript = {
                            if ((get-gpo -name "PKI AutoEnroll" -domain $Using:DCData.DomainName -ErrorAction SilentlyContinue) -eq $Null) {
                                return $False
                            } 
                            else {
                                return $True}
                        }
            SetScript = {
                            new-gpo -name "PKI AutoEnroll" -domain $Using:DCData.DomainName
                        }
            GetScript = {
                            $GPO= (get-gpo -name "PKI AutoEnroll" -domain $Using:DCData.DomainName)
                            return @{Result = $($GPO.DisplayName)}
                        }
            DependsOn = '[Script]DSPublish'   
            }

       
        script setAEGPRegSetting1
        {
            Credential = $DACredential
            TestScript = {
                            if ((Get-GPRegistryValue -name "PKI AutoEnroll" -domain $Using:DCData.DomainName -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName "AEPolicy" -ErrorAction SilentlyContinue).Value -eq 7) {
                                return $True
                            }
                            else {
                                return $False
                            }
                        }
            SetScript = {
                            Set-GPRegistryValue -name "PKI AutoEnroll" -domain $Using:DCData.DomainName -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName "AEPolicy" -Value 7 -Type DWord
                        }
            GetScript = {
                            $RegVal1 = (Get-GPRegistryValue -name "PKI AutoEnroll" -domain $Using:DCData.DomainName -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName "AEPolicy")
                            return @{Result = "$($RegVal1.FullKeyPath)\$($RegVal1.ValueName)\$($RegVal1.Value)"}
                        }
            DependsOn = '[Script]CreatePKIAEGpo'
        }

        script setAEGPRegSetting2 
        {
            Credential = $DACredential
            TestScript = {
                            if ((Get-GPRegistryValue -name "PKI AutoEnroll" -domain $Using:DCData.DomainName -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName "OfflineExpirationPercent" -ErrorAction SilentlyContinue).Value -eq 10) {
                                return $True
                                }
                            else {
                                return $False
                                 }
                         }
            SetScript = {
                            Set-GPRegistryValue -Name "PKI AutoEnroll" -domain $Using:DCData.DomainName -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName "OfflineExpirationPercent" -value 10 -Type DWord
                        }
            GetScript = {
                            $Regval2 = (Get-GPRegistryValue -name "PKI AutoEnroll" -domain $Using:DCData.DomainName -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName "OfflineExpirationPercent")
                            return @{Result = "$($RegVal2.FullKeyPath)\$($RegVal2.ValueName)\$($RegVal2.Value)"}
                        }
            DependsOn = '[Script]setAEGPRegSetting1'

        }
                              
        script setAEGPRegSetting3
        {
            Credential = $DACredential
            TestScript = {
                            if ((Get-GPRegistryValue -Name "PKI AutoEnroll" -domain $Using:DCData.DomainName -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName "OfflineExpirationStoreNames" -ErrorAction SilentlyContinue).value -match "MY") {
                                return $True
                                }
                            else {
                                return $False
                                }
                        }
            SetScript = {
                            Set-GPRegistryValue -Name "PKI AutoEnroll" -domain $Using:DCData.DomainName -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName "OfflineExpirationStoreNames" -value "MY" -Type String
                        }
            GetScript = {
                            $RegVal3 = (Get-GPRegistryValue -Name "PKI AutoEnroll" -domain $Using:DCData.DomainName -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName "OfflineExpirationStoreNames")
                            return @{Result = "$($RegVal3.FullKeyPath)\$($RegVal3.ValueName)\$($RegVal3.Value)"}
                        }
            DependsOn = '[Script]setAEGPRegSetting2'
        }
        
        Script SetAEGPLink
        {
            Credential = $DACredential
            TestScript = {
                            try {
                                $GPLink = (get-gpo -Name "PKI AutoEnroll" -Domain $Using:DCData.DomainName).ID
                                $GPLinks = (Get-GPInheritance -Domain $Using:Node.DomainName -Target $Using:DCData.DomainDN).gpolinks | Where-Object {$_.GpoID -like "*$GPLink*"}
                                if ($GPLinks.Enabled -eq $True) {return $True}
                                else {return $False}
                                }
                            catch {
                                Return $False
                                }
                         }
            SetScript = {
                            New-GPLink -name "PKI AutoEnroll" -domain $Using:DCData.DomainName -Target $Using:DCData.DomainDN -LinkEnabled Yes 
                        }
            GetScript = {
                           $GPLink = (get-gpo -Name "PKI AutoEnroll" -Domain $Using:DCData.DomainName).ID
                           $GPLinks = (Get-GPInheritance -Domain $Using:DCData.DomainName -Target $Using:DCData.DomainDN).gpolinks | Where-Object {$_.GpoID -like "*$GPLink*"}
                           return @{Result = "$($GPLinks.DisplayName) = $($GPLinks.Enabled)"}
                        }
            DependsOn = '[Script]setAEGPRegSetting3'
        }  
        
        script CreateDSCTemplate
        {
            DependsOn = '[script]SetAEGPLink'
            Credential = $DACredential
            TestScript = {
                $DCData = $Using:ConfigurationData.DomainData
                try {
                    $DSCTemplate=get-ADObject -Identity "CN=DSCTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($DCData.DomainDN)" -Properties * -ErrorAction Stop
                    return $True
                    }
                catch {
                    return $False
                    }
                }
            SetScript = {
                    $DCData = $Using:ConfigurationData.DomainData
                    $DSCTemplateProps = @{'flags'='131680';
                    'msPKI-Cert-Template-OID'='1.3.6.1.4.1.311.21.8.16187918.14945684.15749023.11519519.4925321.197.13392998.8282280';
                    'msPKI-Certificate-Application-Policy'='1.3.6.1.4.1.311.80.1';
                    'msPKI-Certificate-Name-Flag'='1207959552';
                    #'msPKI-Enrollment-Flag'='34';
                    'msPKI-Enrollment-Flag'='32';
                    'msPKI-Minimal-Key-Size'='2048';
                    'msPKI-Private-Key-Flag'='0';
                    'msPKI-RA-Signature'='0';
                    #'msPKI-Supersede-Templates'='WebServer';
                    'msPKI-Template-Minor-Revision'='3';
                    'msPKI-Template-Schema-Version'='2';
                    'pKICriticalExtensions'='2.5.29.15';
                    'pKIDefaultCSPs'='1,Microsoft RSA SChannel Cryptographic Provider';
                    'pKIDefaultKeySpec'='1';
                    'pKIExtendedKeyUsage'='1.3.6.1.4.1.311.80.1';
                    'pKIMaxIssuingDepth'='0';
                    'revision'='100'}


                    New-ADObject -name "DSCTemplate" -Type pKICertificateTemplate -Path "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($DCData.DomainDN)" -DisplayName DSCTemplate -OtherAttributes $DSCTemplateProps
                    $WSOrig = Get-ADObject -Identity "CN=Workstation,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($DCData.DomainDN)" -Properties * | Select-Object pkiExpirationPeriod,pkiOverlapPeriod,pkiKeyUsage
                    [byte[]] $WSOrig.pkiKeyUsage = 48
                    Get-ADObject -Identity "CN=DSCTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($Using:DCData.DomainDN)" | Set-ADObject -Add @{'pKIKeyUsage'=$WSOrig.pKIKeyUsage;'pKIExpirationPeriod'=$WSOrig.pKIExpirationPeriod;'pkiOverlapPeriod'=$WSOrig.pKIOverlapPeriod}
                    }
                GetScript = {
                                try {
                                    $DCData = $Using:ConfigurationData.DomainData
                                    $dsctmpl = get-ADObject -Identity "CN=DSCTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($DCData.DomainDN)" -Properties * -ErrorAction Stop
                                    return @{Result=$dsctmpl.DistinguishedName}
                                    }
                                catch {
                                    return @{Result=$Null}
                                    }
                            }
        }

          WaitForAll WaitForTemplatePublish {
            NodeName = 'EntSub'
            ResourceName = '[Script]PublishDSCTemplate'
            Retryintervalsec = 60
            RetryCount = 30
        }

        #region template permissions
#Permission beginning with 0e10... is "Enroll".  Permission beginning with "a05b" is autoenroll.
#TODO:  Write-Verbose in other script resources.
#TODO:  Make $Perms a has table with GUID and permission name.  Use name in resource name.

        [string[]]$Perms = "0e10c968-78fb-11d2-90d4-00c04f79dc55","a05b8cc2-17bc-4802-a710-e7c15ab866a2"

        foreach ($P in $Perms) {
                      
                script "Perms_DSCCert_$($P)"
                {
                    DependsOn = '[WaitForAll]WaitForTemplatePublish'
                    Credential = $DACredential
                    TestScript = {
                        Import-Module activedirectory -Verbose:$false
                        $DCData = $Using:ConfigurationData.DomainData
                        $DSCCertACL = (get-acl "AD:CN=DSCTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($DCData.DomainDN)").Access | Where-Object {$_.IdentityReference -like "*Domain Computers*"}
                        if ($DSCCertACL -eq $Null) {
                            write-verbose -Message ("Domain Computers does not have permissions on DSC template")
                            Return $False
                            }
                        elseif (($DSCCertACL.ActiveDirectoryRights -like "*ExtendedRight*") -and ($DSCCertACL.ObjectType -notcontains $Using:P)) {
                            write-verbose -Message ("Domain Computers group has permission, but not the correct permission...")
                            Return $False
                            }
                        else {
                            write-verbose -Message ("ACL on DSC Template is set correctly for this GUID for Domain Computers...")
                            Return $True
                            }
                        }
                     SetScript = {
                        Import-Module activedirectory -Verbose:$false
                        $DCData = $Using:ConfigurationData.DomainData
                        $DomainComputersGroup = get-adgroup -Identity "Domain Computers" | Select-Object SID
                        $EnrollGUID = [GUID]::Parse($Using:P)
                        $ACL = get-acl "AD:CN=DSCTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($DCData.DomainDN)"
                        $ACL.AddAccessRule((New-Object System.DirectoryServices.ExtendedRightAccessRule $DomainComputersGroup.SID,'Allow',$EnrollGUID,'None'))
                        #$ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $WebServersGroup.SID,'ReadProperty','Allow'))
                        #$ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $WebServersGroup.SID,'GenericExecute','Allow'))
                        set-ACL "AD:CN=DSCTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($DCData.DomainDN)" -AclObject $ACL
                        write-verbose -Message ("Permissions set for Domain Computers...")
                        }
                     GetScript = {
                        Import-Module activedirectory -Verbose:$false
                        $DSCCertACL = (get-acl "AD:CN=WebServer2,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($DCData.DomainDN)").Access | Where-Object {$_.IdentityReference -like "*Domain Computers"}
                        if ($DSCCertACL -ne $Null) {
                            return @{Result=$DSCCertACL}
                            }
                        else {
                            Return @{}
                            }
                        }
                 }
      }   
 
    }
        
    Node $AllNodes.Where{$_.Role -eq "ADCSSub"}.NodeName {

        $Secure = ConvertTo-SecureString -String "$($Node.Password)" -AsPlainText -Force 
        $Credential = New-Object -typename Pscredential -ArgumentList Administrator, $secure 
        $DACredential = new-Object -typeName pscredential -ArgumentList "Company.pri\administrator", $secure

        #NonNodeData
        $ADCSSub = $ConfigurationData.ADCSSub
        $ADCSRoot = $ConfigurationData.ADCSRoot
        $DomainData = $ConfigurationData.DomainData

        $OLRoot = $AllNodes.Where({$_.Role -eq "ADCSRoot"}).NodeName
        
        WaitForAll WFADCSRootInstall {
            NodeName = 'olroot.company.pri'
            ResourceName = '[xSMBShare]RootShare'
            RetryIntervalSec = 60
            RetryCount = 30
            PsDscRunAsCredential = $Credential
            }
        
        WaitForAll WFDSPublish {
            NodeName = 'DC1'
            ResourceName = '[Script]DSPublish'
            RetryIntervalSec = 60
            RetryCount = 30
            PsDscRunAsCredential = $Credential
            }

        #Copy Root Cert from OLRoot
        File RootCert {
            SourcePath = "\\$OLRoot\RootShare"
            DestinationPath = "C:\temp"
            Ensure = 'Present'
            MatchSource = $True
            Recurse = $True
            Credential = $Credential
            }
#>
        $RootFile = "$($OlRoot.Split(".")[0])_$($ADCSRoot.CACN).crt"

        #Import Root Cert into Trusted Root Store on SubCA
        #certutil –addstore –f root orca1_ContosoRootCA.crt
        Script ImportRoot {
            TestScript = {
                $Issuer = $Using:ADCSRoot.CaCN
                $Cert = get-childitem -Path Cert:\LocalMachine\Root | Where-Object {$_.Issuer -like "*$issuer*"}
                if ($Cert -eq $Null) {return $False}
                else {return $True}
                }
            SetScript = {
                Import-Certificate -FilePath "C:\temp\$Using:RootFile" -CertStoreLocation "Cert:\LocalMachine\Root"
                }
            GetScript = {
                $Issuer = $Using:ADCSRoot.CaCN
                $Result = Get-ChildItem -path Cert:\LocalMachine\Root | where-object {$_Issuer -like "$Issuer*"} | select-object Subject
                return @{Result=$Result}
                }
            }
          
          #Certutil -addstore -root CRLFile - need code
          #This was accidentally skipped and is new/untested

          script ImportCRL {
            TestScript = {
                $Store = certutil -store root
                $count = 0
                foreach ($obj in $store) { 
                    if ($obj -like "*= CRL*") {
                        $Next = $Count+1 
                        $CRLList = $Store[$Next..$Store.Count]
                        foreach ($Line in $CRLList) {
                            $CACN = $Using:ADCSRoot.CACN
                            if ($Line -like "*$CACN*") {
                                return $True
                                }
                            else {
                                return $False
                                }
                            }
                        }
                    else {$Count++}
                    }
                return $false
                }
            SetScript = {
                $CRLName = $Using:ADCSRoot.CACN
                $CRLFile = "$CRLName.crl"
                certutil -addstore -f root "C:\temp\$CRLFile"
                }
            GetScript = {
             $Store = certutil -store root
             $count = 0
             foreach ($obj in $store) { 
                if ($obj -like "*= CRL*") {
                    $Next = $Count+1 
                    $CRLList = $Store[$Next..$Store.Count]
                    foreach ($Line in $CRLList) {
                        $CACN = $Using:ADCSRoot.CACN
                        if ($Line -like "*$CACN*") {
                            return @{Result=$True}
                                }
                            else {
                                return @{Result=$False}
                                }
                            }
                        }
                    else {$Count++}
                    }
                }
            }
 
 <#       The intent of this part of the code is to try to detect if this is the first time through the IIS settings portion and set a flag for
          a reboot (here) or iisreset after all the settings are set.
          
          ##### ONCE AGAIN, DO NOT USE THIS PART OF THE CODE, IT WILL CAUSE AN INFINITE REBOOT LOOP.  FUN TIMES FOR ALL.  #####
            
          script SetForIISReboot {
            testScript = {
                    if ((get-windowsfeature -name Web-Server).Installed -eq $False) 
                        {return $False}
                    else {return $True}
            }
            setScript = {
                $global:DSCMachineStatus = 1
                }
            getscript = {
                return @{Result = $global:DSCMachineStatus}
            }
        }
#>              
          foreach ($Feature in $ADCSSub.Features) {

            WindowsFeature $Feature {
                Name = $Feature
                Ensure = 'Present'
                }              
        }
           
            #Create directory structure for virtual directory
            File PKICRLDir {
                Ensure = 'Present'
                Type = 'Directory'
                DestinationPath = 'C:\pki'
                }
           
           #Create file
            File PKICRL {
                Ensure = 'Present'
                Type = 'File'
                DestinationPath = 'C:\pki\cps.txt'
                Contents = 'Example CPS Statement'
                }
            #Create Share

            xSmbShare PKIShare {
                Name = 'PKI'
                Path = 'C:\pki'
                FullAccess = "$($Node.DomainShortName)\Domain Admins","NT AUTHORITY\SYSTEM"
                ChangeAccess = "$($Node.DomainShortName)\Cert Publishers"
                }
        

        #Install website for CRL distribution
            xWebvirtualDirectory PKI {
                Website = "Default Web Site"
                Name = 'PKI'
                PhysicalPath = 'C:\pki'
                Ensure = 'Present'
                WebApplication = ''
                }

        #Set ACLs on folder for CRL publishing
       
            Script CertPub {
                TestScript = {
                    $DomainDN = $Using:Node.DomainShortName
                    $UserID = "$($DomainDN)\Cert Publishers"
                    $ACL = (get-ACL -Path C:\PKI).Access | Where-Object {($_.FileSystemRights -like "*Modify*") -and ($_.IdentityReference -eq $UserID) -and ($_.AccessControlType -eq "Allow")}
                    if ($ACL -ne $Null) {
                        return $True
                    }
                    else {
                        return $False
                    }
                }
                SetScript = {
                    icacls C:\PKI /grant "Cert Publishers:(OI)(CI)(M)"
                }
                GetScript = {
                    $UserID = "$Using:Node.DomainShortName\Cert Publishers"
                    return @{Result = (get-ACL -Path C:\PKI).Access | Where-Object {($_.FileSystemRights -like "*Modify*") -and ($_.IdentityReference -eq $Userid) -and ($_.AccessControlType -eq "Allow")}}
                }
            }
       
        #Set ACLs on folder for CRL publishing
            Script Anonymous {
                TestScript = {
                    $ACL = (get-ACL -Path C:\PKI).Access | Where-Object {($_.FileSystemRights -like "*Read*") -and ($_.IdentityReference -eq "IIS AppPool\DefaultAppPool") -and ($_.AccessControlType -eq "Allow")}
                    if ($ACL -ne $Null) {
                        return $True
                    }
                    else {
                        return $False
                    }
                }
                SetScript = {
                    icacls C:\PKI /grant "IIS AppPool\DefaultAppPool:(OI)(CI)(GR)"
                }
                GetScript = {
                    return @{Result = (get-ACL -Path C:\PKI).Access | Where-Object {($_.FileSystemRights -like "*ReadAndExecute*") -and ($_.IdentityReference -eq "IIS AppPool\DefaultAppPool") -and ($_.AccessControlType -eq "Allow")}}
                }
            } 

<#          A fun little custom resource attempt at setting NTFS permissions.  Currently doesn't work, there are problems with Test-TargetResource.
            Could use some help on the resource and don't plan on giving up on it, just gave up for this presentation.

            FileACLs Anonymous {
                Path = "C:\PKI"
                IdentityReference = "IIS AppPool\DefaultAppPool"
                FileSystemRights = 'Read','ReadAndExecute','ListDirectory'
                AccessControlType = 'Allow'
                InheritanceFlags = "ContainerInherit","ObjectInherit"
                PropagationFlags = "None"
                Ensure = 'Present'
            }
 #>

            #Set the double escaping checkbox in IIS

            Script DoubleEscaping {
                TestScript = {
                    $Test = (Get-WebConfiguration -Filter system.webServer/security/requestFiltering -PSPath ‘IIS:\sites\Default Web Site\PKI’ | Select-Object AllowDoubleEscaping)
                    if ($Test.allowDoubleEscaping -eq $True) {
                        return $True
                        }
                    else {return $False}
                    }
                SetScript = {
                    $filter = Get-WebConfiguration -Filter system.webServer/security/requestFiltering -PSPath 'IIS:\sites\Default Web Site\PKI'
                    $Filter.AllowDoubleEscaping = $True
                    $Filter | Set-WebConfiguration -Filter system.webServer/security/requestFiltering -PSPath 'IIS:\sites\Default Web Site\PKI'
                    }
                GetScript = {
                    $Filter = (Get-WebConfiguration -Filter system.webServer/security/requestFiltering -PSPath ‘IIS:\sites\Default Web Site\PKI’ | Select-Object AllowDoubleEscaping)
                    return @{Result = $Filter.AllowDoubleEscaping}
                    }
                }
            
<#            #Reboot to pick up IIS settings (can be changed to iisreset) if needed, but won't do anything until the code to indicate it's necessary is fixed.
            xPendingReboot RebootforIIS {
                Name = 'RebootEntSub'
                DependsOn = '[Script]DoubleEscaping'
            }
#>                                               
            xAdcsCertificationAuthority ADCSSub {
                CAType = $ADCSSub.CAType
                Credential = $DACredential
                CryptoProviderName = $Node.ADCSCryptoProviderName
                HashAlgorithmName = $Node.ADCSHashAlgorithmName
                KeyLength = $Node.ADCSKeyLength
                CACommonName = $ADCSSub.CACN
                CADistinguishedNameSuffix = $ADCSSub.CADNSuffix
                DatabaseDirectory = $Node.CADatabasePath
                LogDirectory = $Node.CALogPath
                ParentCA = "$($OLRoot)\$($ADCSRoot.CACN)"
                Ensure = 'Present'
                DependsOn = '[WindowsFeature]ADCS-Cert-Authority'
                }      
                
            WaitForAll WFIssueCert {
                NodeName = 'OLRoot.company.pri'
                ResourceName = '[Script]IssueIssuingCert'
                RetryIntervalSec = 60
                RetryCount = 30
                PsDscRunAsCredential = $Credential
            } 
            
            File IssuingDir {
                Ensure = 'present'
                SourcePath = "\\olroot\IssuingShare"
                DestinationPath = "C:\Issuing"
                MatchSource = $true
                Type = 'Directory'
                Recurse = $True
                Force = $True 
                Credential = $Credential
                DependsOn = '[WaitForAll]WFIssueCert'
                }

            File PublishedRootCRL {
                Ensure = 'Present'
                SourcePath = "C:\Temp\$($ADCSRoot.CACN).crl"
                DestinationPath = "C:\PKI\$($ADCSRoot.CACN).crl"
                Type = 'File'
                DependsOn = '[File]IssuingDir'
                }

            File PublishedRoot {
                Ensure='Present'
                SourcePath = "C:\Temp\$($ADCSRoot.ShortName)_$($ADCSRoot.CACN).crt"
                DestinationPath = "C:\PKI\$($ADCSRoot.ShortName)_$($ADCSRoot.CACN).crt"
                Type = "File"
                DependsOn = '[File]PublishedRootCRL'
                }


            Script InstallAndStart {
                PsDscRunAsCredential = $DACredential
                TestScript = {
                    $Status = get-service certsvc
                    if ($Status.status -eq "Stopped") {
                        Return $False
                        }
                    else {Return $True}
                    }
                SetScript = {
                    $SN = $Using:ADCSSub.Name
                    $DNSSuffix = $Using:Node.DNSSuffix
                    $CACN = $Using:ADCSSub.CACN
                    $Path = "C:\Issuing\$($SN).$($DNSSuffix)_$($CACN).crt"
                    $command = "certutil -InstallCert $Path"
                    write-verbose "Installing Certificate if needed..."
                    $Null = Invoke-Expression -Command $Command
                    write-verbose "Starting service..."
                    start-service certsvc
                    #Give service a chance to start and create files
                    start-sleep -seconds 60
                    }
                GetScript = {
                    $Status = get-service certsvc
                    Return @{Result = $Status.status}
                    }
                DependsOn = '[File]PublishedRoot'
                }   
      
            File PublishIssuing {
                Ensure='Present'
                SourcePath = "C:\windows\system32\certsrv\certenroll\$($ADCSSub.Name).$($Node.DNSSuffix)_$($ADCSSub.CACN).crt"
                DestinationPath = "C:\PKI\$($ADCSSub.Name).$($Node.DNSSuffix)_$($ADCSSub.CACN).crt"
                Type = "File"
                MatchSource = $True
                DependsOn = '[Script]InstallAndStart'
                }

            File PublishIssuingCRL {
                PsDscRunAsCredential = $DACredential
                Ensure='Present'
                SourcePath = "C:\windows\system32\certsrv\certenroll\$($ADCSSub.CACN).crl"
                DestinationPath = "C:\PKI\$($ADCSSub.CACN).crl"
                Type = "File"
                MatchSource = $True
                DependsOn = '[File]PublishIssuing'
                }

            File PublishIssuingDeltaCRL {
                Ensure='Present'
                SourcePath = "C:\windows\system32\certsrv\certenroll\$($ADCSSub.CACN)+.crl"
                DestinationPath = "C:\PKI\$($ADCSSub.CACN)+.crl"
                Type = "File"
                MatchSource = $True
                DependsOn = '[File]PublishIssuingCRL'
                }

            script SetCRLCDP {
            TestScript = {
                if ((Get-CACrlDistributionPoint).count -ne 3) {Return $False}
                else {Return $True}
                }
            SetScript = {
               $crllist = Get-CACrlDistributionPoint; foreach ($crl in $crllist) {Remove-CACrlDistributionPoint $crl.uri -Force}
               Add-CACRLDistributionPoint -Uri C:\Windows\System32\CertSrv\CertEnroll\%3%8%9.crl -PublishToServer -Force
               $CRLURL = $using:ADCSRoot.CRLURL
               $IssuingName = $Using:adcsSub.Name
               $DNSSuffix = $Using:Node.DNSSuffix
               Add-CACRLDistributionPoint -Uri "http://$($CRLURL)/pki/%3%8%9.crl" -AddToCertificateCDP -Force
               Add-CACRLDistributionPoint -Uri "file://\\$($IssuingName).$($DNSSuffix)\pki\%3%8%9.crl" -PublishToServer -PublishDeltaToServer -Force
               }
            getScript = {
               return @{Result=(Get-CACrlDistributionPoint).Count}
               }
            DependsOn = '[File]PublishIssuingDeltaCRL'
            }

        #Changed from registry resource to script resource, untested
        script ModifyAIAList {
            TestScript = {
                if ((Get-CAAuthorityInformationAccess).Count -ne 1) {return $False}
                else {Return $True}
                }
            SetScript = {
                $aialist = Get-CAAuthorityInformationAccess 
                foreach ($aia in $aialist) {
                    Remove-CAAuthorityInformationAccess $aia.uri -Force
                    }
                $CRLURL = $Using:ADCSRoot.CRLUrl
                Add-CAAuthorityInformationAccess -AddToCertificateAia http://$($CRLURL)/pki/%1_%3%4.crt -Force
                }
            GetScript = {
                return @{Result=(Get-CAAuthorityInformationAccess).Count}
                }
            DependsOn = '[script]SetCRLCDP'
            }

        #Other registry settings that can be set using registry resource

        $Key = "HKEY_Local_Machine\System\CurrentControlSet\Services\CertSvc\Configuration\$($ADCSRoot.CACN)"
        foreach ($Setting in $ADCSSub.RegistrySettings) {

            Registry $Setting.Name  {
                Ensure = 'Present'
                Key = "$Key"
                ValueName = "$($Setting.Name)"
                ValueType = "$($Setting.Type)"
                ValueData = "$($Setting.Value)"
                DependsOn = '[script]ModifyAIAList'
                }
            }

            #publish CRL

#You probably need to change this test.  Publishing the crl should occur any time there is a change to the crl.
            script PublishCRLIssuing {
                testScript = {
                        $CACN=$Using:ADCSSub.CACN
                        if ((get-childitem -Path "C:\Windows\System32\certsrv\certenroll\$($CACN).crl") -eq (get-childitem -Path "C:\pki\$($CACN).crl")) {
                            return $True
                            }
                        else {
                            return $False
                            }
                    }
                setscript = {
                    certutil -crl
                    }
                getscript = {
                    Return @{Result = "None"}
                    }
                DependsOn = '[Registry]ValidityPeriod'
            }
        
        WaitForAll WFCreateDSCTemplate {
            NodeName = 'DC1'
            ResourceName = '[Script]CreateDSCTemplate'
            RetryIntervalSec = 60
            RetryCount = 30
            PsDscRunAsCredential = $DACredential
        } 

    #Note:  The Test section is pure laziness.  Future enhancement:  test for more than just existence.
        
                            
          script PublishDSCTemplate 
        {       
           DependsOn = '[WaitForAll]WFCreateDSCTemplate'
           PsDscRunAsCredential = $DACredential
           TestScript = {
                            $Template= Get-CATemplate | Where-Object {$_.Name -match "DSCTemplate"}
                            if ($Template -eq $Null) {return $False}
                            else {return $True}
                        }
           SetScript = {
                            add-CATemplate -name "DSCTemplate" -force
                            write-verbose -Message ("Publishing Template DSCTemplate...")
                        }
           GetScript = {
                            $pubDSC = Get-CATemplate | Where-Object {$_.Name -match "DSCTemplate"}
                            return @{Result=$pubDSC.Name}
                        }
         }
                  

          
            #DSC templates - have that coded   
 #>        
    }
}

PKIDeploy -ConfigurationData .\PKIDeploy.psd1 -outputpath "C:\DSC\Configs"
