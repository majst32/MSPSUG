﻿@{
    AllNodes = @(
        @{
            NodeName = '*'
            PSDscAllowPlainTextPassword = $true
            CADatabasePath = 'C:\windows\system32\CertLog'
            CALogPath = 'C:\CA_Logs'
            ADCSCryptoProviderName = 'RSA#Microsoft Software Key Storage Provider'
            ADCSHashAlgorithmName = 'SHA256'
            ADCSKeyLength = '2048'
            ADCSValidityPeriod = 'Years'
            ADCSValidityPeriodUnits = '2'
            DNSSuffix = 'company.pri'
            DomainShortName = "COMPANY"
           }
      
     @{
            NodeName = 'OLROOT.company.pri'
            Role = 'ADCSRoot'
            Password = 'P@ssw0rd'
            PsDscAllowDomainUser = $True

        }

     @{
            NodeName = 'ENTSub'
            Role = 'ADCSSub'
            Password = 'P@ssw0rd'
            PsDscAllowDomainUser = $True
        }
     
     @{     NodeName = 'DC1'
            Role = 'DC'
            Password = 'P@ssw0rd'
            #PsDSCAllowDomainUser = $True
            EntSubIP = '192.168.3.30'
        }
    )
    ADCSRoot = @{
            # ADCS Certificate Services information  for offline root
            Features = @('ADCS-Cert-Authority')
            CAType = 'StandaloneRootCA'
            CACN = 'CompanyRoot'
            CADNSuffix = 'C=US,L=Philadelphia,S=Pennsylvania,O=Company'
            CRLURL = "www.company.pri"
            ShortName = "OLRoot"
            RegistrySettings = @(
                #@{Name = "CRLPublicationURLs";Type = "MultiString";Value = '1:C:\Windows\system32\CertSrv\CertEnroll\%3%8.crl\n\02:http://www.company.pri/pki/%3%8.crl'},
                #@{Name = "CACertPublicationURLs"; Type = "MultiString"; Value = "2:http://www.company.pri/pki/%1_%3%4.crt"},
                @{Name = "CRLOverlapPeriodUnits"; Type = "Dword"; Value = 12},
                @{Name = "CRLOverlapPeriod"; Type = "String"; Value = "Hours"},
                @{Name = "ValidityPeriodUnits"; Type = "Dword";Value = 10},
                @{Name = "ValidityPeriod"; Type = "String"; Value = "Years"},
                @{Name = "DSConfigDN"; Type = "String"; Value = "CN=Configuration,DC=company,DC=pri"}
                )
            }

    ADCSSub = @{
            # ADCS Certificate Services info for Enterprise Subordinate
            Features = @('ADCS-Cert-Authority';'Web-Server')
            CAType = 'EnterpriseSubordinateCA'
            CACN = 'IssuingCA-CompanyRoot'
            CADNSuffix = 'DC=Company,DC=pri'
            Name = "ENTSUB"
            RegistrySettings = @(
                #@{Name = "CRLPublicationURLs";Type = "MultiString";Value = '1:C:\Windows\system32\CertSrv\CertEnroll\%3%8.crl\n\02:http://www.company.pri/pki/%3%8.crl'},
                #@{Name = "CACertPublicationURLs"; Type = "MultiString"; Value = "2:http://www.company.pri/pki/%1_%3%4.crt"},
                @{Name = "CRLPeriodUnits"; Type = "Dword"; Value = 2},
                @{Name = "CRLPeriod"; Type = "String"; Value = "Weeks"},
                @{Name = "CRLDeltaPeriodUnits"; Type = "Dword"; Value = 1},
                @{Name = "CRLDeltaPeriod"; Type = "String"; Value = "Days"},
                @{Name = "CRLOverlapPeriodUnits"; Type = "Dword"; Value = 12},
                @{Name = "CRLOverlapPeriod"; Type = "String"; Value = "Hours"},
                @{Name = "ValidityPeriodUnits"; Type = "Dword";Value = 5},
                @{Name = "ValidityPeriod"; Type = "String"; Value = "Years"}
                )
            }

    DomainData = @{
            DomainDN = "DC=Company,DC=pri"
            DomainName = "company.pri"
            }

 }