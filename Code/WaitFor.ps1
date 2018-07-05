   WaitForAll WFADCSSub {
                NodeName = 'ENTSUB'
                ResourceName = '[xADCSCertificationAuthority]ADCSSub'
                RetryIntervalSec = 60
                RetryCount = 30
                DependsOn = '[xSMBShare]RootShare'
                }