[DSCLocalConfigurationManager()]

Configuration Push {
    Node S1 {
        
    Settings {
        CertificateID = '6E2E9FF8E62EF38C967182330437FAA784E7B6E9'
        RefreshMode = 'Push'
        ActionAfterReboot = 'ContinueConfiguration'
        }
    }
}

Push -outputPath "C:\DSC\LCM"
