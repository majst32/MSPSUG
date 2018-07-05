[DSCLocalConfigurationManager()]

Configuration Push {
    Node S1 {
        
    Settings {
        CertificateID = '4DBA04DB81BA0137D200943BA60261FE4EC29225'
        RefreshMode = 'Push'
        ActionAfterReboot = 'ContinueConfiguration'
        }
    }
}

Push -outputPath "C:\DSC\LCM"
