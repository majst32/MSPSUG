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