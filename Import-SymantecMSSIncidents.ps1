# To configure the script to run properly the following items need to be completed
# 1. Download the production Web certificate from Symantec MSS portal. Install on the local machine
# 2. Update the following to reflect the Subject of the certificate previously installed.
$MSSCert = Get-ChildItem -Path Cert:\LocalMachine\My | where-Object {$_.Subject -like 'O=Company, CN=SII785438, L=City, S=State, C=Country'}
# 3. Update the following items with the correct URI for TheHive API, and your API key. 
[string]$HiveUri = "http://server.domain.com:9002/api"
[string]$HiveToken = "tH1sIsth3ap1keY/Pr0vid3diNtH3hiV3"

############ Define Functions #############

# List incidents within a time frame
function MSSIncidentList {
<#
        .DESCRIPTION
        Based on xml input search and export a list of cases from Symantec MSS portal. 

        .PARAMETER $Days
        Show data for the last X number of days. Value can be 0-10.
        
        .PARAMETER $Hours
        Show data for the last X number of hours. Value can be 0-24.

        .PARAMETER $Minutes
        Show data for the last X number of minutes. Value can be 0-60.

        .EXAMPLE
        MSSIncidentQuery -Days 1 -Hours 2 -Minutes 30

        .NOTES
        This was created by VI-or-Die. install Production Web Service certificate from MSS portal on local computer and modify the $Cert line in the function
    #>

        param(
        [Parameter(mandatory=$True)][validateRange(0,10)][int]$Days,
        [Parameter(mandatory=$True)][validateRange(0,24)][int]$Hours,
        [Parameter(mandatory=$True)][validateRange(0,60)][int]$Minutes,
        [Parameter(mandatory=$True)]$SymantecMssCert
        )
    $Cert = $SymantecMssCert
    [String] $URL = 'https://api.monitoredsecurity.com/SWS/incidents.asmx'
    
    $StartDate = (Get-Date).AddDays(-$Days).AddHours(-$Hours).AddMinutes(-$Minutes).ToUniversalTime()
    $StartDate = Get-Date $StartDate -Format o
    
$SOAPRequest = [xml]@"
<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://schemas.xmlsoap.org/soap/envelope/">
    <soap12:Body>
    <IncidentGetList xmlns="https://www.monitoredsecurity.com/">
        <Severity>Critical,Warning</Severity>
        <StartTimeStampGMT>$StartDate</StartTimeStampGMT>
    </IncidentGetList>
    </soap12:Body>
</soap12:Envelope>
"@


    if($cert)
    {
        Try
        {
 
            # Sending SOAP Request To Server 
            $soapWebRequest = [System.Net.WebRequest]::Create($URL) 
            $soapWebRequest.ClientCertificates.Add($cert) >$null 2>&1
            $soapWebRequest.Headers.Add("SOAPAction","https://www.monitoredsecurity.com/IncidentGetList")
            $soapWebRequest.ContentType = "text/xml;charset=utf-8"
            $soapWebRequest.Accept      = "text/xml"
            $soapWebRequest.Method      = "POST"
            $soapWebRequest.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
            $soapWebRequest.UseDefaultCredentials = $true
    
            #Initiating Send
            $requestStream = $soapWebRequest.GetRequestStream() 
            $SOAPRequest.Save($requestStream)
            $requestStream.Close() 
       
            #Send Complete, Waiting For Response.
            $resp = $soapWebRequest.GetResponse() 
            $responseStream = $resp.GetResponseStream() 
            $soapReader = [System.IO.StreamReader]($responseStream) 
            $ReturnXml = [Xml] $soapReader.ReadToEnd() 
            $responseStream.Close() 
 
        }
        Catch
        {
            $ErrorMessage = $_.Exception.Message
            $ErrorMessage
        }
        $ReturnXml.Envelope.Body.IncidentGetListResponse.IncidentGetListResult.SecurityIncidentList.SecurityIncidentSummary
    }
 
    else
    {
        $Return = "Certificate not found"
    }

}

# Query specific function
function MSSIncidentQuery {
<#
        .DESCRIPTION
        Lookup case details based on incident number.

        .Parameter IncidentNumber
        Specifies the incident number to retrieve details about.

        .EXAMPLE
        MSSIncidentQuery -IncidentNumber 151748910

        .NOTES
        This was created by VI-or-Die, install Production Web Service certificate from MSS portal on local computer and modify the $Cert line in the function.
    #>
    param(
        [Parameter(mandatory=$True)] [int]$IncidentNumber,
        [Parameter(mandatory=$True)]$SymantecMssCert

    )
    $cert = $SymantecMssCert
    [String] $URL = 'https://api.monitoredsecurity.com/SWS/incidents.asmx'



$SOAPRequest = [xml]@"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:mon="https://www.monitoredsecurity.com/">
   <soapenv:Header/>
   <soapenv:Body>
      <mon:IncidentWorkflowQuery>
         <mon:IncidentNumber>$IncidentNumber</mon:IncidentNumber>
      </mon:IncidentWorkflowQuery>
   </soapenv:Body>
</soapenv:Envelope>
"@




    if($cert)
    {
        Try
        {
 
            # Sending SOAP Request To Server 
            $soapWebRequest = [System.Net.WebRequest]::Create($URL) 
            $soapWebRequest.ClientCertificates.Add($cert) >$null 2>&1
            $soapWebRequest.Headers.Add("SOAPAction","https://www.monitoredsecurity.com/IncidentWorkflowQuery")
            $soapWebRequest.ContentType = "text/xml;charset=utf-8"
            $soapWebRequest.Accept      = "text/xml"
            $soapWebRequest.Method      = "POST"
            $soapWebRequest.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
            $soapWebRequest.UseDefaultCredentials = $true
    
            #Initiating Send
            $requestStream = $soapWebRequest.GetRequestStream() 
            $SOAPRequest.Save($requestStream)
            $requestStream.Close() 
       
            #Send Complete, Waiting For Response.
            $resp = $soapWebRequest.GetResponse() 
            $responseStream = $resp.GetResponseStream() 
            $soapReader = [System.IO.StreamReader]($responseStream) 
            $ReturnXml = [Xml] $soapReader.ReadToEnd() 
            $responseStream.Close() 
 
        }
        Catch
        {
            $ErrorMessage = $_.Exception.Message
            Write-Host This script screwed up.
            $ErrorMessage
        }
        # Parse XML response for valuable data.
        $Output = $ReturnXml.Envelope.Body.IncidentWorkflowQueryResponse.IncidentWorkflowQueryResult.SecurityIncident
        $Output = $Output | Select IncidentNumber, TimeCreated, Correlation, Severity, Classification, Description, AnalystAssessment, CountryCode, CountryName, NumberOfAnalyzedSignatures, SourceOrganizationList, DestinationOrganizationList, RelatedTickets, SignatureList, WorkFlowDetail, IncidentComments, ActivityLogs, IncidentAttachmentItems, IsGroupIncidentAvailable, RelatedIncidents
        # Print meaningful data. 
        $Output
    }
 
    else
    {
        $Return = "Certificate not found"
    }

}

# Function to Create an alert in thehive
Function CreateHiveAlert {
param(
    [Parameter(mandatory=$True)] [string]$Title,
    [Parameter(mandatory=$True)] $Description,
    [Parameter(mandatory=$True)] [string]$Source,
    [Parameter(mandatory=$True)] [string]$SourceRef,
    [Parameter(mandatory=$True)] [string]$Token,
    [Parameter(mandatory=$True)] [int]$Severity = 1,
    [Parameter(mandatory=$False)] $Artifacts
)

    [int]$tlp = 1
    [string]$API_Uri = "$HiveUri/alert"
    [string]$API_Method = "Post"
    $description = $Alert_Description -replace '<[^>]+>',''
    
    $API_headers = @{Authorization = "Bearer $Token"}
    
    $HiveArtifactArray = @()
    $HiveArtifactArray += $Artifacts
    $body = "" | select title, description, type, source, sourceRef, severity, tlp, artifacts
    $body.title = "$Title"
    $body.description = "$description"
    $body.type = "internal"
    $body.source ="$Source"
    $body.sourceRef ="$SourceRef"
    $body.severity = $Severity
    $body.tlp = $tlp
    $body.artifacts = $HiveArtifactArray

    $JsonBody = $body | ConvertTo-Json -Depth 100
    Invoke-RestMethod -Uri $API_Uri -Headers $API_headers -Body $JsonBody -Method $API_Method -ContentType 'application/json' -Verbose
}

# Function to download all Hive Alerts related to MSS incidents
Function DumpTheHiveAlerts {
<#
        .DESCRIPTION
        Dumps all alerts from TheHive that are related to MSS Incidents.

        .PARAMETER TheHiveUri
        Specifies the base uri for TheHive server.

        .Parameter TheHiveToken
        Specifies api key for access to Hive. 

        .EXAMPLE
        DumpTheHiveCases -TheHiveUri "http://server.domain.com:9002/api" -TheHiveToken "tH1sIsth3ap1keY/Pr0vid3diNtH3hiV3"

        .NOTES
        This was created by VI-or-Die.

        .NOTES
        If case totals are more than 10000 see comment in function.
    #>
    param(
        [Parameter(mandatory=$True)] [string]$TheHiveToken,
        [Parameter(mandatory=$True)] [string]$TheHiveUri
    )


    # To increase quantity of case output modify range to be "0-x". Where x is the max number of cases to export.
    [string]$API_Uri = "$TheHiveUri/alert/_search?range=0-10000"
    [string]$API_Method = "Post"
    $API_headers = @{Authorization = "Bearer $TheHiveToken"}
    $body = @{
        query = @{
            "_and" = @(
                @{
                    "_string" = '(source:"SymantecMSS")'
                    
                }
            )
        }
    }
    $JsonBody = $body | ConvertTo-Json -Depth 5 -Compress
    Invoke-RestMethod -Uri $API_Uri -Headers $API_headers -Body $jsonbody -Method $API_Method -ContentType 'application/json' -Verbose
}

########################################

###     BEGIN CORE SCRIPT           ###

########################################

# Grab current alerts from MSS
$AlertList = MSSIncidentList -Days 3 -hours 0 -Minutes 0 -SymantecMssCert $MSSCert

# Dump existing alerts from The Hive
$ExistingAlerts = DumpTheHiveAlerts -TheHiveToken $HiveToken -TheHiveUri $HiveUri
$ExistingAlert_ReferenceArray = @()
$ExistingAlert_ReferenceArray += $ExistingAlerts.sourceRef

$RemovealIDs =@()
$Iteration = 0
Foreach ($Alert in $AlertList) {
    if ($Iteration -eq 29){
        Wait-Event -Timeout 60
        $Iteration = -1
    }
    # Skip Incident import if Already imported
    if ($ExistingAlert_ReferenceArray.Contains($Alert.IncidentNumber)){
        Write-Host "Skipping $($Alert.IncidentNumber)"
        continue 
    }

    # Grab all data for an alert (Connect again to MSS)
    $Alert_Data = MSSIncidentQuery -IncidentNumber $Alert.IncidentNumber -SymantecMssCert $MSSCert
    
    # Clear out old values
    $Alert_Title = ""
    $Alert_Description = ""
    $Alert_id = ""
    $Alert_severity = ""

    # Define New Hive Alert Configuration
    $Alert_Title = $Alert.Classification + " " + $Alert.IncidentNumber
    $Alert_Description = "### Description `n`n Creation Time: $($Alert_Data.TimeCreated) `n`n$($Alert_Data.Description) `n`n### Analyst Assessment `n`n$($Alert_Data.AnalystAssessment) `n`n### Organization Names`n`n+ $($alert_data.SourceOrganizationList.Organization.OrganizationName)`n`n### Destination Organization Names`n`n+ $($alert_data.DestinationOrganizationList.Organization.OrganizationName)"
    $Alert_id = $Alert.IncidentNumber
    
    # Set Hive Alert Severity
    if ($Alert.Severity -eq "Warning"){$Alert_severity = 1}
    elseif ($Alert.Severity -eq "Critical"){$Alert_severity = 2}
    elseif ($Alert.Severity -eq "Emergency"){$Alert_severity = 3}
    else {$Alert_severity = 1}

    # Build array of observables

    $Artifacts = @()
    $Artifact = "" | select dataType, data, message, tags

        Write-host "Alert Data preparse $($Alert_Data.SignatureList.Signature.Count)"
        foreach ($Signature in $Alert_Data.SignatureList.Signature){
            if ($Signature.IsKey -match "true"){ $Tag = "MSS:Key Event" }
            else{$Tag = "MSS:Other Event"}
            $message = "+ $($Signature.TimeCreated)Z (UTC) | $($Signature.SignatureName) | $($Signature.VendorSignature)"
            $UserNames = @()
            $UserNames += $Signature.SourceHostDetailList.SourceHostDetail.UserName | Select -Unique
            $HostNames = @()
            $HostNames += $Signature.SourceHostDetailList.SourceHostDetail.HostName | Select -Unique
            $IPAddresses = @()
            $IPAddresses += $Signature.SourceIPString | Select -Unique
            $Domains = @()
            $Domains += $Signature.SourceHostDetailList.SourceHostDetail.HostDomain
            $Tags = @()
            $Tags += $Tag
            #User 
            foreach ($user in $UserNames){
                $Artifact = "" | select dataType, data, message, tags
                $Artifact.dataType = "mail"
                $Artifact.data = $user
                $Artifact.message = "$message"
                $Artifact.tags = $Tags
                $Artifacts += $Artifact
            }
            # FQDN
            foreach ($HostName in $HostNames){
                $Artifact = "" | select dataType, data, message, tags
                $Artifact.dataType = "fqdn"
                $Artifact.data = $HostName
                $Artifact.message = "$message"
                $Artifact.tags = $Tags
                $Artifacts += $Artifact
            }
            # Append Each IP to Table
            foreach ($Address in $IPAddresses){
                $Artifact = "" | select dataType, data, message, tags
                $Artifact.dataType = "ip"
                $Artifact.data = $Address
                $Artifact.message = "$Message"
                $Artifact.tags = $Tags
                $Artifacts += $Artifact
            }
            # Append each domain to Table
            foreach ($Domain in $Domains){
                $Artifact = "" | select dataType, data, message, tags
                $Artifact.dataType = "domain"
                $Artifact.data = $Domain
                $Artifact.message = "$Message"
                $Artifact.tags = $Tags
                $Artifacts += $Artifact
            }
            
            if ($Signature.IsKey -match "true"){
                # Build file info
                $FileList = $Signature.FileDetails.file
                foreach ($file in $FileList){
                    $FileName = $File.FileName
                    $Detail = ""
                    $Detail = "+ FileName: $($File.Filename) `n+ URL: $($File.URL) `n+ TrustedorUnknown: $($File.TrustedOrUnknown) `n+ Prevalence: $($File.Prevalence) `n+ FirstSeen: $($File.FirstSeenTimeStamp) `n+ MD5: $($File.MD5Hash) `n+ SHA256: $($File.SHA256Hash)"
                    $url = $File.URL
                    $Hashes = @()
                    $Hashes += $File.MD5Hash
                    $Hashes += $File.SHA256Hash
                
                    # URL
                        $Artifact = "" | select dataType, data, message, tags
                        $Artifact.dataType = "url"
                        $Artifact.data = "$($File.URL)"
                        $Artifact.message = "$Detail"
                        $Artifact.tags = $Tags
                        $Artifacts += $Artifact
                    # FileNames
                        $Artifact = "" | select dataType, data, message, tags
                        $Artifact.dataType = "filename"
                        $Artifact.data = "$FileName"
                        $Artifact.message = "$Detail"
                        $Artifact.tags = $Tags
                        $Artifacts += $Artifact
                    # Hash
                    foreach ($Hash in $Hashes){
                        $Artifact = "" | select dataType, data, message, tags
                        $Artifact.dataType = "hash"
                        $Artifact.data = "$Hash"
                        $Artifact.message = "$Detail"
                        $Artifact.tags = $Tags
                        $Artifacts += $Artifact
                    }
                }
            }
            
        }

        $Artifacts = $Artifacts | Where-Object {($_.data -notlike $null) -and ($_.data -notlike "-")}
        $Condensed = $Artifacts | Group-Object -Property data
        $Condensedresult = foreach ($value in $Condensed){
            if ($value.Group.tags.Contains('MSS:Key Event')){
                $TableTags = @()
                $TableTags += "MSS:Key Event"
                [PSCustomObject]@{
                    dataType = $value.Group.dataType | Select -Unique
                    data = $value.name
                    message = ($value.Group.message) -join "`n"
                    tags = $TableTags
                }
            }
            else{
                $TableTags = @()
                $TableTags += "MSS:Other Event"
                [PSCustomObject]@{
                    dataType = $value.Group.dataType | Select -Unique
                    data = $value.name
                    message = ($value.Group.message) -join "`n"
                    tags = $TableTags
                }
            }
        }

        
        $artifactArray = $Condensedresult | select datatype, data, message, tags
        Write-host "Post Parse $($artifactArray.count)"

    # Hive API Call to Create alert
    $HiveAlert = CreateHiveAlert -Title $Alert_Title -Description $Alert_Description -Source "SymantecMSS" -SourceRef $Alert_id -Token $HiveToken -Severity $Alert_Severity -Artifacts $ArtifactArray -Verbose
    
    # Append new Alert ID to Array
    $RemovealIDs += $HiveAlert | Select _id


    $Iteration ++
}
