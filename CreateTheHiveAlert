Function CreateTheHiveAlert {
<#
        .DESCRIPTION
        Creates an alert in TheHive.
        .PARAMETER TheHiveUri
        Specifies the base uri for TheHive server.
        .Parameter APIToken
        Specifies api key for access to TheHive. 
        
        .Parameter Title
        Specifies the alert title.
        
        .Parameter Description
        Specifies the description for alert.
        
        .Parameter Source
        Specifies the friendly name of alert source.
        
        .Parameter SourceRef
        Specifies the reference id value from source system. 
        
        .Parameter Severity
        Specifies the severity of case. Default is low this is an INT value 1-3. 
        
        .EXAMPLE
        CreateTheHiveAlert -APIToken "tH1sIsth3ap1keY/Pr0vid3diNtH3hiV3" -TheHiveUri "http://server.domain.com:9002/api" -Title "Test Alert" -Description "This is a test case" -Source "Development" -SourceRef 00001 -Severity 1
        
        .NOTES
        This was created by VI-or-Die.
    #>
param(
    [Parameter(mandatory=$True)] [string]$Title,
    [Parameter(mandatory=$True)] $Description,
    [Parameter(mandatory=$True)] [string]$Source,
    [Parameter(mandatory=$True)] [string]$SourceRef,
    [Parameter(mandatory=$True)] [string]$APIToken,
    [Parameter(mandatory=$True)] [int]$Severity = 1,
    [Parameter(mandatory=$True)] [string]$TheHiveUri
)

    [int]$tlp = 1
    [string]$API_Uri = "$TheHiveUri/alert"
    [string]$API_Method = "Post"
    $Alert_Description = $Description -replace '<[^>]+>',''
    
    $API_headers = @{Authorization = "Bearer $APIToken"}
    $body = @{
        title = "$title"
        description = "$Alert_Description"
        type ="external"
        source ="$Source"
        sourceRef ="$SourceRef"
        severity = $Severity
        tlp = $tlp
    }
    $JsonBody = $body | ConvertTo-Json
    Invoke-RestMethod -Uri $API_Uri -Headers $API_headers -Body $JsonBody -Method $API_Method -ContentType 'application/json' -Verbose
}
