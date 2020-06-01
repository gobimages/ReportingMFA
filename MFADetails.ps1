
$clientId = "0f10232a-608d-4c47-b446-e22291753743"
$tenantId = "eb8208b2-7983-425a-b55d-9c2c280c2d2c"
$clientSecret = 'ypzclJ_-6NgHr5H.0idw8XQ9o8v17W~N35'
$date = (Get-Date).AddDays(-1).ToString("yyyy-MM-ddTHH:MM:ssZ")
$Properties = @()
# Construct URI
$uri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

# Construct Body
$body = @{
    client_id     = $clientId
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $clientSecret
    grant_type    = "client_credentials"
}

# Get OAuth 2.0 Token
$tokenRequest = Invoke-WebRequest -Method Post -Uri $uri -ContentType "application/x-www-form-urlencoded" -Body $body -UseBasicParsing

# Access Token
$token = ($tokenRequest.Content | ConvertFrom-Json).access_token
$Time = Get-Date -Format HH:mm:ss

### Query ###
$Headers = @{"Authorization" = "Bearer $token" }

$currentUri = "https://graph.microsoft.com/beta/groups/a46fe605-eabf-4ad0-a63b-f36b3c0649ca/members"

$content = while (-not [string]::IsNullOrEmpty($currentUri)) {

    # API Call
    Write-Host "`r`nQuerying $currentUri..." -ForegroundColor Yellow
    $apiCall = Invoke-WebRequest -Method "GET" -Uri $currentUri -ContentType "application/json" -Headers $Headers -ErrorAction Stop
    
    $nextLink = $null
    $currentUri = $null

    if ($apiCall.Content) {

        # Check if any data is left
        $nextLink = $apiCall.Content | ConvertFrom-Json | Select-Object '@odata.nextLink'
        $currentUri = $nextLink.'@odata.nextLink'

        $apiCall.Content | ConvertFrom-Json

    }

}
$content.value.userPrincipalName.count
 ForEach ($Item in $content.value.userPrincipalName) {
    if ($item -match "#EXT#"){
    Write-Host $Item -ForegroundColor Red
    [string]$Item = [System.Web.HttpUtility]::UrlEncode($Item)
    $AuthMethod = "https://graph.microsoft.com/beta/reports/credentialUserRegistrationDetails?`$filter=userPrincipalName eq '$($Item)'"
    $AddUserGraph = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=createdDateTime ge $date and userPrincipalName eq '$($Item)'"
    $DataMemberGraph = (Invoke-RestMethod -Headers $Headers -Uri $AddUserGraph -Method Get).value | Select-Object -First 10
    $AuthMethodGraph = (Invoke-RestMethod -Headers $Headers -Uri $AuthMethod -Method Get).value
    if (($DataMemberGraph.clientAppUsed -ne "IMAP4") -or ($DataMemberGraph.clientAppUsed -ne "Exchange ActiveSync")){
        $Properties += [PSCustomObject]@{
        userPrincipalName = $AuthMethodGraph.userPrincipalName
        DisplayName       = $AuthMethodGraph.userDisplayName
        "Authentication Method" = ($AuthMethodGraph.authMethods) -join ","
        IsRegistered = $AuthMethodGraph.isMfaRegistered
        Application       = $DataMemberGraph.appDisplayName
        ClientAppUsed     = $DataMemberGraph.clientAppUsed
        MFADetails        = $DataMemberGraph.mfaDetail.authMethod
        AutheDetail       = (Out-String -InputObject $DataMemberGraph.authenticationDetails.succeeded)
        Time              = (Out-String -InputObject $DataMemberGraph.createdDateTime)
        AutheDetailMore   = (Out-String -InputObject $DataMemberGraph.authenticationDetails.authenticationStepResultDetail)
        Status            = if($DataMemberGraph.status.errorCode -eq "0"){"success"}else{$DataMemberGraph.status.failureReason}
        StatusAdd         = $DataMemberGraph.status.additionalDetails
        #CAPolicy = $DataMemberGraph.value.appliedConditionalAccessPolicies
    }
    }}Else{
    Write-Host $Item -ForegroundColor Green
    if (($DataMemberGraph.clientAppUsed -ne "IMAP4") -or ($DataMemberGraph.clientAppUsed -ne "Exchange ActiveSync")){
    $AuthMethod = "https://graph.microsoft.com/beta/reports/credentialUserRegistrationDetails?`$filter=userPrincipalName eq '$($Item)'"
    $AddUserGraph = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=createdDateTime ge $date and userPrincipalName eq '$($Item)'"
    $DataMemberGraph = (Invoke-RestMethod -Headers $Headers -Uri $AddUserGraph -Method Get).value | Select-Object -First 1
    $AuthMethodGraph = (Invoke-RestMethod -Headers $Headers -Uri $AuthMethod -Method Get).value
    $Properties += [PSCustomObject]@{
        userPrincipalName = $AuthMethodGraph.userPrincipalName
        DisplayName       = $AuthMethodGraph.userDisplayName
        "Authentication Method" = ($AuthMethodGraph.authMethods) -join ","
        IsRegistered = $AuthMethodGraph.isMfaRegistered
        Application       = $DataMemberGraph.appDisplayName
        ClientAppUsed     = $DataMemberGraph.clientAppUsed
        MFADetails        = $DataMemberGraph.mfaDetail.authMethod
        AutheDetail       = (Out-String -InputObject $DataMemberGraph.authenticationDetails.succeeded)
        Time              = (Out-String -InputObject $DataMemberGraph.createdDateTime)
        AutheDetailMore   = (Out-String -InputObject $DataMemberGraph.authenticationDetails.authenticationStepResultDetail)
        Status            = if($DataMemberGraph.status.errorCode -eq "0"){"success"}else{$DataMemberGraph.status.failureReason}
        StatusAdd         = $DataMemberGraph.status.additionalDetails
        #CAPolicy = $DataMemberGraph.value.appliedConditionalAccessPolicies
    }
    $Properties
    }}
}
#$Properties | Export-Csv C:\Users\v-gomage\Desktop\reporting3.csv -NoTypeInformation
#}
