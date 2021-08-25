<#
.SYNOPSIS
Test-VMwareHealth.ps1 - VMware Health Check Script.

.DESCRIPTION 
Performs a series of health checks on vCenters and ESXi hosts and outputs the results to screen, and optionally to log file, HTML report,
and HTML email.

Use the ignorelist.txt file to specify any servers you want the script to ignore (eg test/dev servers).

.OUTPUTS
Results are output to screen, as well as optional log file, HTML report, and HTML email

.PARAMETER Server
Perform a health check of a single server

.PARAMETER ReportMode
Set to $true to generate a HTML report. A default file name is used if none is specified.

.PARAMETER ReportFile
Allows you to specify a different HTML report file name than the default.

.PARAMETER SendEmail
Sends the HTML report via email using the SMTP configuration within the script.

.PARAMETER AlertsOnly
Only sends the email report if at least one error or warning was detected.

.PARAMETER Log
Writes a log file to help with troubleshooting.

.EXAMPLE
.\Test-VMwareHealth.ps1
Checks all servers in the organization and outputs the results to the shell window.

.EXAMPLE
.\Test-VMwareHealth.ps1 
Checks all servers in the federation, and outputs the results to the shell window, HTML report and email.

.EXAMPLE
.\Test-VMwareHealth.ps1 -ReportMode -SendEmail
Checks all servers in the federation, outputs the results to the shell window, a HTML report, and
emails the HTML report to the address configured in the script.

.LINK


.NOTES
Written by: Kevin Snook (some portions Paul Cunningham)

.OVERVIEW
The script runs through a number of checks on vCenters and ESXi servers in a VMware estate and reports them on a Pass/Fail basis.
If the SendEMail parameter is selected an email is sent showing an overall status i.e. if ANY check has FAILed or everything has PASSed.
Check out the VARIABLES section below to make changes to thresholds/recipients etc
#>

#requires -version 2

[CmdletBinding()]
param (
        [Parameter( Mandatory=$false)]
        [string]$Server,

        [Parameter( Mandatory=$false)]
        [string]$ServerList,    
        
        [Parameter( Mandatory=$false)]
        [string]$ReportFile="C:\inetpub\wwwroot\monitor\vmwarehealth.html",

        [Parameter( Mandatory=$false)]
        [switch]$ReportMode=$true,
        
        [Parameter( Mandatory=$false)]
        [switch]$SendEmail=$true,

        [Parameter( Mandatory=$false)]
        [switch]$AlertsOnly=$true,    
        
        [Parameter( Mandatory=$false)]
        [switch]$Log
    )


# This should match the word for "Success"
$success = "Success"



#...................................
# Functions
#...................................
#Just a little function to blink message when running in interactive mode
function Blink-Message {
 param([String]$Message,[int]$Delay,[int]$Count,[ConsoleColor[]]$Colors) 
    $startColor = [Console]::ForegroundColor
    $startLeft  = [Console]::CursorLeft
    $startTop   = [Console]::CursorTop
    $colorCount = $Colors.Length
    for($i = 0; $i -lt $Count; $i++) {
        [Console]::CursorLeft = $startLeft
        [Console]::CursorTop  = $startTop
        [Console]::ForegroundColor = $Colors[$($i % $colorCount)]
        #[Console]::WriteLine($Message)
	write-host $Message -nonewline
        Start-Sleep -Milliseconds $Delay
    }
    [Console]::ForegroundColor = $startColor
}


function Get_Diskspace 	{
param (
    $HostList
)

foreach ($OVCHost in $HostList){
    ################################ DISK CHECKS START ################################
    #A few calculations
    #"Disk checks"
        
    $OVCPercentFreeSpace = [math]::round($OVCHost.FreeSpaceGB/$OVCHost.AllocatedCapacityGB*100)
    #$OVCPercentFreeSpace
    #write-host "$($OVCHost.HostName) working on $($OVCHost.Model) is $($OVCHost.State) running $($OVCHost.Version). It has $($OVCHost.StoredVMDataGB)GB worth of VM data on total of $($OVCHost.AllocatedCapacityGB)GB disks ($($OVCHost.FreeSpaceGB)GB free space after compression) ($($OVCPercentFreeSpace)% free space)"
    if ($OVCPercentFreeSpace -lt 10){
        #write-host "$($OVCHost.HostName) is low on disk space"
        #$STATUS="RED"
        write-host "$($OVCHost.HostName) is low on disk space. ($($OVCHost.FreeSpaceGB)GB free space ($($OVCPercentFreeSpace)% after compression)" -ForegroundColor $fail
        "$($OVCHost.HostName) is low on disk space. ($($OVCHost.FreeSpaceGB)GB free space ($($OVCPercentFreeSpace)% after compression)" 
        }
    try{$Disks = Get-SVTDisk -hostname $OVCHost.HostName}
    catch{}
    foreach ($Disk in $Disks){
        #"#Disk $($Disk.SerialNumber) in slot $($Disk.Slot) is $($Disk.Health)"
        if ($($Disk.Health) -ne "HEALTHY"){
            #$STATUS="RED"
            "$($OVCHost.HostName) #Disk $($Disk.SerialNumber) in slot $($Disk.Slot) is $($Disk.Health)" 
            }
        }
    ################################ DISK CHECKS END ################################
    }
}


#This function is used to generate HTML for the server health report
Function New-ServerHealthHTMLTableCell()
{
    param( $lineitem )
    
    $htmltablecell = $null
    
    switch ($($reportline."$lineitem"))
    {
        $success {$htmltablecell = "<td class=""pass"">$($reportline."$lineitem")</td>"}
        "Success" {$htmltablecell = "<td class=""pass"">$($reportline."$lineitem")</td>"}
        "Pass" {$htmltablecell = "<td class=""pass"">$($reportline."$lineitem")</td>"}
        "Warn" {$htmltablecell = "<td class=""warn"">$($reportline."$lineitem")</td>"}
        "Access Denied" {$htmltablecell = "<td class=""warn"">$($reportline."$lineitem")</td>"}
        "Fail" {$htmltablecell = "<td class=""fail"">$($reportline."$lineitem")</td>"}
        "Could not test service health. " {$htmltablecell = "<td class=""warn"">$($reportline."$lineitem")</td>"}
        "Unknown" {$htmltablecell = "<td class=""warn"">$($reportline."$lineitem")</td>"}
        default {$htmltablecell = "<td>$($reportline."$lineitem")</td>"}
    }
    
    return $htmltablecell
}

#This function is used to write the log file if -Log is used
Function Write-Logfile()
{
    param( $logentry )
    $timestamp = Get-Date -DisplayHint Time
    "$timestamp $logentry" | Out-File $logfile -Append
}

Function Check_VMHost_Running_Services
{
param (
    $VMHostList
)
$NORMALSERVICES = @("DCUI","TSM","TSM-SSH","lbtd","ntpd","sfcbd-watchdog","vmsyslogd","vmware-fdm","vpxa")
foreach ($NORMALSERVICE in $NORMALSERVICES){
    write-host "Is service $($NORMALSERVICE) running"
    if ($RUNNINGSERVICES -match $SERVICE){
        write-host "$($NORMALSERVICE) in $($RUNNINGSERVICES)"
        }
    else{
        write-host "$($NORMALSERVICE) not in $($RUNNINGSERVICES)"
        $ERRORSERVICE += $NORMALSERVICE
        }
    }
 
return $ERRORSERVICES
}

function Get-vCSA-Services {
    param (
       [Parameter(Mandatory=$true)][string]$AuthTokenValue,
       [Parameter(Mandatory=$true)][string]$vCSAVersion
    )

       $headers = @{
                        'Accept' = 'application/json';
                        'vmware-api-session-id'= $AuthTokenValue;
                   }
       $method = "GET"
       
       if (([regex]::match($vCSAVersion,"6.7")).success){
           $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/services
           $listvCSAServices = $respond.value | Select-Object -Property @{N='Service Name';E={$_.key}},@{N='State';E={$_.value.state}},@{N='Description';E={$_.value.description}} | Sort-Object -Property 'State'
      } else{
           $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/techpreview/services
           $listvCSAServices = $respond.value | Select-Object -Property @{N='Service Name';E={$_.name}},@{N='Description';E={$_.description}}
      }
  
       return $listvCSAServices
}


Function Test-WebServerSSL {
# Function original location: http://en-us.sysadmins.lv/Lists/Posts/Post.aspx?List=332991f0-bfed-4143-9eea-f521167d287c&ID=60
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string]$URL,
        [Parameter(Position = 1)]
        [ValidateRange(1,65535)]
        [int]$Port = 443,
        [Parameter(Position = 2)]
        [Net.WebProxy]$Proxy,
        [Parameter(Position = 3)]
        [int]$Timeout = 15000,
        [switch]$UseUserContext
    )
Add-Type @"
using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;
namespace PKI {
    namespace Web {
        public class WebSSL {
            public Uri OriginalURi;
            public Uri ReturnedURi;
            public X509Certificate2 Certificate;
            //public X500DistinguishedName Issuer;
            //public X500DistinguishedName Subject;
            public string Issuer;
            public string Subject;
            public string[] SubjectAlternativeNames;
            public bool CertificateIsValid;
            //public X509ChainStatus[] ErrorInformation;
            public string[] ErrorInformation;
            public HttpWebResponse Response;
        }
    }
}
"@
    $ConnectString = "https://$($url):$($port)"
    $WebRequest = [Net.WebRequest]::Create($ConnectString)
    $WebRequest.Proxy = $Proxy
    $WebRequest.Credentials = $null
    $WebRequest.Timeout = $Timeout
    $WebRequest.AllowAutoRedirect = $true
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
    try {$Response = $WebRequest.GetResponse()}
    catch {}
    if ($WebRequest.ServicePoint.Certificate -ne $null) {
        $Cert = [Security.Cryptography.X509Certificates.X509Certificate2]$WebRequest.ServicePoint.Certificate.Handle
        #$Cert
        try {$SAN = ($Cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.17"}).Format(0) -split ", "}
        catch {$SAN = $null}
        $chain = New-Object Security.Cryptography.X509Certificates.X509Chain -ArgumentList (!$UseUserContext)
        #$chain
        [void]$chain.ChainPolicy.ApplicationPolicy.Add("1.3.6.1.5.5.7.3.1")
        $Status = $chain.Build($Cert)
        New-Object PKI.Web.WebSSL -Property @{
            OriginalUri = $ConnectString;
            ReturnedUri = $Response.ResponseUri;
            Certificate = $WebRequest.ServicePoint.Certificate;
            Issuer = $WebRequest.ServicePoint.Certificate.Issuer;
            Subject = $WebRequest.ServicePoint.Certificate.Subject;
            SubjectAlternativeNames = $SAN;
            CertificateIsValid = $Status;
            Response = $Response;
            #ErrorInformation = $chain.ChainStatus | ForEach-Object {$_.Status}
        }
        $chain.Reset()
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    } else {
        Write-Error $Error[0]
    }
}

Function get-VCAlarms{
param (
    $HostList
)
$TimeInPast = (Get-Date).AddHours(-$MaxHoursToScanLog)
#write-host $TimeInPast
#$HostList is a OVC or a Host - add VMs to the list:
#$VMList = Get-SVTvm -HostName $HostList | select VmName
#write-host $VMList.VMName
#$HostList += $VMList.VMName
#write-host $HostList
#if ($HostList -like "*BOH2-EUD-SQL102*" ){
#    write-host "yep"
#    }
#exit
#Return all alarms for this host that have come after the $MaxHoursToScanLog
#$triggeredalarms = (get-datacenter).extensiondata.triggeredalarmstate | where {$_.Time -gt $TimeInPast -and $HostList -contains ((Get-View $_.Entity).Name)} 
$triggeredalarms = (get-datacenter).extensiondata.triggeredalarmstate | where {$_.Time -gt $TimeInPast -and ((Get-View $_.Entity).Name) -match $HostList }
#$triggeredalarms = (get-datacenter).extensiondata.triggeredalarmstate | where {$_.Time -gt $TimeInPast}
#$triggeredalarms = (get-datacenter).extensiondata.triggeredalarmstate | where {$HostList -contains ((Get-View $_.Entity).Name)} 
#$triggeredalarms = (get-datacenter).extensiondata.triggeredalarmstate | select ($_.Entity).Name 
#$triggeredalarms = (get-datacenter).extensiondata.triggeredalarmstate | where {$_.Time -gt $TimeInPast -and ((Get-View $_.Entity).Name) -match "BOH2-EUD-SQL102" }
#$triggeredalarms = (get-datacenter).extensiondata.triggeredalarmstate | where {$_.Time -gt $TimeInPast -and $HostList -like "*BOH2-EUD-SQL102*"}
#$triggeredalarms = (get-datacenter).extensiondata.triggeredalarmstate | where {$_.Time -gt $TimeInPast -and $HostList -match "((Get-View $_.Entity).Name)"}
#$triggeredalarms = (get-datacenter).extensiondata.triggeredalarmstate
#write-host $triggeredalarms
#exit

foreach ($triggeredalarm in $triggeredalarms){
    #write-host (Get-View $triggeredalarm.Entity).Name
    $alarm = "" | Select-Object VC, EntityType, Alarm, Entity, Status, Time, Acknowledged, AckBy, AckTime
  	$alarm.Alarm = (Get-View $triggeredalarm.Alarm).Info.Name
    #if ((Get-View $triggeredalarm.Entity).Name -in $HostList){
    #    write-host "$($HostList) contains ((Get-View $triggeredalarm.Entity).Name)"
    #    } 
    $alarm.Entity = (Get-View $triggeredalarm.Entity).Name
    write-host $alarm.Entity
    $alarm.Status = $triggeredalarm.OverallStatus
  	$alarm.Time = $triggeredalarm.Time
    if ($alarm.Status -eq "red"){
        #write-host "$($alarm.Entity) has a critical alert ($($alarm.Alarm)) timed at $($alarm.Time)"
        if ($alarm.Entity -notcontains "OmniStackVC" -and $alarm.Alarm[0] -notcontains "Virtual machine memory usage"){
            "`n`r$($alarm.Entity) has a critical alert ($($alarm.Alarm[0])) timed at $($alarm.Time)"
            #exit
            }
        }
    }
}
Function run-ssh-command{
param (
    
    $ESXiHostList,
    $UserName,
    $EncryptedPassword,
    $Command,
    [boolean]$isvCenter
    
)

$Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($EncryptedPassword)
$decrypted = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
$sshpreviousstatus=$null
foreach ($ESXiHost in $ESXiHostList){
    Write-Host -Object "starting ssh services on $ESXiHost"
    if ($isvCenter){
        write-host "it's a vcenter"
        $sshService = Get-vCSA-Services -AuthTokenValue $FuncAuthToken -vCSAVersion $vcsaVersion | where {$_."Service Name" -eq "sshd"}
        if ($sshService.State -eq "STOPPED"){
            write-host "SSH service stopped on vCenter $($vCenterFQDN) - starting it"
            $sshpreviousstatus = "Off"
            $startedService = Start-vCSA-Service -ServiceName "sshd" -AuthTokenValue $FuncAuthToken -vCSAVersion $vcsaVersion
            $sshService = Get-vCSA-Services -AuthTokenValue $FuncAuthToken -vCSAVersion $vcsaVersion | where {$_."Service Name" -eq "sshd"}
            #$sshService
            }
        
        Write-Host -Object "Executing Command on $ESXiHost"
        #$output = $plink + " " + "-ssh" + " " + $root + "@" + $ESXiHost + " " + "-pw" + " " + $decrypted + " " + $remoteCommand
        $output = $plink + " " + "-ssh" + " " + $UserName + "@" + $ESXiHost + " " + "-pw" + " " + $decrypted + " " + $remoteCommand
        write-host $output
        try {$message = Invoke-Expression -command $output}
        catch {Write-Host -ForegroundColor $warn "Exception message is $($_.Exception.Message)"
            $message = "Error Logging On $($_.Exception.Message)"
            }
        #$message = Invoke-Expression -command $output
        $message
        
        if ($sshpreviousstatus -eq "Off"){
            write-host "SSH service previously stopped on vCenter $($vCenterFQDN) - stopping it"
            $stoppedService = Stop-vCSA-Service -ServiceName "sshd" -AuthTokenValue $FuncAuthToken -vCSAVersion $vcsaVersion
            $sshService = Get-vCSA-Services -AuthTokenValue $FuncAuthToken -vCSAVersion $vcsaVersion | where {$_."Service Name" -eq "sshd"}
            #$sshService
            }
        }
    else{
        write-host "It's a host"
        $sshstatus= Get-VMHostService  -VMHost $ESXiHost| where {$psitem.key -eq "tsm-ssh"}
        if ($sshstatus.Running -eq $False) {
            $sshpreviousstatus = "Off"
            Get-VMHostService -VMHost $ESXiHost| where {$psitem.key -eq "tsm-ssh"} | Start-VMHostService 
            }
        Write-Host -Object "Executing Command on $ESXiHost"
        #$output = $plink + " " + "-ssh" + " " + $root + "@" + $ESXiHost + " " + "-pw" + " " + $decrypted + " " + $remoteCommand
        $output = $plink + " " + "-ssh" + " " + $UserName + "@" + $ESXiHost + " " + "-pw" + " " + $decrypted + " " + $remoteCommand
        write-host $output
        try {$message = Invoke-Expression -command $output}
        catch {Write-Host -ForegroundColor $warn "Exception message is $($_.Exception.Message)"
            $message = "Error Logging On $($_.Exception.Message)"
            }
        #$message = Invoke-Expression -command $output
        $message
        if ($sshpreviousstatus -eq "Off"){
            Write-Host -Object "SSH service on $ESXiHost was previously off so stopping service"
            $tsmsshservice = Get-VMHostService -VMHost $ESXiHost| where {$psitem.key -eq "tsm-ssh"} 
            Stop-VMHostService -HostService $tsmsshservice -Confirm:$false
            }
        }
    
    }
}

#Function to convert the given credentials to Base64 encode
function Set-Credentials {
    param (
       [Parameter(Mandatory=$true)][string]$username,
       [Parameter(Mandatory=$true)][string]$password
    )
    
    $pair = "${username}:${password}"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
 
    $basicAuthValue = "Basic $base64"
    return $basicAuthValue
}

#Function to request session id
function Create-Session {

	Ignore-Certificate
	$responsesessionid = Invoke-vCenterTokenRequest -Uri $RestApiUrl/com/vmware/cis/session -method "POST"
	
    return $responsesessionid
}

#Function to create session id
function Invoke-vCenterTokenRequest {
    param (
        [string]$uri=$REST_URL,
        [string]$method,
        [string]$body=$null
    )
    
    $headers = @{
        'authorization' =  $creds;
        'content-type' =  'application/json';
        'Accept' = 'application/json';
        
    }
    $response = Invoke-RestMethod -uri $uri -Headers $headers -Method $method -Body $body 
    
    return $response
}

#Function to ignore vCenter certificate
function Ignore-Certificate {

if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
 }
[ServerCertificateValidationCallback]::Ignore()

}

#Function to list the Health of vCSA
function Get-Health-Message{
    param (
       [Parameter(Mandatory=$true)][string]$colour
    )
            switch($colour){
                "green" {$message = "Service is healthy"}
                "orange" {$message = "The service health is degraded. The service might have serious problems"}
                "red"  {$message = "The service is unavaiable and is not functioning properly or will stop functioning soon"}
                "yellow" {$message = "The service is healthy state, but experiencing some levels of problems.Database storage health"}
                "gray"  {$message = "No health data is available for this service"}
                "unknown" {$message = "No health data is available for this service"}
                default {$message = "No health data is available for this service"}
            }

    return $message
}

#Function to list vCSA disks and partitions
function Get-vCSA-Disks{
    param (
       [Parameter(Mandatory=$true)][string]$AuthTokenValue
    )
    #curl -X GET --header 'Accept: application/json' --header 'vmware-api-session-id: 82427d1baafec43f7d1b71ef02ab17b8' 'https://vcsa67.ipats.local/rest/appliance/system/storage'
       
       $headers = @{
            'Accept' = 'application/json';
            'vmware-api-session-id'= $AuthTokenValue;
       }
       $method = "GET"       

       $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/system/storage
       $listvCSADisks = $respond.value | Select-Object -Property @{N='Disk Number';E={$_.disk}},@{N='Partition Name';E={$_.partition}},@{N='Description';E={$_.description.default_message}} | Sort-Object -Property 'Disk Number'

       return $listvCSADisks
}


#Function to list the vCSA health status
function Get-Health-Status{
    param (
       [Parameter(Mandatory=$true)][string]$AuthTokenValue
    )

       $headers = @{
            'Accept' = 'application/json';
            'vmware-api-session-id'= $AuthTokenValue;
       }
       $method = "GET"       

       $respondOverallHealth = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/health/system
       $overallHealthMessage = Get-Health-Message -colour $respondOverallHealth.value

       $lastCheck = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/health/system/lastcheck

       $respondLoad = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/health/load
       $loadHealthMessage = Get-Health-Message -colour $respondLoad.value

       $respondMemory = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/health/mem
       $memoryHealthMessage = Get-Health-Message -colour $respondMemory.value

       $respondStorage = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/health/storage
       $storageHealthMessage = Get-Health-Message -colour $respondStorage.value

       $respondDatabase = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/health/database-storage
       $databaseHealthMessage = Get-Health-Message -colour $respondDatabase.value

       $respondSwap = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/health/swap
       $swapHealthMessage = Get-Health-Message -colour $respondSwap.value


       $healthStatus = New-Object -TypeName psobject 
       $healthStatus | Add-Member -MemberType NoteProperty -Name 'Overall Health' -Value $("$($respondOverallHealth.value) , Health Message: $($overallHealthMessage) , LastCheck: $($lastCheck.value)")
       $healthStatus | Add-Member -MemberType NoteProperty -Name 'CPU Load' -Value $("$($respondLoad.value) , Health Message: $($loadHealthMessage)")
       $healthStatus | Add-Member -MemberType NoteProperty -Name 'Memory' -Value $("$($respondMemory.value) , Health Message: $($memoryHealthMessage)")
       $healthStatus | Add-Member -MemberType NoteProperty -Name 'Storage' -Value $("$($respondStorage.value) , Health Message: $($storageHealthMessage)")
       $healthStatus | Add-Member -MemberType NoteProperty -Name 'Database' -Value $("$($respondDatabase.value) , Health Message: $($databaseHealthMessage)")
       $healthStatus | Add-Member -MemberType NoteProperty -Name 'Swap' -Value $("$($respondSwap.value) , Health Message: $($swapHealthMessage)")
      

       return $healthStatus
}

#Function to list the status of all vCSA services. Available only in vCSA 6.7.
function Get-vCSA-Services {
    param (
       [Parameter(Mandatory=$true)][string]$AuthTokenValue,
       [Parameter(Mandatory=$true)][string]$vCSAVersion
    )

       $headers = @{
                        'Accept' = 'application/json';
                        'vmware-api-session-id'= $AuthTokenValue;
                   }
       $method = "GET"
       
       if (([regex]::match($vCSAVersion,"6.7")).success){
       
           $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/services
           $listvCSAServices = $respond.value | Select-Object -Property @{N='Service Name';E={$_.key}},@{N='State';E={$_.value.state}},@{N='Description';E={$_.value.description}} | Sort-Object -Property 'State'
      } else{
           $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/techpreview/services
           $listvCSAServices = $respond.value | Select-Object -Property @{N='Service Name';E={$_.name}},@{N='Description';E={$_.description}}
      }
  
       return $listvCSAServices
}

#Function to get vCSA version and uptime
function Get-vCSA-Version {
    param (
       [Parameter(Mandatory=$true)][string]$AuthTokenValue
    )
    
       $headers = @{
            'Accept' = 'application/json';
            'vmware-api-session-id'= $AuthTokenValue;
       }
        
       $method = "GET"
        write-host "starting $($RestApiUrl)"
       $respondVersion = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/system/version
       $listvCSAVersion = $respondVersion.value | Select-Object -Property @{N='Product';E={$_.product}},@{N='Summary';E={$_.summary}},@{N='Type';E={$_.type}},@{N='Install Time';E={$_.install_time}},@{N='Build';E={$_.build}},@{N='Version';E={$_.version}},@{N='Release Date';E={$_.releasedate}}
       write-host "finished version"
       $respondUptime = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/system/uptime
       $listvCSAUptime = $respondUptime.value 
        write-host "finished uptime"
       $Timespan = New-Timespan -Seconds $listvCSAUptime 
       $listvCSAVersion | Add-Member -MemberType NoteProperty -Name 'System uptime' -Value $("$($Timespan.Days) Days, $($Timespan.Hours) Hours, $($Timespan.Minutes) Minutes")
        
       return $listvCSAVersion
}

#Function to list the status of the services managed by vmware-vmon(VMware Service Lifecycle Manager) service.
function Get-vMon-Services{
    param (
       [Parameter(Mandatory=$true)][string]$AuthTokenValue
    )
    
       $headers = @{
            'Accept' = 'application/json';
            'vmware-api-session-id'= $AuthTokenValue;
       }
       $method = "GET"            
 
       $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/vmon/service
       $listVmonServices = $respond.value | Select-Object -Property @{N='Service Name';E={$_.key}},@{N='State';E={$_.value.state}},@{N='Health';E={$_.value.health}},@{N='Startup Type';E={$_.value.startup_type}} | Sort-Object -Property 'State'
        
       return $listVmonServices
}

#Function to list the status of all vCSA services. Available only in vCSA 6.7.
function Stop-vCSA-Service {
    param (
       [Parameter(Mandatory=$true)][string]$ServiceName,
       [Parameter(Mandatory=$true)][string]$AuthTokenValue,
       [Parameter(Mandatory=$true)][string]$vCSAVersion
    )

       $headers = @{
                        'Accept' = 'application/json';
                        'vmware-api-session-id'= $AuthTokenValue;
                   }
       $method = "POST"
       write-host "Stopping service $($ServiceName)"
       if (([regex]::match($vCSAVersion,"6.7")).success){
            #https://{api_host}/rest/vcenter/services/{service}/stop
           #https://{api_host}/api/vcenter/services/{service}?action=stop
           $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/services/$ServiceName/stop
           $listvCSAService = $respond.value | Select-Object -Property @{N='Service Name';E={$_.key}},@{N='State';E={$_.value.state}},@{N='Description';E={$_.value.description}} | Sort-Object -Property 'State'
      } else{
           #$respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/techpreview/services
           $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/techpreview/services/{$ServiceName}/stop
           
           $listvCSAService = $respond.value | Select-Object -Property @{N='Service Name';E={$_.name}},@{N='Description';E={$_.description}}
      }
  
       return $listvCSAService
}

#Function to list the status of all vCSA services. Available only in vCSA 6.7.
function Start-vCSA-Service {
    param (
       [Parameter(Mandatory=$true)][string]$ServiceName,
       [Parameter(Mandatory=$true)][string]$AuthTokenValue,
       [Parameter(Mandatory=$true)][string]$vCSAVersion
    )

       $headers = @{
                        'Accept' = 'application/json';
                        'vmware-api-session-id'= $AuthTokenValue;
                   }
       $method = "POST"
       write-host "Stopping service $($ServiceName)"
       if (([regex]::match($vCSAVersion,"6.7")).success){
            #https://{api_host}/rest/vcenter/services/{service}/stop
           #https://{api_host}/api/vcenter/services/{service}?action=stop
           $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/services/$ServiceName/start
           $listvCSAService = $respond.value | Select-Object -Property @{N='Service Name';E={$_.key}},@{N='State';E={$_.value.state}},@{N='Description';E={$_.value.description}} | Sort-Object -Property 'State'
      } else{
           #$respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/techpreview/services
           $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/techpreview/services/{$ServiceName}/start
           
           $listvCSAService = $respond.value | Select-Object -Property @{N='Service Name';E={$_.name}},@{N='Description';E={$_.description}}
      }
  
       return $listvCSAService
}



#Function to terminate the session 
function Terminate-Session {
    param (
       [Parameter(Mandatory=$true)][string]$AuthTokenValue
    )
    
       $headers = @{
            'Accept' = 'application/json';
            'vmware-api-session-id'= $AuthTokenValue;
       }
            
       $method = "DELETE"
            
       $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/com/vmware/cis/session
       $terminateSession = $respond.value | Select-Object -Property @{N='ESXi Host Name';E={$_.name}},@{N='Connection State';E={$_.connection_state} } ,@{N='Power State';E={$_.power_state} }
   
       return $terminateSession
}
#...................................
# Script
#...................................
#Find run directory 
$runDir = Split-Path -Parent $MyInvocation.MyCommand.Path
#$reportemailsubject = "VMware Health Report"
$ignorelistfile = "$($runDir)\ignorelist.txt"

################################ Start a transcript log ####################################################

Start-Transcript -Path "$($runDir)\VMware_health_transcript.log"

################################ Initialise some variables #################################################



# dot source the External variables PowerShell File

if (Test-Path "$($runDir)\Test-VMwareHealth-cfg.ps1"){
    . "$($runDir)\Test-VMwareHealth-cfg.ps1"
    }
else{
    write-host "Cannot find config file - please create $($runDir)\Test-VMwareHealth-cfg.ps1" -ForegroundColor Red
    exit
    }


write-host "Running with the following parameters:"
write-host -object $MaxDaysSinceBackup
write-host -object $MaxHoursToScanLog
write-host $logfile
write-host -object $VCServer
write-host -object $CertificateTimeToAlert
write-host -object $CheckPowerOffVMs
write-host -object $datastorePercentFree
write-host -object $IgnoreVMAlarms
write-host -object $IgnoreHostAlarms
write-host -object $PuttyLinkPath

#exit

$now = Get-Date                                             #Used for timestamps
$date = $now.ToShortDateString()                            #Short date format for email message subject
#$MaxDaysSinceBackup = 1                                     #Max days since last full backup
#$MaxHoursToScanLog = 24                                     #Max hours to go back and alert in logs

#Colours for web page
$pass = "Green"
$warn = "Yellow"
$fail = "Red"
$ip = $null
[array]$serversummary = @()                                 #Summary of issues found during server health checks
[array]$report = @()
[bool]$alerts = $false
$servicestatus = "Pass"
$diskstatus = "Pass"
$myDir = Split-Path -Parent $MyInvocation.MyCommand.Path
#$reportemailsubject = "VMware Health Report"
$ignorelistfile = "$myDir\ignorelist.txt"
#$logfile = "C:\Source\Scripts\VMware\VMware_health.log"
#$VCServer = "BOH2-EUD-VCM001.eu.cobham.net"

$ERRORS=$null
$OutputFolder = [System.IO.Path]::GetDirectoryName($ReportFile)
#$CertificateTimeToAlert = 30        #Number of days back before we alert about a cert being about to expire
#$CheckPowerOffVMs = $true

#$datastorePercentFree = 10
#Comma separated array of VM alarms to ignore
#$IgnoreVMAlarms = @("Virtual machine memory usage","rubbish")
#Comma separated array of Host alarms to ignore
#$IgnoreHostAlarms = @("Virtual machine memory usage","rubbish")

#...................................
# Email Settings
#...................................

#$recipients = @("kevin.snook@cobham.com")
#$smtpsettings = @{
#    #To =  "kevin.snook@cobham.com"
#    #To =  "ERoW-IT-Datacentre-Callout-Team@cobham.com"
#    From = "CMS-SIMP-Alerts@cobham.com"
#    SmtpServer = "smtp.eu.cobham.net"
#    }

$smtpsettings = @{
    #To =  "kevin.snook@cobham.com"
    #To =  "ERoW-IT-Datacentre-Callout-Team@cobham.com"
    From = $fromaddress
    SmtpServer = $smtpserver
    }

#...................................
# Initialize
#...................................

if (Test-Path "$($OutputFolder)\VMware_Error_Status_Fail.txt"){
    del "$($OutputFolder)\VMware_Error_Status_Fail.txt"
    }

#Log file is overwritten each time the script is run to avoid
#very large log files from growing over time
if ($Log) {
    $timestamp = Get-Date -DisplayHint Time
    "$($timestamp) =====================================" | Out-File $logfile
    Write-Logfile " VMware Server Health Check"
    Write-Logfile "  $now"
    Write-Logfile "====================================="
}

Write-Host "Initializing..."
if ($Log) {Write-Logfile "Initializing..."}

#...................................
# Credentials
#...................................
#SSO Login for vCenter
#$Credential = Import-CliXml -Path c:\source\scripts\admin@sso_boh2.xml
#$ILOCredential = Import-CliXml -Path c:\source\scripts\hpeloginonly.xml
#$VCCredential = Import-CliXml -Path c:\source\scripts\ks_cred.xml
#$ESXiCredential = Import-CliXml -Path c:\source\scripts\root_cred.xml
#$VCRootCredential = Import-CliXml -Path c:\source\scripts\vc_root_cred.xml

#...................................
# vCenter connection
#$VCServer
#disconnect-viserver * -confirm:$false
$VCConnection = Connect-VIServer $VCServer -Credential $VCCredential -AllLinked
#$VCServerList = $null
$VCServerList = $global:DefaultVIServers

#$VCConnection
#$VCServerList
#exit
#...................................
#Grab ESXi Hosts
$VMHosts = Get-VMHost | sort-object -Property Name
#...................................

#Find all VCs on this connection

#$VCServers = $global:DefaultVIServers
$VCStatus = @{}
foreach ($VCServer in $VCConnection){
    $VCStatusOK = $true
    $VCStatus.Add($VCServer.Name,"Pass")
    write-host "Processing vCenter $($VCServer)"
    #$VCServer | fl
    #exit
    #Ignore-Certificate
    #$RestApiUrl ='https://'+$vCenterFQDN+'/rest/'
    #Check VC services
    #$vCenterFQDN = $VCServer
    #$vCenterFQDN = $VCenter.Name
    $vCenterFQDN = $VCServer.Name
    #$vCenterFQDN
    #Main Program
    DO{
        Write-Host " vCenter Server:" 
        #$vCenterFQDN = Read-Host 
    
        Ignore-Certificate
        $response = try { 
                            write-host "Invoking $($vCenterFQDN)"
                            Invoke-WebRequest $vCenterFQDN
                            $RestApiUrl ='https://'+$vCenterFQDN+'/rest/'
                        } catch { 
                            $_.Exception.Response; 
                            Write-Host "FQDN is not correct or vCenter IP is not reachable. Please check and try again." -ForegroundColor Red 
                        }
   
        }While ($response.StatusCode -ne '200')


    DO{
        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($VCCredential.Password))
        $creds = Set-Credentials -username $VCCredential.UserName -password $password
        $correctToken = 1

        try{
            $AuthenticationToken = Create-Session
            write-host "Creting session"
            if ($AuthenticationToken.Value){
                #Write-Host "Authentication Token acquired successfully" -ForegroundColor Green
                Start-Sleep -Seconds 2
                $correctToken = 0
                $FuncAuthToken = $AuthenticationToken.Value
            }
        
        }
        catch{
            Write-Host "Wrong Username or Password" -ForegroundColor Red
            Start-Sleep -Seconds 2
        }

        }While ($correctToken -eq 1)  

    ##Get the vCSA version 
    write-host "VCSA Version"
    #$vcsaVersion = Get-vCSA-Version -AuthTokenValue $FuncAuthToken
    $vcsaVersion = $VCServer.Version
    write-host $vcsaVersion
    write-host "non-running services"
    $NonRunningVMONServices = Get-vMon-Services -AuthTokenValue $FuncAuthToken | where {$_.State -ne "STARTED" -and $_.'Startup Type' -ne "MANUAL" -and $_.'Startup Type' -ne "DISABLED"} | Select "Service Name"
    #$NonRunningVMONServices = Get-vMon-Services -AuthTokenValue $FuncAuthToken | where {$_.State -eq "STARTED"} | Select "Service Name"
    #$NonRunningVMONServices
    #exit
    if ($NonRunningVMONServices){
        $serversummary += "Service not running on vCenter $($vCenterFQDN): $($NonRunningVMONServices."Service Name")"
        $VCStatus[$VCServer.Name] = "Fail"
        $VCStatusOK = $fail
        
        }
    
    #$vcsaVersionSelection = Get-vCSA-Version -AuthTokenValue $FuncAuthToken | fl
    #$vcsaVersionSelection
    write-host "Health status"
    $vcsaHealthStatus = Get-Health-Status -AuthTokenValue $FuncAuthToken #| where {$_.Definition -contains "green"}
    $vcsaHealth = $vcsaHealthStatus  | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Definition | where {$_ -notmatch "green"}
    if ($vcsaHealth){
        $serversummary += "Health Status Issue on $($vCenterFQDN): $($vcsaHealth)"
        $VCStatus[$VCServer.Name] = "Fail"
        $VCStatusOK = $fail
        
        }
    #$vcsaDisks = Get-vCSA-Disks -AuthTokenValue $FuncAuthToken | ft
    #$vcsaDisks

    
    

    #Check disk space on vCenter
    write-host "disk space"
    $root = $VCRootCredential.UserName
    $cmd = "df -h"
    if (!(Test-Path "C:\PROGRA~1\PUTTY\plink.exe")) {Throw "Plink.exe is not available in the specified folder."}
    $plink = "echo y | C:\PROGRA~1\PUTTY\plink.exe"
    $remoteCommand = '"' + $cmd + '"'
    $commandoutput = run-ssh-command $vCenterFQDN $VCRootCredential.UserName $VCRootCredential.Password $remoteCommand $true
    $commandoutput
    #exit
    #write-host "Output is $($commandoutput)" 
    if ($commandoutput -match "Error Logging On" -or $commandoutput -match "Access Denied" -or $commandoutput -match "Using keyboard-interactive authentication"){
        $serversummary += "$($VMHost) - Error logging on to vCenter $($vCenterFQDN) using SSH"
        $VCStatusOK = $false
        }
    
    else{
        foreach ($line in $commandoutput){
            write-host $line
            [int]$linelength = $line.length
            $MountPoint = $Size = $Used = $Available =$UsePercentage = $null
            if ($line -notmatch "Filesystem"){
                $MountPoint = ($line.Substring(0,42)).trim()
                $Size = ($line.Substring(43,6)).trim()
                $Used = ($line.Substring(49,5)).trim()
                $Available = ($line.Substring(54,5)).trim()
                [int]$UsePercentage = ($line.Substring(59,5)).trim().replace("%","")
                write-host -object "$MountPoint is $UsePercentage% used"
                if ($UsePercentage -gt $PartitionPercentFull){
                    $serversummary += "$($vCenterFQDN) - Disk Space on mountpoint /$($MountPoint) is $($UsePercentage)% used"
                    $VCStatus[$VCServer.Name] = "Fail"
                    $VCStatusOK = $fail
                    }
                }
        
            }
        }
    #No use for the REST API any more so close session
    $quit = Terminate-Session -AuthTokenValue $FuncAuthToken | ft 
    
    #exit
    #Check VC certificate
    try {$VCCert = Test-WebServerSSL -URL $VCServer} #| Select OriginalURi, CertificateIsValid, Issuer, @{N="Expires";E={$_.Certificate.NotAfter} }, @{N="DaysTillExpire";E={(New-TimeSpan -Start (Get-Date) -End ($_.Certificate.NotAfter)).Days} | where (DaysTillExpire -lt 30) }
    catch {Write-Output "Ran into an issue: $($PSItem.ToString())"}
    $TimeTilExpire = (New-TimeSpan -Start (Get-Date) -End ($VCCert.Certificate.NotAfter.Date)).Days
    #write-host $TimeTilExpire
    if ($Log) {Write-Logfile "`n`rCertificate issued to $($VCCert.OriginalURi.Host) by $($VCCert.Issuer) expires on $($VCCert.Certificate.NotAfter.Date.Date) in $($TimeTilExpire) days"}
    write-host "`n`rCertificate issued to $($VCCert.OriginalURi.Host) by $($VCCert.Issuer) expires on $($VCCert.Certificate.NotAfter.Date.Date) in $($TimeTilExpire) days"
    if ($TimeTilExpire -lt $CertificateTimetoAlert -and $TimeTilExpire -ne $null){
        #$cert_alert += "`n`rCertificate issued to $($VCCert.OriginalURi.Host) by $($VCCert.Issuer) expires on $($VCCert.Certificate.NotAfter.Date.Date) in $TimeTilExpire days"
        #write-host "Warning"
        $serversummary += "`n`rCertificate issued to $($VCCert.OriginalURi.Host) by $($VCCert.Issuer) expires on $($VCCert.Certificate.NotAfter.Date.Date) in $TimeTilExpire days;"
        #$VCStatus.Add($VCServer.Name,"Fail")
        $VCStatus[$VCServer.Name] = "Fail"
        $VCStatusOK = $fail
        #$serverObj | Add-Member NoteProperty -Name "vCenter" -Value "Fail" -Force
        }
    #else{
    #    $VCStatus.Add($VCServer.Name,"Pass")
    #    #$serverObj | Add-Member NoteProperty -Name "vCenter" -Value $vCenter -Force
    #    }
    }       

$VCStatus 
#exit
foreach($VMHost in $VMHosts){ 
    Write-Host $VMHost -ForegroundColor Blue 
    #$VMHost | fl
    #$VMHost.Manufacturer
    #ex
    $vCenter = $VMHost.Uid.Split('@')[1].Split(':')[0]
    write-host $vCenter
    #Custom object properties
    $serverObj = New-Object PSObject
    $serverObj | Add-Member NoteProperty -Name "Host" -Value $VMHost
    write-host $VCStatus[$vCenter]

    if ($VCStatus.$vCenter -eq "Fail"){
        $serverObj | Add-Member NoteProperty -Name "vCenter" -Value "Fail"
        }
    else{
        #$serverObj | Add-Member NoteProperty -Name "vCenter" -Value $vCenter
        $serverObj | Add-Member NoteProperty -Name "vCenter" -Value "Pass"
        }       
    #Null and n/a the rest, will be populated as script progresses
    $serverObj | Add-Member NoteProperty -Name "DNS" -Value $null
    $serverObj | Add-Member NoteProperty -Name "Ping" -Value $null
    $serverObj | Add-Member NoteProperty -Name "Uptime (hrs)" -Value $null
    $serverObj | Add-Member NoteProperty -Name "VMs" -Value $null
    $serverObj | Add-Member NoteProperty -Name "Host Alarms" -Value $null
    $serverObj | Add-Member NoteProperty -Name "OVC Alarms" -Value $null
    $serverObj | Add-Member NoteProperty -Name "Services" -Value $null
    $serverObj | Add-Member NoteProperty -Name "Network" -Value "n/a"
    $serverObj | Add-Member NoteProperty -Name "Hardware" -Value "n/a"
    $serverObj | Add-Member NoteProperty -Name "Disk Space" -Value "n/a"
    #write-host "Done next"
    ## Check Vcenter Web Client
    #$VCName = $VCConnection.Name
    $VCURL = "HTTPS://$vCenter/ui"

# Exclude SSL check for Invoke web request
#add-type @"
#    using System.Net;
#    using System.Security.Cryptography.X509Certificates;
#    public class TrustAllCertsPolicy : ICertificatePolicy {
#        public bool CheckValidationResult(
#            ServicePoint srvPoint, X509Certificate certificate,
#            WebRequest request, int certificateProblem) {
#            return true;
#        }
#    }
#"@
#    #[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
#    try {$VCWebCheck = Invoke-WebRequest -Uri $VCURL -UseBasicParsing} 
#    catch {
#        $ErrorException = $_.Exception
#        $ErrorResponse = $_.Exception.Response
#        }
#    if ($VCWebCheck.StatusCode -eq "200") {
#        $VCResponseStatus = $VCWebCheck| Select-Object @{N="VC Web URL";E={$VCURL}},StatusCode,@{N="StatusDescription";E={"OK"}} 
#        write-host $VCResponseStatus
#        #ConvertTo-Html -Fragment -PreContent "<h2>vCenter Connection Response</h2>"
#        }
#    Else
#        {
#        $VCResponseStatus = $ErrorResponse | Select-Object @{N="VC Web URL";E={$_.ResponseUri}},StatusCode,@{N="StatusDescription";E={$ErrorException.Message}}  
#        write-host $VCResponseStatus
#        #ConvertTo-Html -Fragment -PreContent "<h2>vCenter Connection Response</h2>"
#        }
#    write-host "Done VC check"
#    #exit
    #DNS Check
    Write-Host "DNS Check: " -NoNewline;
    try {$ip = @([System.Net.Dns]::GetHostByName($VMHost).AddressList | Select-Object IPAddressToString -ExpandProperty IPAddressToString)}
    catch {
        Write-Host -ForegroundColor $_.Exception.Message
        $ip = $null
        }
    #write-host $ip
    
    if ( $ip -ne $null ){
        Write-Host -ForegroundColor $pass "Pass"
        $serverObj | Add-Member NoteProperty -Name "DNS" -Value "Pass" -Force
        #Is server online
        Write-Host "Ping Check: " -NoNewline; 
        $ping = $null
        try {$ping = Test-Connection $VMHost -Quiet -ErrorAction Stop}
        catch {Write-Host -ForegroundColor $warn $_.Exception.Message}

        switch ($ping)
        {
            $true {
                Write-Host -ForegroundColor $pass "Pass"
                $serverObj | Add-Member NoteProperty -Name "Ping" -Value "Pass" -Force
                }
            default {
                Write-Host -ForegroundColor $fail "Fail"
                $serverObj | Add-Member NoteProperty -Name "Ping" -Value "Fail" -Force
                $serversummary += "$($VMHost.HostName) - Ping Failed"
                }
            }
        }
    #exit    
    
    #Uptime Check
    Write-Host "Uptime (hrs): " -NoNewline
    [int]$uptimehours = $null
    #$vmhost = get-VMhost $VMHost
    #write-host $vmhost.ExtensionData.Summary.Runtime.BootTime
    #[math]::round($a.Length / 1MB, 2)
    #$uptimehours = [math]::round((New-TimeSpan -Start $vmhost.ExtensionData.Summary.Runtime.BootTime -End (Get-Date)).TotalHours,0) #| Select-Object -ExpandProperty Days
    $uptimehours = [math]::round((New-TimeSpan -Start $VMHost.ExtensionData.Summary.Runtime.BootTime -End (Get-Date)).TotalHours,0) #| Select-Object -ExpandProperty Days
    Write-Host "up for $($uptimehours)"
    #[int]$uptime = "{0:00}" -f $timespan.TotalHours
    Switch ($uptimehours -gt 23) {
        $true { Write-Host -ForegroundColor $pass $uptimehours}
        $false { Write-Host -ForegroundColor $warn $uptimehours; $serversummary += "$($VMHost) - Uptime is less than 24 hours ($uptimehours)"}
        default { Write-Host -ForegroundColor $warn $uptimehours; $serversummary += "$($VMHost) - Uptime is less than 24 hours ($uptimehours)"}
        }

    $serverObj | Add-Member NoteProperty -Name "Uptime (hrs)" -Value $uptimehours -Force 
    #exit
    
    ## VMHost Alarms
    Write-Host "Checking for active VMware host alarms" -ForegroundColor Green
    $VMHAlarms = @()
    #$WholeView = ($VMHost | Get-View)
    #$WholeView
    $VMHostStatus = ($VMHost | Get-View) | where {$_.OverallStatus -ne "Green" -or $_.ConfigStatus -ne "Green"} | Select-Object Name,OverallStatus,ConfigStatus,TriggeredAlarmState | sort -property Name | get-unique
    #$VMHostStatus | fl
    
    if ($VMHostStatus){
        foreach($TriggeredAlarm in ($HostStatus.TriggeredAlarmstate | sort | get-unique)){
            foreach ($Alarm in ($TriggeredAlarm.Alarm| sort | get-unique)){
                $TriggeredAlarmName = (Get-AlarmDefinition -Id $Alarm) | get-unique | select $_.Name
                write-host "Triggered alarm name is $($TriggeredAlarmName)"
                if ($TriggeredAlarmName -notin $IgnoreHostAlarms){
                    write-host -object "$TriggeredAlarmName not in $($IgnoreHostAlarms)"
                    $Hprops = @{
                        Host = $VMHostStatus.Name
                        OverAllStatus = $VMHostStatus.OverallStatus
                        TriggeredAlarms = (Get-AlarmDefinition -Id $Alarm).Name | sort | get-unique
                        }
                    $VMHAlarms += New-Object PSObject -Property $Hprops
                    }
                else{
                    write-host -object "$TriggeredAlarmName in $($IgnoreHostAlarms)"
                    }
                }
            }
        
        if (!($VMHostStatus.TriggeredAlarmState) -and ($VMHostStatus.OverallStatus -ne "Green")){
            $Hprops = @{
                        Host = $VMHostStatus.Name
                        OverAllStatus = $VMHostStatus.OverallStatus
                        TriggeredAlarms = "Host Error - configuration issue(s)"
                        }
            $VMHAlarms += New-Object PSObject -Property $Hprops
            }
        }
    
    
    
    if ($VMHAlarms){
        $VMHAlarms | fl
        write-host "$($VMHost) - Host Alarm(s): $($VMHAlarms.TriggeredAlarms)"
        Write-Host -ForegroundColor $fail "Fail"; $serversummary += "$($VMHost) - Host Alarm(s): $($VMHAlarms.TriggeredAlarms)";$serverObj | Add-Member NoteProperty -Name "Host Alarms" -Value "Fail" -Force
        }
    else{
        write-host "No active alarms for Host"
        Write-Host -ForegroundColor $pass "Pass"; $serverObj | Add-Member NoteProperty -Name "Host Alarms" -Value "Pass" -Force
        }
    
    
    #VM Alarms Check
    Write-Host "Checking for active VM alarms" -ForegroundColor Green
    #$VMAlarmReport = @()
    $VMAlarms = @()
    $VMStatus = ($VMHost |Get-VM | Get-View) | where {$_.OverallStatus -ne "Green" -or $_.ConfigStatus -ne "Green" } | Select-Object Name,OverallStatus,ConfigStatus,TriggeredAlarmState | sort -property Name | get-unique
    $VMStatus | fl
    #exit
    if ($VMStatus) {
        foreach ($TriggeredAlarm in ($VMStatus.TriggeredAlarmstate | sort | get-unique)) {
            #write-host $TriggeredAlarm.Alarm.Count
            foreach ($Alarm in ($TriggeredAlarm.Alarm| sort | get-unique)){
                $FullAlarmDetails = Get-AlarmDefinition -Id $Alarm | where {$_.Uid -match $vCenter}
                $FullAlarmDetails | fl
                $TriggeredAlarmName = Get-AlarmDefinition -Id $Alarm | where {$_.Uid -match $vCenter} #| sort -property Name | get-unique | select $_.Name
                write-host "Triggered alarm name is $($TriggeredAlarmName)"
                
                if ($TriggeredAlarmName -notin $IgnoreVMAlarms){
                    write-host -object "$TriggeredAlarmName not in $($IgnoreVMAlarms)"
                    $VMprops = @{
                        VM = $VMStatus.Name
                        OverallStatus = $VMStatus.OverallStatus
                        #TriggeredAlarms = (Get-AlarmDefinition -Id $TriggeredAlarm.Alarm).Name
                        TriggeredAlarms = (Get-AlarmDefinition -Id $Alarm | where {$_.Uid -match $vCenter}).Name #| sort | get-unique
                        }
                    $VMAlarms += New-Object PSObject -Property $VMprops
                    }
                else{
                    write-host -object "$TriggeredAlarmName in $($IgnoreVMAlarms)"
                    }
                }
            }
        }
    
    #exit
    if ($VMAlarms){
        #$VMAlarms | fl
        write-host "$($VMHost) ($($VMAlarms.VM)) - VM Alarm(s): $($VMAlarms.TriggeredAlarms)"
        Write-Host -ForegroundColor $fail "Fail"; $serversummary += "$($VMHost) ($($VMAlarms.VM)) - VM Alarm(s): $($VMAlarms.TriggeredAlarms)";$serverObj | Add-Member NoteProperty -Name "VM Alarms" -Value "Fail" -Force
        }
    else{
        write-host "No active alarms for VM"
        Write-Host -ForegroundColor $pass "Pass"; $serverObj | Add-Member NoteProperty -Name "VM Alarms" -Value "Pass" -Force
        }
    
    #exit
    
    #VMs Check
    $VMErrors = @()
    $HostVMs = ($VMHost |Get-VM | Get-View)
    
    $BadVMs = $HostVMs  | where {$_.RunTime.ConnectionState -ne "connected"} | select name 
    if ($BadVMs){
        $VMErrors += "Bad Connection State VM(s): $($BadVMs.Name)"
        }
    #Check for powered off VMs - there may be legitimate reasons for VMs to be powered off- to not check for this change the $CheckPowerOffVMs variable to $false in the Variables section
    if ($CheckPowerOffVMs){
        $PoweredOffVMs = $HostVMs | where {$_.RunTime.PowerState -eq ’PoweredOff’} | select name 
        if ($PoweredOffVMs){
            $VMErrors += "Powered Off VM(s): $($PoweredOffVMs.Name)"
            }
        }
    #$PoweredOffVMs
    #exit
    Switch (!$VMErrors) {
        $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "VMs" -Value "Pass" -Force}
        default { Write-Host -ForegroundColor $fail $VMErrors; $serversummary += "$($VMHost) - VM Error(s) $($VMErrors)";$serverObj | Add-Member NoteProperty -Name "VMs" -Value "Fail" -Force}
        }

    #Write-Host "VM HA Check: " -NoNewline
    #$ERRORS = $null
    #$ERRORS += Find_NonHA_VMs $VMHost
    #Switch (!$ERRORS) {
    #    $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "HA" -Value "Pass" -Force}
    #    default { Write-Host -ForegroundColor $fail $ERRORS; $serversummary += "$($VMHost.HostName) - Simplivity VM HA $($ERRORS)";$serverObj | Add-Member NoteProperty -Name "HA" -Value "Fail" -Force}
    #    }
   
    
    #Host Services

    #COmpliance
    #Get-Compliance -Detailed -Entity VMHost
    #exit
    Write-Host "Host Services: " -NoNewline
    $ERRORS = $null
    #$RUNNINGSERVICES=@()
    #$RUNNINGSERVICES = get-vmhostservice -VMHost $VMHost | where{($_.Running)}
    #$RUNNINGSERVICES | fl
    #$RUNNINGSERVICES.gettype()
    #$RUNNINGSERVICES | gm
    #$RUNNINGSERVICES = $RUNNINGSERVICES.split("")
    #foreach ($SERVICE in $RUNNINGSERVICES){
    #        write-host "service is $($SERVICE)"
    #        }
    #write-host $RUNNINGSERVICES.gettype()
    #$NORMALSERVICES = @("DCUI","TSM","TSM-SSH","lbtd","ntpd","sfcbd-watchdog","vmsyslogd","vmware-fdm","vpxa")
    #foreach ($NORMALSERVICE in $NORMALSERVICES){
    #    write-host "Is service $($NORMALSERVICE) running"
    #    if ($RUNNINGSERVICES -match $SERVICE){
    #        write-host "$($NORMALSERVICE) in $($RUNNINGSERVICES)"
    #        }
    #    else{
    #        write-host "$($NORMALSERVICE) not in $($RUNNINGSERVICES)"
    #        }
    #    }
    #write-host $NORMALSERVICES.gettype()
    #exit

    #$SERVICE = "DCUI"
    #write-host $SERVICE.gettype()
    #if ($RUNNINGSERVICES -match $SERVICE){
    #    write-host "$($SERVICE) in $($RUNNINGSERVICES)"
    #    }
    #else{
     #   write-host "$($SERVICE) not in $($RUNNINGSERVICES)"
     #   }
    #$RUNNINGSERVICESSTRING = $RUNNINGSERVICES.tostring()
    #$RUNNINGSERVICESSTRING
    #e#xit
    
    $ERRORS +=  Check_VMHost_Running_Services $VMHost
    $ERRORS 
    
    Switch (!$ERRORS) {
        $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Services" -Value "Pass" -Force}
        default { Write-Host -ForegroundColor $fail $ERRORS; $serversummary += "$($VMHost) - Service(s) $($ERRORS)";$serverObj | Add-Member NoteProperty -Name "Services" -Value "Fail" -Force}
        }
    #exit
    #Network
    #Write-Host "Network: " -NoNewline
    #$NetworkOK = $true
    ##Ping the OVC
    #$ip =(Get-VM -Name $VMHost.VirtualControllerName | select @{N="IPAddress";E={@($_.guest.IPAddress[0])}}).IPAddress
    #if ( $ip -ne $null ){
    #    #Write-Host -ForegroundColor $pass "Pass"
    #    #Is server online
    #    #Write-Host "Ping Check: " -NoNewline;
    #    if ($Log) {Write-Logfile "Ping check:"}
    #    $ping = $null
    #    try {$ping = Test-Connection $ip -Quiet -ErrorAction Stop}
    #    catch {Write-Host -ForegroundColor $warn $_.Exception.Message
    #        if ($Log) {Write-Logfile "$_.Exception.Message"}
    #        }
    #    }
    #if (!$ping) {
    #    $NetworkOK = $false
    #    $serversummary += "$($VMHost.HostName) -  OVC interface at address $($ip) is not pingable;"
    #    if ($Log) {Write-Logfile "$($VMHost.HostName) -  OVC interface at address $($ip) is not pingable"}
    #    write-host "$($VMHost.HostName) -  OVC interface at address $($ip) is not pingable"
    #    }
    #else{
    #    if ($Log) {Write-Logfile "$($VMHost.HostName) -  OVC interface at address $($ip) is pingable"}
    #    write-host "$($VMHost.HostName) -  OVC interface at address $($ip) is pingable"
    #    }
   # 
   # 
    #Switch ($NetworkOK) {
    #        $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Network" -Value "Pass" -Force}
    #        $false { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Network" -Value "Fail" -Force}
    #        default { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Network" -Value "Fail" -Force}
    #        }




    
    #Hardware Health
    Write-Host "Host Hardware: " -NoNewline
    $HardwareErrors = @()
    $hs = $SensorInfo = $MemoryInfo = $CPUInfo= $StorageInfo = $null
    $hs = Get-View -Id $VMHost.ExtensionData.ConfigManager.HealthStatusSystem
    $SensorInfo = $hs.Runtime.SystemHealthInfo.NumericSensorInfo | where{$_.HealthState.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} | Select @{N='Host';E={$VMHost.Name}},Name,@{N='Health';E={$_.HealthState.Label}}
    if ($SensorInfo){
        $HardwareErrors += $SensorInfo
        }
    $MemoryInfo = $hs.Runtime.HardwareStatusInfo.MemoryStatusInfo.Status | where{$_.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} 
    #$MemoryInfo | fl
    if ($MemoryInfo){
        $HardwareErrors += "Memory Fault $($MemoryInfo.Summary)"
        }
    #$hs.Runtime.HardwareStatusInfo.CPUStatusInfo.Status
    $CPUInfo = $hs.Runtime.HardwareStatusInfo.CPUStatusInfo.Status | where{$_.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} 
    if ($CPUInfo){
        $HardwareErrors += "CPU Fault $($CPUInfo.Summary)"
        }
    $StorageInfo = $hs.Runtime.HardwareStatusInfo.StorageStatusInfo.Status | where{$_.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} 
    #$StorageInfo = $hs.Runtime.HardwareStatusInfo.StorageStatusInfo | where{$_.Status.Label -notmatch "Green|Unknown" -and $_.Status.Name -notmatch 'Rollup'} 
    if ($StorageInfo){
        $HardwareErrors += "Storage Fault $($StorageInfo.Summary)"
        ##$StorageInfo | gm
        #$StorageInfo.OperationalInfo | gm
        #$StorageInfo.Status | gm
        #exit
        }
    #exit
    Switch (!$HardwareErrors) {
        $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Pass" -Force}
        default { Write-Host -ForegroundColor $fail $HardwareErrors; $serversummary += "$($VMHost) - VMware Host Hardware Error(s) $($HardwareErrors)";$serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Fail" -Force}
        }
    
    #Disk Space
    Write-Host "Disk Space: " -NoNewline
    #write-host $VMHost -ForegroundColor Yellow
    $DiskSpaceOK = $true
    $root = "root"
    #$cmd = "esxcli storage filesystem list"
    $cmd = "vdf -h"
    if (!(Test-Path "C:\PROGRA~1\PUTTY\plink.exe")) {Throw "Plink.exe is not available in the specified folder."}
    $plink = "echo y | C:\PROGRA~1\PUTTY\plink.exe"
    $remoteCommand = '"' + $cmd + '"'
    $commandoutput = run-ssh-command $VMHost $ESXiMonitorCredential.UserName $ESXiMonitorCredential.Password $remoteCommand $false
    write-host "Output is $($commandoutput)" 
    if ($commandoutput -match "Error Logging On" -or $commandoutput -match "Access Denied" -or $commandoutput -match "Using keyboard-interactive authentication"){
        $serversummary += "$($VMHost) - Error logging on to VM Host using SSH"
        $DiskSpaceOK = $false
        }
    
    else{
        foreach ($line in $commandoutput){
        
            [int]$linelength = $line.length
            $MountPoint = $Size = $Used = $Available =$UsePercentage = $null
            if ($linelength -eq 58){
                $MountPoint = ($line.Substring(0,24)).trim()
                $Size = ($line.Substring(25,6)).trim()
                $Used = ($line.Substring(31,10)).trim()
                $Available = ($line.Substring(41,10)).trim()
                [int]$UsePercentage = ($line.Substring(51,5)).trim().replace("%","")
                write-host -object "$MountPoint is $UsePercentage % used"
                if ($UsePercentage -gt $PartitionPercentFull){
                    #write-host "$MountPoint is $UsePercentage % used" -ForegroundColor Red
                    $serversummary += "$($VMHost) - Disk Space on mountpoint /$($MountPoint) is $($UsePercentage) % used"
                    $DiskSpaceOK = $false
                    }
                }
        
            }
        }
    ## Datastore Functions
    Write-Host "Checking for datastores below $($datastorePercentFree)% free space" -ForegroundColor Green
    $DSReport = $VMHost | Get-Datastore | Select-Object Name,@{N="UsedSpaceGB";E={[math]::Round(($_.CapacityGB),2)}},@{N="FreeSpaceGB";E={[math]::Round(($_.FreeSpaceGB),2)}},@{N="%Free";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}}
    $DSBelow = $DSReport | Where-Object {$_."%Free" -lt $($datastorePercentFree)} | Select-Object Name,"%Free"
    #write-host $DSBelow
    if ($DSBelow) {
        #$DSExport = $DSBelow | ConvertTo-HTML -Fragment -PreContent "<h2>DataStore Under $($datastorePercentFree)% Free Space</h2>"
        $serversummary += "$($VMHost) - Disk Space on Datastore(s) is below $($datastorePercentFree)%: $($DSBelow.Name) ($($DSBelow."%Free")%)"
        $DiskSpaceOK = $false
        }
    
    Switch ($DiskSpaceOK) {
        $false { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Disk Space" -Value "Fail" -Force}
        $true { Write-Host -ForegroundColor $pass "Pass"; $serverObj | Add-Member NoteProperty -Name "Disk Space" -Value "Pass" -Force}
        }

    #exit

    #Certificates

    
    #Add this servers output to the $report array
    $report = $report + $serverObj
    
    }         


### Begin report generation
if ($ReportMode -or $SendEmail)
{
    #Get report generation timestamp
    $reportime = (Get-Date).ToString("dd/MM/yyyy HH:mm")

    #Create HTML Report
    #Common HTML head and styles
    $htmlhead="<html>
                <style>
                BODY{font-family: Tahoma; font-size: 8pt;}
                H1{font-size: 16px;}
                H2{font-size: 14px;}
                H3{font-size: 12px;}
                TABLE{Margin: 0px 0px 0px 4px;Border: 1px solid rgb(190, 190, 190);Font-Family: Tahoma;Font-Size: 8pt;Background-Color: rgb(252, 252, 252);}
                tr:hover td{Background-Color: rgb(0, 127, 195);Color: rgb(255, 255, 255);}
                tr:nth-child(even){Background-Color: rgb(110, 122, 130);}
                th{Text-Align: Left;Color: rgb(150, 150, 220);Padding: 1px 4px 1px 4px;}
                td{Vertical-Align: Top;Padding: 1px 4px 1px 4px;}
                td.pass{background: #7FFF00;}
                td.warn{background: #FFE600;}
                td.fail{background: #FF0000; color: #ffffff;}
                td.info{background: #85D4FF;}
                </style>
                <body>
                <h1 align=""center"">VMware Health Check Report</h1>
                <h3 align=""center"">Generated: $reportime</h3>"

    
                
    #Check if the server summary has 1 or more entries
    if ($($serversummary.count) -gt 0)
    {
        #Set alert flag to true
        $alerts = $true
        # Create the error status file (if not already there)
        Out-File -FilePath "$($OutputFolder)\VMware_Error_Status_Fail.txt"
        #Generate the HTML
        $serversummaryhtml = "<h3>VMware Health Details</h3>
                        <p>The following server errors and warnings were detected.</p>
                        <p>
                        <ul>"
        foreach ($reportline in $serversummary)
        {
            $serversummaryhtml +="<li>$reportline</li>"
        }
        $servicestatus = "Fail"
        $serversummaryhtml += "</ul></p>"
        $alerts = $true
    }
    else
    {
        #Generate the HTML to show no alerts
        $serversummaryhtml = "<h3>VMware Health Details</h3>
                        <p>No VMware  health errors or warnings.</p>"
    }
    
        
    #VMware Health Report Table Header
    $htmltableheader = "<h3>VMware Health Summary</h3>
                        <p>
                        <table>
                        <tr>
                        <th>Host</th>
                        <th>vCenter</th>
                        <th>DNS</th>
                        <th>Ping</th>
                        <th>Uptime</th>
                        <th>VMs</th>
                        <th>HA</th>
                        <th>Host Alarms</th>
                        <th>VM Alarms</th>
                        <th>Services</th>
                        <th>Network</th>
                        <th>Hardware</th>
                        <th>Disk Space</th>
                        </tr>"

    #VMware Health Report Table
    
    $serverhealthhtmltable = $null
    $serverhealthhtmltable = $serverhealthhtmltable + $htmltableheader                    
                        
    foreach ($reportline in $report)
    {
        $htmltablerow = "<tr>"
        $htmltablerow += "<td>$($reportline.host)</td>"
        #$htmltablerow += "<td>$($reportline.vCenter)</td>"
        $htmltablerow += (New-ServerHealthHTMLTableCell "vcenter")
        $htmltablerow += (New-ServerHealthHTMLTableCell "dns")
        $htmltablerow += (New-ServerHealthHTMLTableCell "ping")
        
        if ($($reportline."uptime (hrs)") -eq "Access Denied")
        {
            $htmltablerow += "<td class=""warn"">Access Denied</td>"        
        }
        elseif ($($reportline."uptime (hrs)") -eq "Unable to retrieve uptime. ")
        {
            $htmltablerow += "<td class=""warn"">Unable to retrieve uptime. </td>"
        }
        else
        {
            $hours = [int]$($reportline."uptime (hrs)")
            if ($hours -le 24)
            {
                $htmltablerow += "<td class=""warn"">$hours</td>"
            }
            else
            {
                $htmltablerow += "<td class=""pass"">$hours</td>"
            }
        }

        #$htmltablerow += (New-ServerHealthHTMLTableCell "Backups")
        $htmltablerow += (New-ServerHealthHTMLTableCell "VMs")
        $htmltablerow += (New-ServerHealthHTMLTableCell "HA")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Host Alarms")
        $htmltablerow += (New-ServerHealthHTMLTableCell "VM Alarms")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Services")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Network")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Hardware")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Disk Space")
        $htmltablerow += "</tr>"
        
        $serverhealthhtmltable = $serverhealthhtmltable + $htmltablerow
    }

    $serverhealthhtmltable = $serverhealthhtmltable + "</table></p>"

    $htmltail = "</body>
                </html>"

    #$htmlreport = $htmlhead + $serversummaryhtml + $dagsummaryhtml + $serverhealthhtmltable + $dagreportbody + $htmltail
    $htmlreport = $htmlhead + $serverhealthhtmltable + $serversummaryhtml + $htmltail
    
    if ($ReportMode -or $ReportFile)
    {
        $htmlreport | Out-File $ReportFile -Encoding UTF8
    }

    if ($SendEmail)
    {
        if ($alerts -eq $false -and $AlertsOnly -eq $true)
        {
            #Do not send email message
            Write-Host "DO NOT send email message"
            if ($Log) {Write-Logfile "DO NOT send email message"}
        }
        else
        {
            #Send email message
            Write-Host "DO send email message - $servicestatus"
            #Send-MailMessage @smtpsettings -Body $htmlreport -BodyAsHtml -Encoding ([System.Text.Encoding]::UTF8)
            $servicestatus = $servicestatus.ToUpper()
            if ($servicestatus -eq "FAIL"){
                #Send-MailMessage @smtpsettings -Subject "$servicestatus - $reportemailsubject - $now" -Body $htmlreport -BodyAsHtml -Encoding ([System.Text.Encoding]::UTF8) -Priority High
                Send-MailMessage @smtpsettings -To $recipients -Subject "$servicestatus - $reportemailsubject - $reportime" -Body $htmlreport -BodyAsHtml -Encoding ([System.Text.Encoding]::UTF8) -Priority High
                
                }
            else
                {
                #Send-MailMessage @smtpsettings -Subject "$servicestatus - $reportemailsubject - $now" -Body $htmlreport -BodyAsHtml -Encoding ([System.Text.Encoding]::UTF8) 
                Send-MailMessage @smtpsettings -To $recipients -Subject "$servicestatus - $reportemailsubject - $reportime" -Body $htmlreport -BodyAsHtml -Encoding ([System.Text.Encoding]::UTF8)
                }
        }
    }
}
### End report generation

Remove-Variable * -ErrorAction SilentlyContinue; Remove-Module *; $error.Clear();
Write-Host "End"
if ($Log) {Write-Logfile "End"}
Stop-Transcript

