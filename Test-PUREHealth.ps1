<#
.SYNOPSIS
Test-PUREHealth.ps1 - PURE Health Check Script.

.DESCRIPTION 
Performs a series of health checks on PURE hosts and outputs the results to screen, and optionally to log file, HTML report,
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
.\Test-PUREHealth.ps1
Checks all servers in the organization and outputs the results to the shell window.

.EXAMPLE
.\Test-PUREHealth.ps1 
Checks the specified PURE arrays and outputs the results to the shell window.

.EXAMPLE
.\Test-PUREHealth.ps1 -ReportMode -SendEmail
Checks the specified PURE arrays, outputs the results to the shell window, a HTML report, and
emails the HTML report to the address configured in the script.

.LINK


.NOTES
Written by: Kevin Snook (some portions Paul Cunningham)

.OVERVIEW
The script runs through a number of checks on PURE arrays and reports them on a Pass/Fail basis.
If the SendEMail parameter is selected an email is sent showing an overall status i.e. whether ANY check has FAILed or everything has PASSed.
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
        #[string]$ReportFile="c:\source\scripts\PURE\PUREhealth.html",
        [string]$ReportFile="C:\inetpub\wwwroot\monitor\PUREhealth.html",

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
        "Warn" {$htmltablecell = "<td class=""warn""><p class=""blink"">$($reportline."$lineitem")</p></td>"}
        "Access Denied" {$htmltablecell = "<td class=""warn"">$($reportline."$lineitem")</td>"}
        "Fail" {$htmltablecell = "<td class=""fail""><p class=""blink"">$($reportline."$lineitem")</p></td>"}
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

function get_previous_x_day {
param(
$DayofWeek
)

[Int]$DaytoSearchIndex = [DayOfWeek] $DayofWeek  # returns index of day to search for
[Int]$TodayIndex = Get-Date  | Select-Object -ExpandProperty DayOfWeek # returns index of todays day
if ($DaytoSearchIndex -gt $TodayIndex){
    #Today is later in the week than the day required
    #So we need to go back todays index - day's index
    $LastDay = (Get-Date).AddDays(-(7+$TodayIndex-$DaytoSearchIndex)).ToString("dd/MM/yyyy")
    }
else{
    #Today is earlier in the week than the day required
    #So we need to go back day's index - todays index
    $LastDay = (Get-Date).AddDays(-($TodayIndex-$DaytoSearchIndex)).ToString("dd/MM/yyyy")
    }

return $LastDay
}






#...................................
# Script
#...................................

#Find run directory 
$runDir = Split-Path -Parent $MyInvocation.MyCommand.Path
#$reportemailsubject = "PURE Health Report"
$ignorelistfile = "$($runDir)\ignorelist.txt"

################################ Start a transcript log ####################################################

Start-Transcript -Path "$runDir\PURE_health_transcript.log"

################################ Initialise some variables #################################################



# dot source the External variables PowerShell File

if (Test-Path "$($runDir)\Test-PUREHealth-cfg.ps1"){
    . "$($runDir)\Test-PUREHealth-cfg.ps1"
    }
else{
    write-host "Cannot find config file - please create $($runDir)\Test-PUREHealth-cfg.ps1" -ForegroundColor Red
    exit
    }

#...................................
# Variables
#...................................

$now = Get-Date                                             #Used for timestamps
$date = $now.ToShortDateString()                            #Short date format for email message subject
#[array]$PUREservers = @()                                #Array for the PURE filers to check

#Maxima and minima
#$MaxMinutesSinceSnapshot = 60                               #Max minutes since last snapshot
#$MaxDaysToScanLog = 1                                       #Max days to go back and alert in logs
#$VolumeFullPercentageError = 95                             #Percentage full before Error
#$VolumeFullPercentageWarning = 85                           #Percentage full before Warning


#Colours for web page
$pass = "Green"
$warn = "Yellow"
$fail = "Red"

#Report variables
$ip = $null
[array]$serversummary = @()                                 #Summary of issues found during server health checks
[array]$report = @()
[array]$failreport = @()
[array]$passreport = @()
[bool]$alerts = $false
$servicestatus = "Pass"
$diskstatus = "Pass"
$runDir = Split-Path -Parent $MyInvocation.MyCommand.Path
#$reportemailsubject = "PURE Health Report"
$ignorelistfile = "$runDir\ignorelist.txt"
#$logfile = "C:\Source\Scripts\PURE\PURE_health.log"
$ERRORS=$null
$OVC="Not Connected"
$PUREHosts=$null
$OutputFolder = [System.IO.Path]::GetDirectoryName($ReportFile)
write-host $OutputFolder
#$ReportURL = "http://NHC0-EUD-VMAN01\Monitor\PUREHealth_errors.html" #Enter the name of the server where ae are saving the errors (probably the server where this script is running)
if (Test-Path "$($OutputFolder)\PUREHealth_errors.html" -PathType Leaf){
    del "$($OutputFolder)\PUREHealth_errors.html"
    }
$SystemErrors = $false                                    #Variable to show whether system errors have been encountered on any node
$AlertSeverity = "warning"                               #Variable to pick which system errors to pick up: warning, error, critical, debug, informational, notice

#Times on PURE are held in GMT (UTC) - so let's work out current offset to GMT
$tz = Get-CimInstance win32_timezone
$GMTOffsetMinutes = ($tz.Bias + $tz.DaylightBias)
$GMTOffsetMinutes
#exit


#...................................
# Email Settings
#...................................

#$recipients = @("kevin.snook@cobham.com")
#$emailFrom = "PUREhealth@cobham.com"
#$smtpServer = "smtp.eu.cobham.net"

#$smtpsettings = @{
    #To =  "kevin.snook@cobham.com"
    #To =  "ERoW-IT-Datacentre-Callout-Team@cobham.com"
    #From = "HoldCo-PURE-Alerts@cobham.com"
    #SmtpServer = "smtp.eu.cobham.net"
    #}

    $smtpsettings = @{
    #To =  "kevin.snook@cobham.com"
    #To =  "ERoW-IT-Datacentre-Callout-Team@cobham.com"
    From = $fromaddress
    SmtpServer = $smtpserver
    }

#...................................
# Initialize
#...................................

if (Test-Path "$($OutputFolder)\PURE_Error_Status_Fail.txt"){
    del "$($OutputFolder)\PURE_Error_Status_Fail.txt"
    }

#Log file is overwritten each time the script is run to avoid
#very large log files from growing over time
if ($Log) {
    $timestamp = Get-Date -DisplayHint Time
    "$($timestamp) =====================================" | Out-File $logfile
    Write-Logfile " PURE Server Health Check"
    Write-Logfile "  $now"
    Write-Logfile "====================================="
}

Write-Host "Initializing..."
if ($Log) {Write-Logfile "Initializing..."}


#...................................
# Credentials
#...................................

#Login to monitoring user (RO user setup on PURE clusters)
#$PURECredential = Import-CliXml -Path c:\source\scripts\PURE\pureuser.xml

#...................................
# PURE controllers
#$PUREControllers = "10.251.238.40","10.250.238.40"
#...................................


foreach($PUREController in $PUREControllers){ 
    $PUREArray = New-PfaArray -EndPoint $PUREController -Credentials $PURECredential -IgnoreCertificateError -ErrorAction Stop
    Write-Host $PUREController -ForegroundColor Blue
    $PUREArrayAttributes = Get-PfaArrayAttributes -Array $PUREArray
    
    #Custom object properties
    $serverObj = New-Object PSObject
    $serverObj | Add-Member NoteProperty -Name "Array" -Value $PUREArrayAttributes.array_name
                
    #Null and n/a the rest, will be populated as script progresses
    $serverObj | Add-Member NoteProperty -Name "DNS" -Value $null
    $serverObj | Add-Member NoteProperty -Name "Ping" -Value $null
    $serverObj | Add-Member NoteProperty -Name "System" -Value $null
    $serverObj | Add-Member NoteProperty -Name "Health" -Value $null
    #$serverObj | Add-Member NoteProperty -Name "Uptime (hrs)" -Value $null
    $serverObj | Add-Member NoteProperty -Name "Protection Groups" -Value $null
    $serverObj | Add-Member NoteProperty -Name "Snapshots" -Value $null
    $serverObj | Add-Member NoteProperty -Name "Alerts" -Value $null
    $serverObj | Add-Member NoteProperty -Name "Networks" -Value $null
    $serverObj | Add-Member NoteProperty -Name "Hardware" -Value "n/a"
    $serverObj | Add-Member NoteProperty -Name "Volumes" -Value "n/a"
        
        
    
    if ($Log) {Write-Logfile "Processing array $($PUREArrayAttributes.array_name) id $($PUREArrayAttributes.id) running version $($PUREArrayAttributes.version)"}
    

#...................................
#DNS Check
#...................................
        Write-Host "DNS Check: " -NoNewline;
        if ($Log) {Write-Logfile "DNS Check: "}
        $PUREArrayDNS = Get-PfaDnsAttributes -Array $PUREArray
        if ($Log) {Write-Logfile "$($PUREArrayAttributes.array_name).$($PUREArrayDNS.domain)"}
        try {$ip = @([System.Net.Dns]::GetHostByName("$($PUREArrayAttributes.array_name).$($PUREArrayDNS.domain)").AddressList | Select-Object IPAddressToString -ExpandProperty IPAddressToString)}
        catch {
            Write-Host -ForegroundColor $fail $_.Exception.Message
            if ($Log) {Write-Logfile "$_.Exception.Message"}
            $ip = $null
            $serverObj | Add-Member NoteProperty -Name "DNS" -Value "Fail" -Force
            $serversummary += "$($PUREArrayAttributes.array_name) - DNS Lookup Failed"
            }
        if ( $ip -ne $null ){
            Write-Host -ForegroundColor $pass "Pass"
            $serverObj | Add-Member NoteProperty -Name "DNS" -Value "Pass" -Force
            if ($Log) {Write-Logfile "DNS Success: $ip"}
            #Is server online
            Write-Host "Ping Check: " -NoNewline;
            if ($Log) {Write-Logfile "Ping check:"}
            $ping = $null
            try {$ping = Test-Connection $PUREController -Quiet -ErrorAction Stop}
            catch {Write-Host -ForegroundColor $warn $_.Exception.Message
                    if ($Log) {Write-Logfile "$_.Exception.Message"}
                    }

            switch ($ping)
            {
                $true {
                    Write-Host -ForegroundColor $pass "Pass"
                    $serverObj | Add-Member NoteProperty -Name "Ping" -Value "Pass" -Force
                    if ($Log) {Write-Logfile "Pass"}
                    }
                default {
                    Write-Host -ForegroundColor $fail "Fail"
                    $serverObj | Add-Member NoteProperty -Name "Ping" -Value "Fail" -Force
                    $serversummary += "$($PUREArrayAttributes.array_name) - $($PUREController) - Ping Failed"
                    if ($Log) {Write-Logfile "Fail"}
                    }
                }
            }
        else{
            Write-Host -ForegroundColor $fail "Fail"
            $serverObj | Add-Member NoteProperty -Name "Ping" -Value "Fail" -Force
            $serversummary += "$($PUREArrayAttributes.array_name) - $($PUREController) - Ping Failed"
            if ($Log) {Write-Logfile "Fail"}
            }
 
 #...................................
#System Check
#...................................
    $SystemOK = $pass
    Write-Host "System Check: " -NoNewline;
    $PUREArrayNTPServers = Get-PfaNtpServers -Array $PUREArray
    if (!$PUREArrayNTPServers.ntpserver){
        write-host "NTP Servers not setup"
        $SystemOK = $warn
        $serversummary += "NTP Servers not setup;"
        if ($Log) {Write-Logfile "NTP Servers not setup"}
                   
        }
    else{
        write-host "NTP Servers setup - $($PUREArrayNTPServers.ntpserver)"
        if ($Log) {Write-Logfile "NTP Servers setup - $($PUREArrayNTPServers.ntpserver)"}
        #Can we contact NTP servers
        }
 
    #    Write-Host "Connected Arrays: " -NoNewline;
    #    $PUREConnectedArrays = Get-PfaArrayConnections -Array $PUREArray
    #    foreach ($PUREConnectedArray in $PUREConnectedArrays){
    #        $PUREConnectedArray.name
    #        #Check corrected arrays are contactable
    #        }   
    
    
    $PUREArrayRemoteAssistSession = Get-PfaRemoteAssistSession -Array $PUREArray
    write-host "Remote assist is $($PUREArrayRemoteAssistSession.status)"
    if ($Log) {Write-Logfile "Remote assist is $($PUREArrayRemoteAssistSession.status)"}
    
    $PUREArrayPhoneHomeStatus = Get-PfaPhoneHomeStatus -Array $PUREArray
    write-host "Phone home is $($PUREArrayPhoneHomeStatus.phonehome)"
    if ($Log) {Write-Logfile "Phone home is $($PUREArrayPhoneHomeStatus.phonehome)"}
    
    $PUREArrayAlerts = Get-PfaAlerts -Array $PUREArray
    if (!$PUREArrayAlerts.enabled){
        $SystemOK = $warn
        $serversummary += "Array alerts are not enabled;"
        if ($Log) {Write-Logfile "Array alerts are not enabled"}
        write-host "Array alerts are not enabled"
        }
    
    $PUREArrayRelayHost = Get-PfaRelayHost -Array $PUREArray
    if (!$PUREArrayRelayHost.relayhost){
        $SystemOK = $warn
        $serversummary += "SMTP relay host not setup;"
        if ($Log) {Write-Logfile "SMTP relay host not setup"}
        write-host "SMTP relay host not setup"
        }
    
    $PUREArraySenderDomain = Get-PfaSenderDomain -Array $PUREArray
    if (!$PUREArraySenderDomain.senderdomain){
        if ($Log) {Write-Logfile "Sender domain not setup"}
        write-host "Sender domain not setup"
        }
    
    $PUREArraySNMPManagers = Get-PfaSnmpManagers -Array $PUREArray
    if (!$PUREArraySNMPManagers.community){
        if ($Log) {Write-Logfile "SNMP not setup"}
        write-host "SNMP not setup"
        }
    
    #$PUREArraySSLCertificate = Get-PfaCurrentCertificateAttributes -Array $PUREArray
    $PUREArraySyslogServers = Get-PfaSyslogServers -Array $PUREArray
    if (!$PUREArraySyslogServers){
        if ($Log) {Write-Logfile "Syslog not setup"}
        write-host "Syslog not setup"
        }
    
    $PUREArrayDNS = Get-PfaDnsAttributes -Array $PUREArray
    if (!$PUREArrayDNS){
        write-host "$($PUREArrayAttributes.array_name) - DNS Attributes not setup"
        $SystemOK = $fail
        $serversummary += "$($PUREArrayAttributes.array_name) - DNS Attributes not setup;"
        if ($Log) {Write-Logfile "$($PUREArrayAttributes.array_name) - DNS Attributes not setup"}
        }
    if ($PUREArrayDNS.domain){
        if ($Log) {Write-Logfile "$($PUREArrayAttributes.array_name) - DNS domain set to $($PUREArrayDNS.domain)"}
        write-host "DNS domain set to $($PUREArrayDNS.domain)"
        }
    if ($PUREArrayDNS.nameservers){
        foreach ($PUREnameserver in $PUREArrayDNS.nameservers){
            #Is DNS working and correct
            #Ping DNS serevr to add
            if ($Log) {Write-Logfile "$($PUREArrayAttributes.array_name) - Name server set to $($PUREnameserver)"}
            write-host "Name server set to $($PUREnameserver)"
        
            }
        }

    $PUREArrayDirectoryService = Get-PfaDirectoryServiceConfiguration -Array $PUREArray
    if ($PUREArrayDirectoryService){
        if ($Log) {Write-Logfile "$PUREArrayDirectoryService.bind_user`n$PUREArrayDirectoryService.enabled`n$PUREArrayDirectoryService.uri`n$PUREArrayDirectoryService.user_login_attribute`n$PUREArrayDirectoryService.user_object_class`n"}
        if ($Log) {Write-Logfile "$PUREArrayDirectoryService.bind_password`n$PUREArrayDirectoryService.base_dn`n$PUREArrayDirectoryService.check_peer`n"}
        write-host $PUREArrayDirectoryService.bind_user
        write-host $PUREArrayDirectoryService.enabled
        write-host $PUREArrayDirectoryService.uri
        write-host $PUREArrayDirectoryService.user_login_attribute
        write-host $PUREArrayDirectoryService.user_object_class
        write-host $PUREArrayDirectoryService.bind_password
        write-host $PUREArrayDirectoryService.base_dn
        write-host $PUREArrayDirectoryService.check_peer
        }
    else{
        write-host "Directory service not setup"
        $SystemOK = $warn
        $serversummary += "Directory service not setup;"
        if ($Log) {Write-Logfile "Directory service not setup"}
        }

 Switch ($SystemOK) {
        $pass { Write-Host -ForegroundColor $pass "Pass"; $serverObj | Add-Member NoteProperty -Name "System" -Value "Pass" -Force}
        $warn { Write-Host -ForegroundColor $warn "Warn";$serverObj | Add-Member NoteProperty -Name "System" -Value "Warn" -Force}
        $fail { Write-Host -ForegroundColor $fail "Fail";$serverObj | Add-Member NoteProperty -Name "System" -Value "Fail" -Force}
        }
 
#...................................
#Volumes check (includes Protection Group and snapshot checks)
#...................................
        Write-Host "Volumes: " -NoNewline
        if ($Log) {Write-Logfile "Volumes: "}
        $PUREArrayVolumes = Get-PfaVolumes -Array $PUREArray
        $VolumesOK = $pass
        $PGsOK = $pass
        $SnapshotsOK = $pass
        $IntellisnapAddition = "SP-2-"
        foreach ($PUREArrayVolume in $PUREArrayVolumes){
            #$PUREArrayVolume | gm
            write-host $PUREArrayVolume.name -ForegroundColor Yellow
            #write-host $PUREArrayVolume.size
            $PUREArrayVolumeIOMetrics = Get-PfaVolumeIOMetrics -Array $PUREArray -VolumeName $PUREArrayVolume.name
            $PUREArrayVolumeSpaceMetrics = Get-PfaVolumeSpaceMetrics -Array $PUREArray -VolumeName $PUREArrayVolume.name
            #write-host $PUREArrayVolumeSpaceMetrics
            $PUREArrayVolumeSpace = $PUREArrayVolumeSpaceMetrics.size - $PUREArrayVolumeSpaceMetrics.total
            $PUREArrayVolumeSpacePercentage = [math]::Round(($PUREArrayVolumeSpace / $PUREArrayVolumeSpaceMetrics.size *100),2)
            $PUREArrayVolumeUsedPercentage = 100-$PUREArrayVolumeSpacePercentage
            write-host "Size is $($PUREArrayVolumeSpaceMetrics.size)"
            write-host "Spac is $($PUREArrayVolumeSpace)"
            write-host "Space available on volume $($PUREArrayVolume.name) is $($PUREArrayVolumeSpace) ($($PUREArrayVolumeSpacePercentage)%)"
            switch ($PUREArrayVolumeUsedPercentage){
                {$_ -gt $VolumeFullPercentageWarning -and $_ -lt $VolumeFullPercentageError} {$VolumesOK = $warn;$serversummary += "Warning - $($PUREArrayAttributes.array_name) - $($PUREArrayVolume.name) is $($PUREArrayVolumeUsedPercentage))% full;";if ($Log) {Write-Logfile "$($PUREArrayAttributes.array_name) - $($PUREArrayVolume.name) is $($PUREArrayVolumeUsedPercentage)% full"}}
                {$_ -gt $VolumeFullPercentageError} {$VolumesOK = $fail;$serversummary += "Error - $($PUREArrayAttributes.array_name) - $($PUREArrayVolume.name) is $($PUREArrayVolumeUsedPercentage)% full;";if ($Log) {Write-Logfile "$($PUREArrayAttributes.array_name) - $($PUREArrayVolume.name) is $($PUREArrayVolumeUsedPercentage)% full"}}
                }
            
            $PUREProtectionGroup = Get-PfaProtectionGroups -Array $PUREArray | where {$_.volumes -contains $PUREArrayVolume.name}
            if ($PUREProtectionGroup){
                write-host "Protection group for $($PUREArrayVolume.name) is $($PUREProtectionGroup.name)"
                if ($Log) {Write-Logfile "Protection group for $($PUREArrayVolume.name) is $($PUREProtectionGroup.name)"}
                $PUREPGSchedule = Get-PfaProtectionGroupSchedule -Array $PUREArray -ProtectionGroupName $PUREProtectionGroup.name 
                if (!$PUREPGSchedule){
                    if ($Log) {Write-Logfile "No Protection Group Schedules for $($PUREProtectionGroup.name)"}
                    $PGsOK = $fail
                    $serversummary += "Error - $($PUREArrayAttributes.array_name) - No Protection Group Schedules for $($PUREProtectionGroup.name);"
                    }
                }
            if ($Log) {Write-Logfile $PUREArrayVolume.name}
            #write-host $PUREArrayVolume.source #if it's a PG target????
            #Check space and snapshots
            Write-Host "Snapshots Check: " 
            if ($Log) {Write-Logfile "Snapshots Check: "}
            $LastSnapshotOK = $false
            $PURESnapshots = Get-PfaVolumeSnapshots -Array $PUREArray -VolumeName $PUREArrayVolume.name | where {$_.name -notmatch $IntellisnapAddition}
            write-host "snap frequency is $($PUREPGSchedule.snap_frequency/60)"
            Write-Host "Volume Snapshots Count: $($PURESnapshots.Count)"
            if ($Log) {Write-Logfile "Volume Snapshots Count: $($PURESnapshots.Count)"}
            if($PURESnapshots){
                $LastSnapshot = $PURESnapshots |  sort -Property created | select -Last 1
                $FirstSnapshot = $PURESnapshots |  sort -Property created | select -First 1
                #(Get-Date)
                $LastSnapShotCreatedDate = get-date $LastSnapshot.Created
                $LastSnapShotCreatedDate = $LastSnapShotCreatedDate.AddMinutes(-$GMTOffsetMinutes)
                $LastSnapshotTaken = New-TimeSpan -Start $LastSnapShotCreatedDate -End (Get-Date)
                $FirstSnapShotCreatedDate = get-date $FirstSnapshot.Created
                $FirstSnapShotCreatedDate = $FirstSnapShotCreatedDate.AddMinutes(-$GMTOffsetMinutes)
                $FirstSnapshotTaken = New-TimeSpan -Start $FirstSnapShotCreatedDate -End (Get-Date)
                #$FirstSnapshotTaken
                write-host "$($LastSnapshot.name) was taken $(([Math]::Round($LastSnapshotTaken.TotalMinutes, 0))) minutes ago at $($LastSnapShotCreatedDate)"
                if ($Log) {Write-Logfile "$($LastSnapshot.name) was taken $(([Math]::Round($LastSnapshotTaken.TotalMinutes, 0))) minutes ago at $($LastSnapShotCreatedDate)"}
                if ($LastSnapshotTaken.TotalMinutes -gt $PUREPGSchedule.snap_frequency/60){
                    write-host "$($LastSnapshot.name) was taken $(([Math]::Round($LastSnapshotTaken.TotalMinutes, 0))) minutes ago which is NOT within the snap frequency of $($PUREPGSchedule.snap_frequency/60)"
                    if ($Log) {Write-Logfile "$($LastSnapshot.name) was taken $(([Math]::Round($LastSnapshotTaken.TotalMinutes, 0))) minutes ago which is NOT within the snap frequency of $($PUREPGSchedule.snap_frequency/60)"}
                    $SnapshotsOK = $fail
                    $serversummary += "Error - $($LastSnapshot.name) was taken $(([Math]::Round($LastSnapshotTaken.TotalMinutes, 0))) minutes ago which is NOT within the snap frequency of $($PUREPGSchedule.snap_frequency/60);"
                    $LastSnapshotOK = $false
                    }
                else{
                    $LastSnapshotOK = $true
                    }

                }
            
            #$PUREArrayProtectionGroup = Get-PfaVolumeProtectionGroups -Array $PUREArray -VolumeName $PUREArrayVolume.name 
            $PUREProtectionGroup = Get-PfaProtectionGroups -Array $PUREArray | where {$_.volumes -contains $PUREArrayVolume.name } #gives a bit more info than the Get-PfaVolumeProtectionGroups version
            #$PUREProtectionGroup
            #exit
            if ($PUREProtectionGroup){
                Write-Host "Protection Group Check: "
                if ($Log) {Write-Logfile "Protection Group Check: "}
           
                
                $PUREPGSnapEnabled = $PUREPGSchedule.snap_enabled
                [int]$PUREPGSnapFrequency = $PUREPGSchedule.snap_frequency
                Write-Host "PG Snapshot Frequency: $($PUREPGSnapFrequency)"
                if ($Log) {Write-Logfile  "PG Snapshot Frequency: $($PUREPGSnapFrequency)"}
                
                switch ($PUREPGSnapFrequency){
                    {$_ -lt 60} {$PUREPGSnapFrequency_TimeDescriptor = "minutes"}
                    {$_ -ge 60 -and $_ -lt 86400} {$PUREPGSnapFrequency_TimeDescriptor = "hours";$PUREPGSnapFrequency = $PUREPGSnapFrequency/3600}
                    {$_ -ge 86400} {$PUREPGSnapFrequency_TimeDescriptor = "days";;$PUREPGSnapFrequency = $PUREPGSnapFrequency/86400}
                    }
                $PUREPGReplicationEnabled = $PUREPGSchedule.replicate_enabled
                [int]$PUREPGReplicationFrequency = $PUREPGSchedule.replicate_frequency
                switch ($PUREPGReplicationFrequency){
                    {$_ -lt 60} {$PUREPGReplicationFrequency_TimeDescriptor = "minutes"}
                    {$_ -ge 60 -and $_ -lt 86400} {$PUREPGReplicationFrequency_TimeDescriptor = "hours";$PUREPGReplicationFrequency = $PUREPGReplicationFrequency/3600}
                    {$_ -ge 86400} {$PUREPGReplicationFrequency_TimeDescriptor = "days";$PUREPGReplicationFrequency = $PUREPGReplicationFrequency/86400}
                    }
                $PUREPGSnapshots = Get-PfaProtectionGroupSnapshots -Array $PUREArray -Name * | where {$_.source -match $PUREArrayVolume.name} 
                #$PUREPGSnapshots
                Write-Host "PG Snapshots Count: $($PUREArrayPGSnapshots.Count)"
                if ($Log) {Write-Logfile "PG Snapshots Count: $($PUREArrayPGSnapshots.Count)"}
                $PUREPGSnapshots |  sort -Property created | select -Last 1
                $PUREPGRetention = Get-PfaProtectionGroupRetention -Array $PUREArray -ProtectionGroupName $PUREProtectionGroup.name
                $PUREPGRetention | fl
                [int]$PUREPGall_for = $PUREPGRetention.all_for
                switch ($PUREPGall_for){
                    {$_ -lt 60} {$PUREPGall_for_TimeDescriptor = "minutes"}
                    {$_ -ge 60 -and $_ -lt 86400} {$PUREPGall_for_TimeDescriptor = "hours";$PUREPGall_for = $PUREPGall_for/3600}
                    {$_ -ge 86400} {$PUREPGall_for_TimeDescriptor = "days";$PUREPGall_for = $PUREPGall_for/86400}
                    }
                $PUREPGperday = $PUREPGRetention.per_day
                write-host "Retention for $($PUREPGRetention.per_day) per day"
                $PUREPGdays = $PUREPGRetention.days
                write-host "Retention for $($PUREPGRetention.days) days"
                [int]$PUREPGtarget_all_for = $PUREPGRetention.target_all_for
                write-host $PUREPGRetention.target_all_for
                switch ($PUREPGtarget_all_for){
                    {$_ -le 60} {$PUREPGtarget_all_for_TimeDescriptor = "minutes"}
                    {$_ -gt 60 -and $_ -lt 86400} {$PUREPGtarget_all_for_TimeDescriptor = "hours";$PUREPGtarget_all_for = $PUREPGtarget_all_for/3600}
                    {$_ -ge 86400} {$PUREPGtarget_all_for_TimeDescriptor = "days";$PUREPGtarget_all_for = $PUREPGtarget_all_for/86400}
                    }
                $PUREPGtarget_per_day = $PUREPGRetention.target_per_day
                $PUREPGtarget_days = $PUREPGRetention.target_days
                
                #Compare the oldest snapshot to the retained days set in the schedule
                write-host "$($FirstSnapshot.name) was taken $(([Math]::Round($FirstSnapshotTaken.TotalDays, 0))) days ago at $($FirstSnapShotCreatedDate)"
                #Have to add a day here as the PURE takes a day to work out the threshold has been traversed and tidy up 
                write-host "Retention is $($PUREPGRetention.days) days - no snapshots should be retained before $((get-date).AddDays(-$PUREPGRetention.days-1))"
                if (([Math]::Round($FirstSnapshotTaken.TotalDays, 0)) -gt $PUREPGRetention.days+1){
                    write-host "$($PUREProtectionGroup.name) - There are snapshots older than the maximum retention time ($($PUREPGRetention.days+1)). The oldest was created on $($FirstSnapShotCreatedDate)"
                    $SnapshotsOK = $fail
                    $PGsOK = $fail
                    $serversummary += "Error - $($PUREProtectionGroup.name) - There are snapshots older than the maximum retention time ($($PUREPGRetention.days+1)). No snapshots should be retained before $((get-date).AddDays(-$PUREPGRetention.days-1)). The oldest was created on $($FirstSnapShotCreatedDate);"
                    if ($Log) {Write-Logfile "Error - $($PUREProtectionGroup.name) - There are snapshots older than the maximum retention time ($($PUREPGRetention.days+1)). No snapshots should be retained before $((get-date).AddDays(-$PUREPGRetention.days-1)). The oldest was created on $($FirstSnapShotCreatedDate)"}
                    }

                write-host "Snapshot Schedule"
                if ($Log) {Write-Logfile "Snapshot Schedule"}
                write-host "Enabled: $PUREPGSnapEnabled"
                if ($Log) {Write-Logfile "Enabled: $PUREPGSnapEnabled"}
                write-host "Create a snapshot on source every $($PUREPGSnapFrequency) $($PUREPGSnapFrequency_TimeDescriptor)"
                if ($Log) {Write-Logfile "Create a snapshot on source every $($PUREPGSnapFrequency) $($PUREPGSnapFrequency_TimeDescriptor)"}
                write-host "Retain all snapshots on source for $($PUREPGall_for) $($PUREPGall_for_TimeDescriptor)"
                if ($Log) {Write-Logfile "Retain all snapshots on source for $($PUREPGall_for) $($PUREPGall_for_TimeDescriptor)"}
                write-host "`tthen retain $($PUREPGperday) snapshots per day for $($PUREPGdays) more days"
                if ($Log) {Write-Logfile "`tthen retain $($PUREPGperday) snapshots per day for $($PUREPGdays) more days"}
                write-host "Replication Schedule"
                if ($Log) {Write-Logfile "Replication Schedule"}
                write-host "Enabled: $PUREPGReplicationEnabled"
                if ($Log) {Write-Logfile "Enabled: $PUREPGReplicationEnabled"}
                write-host "Replicate a snapshot to targets every $($PUREPGReplicationFrequency) $($PUREPGReplicationFrequency_TimeDescriptor)"
                if ($Log) {Write-Logfile  "Replicate a snapshot to targets every $($PUREPGReplicationFrequency) $($PUREPGReplicationFrequency_TimeDescriptor)"}
                write-host "Retain all snapshots on targets for $($PUREPGtarget_all_for) $($PUREPGtarget_all_for_TimeDescriptor)"
                if ($Log) {Write-Logfile "Retain all snapshots on targets for $($PUREPGtarget_all_for) $($PUREPGtarget_all_for_TimeDescriptor)"}
                write-host "`tthen retain $($PUREPGtarget_per_day) snapshots per day for $($PUREPGtarget_days) more days"
                if ($Log) {Write-Logfile "`tthen retain $($PUREPGtarget_per_day) snapshots per day for $($PUREPGtarget_days) more days"}
                #How many snapshots taken per day 
                $PGSnapshotsperday = (86400/$PUREPGSchedule.snap_frequency)
                Write-Host "PG Policy Snapshots per day Count: $($PGSnapshotsperday)"
                if ($Log) {Write-Logfile "PG Policy Snapshots per day Count: $($PGSnapshotsperday)"}
                $TotalDailyPGSnapshotsRetained = ($PGSnapshotsperday*($PUREPGRetention.all_for/86400))
                Write-Host "PG Policy Total Daily Snapshots Retained Count: $($TotalDailyPGSnapshotsRetained)"
                if ($Log) {Write-Logfile "PG Policy Total Daily Snapshots Retained Count: $($TotalDailyPGSnapshotsRetained)"}
                #How many days retention 
                $TotalPreviousDailyPGSnapshotsRetained = $PUREPGperday*$PUREPGdays
                Write-Host "PG Total Previous Daily Snapshots Retained Count: $($TotalPreviousDailyPGSnapshotsRetained)"
                if ($Log) {Write-Logfile "PG Total Previous Daily Snapshots Retained Count: $($TotalPreviousDailyPGSnapshotsRetained)"}
                $PGRetainedSnapshots = $TotalDailyPGSnapshotsRetained + $TotalPreviousDailyPGSnapshotsRetained
                Write-Host "Overall PG Total Daily Snapshots Retained Count: $($PGRetainedSnapshots)"
                switch ($PGRetainedSnapshots - $PUREPGSnapshots.Count){
                    {$_ -lt 0} {write-host "There are too many snapshots retained - Policy set to $($PGRetainedSnapshots) but $($PUREPGSnapshots.Count) actually retained"
                            if ($Log) {Write-Logfile "There are too many snapshots retained - Policy set to $($PGRetainedSnapshots) but $($PUREPGSnapshots.Count) actually retained"}
                            }
                    {$_ -gt 0} {
                        if ($LastSnapshotOK){
                            write-host "There are too few snapshots retained - Policy set to $($PGRetainedSnapshots) but $($PUREPGSnapshots.Count) actually retained"
                            write-host "There are too few snapshots retained but it's OK because the latest snapshot is up-to-date so we are probably catching up"
                            if ($Log) {Write-Logfile "There are too few snapshots retained but it's OK because the latest snapshot is up-to-date so we are probably catching up"}
                            }
                        else{
                            write-host "There are too few snapshots retained - Policy set to $($PGRetainedSnapshots) but $($PUREPGSnapshots.Count) actually retained"
                            write-host "There are too few snapshots retained and the last snapshot is not within the snapshot frequency configured (taken $($LastSnapshotTaken.Minutes) minutes ago)"
                            if ($Log) {Write-Logfile "There are too few snapshots retained and the last snapshot is not within the snapshot frequency configured (taken $($LastSnapshotTaken.Minutes) minutes ago)"}
                            $SnapshotsOK = $fail
                            $PGsOK = $fail
                            $serversummary += "There are too few snapshots retained and the last snapshot is not within the snapshot frequency configured (taken $($LastSnapshotTaken.Minutes) minutes ago);"
                   
                            }
                        }
                   } 
                }
            #exit
            }
        

    Switch ($VolumesOK) {
        $pass { Write-Host -ForegroundColor $pass "Pass"; $serverObj | Add-Member NoteProperty -Name "Volumes" -Value "Pass" -Force}
        $warn { Write-Host -ForegroundColor $warn "Warn";$serverObj | Add-Member NoteProperty -Name "Volumes" -Value "Warn" -Force}
        $fail { Write-Host -ForegroundColor $fail "Fail";$serverObj | Add-Member NoteProperty -Name "Volumes" -Value "Fail" -Force}
        }

    Switch ($PGsOK) {
        $pass { Write-Host -ForegroundColor $pass "Pass"; $serverObj | Add-Member NoteProperty -Name "Protection Groups" -Value "Pass" -Force}
        $fail { Write-Host -ForegroundColor $fail "Fail";$serverObj | Add-Member NoteProperty -Name "Protection Groups" -Value "Fail" -Force}
        }

    Switch ($SnapshotsOK) {
        $pass { Write-Host -ForegroundColor $pass "Pass"; $serverObj | Add-Member NoteProperty -Name "Snapshots" -Value "Pass" -Force}
        $fail { Write-Host -ForegroundColor $fail "Fail";$serverObj | Add-Member NoteProperty -Name "Snapshots" -Value "Fail" -Force}
        }




#...................................
#Controller Alarms check
#...................................
        Write-Host "Controller Alerts: " -NoNewline
        if ($Log) {Write-Logfile "Controller Alerts: "}
        #write-host ($(get-date).AddDays(-$MaxDaysToScanLog)) 
        if ($Log) {Write-Logfile "Looking for alerts after ($(get-date).AddDays(-$MaxDaysToScanLog)) "}
        $AlertResults = Get-PfaRecentMessages -Array $PUREArray | where {$_.current_severity -eq $AlertSeverity} | Select component_name, opened, component_type,event, details | where {$_.opened -gt ((get-date).AddDays(-$MaxDaysToScanLog))}
        #$AlertResults | fl
        if ($AlertResults){
            $errorhtmlhead="<html>
                    <style>
                    BODY{font-family: Tahoma; font-size: 8pt;}
                    H1{font-size: 16px;}
                    H2{font-size: 14px;}
                    H3{font-size: 12px;}
                    TABLE{Margin: 0px 0px 0px 4px;Border: 1px solid rgb(190, 190, 190);Font-Family: Tahoma;Font-Size: 8pt;Background-Color: rgb(252, 252, 252);}
                    tr:hover td{Background-Color: rgb(0, 127, 195);Color: rgb(255, 255, 255);}
                    th{Text-Align: Left;Color: rgb(150, 150, 220);Padding: 1px 4px 1px 4px;}
                    td{Vertical-Align: Top;Padding: 1px 4px 1px 4px;}
                    td.pass{background: #7FFF00;}
                    td.warn{background: #FFE600;}
                    td.fail{background: #FF0000; color: #ffffff;}
                    td.info{background: #85D4FF;}
                    </style>"
                
            $AlertResults | ConvertTo-HTML -head $errorhtmlhead| out-file "$($OutputFolder)\PUREHealth_errors.html" -append
            }
        Switch (!$AlertResults) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Alerts" -Value "Pass" -Force;if ($Log) {Write-Logfile "No controller alerts"}}
            $false { Write-Host -ForegroundColor $fail "Fail"; $serversummary += "$($PURENode.Node) - System Errors - Check log for errors (click link above);";$serverObj | Add-Member NoteProperty -Name "Alerts" -Value "Fail" -Force;$SystemErrors = $true;if ($Log) {Write-Logfile "There are controller alerts`n`r$AlertResults"}}
            default { Write-Host -ForegroundColor $fail "Fail"; $serversummary += "$($PURENode.Node) - System Errors - Check log for errors (click link above);";$serverObj | Add-Member NoteProperty -Name "Alerts" -Value "Fail" -Force;$SystemErrors = $true;if ($Log) {Write-Logfile "There are controller alerts`n`r$AlertResults"}}
            }
        
#...................................        
#Networks check
#...................................
        Write-Host "Networks: " -NoNewline
        if ($Log) {Write-Logfile "Networks: "}
        
        $NetworkOK = $true

        $PUREInterfaces = Get-PfaNetworkInterfaces  -Array $PUREArray | where {$_.enabled -eq "true"}
        #$PUREArrayNetworkInterfaces
        foreach ($PUREArrayNetworkInterface in $PUREInterfaces){
            write-host $PUREArrayNetworkInterface.address 
            if ($PUREArrayNetworkInterface.subnet ){
                write-host $PUREArrayNetworkInterface.subnet 
                }   
            write-host $PUREArrayNetworkInterface.mtu      
            write-host $PUREArrayNetworkInterface.hwaddr   
            write-host $PUREArrayNetworkInterface.netmask   
            if ($PUREArrayNetworkInterface.slaves ){
                write-host $PUREArrayNetworkInterface.slaves
                }   
          
            write-host $PUREArrayNetworkInterface.services 
            write-host $PUREArrayNetworkInterface.speed    
            write-host $PUREArrayNetworkInterface.gateway   
            if ($Log) {Write-Logfile "Address=$($PUREArrayNetworkInterface).address`nSubnet=$($PUREArrayNetworkInterface).subnet`nMTU=$($PUREArrayNetworkInterface).mtu`nSubnetMask=$($PUREArrayNetworkInterface).netmask`n"}
            if ($Log) {Write-Logfile "Slaves=$($PUREArrayNetworkInterface).slaves`nServices=$($PUREArrayNetworkInterface).services`nSpeed=$($PUREArrayNetworkInterface).speed`nHWAddr=$($PUREArrayNetworkInterface).hwaddr`nGateway=$($PUREArrayNetworkInterface).gateway`n"}
            }
   

        #$PUREInterfaces | fl
        foreach ($PUREInterface in $PUREInterfaces){
            $ip = $PUREInterface.address
            if ( $ip -ne $null ){
                #Write-Host -ForegroundColor $pass "Pass"
                #Is server online
                #Write-Host "Ping Check: " -NoNewline;
                if ($Log) {Write-Logfile "Ping check:"}
                $ping = $null
                try {$ping = Test-Connection $ip -Quiet -ErrorAction Stop}
                catch {Write-Host -ForegroundColor $warn $_.Exception.Message
                    if ($Log) {Write-Logfile "$_.Exception.Message"}
                    }
                }
            if (!$ping) {
                $NetworkOK = $false
                $serversummary += "$($PUREArrayAttributes.array_name) -  interface $($PUREInterface.name) at address $($PUREInterface.address) is not pingable;"
                        
                if ($Log) {Write-Logfile "$($PUREArrayAttributes.array_name) -  interface $($PUREInterface.name) at address $($PUREInterface.address) is not pingable"}
                write-host "$($PUREArrayAttributes.array_name) -  interface $($PUREInterface.name) at address $($PUREInterface.address) is not pingable"
                }
            else{
                if ($Log) {Write-Logfile "$($PUREArrayAttributes.array_name) -  interface $($PUREInterface.name) at address $($PUREInterface.address) is pingable"}
                write-host "$($PUREArrayAttributes.array_name) -  interface $($PUREInterface.name) at address $($PUREInterface.address) is pingable"
                }
            }
        Switch ($NetworkOK) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Networks" -Value "Pass" -Force}
            $false { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Networks" -Value "Fail" -Force}
            default { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Networks" -Value "Fail" -Force}
            }

#...................................        
#Hosts check
#...................................
    
    
    $PUREArrayHosts = Get-PfaHosts -Array $PUREArray
    foreach ($PUREArrayHost in $PUREArrayHosts){
        write-host $PUREArrayHost.name
        write-host $PUREArrayHost.wwn
        write-host $PUREArrayHost.hgroup
        #Anything here to check?
        }
    $PUREArrayHostGroups = Get-PfaHostGroups -Array $PUREArray
    foreach ($PUREArrayHostGroup in $PUREArrayHostGroups){
        write-host $PUREArrayHostGroup.name
        write-host $PUREArrayHostGroup.hosts
        }
 
 #...................................        
#Ports check
#...................................

    $PUREArrayPorts = Get-PfaArrayPorts -Array $PUREArray
    foreach ($PUREArrayPort in $PUREArrayPorts){
        write-host $PUREArrayPort.name
        write-host $PUREArrayPort.wwn
        write-host $PUREArrayPort.failover
        }
    


#...................................        
#Hardware check
#...................................
        #Controller, Disks,Shelves
        Write-Host "Hardware: " -NoNewline
        if ($Log) {Write-Logfile "Hardware: "}
        
        $HardwareOK = $true

        #Controllers
        $PUREArrayControllers = Get-PfaControllers -Array $PUREArray | where {$_.type -eq "array_controller"}
        foreach ($PUREArrayController in $PUREArrayControllers){
            if ($PUREArrayController.status -ne "ready"){
                $HardwareOK = $false
                if ($Log) {Write-Logfile "Controller $($PUREArrayController.name) model $($PUREArrayController.model) is $($PUREArrayController.status)"}
                write-host "Controller $($PUREArrayController.name) model $($PUREArrayController.model) is $($PUREArrayController.status)"
                }
            }
        #exit

        #Disks
        $PUREArrayBadDisks = Get-PfaAllDriveAttributes -Array $PUREArray | where {$_.status -notmatch "healthy" -and $_.status -notmatch "unused"}
        if ($PUREArrayBadDisks){
            $HardwareOK = $false
            if ($Log) {Write-Logfile "Bad disk(s) on $($PUREArray)"}
            write-host "Bad disk(s) on $($PUREArray)"
            }
       

        #Shelves
        $PUREShelfControllers = Get-PfaControllers -Array $PUREArray | where {$_.type -eq "shelf_controller"}
        foreach ($PUREShelfController in $PUREShelfControllers){
            #$PUREShelfController | fl
            if ($PUREShelfController.status){
                $HardwareOK = $false
                if ($Log) {Write-Logfile "Controller $($PUREShelfController.name) model $($PUREShelfController.model) is $($PUREShelfController.status)"}
                write-host "Controller $($PUREShelfController.name) model $($PUREShelfController.model) is $($PUREShelfController.status)"
                }
            

            }
        
        
        Switch ($HardwareOK) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Pass" -Force}
            $false { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Fail" -Force}
            default { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Fail" -Force}
            }
        

           

    
        #Add this servers output to the $report array
        $report = $report + $serverObj
    
        }         
    #}



### Begin report generation
if ($ReportMode -or $SendEmail)
{
    #Get report generation timestamp
    $reportime = (Get-Date).ToString("dd/MM/yyyy HH:mm")

    #Create HTML Report
    
    if ($SystemErrors){            
                $htmlhead += "<a href=""$ReportURL"">Error Report File</a>"
                }
    #Check if the server summary has 1 or more entries
    if ($($serversummary.count) -gt 0)
    {
        #Set alert flag to true
        $alerts = $true
        # Create the error status file (if not already there)
        Out-File -FilePath "$($OutputFolder)\PURE_Error_Status_Fail.txt"
        
        #Generate the HTML
        $serversummaryhtml = "<h3>PURE Health Details</h3>
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
        $serversummaryhtml = "<h3>PURE Health Details</h3>
                        <p>No PURE health errors or warnings.</p>"
    }
    
    #Common HTML head and styles
    $htmlhead="<html>
                <head><title>PURE GreenScreen - $servicestatus</title></head>
                <style>
                BODY{font-family: Tahoma; font-size: 8pt;}
                H1{font-size: 16px;}
                H2{font-size: 14px;}
                H3{font-size: 12px;}
                TABLE{Margin: 0px 0px 0px 4px;Border: 1px solid rgb(190, 190, 190);Font-Family: Tahoma;Font-Size: 8pt;Background-Color: rgb(252, 252, 252);}
                tr:hover td{Background-Color: rgb(0, 127, 195);Color: rgb(255, 255, 255);}
                tr:nth-child(even){Background-Color: rgb(110, 122, 130);}th{Text-Align: Left;Color: rgb(150, 150, 220);Padding: 1px 4px 1px 4px;}
                td{Vertical-Align: Top;Padding: 1px 4px 1px 4px;}
                td.pass{background: #7FFF00;}
                td.warn{background: #FFE600;}
                td.fail{background: #FF0000; color: #ffffff;}
                td.info{background: #85D4FF;}
                </style>
                <style>
      		    .blink {
      		    animation: blinker 0.8s linear infinite;
                font-weight: bold;
                }
                @keyframes blinker {  
                50% { opacity: 0; }
                }
                </style>
                <body>
                <h1 align=""center"">PURE Health Check Report</h1>
                <h3 align=""center"">Generated: $reportime</h3>"
                   
    #PURE Health Report Table Header
    $htmltableheader = "<h3>PURE Health Summary</h3>
                        <p>
                        <table>
                        <tr>
                        <th>Array</th>
                        <th>DNS</th>
                        <th>Ping</th>
                        <th>System</th>
                        <th>Protection Groups</th>
                        <th>Snapshots</th>
                        <th>Alerts</th>
                        <th>Networks</th>
                        <th>Hardware</th>
                        <th>Volumes</th>
                        </tr>"

    #PURE Health Report Table
    
    $serverhealthhtmltable = $null
    $serverhealthhtmltable = $serverhealthhtmltable + $htmltableheader  
    
    foreach ($line in $report){
        #Pop reportlines into separate arrays based on whether they have errors or not
        #write-host "report line is"
        #write-host $line
        if ($line -match "Fail" -or $line -match "Warn"){
            write-host "$($line.array) has failures/warnings" -ForegroundColor Red
            $failreport += $line
            }
        else{
            write-host "$($line.array) is OK" -ForegroundColor Green
            $passreport += $line
            }
        }                  
                        
    #Add failures to top of table so they show up first
    foreach ($reportline in $failreport)
    {
        $htmltablerow = "<tr>"
        $htmltablerow += "<td>$($reportline.array)</td>"
        #$htmltablerow += "<td>$($reportline.cluster)</td>"
        $htmltablerow += (New-ServerHealthHTMLTableCell "DNS")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Ping")
        
        #if ($($reportline."uptime (hrs)") -eq "Access Denied")
        #{
        #    $htmltablerow += "<td class=""warn"">Access Denied</td>"        
        #}
        #elseif ($($reportline."uptime (hrs)") -eq "Unable to retrieve uptime. ")
        #{
        #    $htmltablerow += "<td class=""warn"">Unable to retrieve uptime. </td>"
        #}
        #else
        #{
        #    $hours = [int]$($reportline."uptime (hrs)")
        #    if ($hours -le 24)
        #    {
        #        $htmltablerow += "<td class=""warn"">$hours</td>"
        #    }
        #    else
        #    {
        #        $htmltablerow += "<td class=""pass"">$hours</td>"
        #    }
        #}

        $htmltablerow += (New-ServerHealthHTMLTableCell "System")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Protection Groups")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Snapshots")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Alerts")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Networks")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Hardware")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Volumes")
        $htmltablerow += "</tr>"
        
        $serverhealthhtmltable = $serverhealthhtmltable + $htmltablerow
    }

     #Add passes to bottom of table so they show up last
    foreach ($reportline in $passreport)
    {
        $htmltablerow = "<tr>"
        $htmltablerow += "<td>$($reportline.array)</td>"
        #$htmltablerow += "<td>$($reportline.cluster)</td>"
        $htmltablerow += (New-ServerHealthHTMLTableCell "DNS")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Ping")
        
        #if ($($reportline."uptime (hrs)") -eq "Access Denied")
        #{
        #    $htmltablerow += "<td class=""warn"">Access Denied</td>"        
        #}
        #elseif ($($reportline."uptime (hrs)") -eq "Unable to retrieve uptime. ")
        #{
        #    $htmltablerow += "<td class=""warn"">Unable to retrieve uptime. </td>"
        #}
        #else
        #{
        #    $hours = [int]$($reportline."uptime (hrs)")
        #    if ($hours -le 24)
        #    {
        #        $htmltablerow += "<td class=""warn"">$hours</td>"
        #    }
        #    else
        #    {
        #        $htmltablerow += "<td class=""pass"">$hours</td>"
        #    }
        #}

        $htmltablerow += (New-ServerHealthHTMLTableCell "System")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Protection Groups")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Snapshots")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Alerts")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Networks")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Hardware")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Volumes")
        $htmltablerow += "</tr>"
        
        $serverhealthhtmltable = $serverhealthhtmltable + $htmltablerow
    }

    $serverhealthhtmltable = $serverhealthhtmltable + "</table></p>"

    $htmltail = "</body>
                </html>"

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
            $servicestatus = $servicestatus.ToUpper()
            #$servicestatus
            if ($servicestatus -eq "FAIL"){
                #write-host $servicestatus - $reportemailsubject - $now
                Send-MailMessage @smtpsettings -To $recipients -Subject "$servicestatus - $reportemailsubject - $reportime" -Body $htmlreport -BodyAsHtml -Encoding ([System.Text.Encoding]::UTF8) -Priority High
                }
            else
                {
                Send-MailMessage @smtpsettings -To $recipients -Subject "$servicestatus - $reportemailsubject - $reportime" -Body $htmlreport -BodyAsHtml -Encoding ([System.Text.Encoding]::UTF8)
                }
        }
    }
}
### End report generation


Write-Host "End"
if ($Log) {Write-Logfile "End"}
Stop-Transcript

