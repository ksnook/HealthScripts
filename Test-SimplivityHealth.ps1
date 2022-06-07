<#
.SYNOPSIS
Test-SimplivityHealth.ps1 - Simplivity Health Check Script.

.DESCRIPTION 
Performs a series of health checks on Simplivity hosts and outputs the results to screen, and optionally to log file, HTML report,
and HTML email.

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
.\Test-SimplivityHealth.ps1
Checks all servers in the organization and outputs the results to the shell window.

.EXAMPLE
.\Test-SimplivityHealth.ps1 
Checks all servers in the federation, and outputs the results to the shell window, HTML report and email.

.EXAMPLE
.\Test-SimplivityHealth.ps1 -ReportMode -SendEmail
Checks all servers in the federation, outputs the results to the shell window, a HTML report, and
emails the HTML report to the address configured in the script.

.LINK


.NOTES
Written by: Kevin Snook (some portions Paul Cunningham)

.OVERVIEW
The script runs through a number of checks on Simplivity servers in a federation and reports them on a Pass/Fail basis.
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
        
        #[Parameter( Mandatory=$false)]
        #[string]$ReportFile="c:\source\scripts\simplivity\simplivityhealth.html",
        #[string]$ReportFile="C:\inetpub\wwwroot\monitor\simplivityhealth.html",

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

Function Compare_VM_Lists
{
param (
    $VCList
)
foreach ($VCServer in $VCList){
    $Connection = Connect-VIServer $VCServer -Credential $VCCredential
    #$VCClusters = Get-Cluster | sort | Get-Unique | where {$VCCluster.Name -eq $SimplivityHost.ClusterName}
    $VCClusters = Get-Cluster $SimplivityHost.ClusterName
    foreach ($VCCluster in $VCClusters){
        if ($VCCluster -match "ROBO"){
            #write-host "Checking $($VCCluster.Name)"
            #Get the VMs in this Simplivity cluster
            try{$RawSimpClusterVMs = Get-SVTvm -ClusterName $VCCluster.Name | select -expand VMname | sort}
            catch{Write-Output "Ran into an issue: $($PSItem.ToString())"}
            #write-host "Simp VMs" -ForegroundColor Yellow
            #write-host $RawSimpClusterVMs
            #Get the VMs in this VMware cluster
            #try{$RawVCClusterVMs = Get-Cluster $VCCluster.Name | get-vm | where {(Get-Datastore -VM $_) -match "SERVERS"} | select -expand Name}
            #write-host $SimplivityDatastores.DataStoreName
            try{$RawVCClusterVMs = Get-Cluster $VCCluster.Name | get-vm | where {(Get-Datastore -VM $_) -in $SimplivityDatastores.DataStoreName} | select -expand Name | sort}
            catch{Write-Output "Ran into an issue: $($PSItem.ToString())"}
            #write-host "VC VMs" -ForegroundColor Yellow
            #write-host $RawVCClusterVMs
            #Records VMs in VC but not on Simplivity
            $MissingVMs = $RawVCClusterVMs | where{$RawSimpClusterVMs -notcontains $_} | where{$_ -notmatch "OmniStackVC"}
            if ($MissingVMs){
                $ErrorList += "$($VCCluster.Name) has the following VMs on vCenter but not showing in Simplivity:`n`r $($MissingVMs)`n`r"
                }
            }
        }       
    }
return $ErrorList
}

Function Find_NonHA_VMs
{
param (
    $HostList
)
foreach ($OVCHost in $HostList){
    #write-host "Checking $($OVCHost.HostName)"
    #Get the VMs on this Simplivity host
    #try{$RawSimpHostVMs = Get-SVTvm -HostName $OVCHost.HostName | where {$_.State -ne "ALIVE" -or $_.HAstatus -ne "SAFE"} | select vmName,State,HAstatus}
    try{$RawSimpHostVMs = Get-SVTvm -HostName $OVCHost.HostName | where {$_.State -ne "ALIVE" -or $_.HAstatus -ne "SAFE"} | select vmName,HAstatus}
    catch{Write-Output "Ran into an issue: $($PSItem.ToString())"}
    #write-host $RawSimpHostVMs.VmName
    if ($RawSimpHostVMs -ne $null){
        #write-host $RawSimpHostVMs
        #write-host $RawSimpHostVMs.Values.ForEach('ToString')
        $ErrorList += "The following VMs are not HA-compliant on host $($OVCHost.HostName) :`n $($RawSimpHostVMs.VmName)"
        }
    }
return $ErrorList
}

Function Check_VMHost_Running_Services
{
param (
    $VMHostList
)
foreach ($VMHost in $VMHostList){
    $RUNNINGSERVICES = get-vmhostservice -VMHost $VMHost | where{($_.Running)}
    if ($RUNNINGSERVICES.Key -notcontains "vpxa"){
        "vpxa service not running"
        }
    
    }
}

Function Get_SVT_Backup_Health
{
param (
    $VMList
)
$TimeInPast = ((Get-Date).AddDays(-$MaxDaysSinceBackup)).ToString("dd/MM/yyyy")
if ($VMList) {
    foreach ($VM in $VMList){
        $FAILED = $null
        try{$FAILED=Get-SVTbackup -Vmname $VM -BackupState FAILED -CreatedAfter $TimeInPast}
        catch{if ($Log) {Write-Logfile "$($VM) Did not return any FAILED backups: $($PSItem.ToString())"}}
        if($FAILED){
            write-host "$($FAILED.CreateDate.Count) FAILED backup(s) for $($VM) within last $($MaxDaysSinceBackup) day(s)"
            "$($FAILED.CreateDate.Count) FAILED backup(s) for $($VM) within last $($MaxDaysSinceBackup) day(s)"
            }
        }
    }
    
}



Function Get_ILO_Health ($HostList,$ShowNoVMs)
{

#"In ILO health function" | out-host
foreach ($OVCHost in $HostList){
    #Let's find the ILO
    $STATUS = $null
    $OVCHostILO = $OVCHost.Replace("inf","ilo")
    $OVCHostILOIP=$(resolve-dnsname -Name $OVCHostILO).IP4Address
    #write-host $OVCHostILOIP
    #exit
    $ILOConnect=$null
    if ($OVCHostILOIP){
        try{$ILOConnect=Connect-HPEiLO -IP $OVCHostILOIP -Credential $ILOCredential -DisableCertificateAuthentication}
        catch{Write-Output "$($OVCHostILOIP) Ran into an issue: $($PSItem.ToString())"}
        }
    if ($ILOConnect){
    ################################ SERVER INFO CHECKS START ################################
        
        #"Server info"
        $getServerInfo = Get-HPEiLOServerInfo -Connection $ILOConnect 
        
        #$getServerInfo.HealthSummaryInfo
        foreach($FanInfo in $getServerInfo.FanInfo){
            if ($FanInfo.State -ne "OK"){
                $STATUS="RED"
                $ERRORTEXT += "`n`r$($OVCHost) $($FanInfo.Name) is $($FanInfo.State)"
                }
            }
        foreach($TemperatureInfo in $getServerInfo.TemperatureInfo){
            if (($TemperatureInfo.State -notlike "Absent") -And ($TemperatureInfo.State -notlike "OK")){
                $STATUS="RED"
                $ERRORTEXT += "`n`r$($OVCHost) $($TemperatureInfo.Name) is $($TemperatureInfo.State)"  
                }
            }
        #foreach($FirmwareInfo in $getServerInfo.FirmwareInfo){
            #$FirmwareInfo
            #write-host "$($FirmwareInfo.FirmwareName) at $($FirmwareInfo.Location) is version $($FirmwareInfo.FirmwareVersion)"
        #    }
        #foreach($ProcessorInfo in $getServerInfo.ProcessorInfo){
        #    #$ProcessorInfo
        #    if ($ProcessorInfo.Model){
        #        #write-host "$($ProcessorInfo.Socket) is occupied with processor model $($ProcessorInfo.Model) with $($ProcessorInfo.TotalCores) cores"
        #        }
        #    else{
        #        #write-host "$($ProcessorInfo.Socket) is empty"
        #        }
        #    }
        #if ($getServerInfo.PowerSupplyInfo.PowerSupplySummary.PowerSystemRedundancy -ne "Redundant"){
        #    #write-host "Power supplies are not redundant" -ForegroundColor Red
        #    $STATUS="RED"
        #    $ERRORTEXT += "`n`r$($OVCHost) Power supplies are not redundant" 
        #    if ($Log) {Write-Logfile "$($SimplivityHost.HostName) -  Power supplies are not redundant - $($getServerInfo.PowerSupplyInfo.PowerSupplySummary.PowerSystemRedundancy)"}
        #    }
        ################################ SERVER INFO CHECKS END ################################
        
        ################################ ILO HEALTH CHECKS START ################################
        $HealthReport = Get-HPEiLOHealthSummary -Connection $ILOConnect
        #$HealthReport
        #write-host $HealthReport
        foreach($HealthLine in $HealthReport|get-member){
            #write-host $Healthline
            if ($HealthLine.MemberType -eq “Property” -and $HealthLine.Name -notlike “__*” -and $HealthLine.Name -notlike “IP" -and $HealthLine.Name -notlike “Hostname" -and $($HealthReport.$($HealthLine.Name))){
                switch -regex ($($HealthReport.$($HealthLine.Name)))
                    {
                    "OK" {write-host "$($HealthLine.Name) is $($HealthReport.$($HealthLine.Name))" -ForegroundColor Green}
                    "Redundant" {write-host "$($HealthLine.Name) is $($HealthReport.$($HealthLine.Name))" -ForegroundColor Green}
                    "No" {write-host "$($HealthLine.Name) is $($HealthReport.$($HealthLine.Name))" -ForegroundColor Green}
                    "Ready" {write-host "$($HealthLine.Name) is $($HealthReport.$($HealthLine.Name))" -ForegroundColor Green}
                    default {write-warning "$($HealthLine.Name) is $($HealthReport.$($HealthLine.Name))";$STATUS="RED";$ERRORTEXT += "`n`r$($OVCHost.HostName) $($HealthLine.Name) is $($HealthReport.$($HealthLine.Name))"}
                    }
                }
            }
        ################################ ILO HEALTH CHECKS END ################################
        
        
        
        ################################ VM CHECKS START ################################
        #"VM checks"
        $VMList = $null
        try{$VMList = Get-SVTvm -hostname $OVCHost} #| select VMname
        catch{Write-Output "Ran into an issue: $($PSItem.ToString())"}
        if ($ShowNoVMs) {
            if (!($VMList)){
                $STATUS="RED"
                $ERRORTEXT += "`n`r$($OVCHost) has no VMs"
                }
            }
        ################################ VM CHECKS START ################################
        
        ################################ ILO IML CHECKS START ################################
        $result = Get-HPEiLOIML -Connection $ILOConnect 
        $TimeInPast = (Get-Date).AddDays(-1)
        foreach($output in $result){
            $sevs = $(foreach ($event in $output.IMLLog) {$event.Severity})
            #$output.IMLLog
            $uniqsev = $($sevs | Sort-Object | Get-Unique)
            $sevcnts = $output.IMLLog | group-object -property Severity –noelement
            $message = $(foreach ($event in $output.IMLLog) {if($event.Severity -eq "Critical" -and $(Get-Date($event.Created)) -gt $TimeInPast) {$($event.Created) + $($event.Message)}})
            $uniqmessage = $($message | Sort-Object | Get-Unique)
            if($uniqmessage -ne $null){
                $allMessage = [string]::Join("`n",$uniqmessage)
                #Write-Host "The critical entry descriptions are: `n$allMessage" -ForegroundColor Red
                $STATUS="RED"
                $ERRORTEXT += "`n`r$($OVCHost) The critical IML entry descriptions are: `n$allMessage"
                #exit
                }
        ################################ ILO IML CHECKS END ################################
        
        ################################ ILO EVENT LOG CHECKS START ################################
        $result=$null
        $result = Get-HPEiLOEventLog -Connection $ILOConnect
        foreach($output in $result){
            $sevs = $(foreach ($event in $output.EventLog) {$event.Severity})
            $uniqsev = $($sevs | Sort-Object | Get-Unique)
            $sevcnts = $output.EventLog | group-object -property Severity –noelement
            $message = $(foreach ($event in $output.IMLLog) {if($event.Severity -eq "Critical" -and $(Get-Date($event.Created)) -gt $TimeInPast) {$($event.Created) + $($event.Message)}})
            $uniqmessage = $($message | Sort-Object | Get-Unique)
            if($uniqmessage -ne $null){
                $allMessage = [string]::Join("`n",$uniqmessage)
                $STATUS="RED"
                $ERRORTEXT += "`n`r$($OVCHost) The critical Event entry descriptions are: `n$allMessage"
                }
          
            }
        
        ################################ ILO EVENT LOG CHECKS END ################################
        
        }
        if ($ILOConnect){
            Disconnect-HPEiLO -Connection $ILOConnect
            }
        }
    else{
        #write-host "Could not connect to $($OVCHostILO)" -ForegroundColor red 
        $STATUS="RED"
        $ERRORTEXT += "`n`r$($OVCHost) Could not connect to $($OVCHostILO)"
        }
    
    if ($STATUS -ne $null){
        write-host "$($OVCHost) has status $($STATUS)" -ForegroundColor red 
        }
    
    }

return $ERRORTEXT
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
    #write-host $alarm.Entity
    $alarm.Status = $triggeredalarm.OverallStatus
  	$alarm.Time = $triggeredalarm.Time
    if ($alarm.Status -eq "red"){
        #write-host "$($alarm.Entity) has a critical alert ($($alarm.Alarm)) timed at $($alarm.Time)"
        if ($alarm.Entity -notcontains "OmniStackVC" -and $alarm.Alarm -notcontains "Virtual machine memory usage"){
            "`n`r$($alarm.Entity) has a critical alert ($($alarm.Alarm)) timed at $($alarm.Time)"
            #exit
            }
        }
    }
}



#...................................
# Script
#...................................

#Find run directory 
$runDir = Split-Path -Parent $MyInvocation.MyCommand.Path
#$reportemailsubject = "Simplivity Health Report"
$ignorelistfile = "$($runDir)\ignorelist.txt"

################################ Start a transcript log ####################################################

Start-Transcript -Path "$($runDir)\Simplivity_health_transcript.log"

################################ Initialise some variables #################################################



# dot source the External variables PowerShell File

if (Test-Path "$($runDir)\Test-SImplivityHealth-cfg.ps1"){
    . "$($runDir)\Test-SimplivityHealth-cfg.ps1"
    }
else{
    write-host "Cannot find config file - please create $($runDir)\Test-SimplivityHealth-cfg.ps1" -ForegroundColor Red
    exit
    }

#...................................
# Variables
#...................................

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
[array]$failreport = @()
[array]$passreport = @()
[bool]$alerts = $false
$servicestatus = "Pass"
$diskstatus = "Pass"
#$myDir = Split-Path -Parent $MyInvocation.MyCommand.Path
#$reportemailsubject = "Simplivity Health Report"
#$ignorelistfile = "$myDir\ignorelist.txt"
#$logfile = "C:\Source\Scripts\simplivity\Simplivity_health.log"
#$VCServer = "NHC0-INF-VCM001.eu.cobham.net"
$VCServerList = $global:DefaultVIServers
$ERRORS=$null
$OVC="Not Connected"
$SimplivityHosts=$null
$OutputFolder = [System.IO.Path]::GetDirectoryName($ReportFile)


#...................................
# Email Settings
#...................................

#$recipients = @("kevin.snook@cobham.com")
#$smtpsettings = @{
    #To =  "kevin.snook@cobham.com"
    #To =  "ERoW-IT-Datacentre-Callout-Team@cobham.com"
#    From = "HoldCO-SIMP-Alerts@cobham.com"
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

if (Test-Path "$($OutputFolder)\Simplivity_Error_Status_Fail.txt"){
    del "$($OutputFolder)\Simplivity_Error_Status_Fail.txt"
    }

#Log file is overwritten each time the script is run to avoid
#very large log files from growing over time
if ($Log) {
    $timestamp = Get-Date -DisplayHint Time
    "$($timestamp) =====================================" | Out-File $logfile
    Write-Logfile " Simplivity Server Health Check"
    Write-Logfile "  $now"
    Write-Logfile "====================================="
}

Write-Host "Initializing..."
if ($Log) {Write-Logfile "Initializing..."}

#...................................
# Credentials
#...................................
#SSO Login for vCenter
#$Credential = Import-CliXml -Path c:\source\scripts\admin@sso_nhc0.xml
#ILO Login
#$ILOCredential = Import-CliXml -Path c:\source\scripts\hpeilo.xml
#VCenter credentials
#$VCCredential = Import-CliXml -Path c:\source\scripts\ks_cred.xml



#...................................
# vCenter connection
$Connection = Connect-VIServer $VCServer -Credential $VCCredential -AllLinked


# Grab OVC details
$OVCIPs=Get-VM -Name OmniStackVC* | select @{N="IPAddress";E={@($_.guest.IPAddress[0])}} | sort IPAddress -unique


#...................................

################################ Search for a connection to an Omnistack ####################################

while($OVC -eq "Not Connected"){
    foreach($OVCIP in $OVCIPs){
        write-host "Trying $($OVCIP.IPAddress)"
        try{$OVC=Connect-SVT -OVC $($OVCIP.IPAddress) -Credential $Credential}
        catch{Write-Output "Ran into an issue: $($PSItem.ToString())"; $ERRORS += "`n`rCould not connect to $($OVCIP.IPAddress) $($PSItem.ToString())";continue}
        if ($OVC){write-host "Connected";break}
        }
} 



#...................................
#Grab Simplivity Hosts and Datastores
$SimplivityHosts = Get-SVThost | sort-object -Property HostName
$SimplivityDatastores = @(Get-SVTdatastore)

#...................................

foreach($SimplivityHost in $SimplivityHosts){ 
    if ($SimplivityHost.HostName -notin $IgnoreHosts){
        Write-Host "Processing $($SimplivityHost.HostName)" -ForegroundColor Blue 
        #$SimplivityHost | fl
        #exit
        #Custom object properties
        $serverObj = New-Object PSObject
        $serverObj | Add-Member NoteProperty -Name "Host" -Value $SimplivityHost.HostName
        $serverObj | Add-Member NoteProperty -Name "Cluster" -Value $SimplivityHost.ClusterName
                
        #Null and n/a the rest, will be populated as script progresses
        $serverObj | Add-Member NoteProperty -Name "DNS" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Ping" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Uptime (hrs)" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Backups" -Value $null
        $serverObj | Add-Member NoteProperty -Name "VMs Match" -Value $null
        $serverObj | Add-Member NoteProperty -Name "HA" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Host Alarms" -Value $null
        $serverObj | Add-Member NoteProperty -Name "OVC Alarms" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Services" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Network" -Value "n/a"
        $serverObj | Add-Member NoteProperty -Name "Hardware" -Value "n/a"
        $serverObj | Add-Member NoteProperty -Name "Disk Space" -Value "n/a"
    

        #DNS Check
        Write-Host "DNS Check: " -NoNewline;
        try {$ip = @([System.Net.Dns]::GetHostByName($SimplivityHost.HostName).AddressList | Select-Object IPAddressToString -ExpandProperty IPAddressToString)}
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
            try {$ping = Test-Connection $SimplivityHost.HostName -Quiet -ErrorAction Stop}
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
                    $serversummary += "$($SimplivityHost.HostName) - Ping Failed"
                    }
                }
            }
        
        #Uptime Check
        Write-Host "Uptime (hrs): " -NoNewline
        [int]$uptimehours = $null
        $vmhost = get-VMhost $SimplivityHost.HostName
        #write-host $vmhost.ExtensionData.Summary.Runtime.BootTime
        #[math]::round($a.Length / 1MB, 2)
        $uptimehours = [math]::round((New-TimeSpan -Start ($vmhost.ExtensionData.Summary.Runtime.BootTime.touniversaltime()) -End (Get-Date -Format U)).TotalHours,0) #| Select-Object -ExpandProperty Days
        #Write-Host $uptimehours
        #[int]$uptime = "{0:00}" -f $timespan.TotalHours
        if ($uptimehours -lt $MinimumUptime){
           Write-Host -ForegroundColor $warn "Uptime is less than $($MinimumUptime) hours ($($uptimehours))"
           $serversummary += "$($SimplivityHost.HostName) - Uptime is less than $($MinimumUptime) hours ($($uptimehours))"
           }
        else{
            Write-Host -ForegroundColor $pass "Uptime is more than $($MinimumUptime) hours ($($uptimehours))"
            }
        #Switch ($uptimehours -lt $MinimumUptime) {
        #    $true { Write-Host -ForegroundColor $pass $uptimehours}
        #    $false { Write-Host -ForegroundColor $warn $uptimehours; $serversummary += "$($SimplivityHost.HostName) - Uptime is less than $($MinimumUptime) hours ($uptimehours)"}
        #    default { Write-Host -ForegroundColor $warn $uptimehours; $serversummary += "$($SimplivityHost.HostName) - Uptime is less than $($MinimumUptime) hours ($uptimehours)"}
        #    }

        $serverObj | Add-Member NoteProperty -Name "Uptime (hrs)" -Value $uptimehours -Force 

        #Backup Check (make this host specific)
        Write-Host "SVT Backups: " -NoNewline
        $VMList = (Get-SVTvm -HostName $SimplivityHost.HostName  | where{$_ -notmatch "OmniStackVC"} | Select -ExpandProperty VMname) 
        $ERRORS = $null
        $ERRORS += Get_SVT_Backup_Health $VMList
        Switch (!$ERRORS) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Backups" -Value "Pass" -Force }
            $false { Write-Host -ForegroundColor $fail "Fail"; $serversummary += "$($SimplivityHost.HostName) - Simplivity Backup Error(s) $($ERRORS)";$serverObj | Add-Member NoteProperty -Name "Backups" -Value "Fail" -Force }
            default { Write-Host -ForegroundColor $fail "Default"; $serversummary += "$($SimplivityHost.HostName) - Simplivity Backup Error(s) $($ERRORS)";$serverObj | Add-Member NoteProperty -Name "Backups" -Value "Fail" -Force}
            }
    
        #VM Match Check
        Write-Host "VM Match Check: " -NoNewline
        $ERRORS = $null
        $ERRORS += Compare_VM_Lists $VCServer
        Switch (!$ERRORS) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "VMs Match" -Value "Pass" -Force}
            default { Write-Host -ForegroundColor $fail $ERRORS; $serversummary += "$($SimplivityHost.HostName) - Simplivity VM Mismatch(s) $($ERRORS)";$serverObj | Add-Member NoteProperty -Name "VMs Match" -Value "Fail" -Force}
            }
    
    
        #HA VM Check
        Write-Host "VM HA Check: " -NoNewline
        $ERRORS = $null
        $ERRORS += Find_NonHA_VMs $SimplivityHost
        Switch (!$ERRORS) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "HA" -Value "Pass" -Force}
            default { Write-Host -ForegroundColor $fail $ERRORS; $serversummary += "$($SimplivityHost.HostName) - Simplivity VM HA $($ERRORS)";$serverObj | Add-Member NoteProperty -Name "HA" -Value "Fail" -Force}
            }
   
    
        #VC Alarms
        Write-Host "Host Alarms: " -NoNewline
        $ERRORS = $null
        #$VMList = Get-SVTvm -HostName $SimplivityHost.HostName | select VmName
        #$HostList = $SimplivityHost.HostName + $VMList.VMName
        #write-host $HostList
        $ERRORS += get-VCAlarms $SimplivityHost.HostName
        #$ERRORS += get-VCAlarms $HostList
        Switch (!$ERRORS) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Host Alarms" -Value "Pass" -Force}
            default { Write-Host -ForegroundColor $fail $ERRORS; $serversummary += "$($SimplivityHost.HostName) - Simplivity Host Alarm(s) $($ERRORS)";$serverObj | Add-Member NoteProperty -Name "Host Alarms" -Value "Fail" -Force}
            }
        Write-Host "OVC Alarms: " -NoNewline
        $ERRORS = $null
        $ERRORS += get-VCAlarms $SimplivityHost.VirtualControllerName
        $ERRORS | fl
        Switch (!$ERRORS) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "OVC Alarms" -Value "Pass" -Force}
            default { Write-Host -ForegroundColor $fail $ERRORS; $serversummary += "$($SimplivityHost.VirtualControllerName) - Simplivity OVC Alarm(s) $($ERRORS)";$serverObj | Add-Member NoteProperty -Name "OVC Alarms" -Value "Fail" -Force}
            }
    
        #Host Services
        Write-Host "Host Services: " -NoNewline
        $ERRORS = $null
        $ERRORS +=  Check_VMHost_Running_Services $SimplivityHost.HostName
        Switch (!$ERRORS) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Services" -Value "Pass" -Force}
            default { Write-Host -ForegroundColor $fail $ERRORS; $serversummary += "$($SimplivityHost.HostName) - Simplivity Service(s) $($ERRORS)";$serverObj | Add-Member NoteProperty -Name "Services" -Value "Fail" -Force}
            }

        #Network
        Write-Host "Network: " -NoNewline
        $NetworkOK = $true
        #Ping the OVC
        $ip =(Get-VM -Name $SimplivityHost.VirtualControllerName | select @{N="IPAddress";E={@($_.guest.IPAddress[0])}}).IPAddress
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
            $serversummary += "$($SimplivityHost.HostName) -  OVC interface at address $($ip) is not pingable;"
            if ($Log) {Write-Logfile "$($SimplivityHost.HostName) -  OVC interface at address $($ip) is not pingable"}
            write-host "$($SimplivityHost.HostName) -  OVC interface at address $($ip) is not pingable"
            }
        else{
            if ($Log) {Write-Logfile "$($SimplivityHost.HostName) -  OVC interface at address $($ip) is pingable"}
            write-host "$($SimplivityHost.HostName) -  OVC interface at address $($ip) is pingable"
            }
    
    
        Switch ($NetworkOK) {
                $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Network" -Value "Pass" -Force}
                $false { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Network" -Value "Fail" -Force}
                default { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Network" -Value "Fail" -Force}
                }




    
        #ILO Health
        Write-Host "Host Hardware: " -NoNewline
        $ERRORS = $null
        if ($SimplivityHost.HostName -in $IgnoreHardwareErrors){
            if ($Log) {Write-Logfile "Host in $($IgnoreHardwareErrors) array - Not checking for hardware errors on $($SimplivityHost.HostName)"}
            $ERRORS = $null
            Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Pass" -Force
            } 
        else{
            #This function when servers are new and you want to see hosts with no VMs 
            #$ERRORS += Get_ILO_Health $SimplivityHost.HostName $True
            #This function when servers are established and you don't want to see hosts with no VMs 
            $ERRORS += Get_ILO_Health $SimplivityHost.HostName $False
            $ERRORS
            Switch (!$ERRORS) {
                $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Pass" -Force}
                default { Write-Host -ForegroundColor $fail $ERRORS; $serversummary += "$($SimplivityHost.HostName) - Simplivity Hardware $($ERRORS)";$serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Fail" -Force}
                }
            }
        #Disk Space
        Write-Host "Disk Space: " -NoNewline
        $ERRORS = $null
        $ERRORS += Get_DiskSpace $SimplivityHost $False
        $ERRORS
        Switch (!$ERRORS) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Disk Space" -Value "Pass" -Force}
            default { Write-Host -ForegroundColor $fail $ERRORS; $serversummary += "$($SimplivityHost.HostName) - Simplivity Disk Space $($ERRORS)";$serverObj | Add-Member NoteProperty -Name "Disk Space" -Value "Fail" -Force}
            }
    

    
        #Add this servers output to the $report array
        $report = $report + $serverObj
    
        }         

    else{
        Write-Host "Ignoring $($SimplivityHost.HostName)" -ForegroundColor Blue
        } 
    }
### Begin report generation
if ($ReportMode -or $SendEmail)
{
    #Get report generation timestamp
    $reportime = (Get-Date).ToString("dd/MM/yyyy HH:mm")
    if ($IgnoreHosts){
        $ignoretext = "Configured to ignore hosts: $($IgnoreHosts)."
        }
    if ($IgnoreHardwareErrors){
        $ignoretext = $ignoretext + "Configured to ignore hardware errors on : $($IgnoreHardwareErrors)."
        }
    #Create HTML Report
    

    
                
    #Check if the server summary has 1 or more entries
    if ($($serversummary.count) -gt 0)
    {
        #Set alert flag to true
        $alerts = $true
        # Create the error status file (if not already there)
        Out-File -FilePath "$($OutputFolder)\Simplivity_Error_Status_Fail.txt"
        
        #Generate the HTML
        #$coloredheader = "<h1 style=`"color: $fail;`" align=`"center`">Simplivity Health</h1>"
        $coloredheader = "<h1 align=""center""><a href=$ReportURL  class=""blink"" style=""color:$fail"" target=""_blank"">$reportsubject</a></h1>"
        $serversummaryhtml = "<h3>Simplivity Health Details</h3>
                        <p>$ignoretext</p>
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
        #$coloredheader = "<h1 style=`"color: $pass;`" align=`"center`">Simplivity Health</h1>"
        $coloredheader = "<h1 align=""center""><a href=$ReportURL style=""color:$pass"" target=""_blank"">$reportsubject</a></h1>"
        $serversummaryhtml = "<h3>Simplivity Health Details</h3>
                        <p>$ignoretext</p>
                        <p>No Simplivity  health errors or warnings.</p>"
    }
    
    #Common HTML head and styles
    $htmlhead="<html>
                <head>
                <title>Simplivity GreenScreen - $servicestatus</title>
                <meta http-Equiv=""Cache-Control"" Content=""no-cache"">
                <meta http-Equiv=""Pragma"" Content=""no-cache"">
                <meta http-Equiv=""Expires"" Content=""0"">
                </head>
                <style>
                BODY{font-family: Tahoma; font-size: 8pt;}
                H1{font-size: 16px;}
                H2{font-size: 14px;}
                H3{font-size: 12px;}
                TABLE{Margin: 0px 0px 0px 4px;width: 100%;Border: 1px solid rgb(190, 190, 190);Font-Family: Tahoma;Font-Size: 8pt;Background-Color: rgb(252, 252, 252);}
                tr:hover td{Background-Color: rgb(0, 127, 195);Color: rgb(255, 255, 255);}
                tr:nth-child(even){Background-Color: rgb(110, 122, 130);}
                th{Text-Align: Left;Color: rgb(150, 150, 220);Padding: 1px 4px 1px 4px;}
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
                $coloredheader
                <h3 align=""center"">Generated: $reportime</h3>"

        
    #Simplivity Health Report Table Header
    $htmltableheader = "<h3>Simplivity Health Summary</h3>
                        <p>
                        <table>
                        <tr>
                        <th>Host</th>
                        <th>Cluster</th>
                        <th>DNS</th>
                        <th>Ping</th>
                        <th>Uptime</th>
                        <th>Backups</th>
                        <th>VMs Match</th>
                        <th>HA</th>
                        <th>Host Alarms</th>
                        <th>OVC Alarms</th>
                        <th>Services</th>
                        <th>Network</th>
                        <th>Hardware</th>
                        <th>Disk Space</th>
                        </tr>"

    #Simplivity Health Report Table
    
    $serverhealthhtmltable = $null
    $serverhealthhtmltable = $serverhealthhtmltable + $htmltableheader                    
                        
    foreach ($line in $report){
        #Pop reportlines into separate arrays based on whether they have errors or not
        #write-host "report line is"
        #write-host $line
        if (($line -match "Fail") -or ($line -match "Warn") -or ($line."uptime (hrs)" -lt $MinimumUptime) ){
            write-host "$($line.host) has failures/warnings" -ForegroundColor Red
            $failreport += $line
            }
        else{
            write-host "$($line.host) is OK" -ForegroundColor Green
            $passreport += $line
            }
        }
    
    #Add failures to top of table so they show up first
    foreach ($reportline in $failreport)
    {
        $htmltablerow = "<tr>"
        $htmltablerow += "<td>$($reportline.host)</td>"
        $htmltablerow += "<td>$($reportline.cluster)</td>"
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
            if ($hours -lt $MinimumUptime)
            {
                $htmltablerow += "<td class=""warn"">$hours</td>"
            }
            else
            {
                $htmltablerow += "<td class=""pass"">$hours</td>"
            }
        }

        $htmltablerow += (New-ServerHealthHTMLTableCell "Backups")
        $htmltablerow += (New-ServerHealthHTMLTableCell "VMs Match")
        $htmltablerow += (New-ServerHealthHTMLTableCell "HA")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Host Alarms")
        $htmltablerow += (New-ServerHealthHTMLTableCell "OVC Alarms")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Services")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Network")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Hardware")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Disk Space")
        $htmltablerow += "</tr>"
        
        $serverhealthhtmltable = $serverhealthhtmltable + $htmltablerow
    }

    #Add passes after so they show up last
    foreach ($reportline in $passreport)
    {
        $htmltablerow = "<tr>"
        $htmltablerow += "<td>$($reportline.host)</td>"
        $htmltablerow += "<td>$($reportline.cluster)</td>"
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
            if ($hours -lt $MinimumUptime)
            {
                $htmltablerow += "<td class=""warn"">$hours</td>"
            }
            else
            {
                $htmltablerow += "<td class=""pass"">$hours</td>"
            }
        }

        $htmltablerow += (New-ServerHealthHTMLTableCell "Backups")
        $htmltablerow += (New-ServerHealthHTMLTableCell "VMs Match")
        $htmltablerow += (New-ServerHealthHTMLTableCell "HA")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Host Alarms")
        $htmltablerow += (New-ServerHealthHTMLTableCell "OVC Alarms")
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
                Send-MailMessage @smtpsettings -To $recipients -Subject "$servicestatus - $reportsubject - $reportime" -Body $htmlreport -BodyAsHtml -Encoding ([System.Text.Encoding]::UTF8) -Priority High
                
                }
            else
                {
                #Send-MailMessage @smtpsettings -Subject "$servicestatus - $reportemailsubject - $now" -Body $htmlreport -BodyAsHtml -Encoding ([System.Text.Encoding]::UTF8) 
                Send-MailMessage @smtpsettings -To $recipients -Subject "$servicestatus - $reportsubject - $reportime" -Body $htmlreport -BodyAsHtml -Encoding ([System.Text.Encoding]::UTF8)
                }
        }
    }
}
### End report generation


Write-Host "End"
if ($Log) {Write-Logfile "End"}
Stop-Transcript

