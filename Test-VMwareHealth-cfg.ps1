#...................................
# Variables
#...................................

#Max days since last full backup
$MaxDaysSinceBackup = 1                                     	
#Max hours to go back and alert in logs
$MaxHoursToScanLog = 24                                     	
#Location of log file
$logfile = "C:\Source\Scripts\VMware\VMware_health.log"
#Vcenter server to monitor
$VCServer = "vcserver.domain.net"
#Number of days back before we alert about a cert being about to expire
$CertificateTimeToAlert = 30        				
#Set to true to alert on powered off VMs
$CheckPowerOffVMs = $false
#Minimum Percentage free on datastores before raising alert
$datastorePercentFree = 10
#Maximum Percentage full on Host/vCenter partitions before raising alert
$PartitionPercentFull = 90
#Comma separated array of VM alarms to ignore
$IgnoreVMAlarms = @("Virtual machine memory usage","rubbish")
#Comma separated array of Host alarms to ignore
$IgnoreHostAlarms = @("Virtual machine memory usage","rubbish")
#Path to PuttyLink executable
$PuttyLinkPath = "C:\PROGRA~1\PUTTY\plink.exe"
$reportemailsubject = "VMware Health Report"

#...................................
# Email Settings
#...................................

#Send email to this address
$recipients = "recipient@domain.net"
#Send email from this address
$fromaddress = "SIMP-Alerts@domain.net"
#Send email using this relay host
$smtpserver = "smtp.domain.net"


#...................................
#Credentials
#....................................

#VMware SSO Credential 
$Credential = Import-CliXml -Path c:\source\scripts\admin@sso_nhc0.xml
#HPe ILO Credential
$ILOCredential = Import-CliXml -Path c:\source\scripts\hpeilo.xml
#vCenter Credential
$VCCredential = Import-CliXml -Path c:\source\scripts\ks_cred.xml
#Root credential on ESXi Hosts
#$ESXiCredential = Import-CliXml -Path c:\source\scripts\root_cred.xml
#Monitoring credential on ESXi Hosts
$ESXiMonitorCredential = Import-CliXml -Path c:\source\scripts\monitoring-user_cred.xml
#Root credential on vCenter
$VCRootCredential = Import-CliXml -Path c:\source\scripts\vc_root_cred.xml

