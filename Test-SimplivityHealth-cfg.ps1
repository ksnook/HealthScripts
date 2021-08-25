#...................................
# Variables
#...................................

$MaxDaysSinceBackup = 1                                     #Max days since last full backup
$MaxHoursToScanLog = 24                                     #Max hours to go back and alert in logs
$logfile = "C:\Source\Scripts\simplivity\Simplivity_health.log"
$VCServer = "x.domain.net"
$reportemailsubject = "Simplivity Health Report"


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

#...................................
# Credentials
#...................................
#SSO Login for vCenter
$Credential = Import-CliXml -Path c:\source\scripts\admin@sso_nhc0.xml
#ILO Login
$ILOCredential = Import-CliXml -Path c:\source\scripts\hpeilo.xml
#VCenter credentials
$VCCredential = Import-CliXml -Path c:\source\scripts\ks_cred.xml


