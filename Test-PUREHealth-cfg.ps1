#...................................
# Variables
#...................................

#Maxima and minima
$MaxMinutesSinceSnapshot = 60                               #Max minutes since last snapshot
$MaxDaysToScanLog = 1                                       #Max days to go back and alert in logs
$VolumeFullPercentageError = 95                             #Percentage full before Error
$VolumeFullPercentageWarning = 85                           #Percentage full before Warning
$logfile = "C:\Source\Scripts\PURE\PURE_health.log"
$reportemailsubject = "PURE Health Report"
$ReportURL = "http://hostname\Monitor\PUREHealth_errors.html" #Enter the name of the server where ae are saving the errors (probably the server where this script is running)

#...................................
# PURE controllers
$PUREControllers = "10.1.1.1","10.2.2.2."
#...................................

#...................................
# Email Settings
#...................................

#Send email to this address
$recipients = "recipient@domain.net"
#Send email from this address
$fromaddress = "PURE-Alerts@domain.net"
#Send email using this relay host
$smtpserver = "smtp.domain.net"


#...................................
#Credentials
#....................................

#Login to monitoring user (RO user setup on PURE clusters)
$PURECredential = Import-CliXml -Path c:\source\scripts\PURE\pureuser.xml

