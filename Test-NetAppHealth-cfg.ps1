#...................................
# Variables
#...................................

#Maxima and minima
$MaxMinutesSinceSnapshot = 60                               #Max minutes since last snapshot
$MaxMinutesSnapMirrorLag = 60                               #Max minutes lag for snapmirrors
$MaxHoursToScanLog = 24                                     #Max hours to go back and alert in logs
$VolumeFullPercentageError = 95                             #Percentage full before Error
$VolumeFullPercentageWarning = 85                           #Percentage full before Warning
$VolumeSnapReserveFullPercentageError = 95                  #Percentage full before Error on snap reserve
$AggregateFullPercentageError = 95                          #Percentage full before Error
$AggregateFullPercentageWarning = 85                        #Percentage full before Warning


$logfile = "C:\Source\Scripts\netapp\netapp_health.log"
$ReportURL = "http://hostname\Monitor\netappreporterrors.html"
$reportemailsubject = "NetApp Health Report"

$NetAppControllers = "10.1.1.1","10.2.2.2"

#...................................
# Email Settings
#...................................

#Send email to this address
$recipients = "recipient@domain.net"
#Send email from this address
$fromaddress = "NetApp-Alerts@domain.net"
#Send email using this relay host
$smtpserver = "smtp.domain.net"


#...................................
# Credentials
#...................................

#Login to monitoring user (RO user "monitoring-user" setup on NetApp clusters)
$NetAppCredential = Import-CliXml -Path c:\source\scripts\netapp\monitoring-user.xml
