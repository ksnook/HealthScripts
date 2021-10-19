<#
.SYNOPSIS
Test-NetAppHealth.ps1 - NetApp Health Check Script.

.DESCRIPTION 
Performs a series of health checks on NetApp arrays and outputs the results to screen, and optionally to log file, HTML report,
and HTML email.

Use the ignorelist.txt file to specify any arrays you want the script to ignore (eg permamnenetly broken arrays).

.OUTPUTS
Results are output to screen, as well as optional log file, HTML report, and HTML email

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
.\Test-NetAppHealth.ps1
Checks all arrays you specify and outputs the results to the shell window.

.EXAMPLE
.\Test-NetAppHealth.ps1 -AlertsOnly
Checks the arrays specified and outputs the results to the shell window and report file but no email is generated unless an error is encountered.

.EXAMPLE
.\Test-NetAppHealth.ps1 -ReportMode -SendEmail
Checks the arrays specified, outputs the results to the shell window, a HTML report, and
emails the HTML report to the address configured in the script.

.LINK


.NOTES
Written by: Kevin Snook (some portions Paul Cunningham)

.OVERVIEW
The script runs through a number of checks on NetApp servers and reports them on a Pass/Fail basis.
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
        #[string]$ReportFile="c:\source\scripts\netapp\netapphealth.html",
        [string]$ReportFile="C:\inetpub\wwwroot\monitor\netapphealth.html",

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

#write-host $DayofWeek
[Int]$DaytoSearchIndex = [DayOfWeek] $DayofWeek  # returns index of day to search for
[Int]$TodayIndex = Get-Date  | Select-Object -ExpandProperty DayOfWeek # returns index of todays day
if ($DaytoSearchIndex -gt $TodayIndex){
    #Today is later in the week than the day required
    #So we need to go back todays index - day's index
    #[datetime]$LastDay = (Get-Date).AddDays(-(7+$TodayIndex-$DaytoSearchIndex)).ToString("MM/dd/yyyy")
    $LastDay = (Get-Date).AddDays(-(7+$TodayIndex-$DaytoSearchIndex))
    }
else{
    #Today is earlier in the week than the day required
    #So we need to go back day's index - todays index
    #[datetime]$LastDay = (Get-Date).AddDays(-($TodayIndex-$DaytoSearchIndex)).ToString("MM/dd/yyyy")
    $LastDay = (Get-Date).AddDays(-($TodayIndex-$DaytoSearchIndex))
    }

return $LastDay
}

function Analyse_Schedule{
param (
        [Parameter( Mandatory=$true)]
        [string]$Schedule,

        [Parameter( Mandatory=$true)]
        [Datetime]$LastSnapshotTaken  
        
        
        )
$MonthList = @()
$MonthDayList = @()
$WeekDayList = @()
$MonthDayofWeekList = @()
$PreviousScheduleDates = @()
$MonthArray =@{Jan=1;Feb=2;Mar=3;Apr=4;May=5;Jun=6;Jul=7;Aug=8;Sep=9;Oct=10;Now=11;Dec=12}
$months = @("Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec")
$monthdays = @(1..31)
$daysoftheweek = @("Mon","Tue","Wed","Thu","Fri","Sat","Sun")
$TodaysDate = Get-Date

  
if ($Log) {Write-Logfile "Processing for schedules"}
#write-host "Schedule is $($Schedule)"
if ($Log) {Write-Logfile "Last Snapshot Taken is $($LastSnapshotTaken)"}
#write-host "Last Snapshot Taken is $($LastSnapshotTaken)"
$LastSnapshotTakenDate = $LastSnapshotTaken.tostring("MM/dd/yyyy")
#write-host "Last Snapshot Taken Date is $($LastSnapshotTakenDate)"
if ($Log) {Write-Logfile "Last Snapshot Taken Date is $($LastSnapshotTakenDate)"}
$LastSnapshotTakenDayofWeek = $LastSnapshotTaken.tostring("ddd")
#write-host "Last Snapshot Taken Day of Week is $($LastSnapshotTakenDayofWeek)"
if ($Log) {Write-Logfile "Last Snapshot Taken Day of Week is $($LastSnapshotTakenDayofWeek)"}
$LastSnapshotTakenDayofMonth = $LastSnapshotTaken.tostring("dd")
#write-host "Last Snapshot Taken Day of month is $($LastSnapshotTakenDayofMonth)"
if ($Log) {Write-Logfile "Last Snapshot Taken Day of month is $($LastSnapshotTakenDayofMonth)"}


$ScheduleLHS = $Schedule.Split("@")[0]

if ($ScheduleLHS){
    $ScheduleLHSElements = $ScheduleLHS.split(",")
    #write-host "Elements are $($ScheduleLHSElements)"
    foreach ($ScheduleLHSElement in $ScheduleLHSElements){
         #write-host $ScheduleLHSElement
         if ($Log) {Write-Logfile $ScheduleLHSElement}
         #Weekday analysis
         if ($ScheduleLHSElement -in $daysoftheweek){
            #write-host "ScheduleLHSElement is $($ScheduleLHSElement)"
            if ($Log) {Write-Logfile "ScheduleLHSElement is $($ScheduleLHSElement)"}
            #write-host "It's a weekday"
            if ($Log) {Write-Logfile  "It's a weekday"}
            #write-host "Run every $($ScheduleLHSElement)"
            if ($Log) {Write-Logfile "Run every $($ScheduleLHSElement)"}
            #Add to weekday list 
            $WeekDayList += $ScheduleLHSElement
            }
         
         #Month analysis
         if ($ScheduleLHSElement -match ( $months -join '|' )){
            #write-host "It's a month string - element is $($ScheduleLHSElement)"
            switch ($ScheduleLHSElement){
            
                {$_.contains("-")} { 
                    #$FirstMonth = $ScheduleMonthElements[0].split("-")[0]
                    $FirstMonth = $ScheduleLHSElement.split("-")[0]
                    $FirstMonth = $MonthArray[$FirstMonth]
                    #write-host "start month is $($FirstMonth)"
                    if ($Log) {Write-Logfile "start month is $($FirstMonth)"}
                    #$LastMonth = $ScheduleMonthElements[0].split("-")[1]
                    $LastMonth = $ScheduleLHSElement.split("-")[1]
                    #write-host "LastMonth is $($LastMonth)"
                    if ($Log) {Write-Logfile "LastMonth is $($LastMonth)"}
                    if ($LastMonth -match " "){
                        #write-host "Month span has space"
                        if ($Log) {Write-Logfile "Month span has space"}
                        #write-host "LastMonth is now $($LastMonth)"
                        if ($Log) {Write-Logfile "LastMonth is now $($LastMonth)"}
                        $ScheduleMonthElements = $ScheduleLHSElement.split(" ")
                        #This is the first day of the monthdays list or a monthday span
                        #write-host "Splitting with space"
                        if ($Log) {Write-Logfile "Splitting with space"}
                        if ($ScheduleMonthElements[1].contains("-")){
                            #write-host "It's got a day span attached"
                            $FirstMonthDay = $ScheduleMonthElements[1].split("-")[0]
                            #write-host "start monthday is $($FirstMonthDay)"
                            $LastMonthDay = $ScheduleMonthElements[1].split("-")[1]
                            #write-host "end monthday is $($LastMonthDay)"
                            #Create array of monthdays in order
                            $MonthDayList += @($FirstMonthDay..$LastMonthDay)
                            ##write-host $MonthList
                            $LastMonth = $LastMonth.split(" ")[0]
                            $LastMonth = $MonthArray[$LastMonth]
                            }   
                        else{
                            #write-host "just a single day"
                            if ($Log) {Write-Logfile "just a single day"}
                            $MonthDayList += $ScheduleMonthElements[1]
                            #write-host $ScheduleMonthElements[0]
                            if ($Log) {Write-Logfile $ScheduleMonthElements[0]}
                            $LastMonth = $LastMonth.split(" ")[0]
                            $LastMonth = $MonthArray[$LastMonth]
                            }
                        }
                    #write-host "end month is $($LastMonth)"
                    if ($Log) {Write-Logfile "end month is $($LastMonth)"}
                    $MonthArrayList = @($FirstMonth..$LastMonth)
                    #Create array of months in order
                    foreach($MonthItem in $MonthArrayList){
                        #write-host "adding to monthlist"
                        if ($Log) {Write-Logfile "adding to monthlist"}
                        $MonthList += (Get-date -month $MonthItem).month
                        }
                    
                    }
                
                default {
                    #It's not a datespan
                    #write-host "month is $($ScheduleLHSElement)"
                    if ($Log) {Write-Logfile "month is $($ScheduleLHSElement)"}
                    if ($ScheduleLHSElement -match " "){
                        #write-host "Month single has space"
                        if ($Log) {Write-Logfile "Month single has space"}
                        $ScheduleMonthElements = $ScheduleLHSElement.split(" ")
                        #This is the first day of the monthdays list
                        #write-host "Splitting with space in single month"
                        if ($Log) {Write-Logfile "Splitting with space in single month"}
                        $MonthDayList += $ScheduleMonthElements[1]
                        $LastMonth = $ScheduleMonthElements[0]
                        $LastMonth = $MonthArray[$LastMonth]
                        #write-host "Month is $($LastMonth)"
                        if ($Log) {Write-Logfile "Month is $($LastMonth)"}
                        }
                    else
                        {
                        $LastMonth = $MonthArray[$ScheduleLHSElement]
                        #write-host "Month is $($LastMonth)"
                        if ($Log) {Write-Logfile "Month is $($LastMonth)"}
                        }
                    #write-host "adding to monthlist"
                    if ($Log) {Write-Logfile "adding to monthlist"}
                    $MonthList += $LastMonth
                    }
               
                }
             }
     
         
         #monthofday analysis
         if ($ScheduleLHSElement  -match ( $monthdays -join '|' )){
            if ($ScheduleLHSElement -notmatch ( $months -join '|' )){
                #It does not contain any month elemnets so is a genuine monthday span
                #write-host "ScheduleLHSElement is $($ScheduleLHSElement)"
                if ($Log) {Write-Logfile "ScheduleLHSElement is $($ScheduleLHSElement)"}
                #write-host "It's a monthday"
                if ($Log) {Write-Logfile "It's a monthday"}
                #write-host "Run every month on $($ScheduleLHSElement)"
                if ($Log) {Write-Logfile "Run every month on $($ScheduleLHSElement)"}
            
                if ($ScheduleLHSElement.contains("-")){
                        $FirstMonthDay = $ScheduleLHSElement.split("-")[0]
                        #write-host "start monthday is $($FirstMonthDay)"
                        if ($Log) {Write-Logfile "start monthday is $($FirstMonthDay)"}
                        $LastMonthDay = $ScheduleLHSElement.split("-")[1]
                    
                        #write-host "end monthday is $($LastMonthDay)"
                        if ($Log) {Write-Logfile "end monthday is $($LastMonthDay)"}
                        #Create array of monthdays in order
                        $MonthDayList += @($FirstMonthDay..$LastMonthDay)
                        ##write-host $MonthList
                        }               
                else{
                    #It's not a datespan
                    $MonthDayList += $ScheduleLHSElement
                    }
                
                }
            }
        }
    #weekday processing
    if ($WeekDayList){
        foreach ($WeekDay in $WeekDayList){
            $PreviousScheduleWeekDay = get_previous_x_day $WeekDay
            #write-host "Previous $($WeekDay) is $($PreviousScheduleWeekDay)"
            #write-host $PreviousScheduleWeekDay
            if ($Log) {Write-Logfile "Previous $($WeekDay) is $($PreviousScheduleWeekDay)"}
            if ($Log) {Write-Logfile "Schedule run on $($PreviousScheduleWeekDay) is same as or after $($LastSnapshotTakenDate)"}
            $PreviousScheduleDates += $PreviousScheduleWeekDay
            #write-host "Previous schedules are $($PreviousScheduleDates)"
            if ($Log) {Write-Logfile "Previous schedules are $($PreviousScheduleDates)"}
            }
        }
    #month and monthday processing
    if ($MonthList){
        #write-host $MonthList
        if ($Log) {Write-Logfile $MonthList}
        
        }
    if ($MonthDayList){
        #write-host $MonthDayList
        if ($Log) {Write-Logfile $MonthDayList}
        #if there's a monthday list but no month list must be set for every month
        if (!$MonthList){
            $MonthList = @(1..12)
            }
        }
    if ($MonthList){
        
        foreach ($MonthLine in $MonthList){
            #write-host "Processing monthlist with $($MonthLine)"
            if ($Log) {Write-Logfile "Processing monthlist with $($MonthLine)"}
            if ($MonthLine){
                foreach ($DayLine in $MonthDayList){
                #write-host "Processing monthday list with $($DayLine)"
                if ($Log) {Write-Logfile "Processing monthday list with $($DayLine)"}
                #write-host "Build string is  $($DayLine) $($MonthLine) $((get-date).tostring("yyyy"))"
                #if the date has passed then it's this year
                $fullscheduledatetime = get-date -Date "$($DayLine)/$($MonthLine)/$((get-date).tostring("yyyy"))" #-Format "dd/MM/yyyy"
                #write-host $fullscheduledatetime
                #write-host $fullscheduledatetime.gettype()
                #write-host $TodaysDate
                if ($Log) {Write-Logfile $fullscheduledatetime}
                #$Now = Get-Date 
                if($fullscheduledatetime -gt $TodaysDate){
                    #write-host "$($fullscheduledatetime) is in the future!"
                    #Set the date to last year
                    $fullscheduledatetime = get-date($fullscheduledatetime).AddMonths(-12)
                    ##write-host "Compare $($fullscheduledatetime)"
                    }
                $PreviousScheduleDates += $fullscheduledatetime 
                }
            }
    
        }
    }
    
    



}
else{
    
    #if there is nothing on the LHS of the @ sign then the schedule is run everyday
    #Return todays date
    #write-host "Nothing on LHS"
    if ($Log) {Write-Logfile "Nothing on LHS so schedule is everyday - return todays date"}
    $fullscheduledatetime = get-date #-Format "dd/MM/yyyy"
    $PreviousScheduleDates += $fullscheduledatetime
    }

$SortedPreviousScheduledDate = $PreviousScheduleDates | sort
$LastPreviousScheduledDate = ($SortedPreviousScheduledDate | select -Last 1).tostring("dd/MM/yyyy")

##Find the last TIME the schedule SHOULD have run
$ScheduleRHS = $Schedule.Split("@")[1]
if ($ScheduleRHS -match ","){
    #if the schedule contains a comma on the RHS then it's a multi-schedule
    if ($Log) {Write-Logfile "Multi-schedule"}
    #write-host "Multi-schedule"       
    [DateTime[]]$DaySchedule = @()
    $RHSTimeArray = $ScheduleRHS.Split(",")
    $HourNow = (Get-Date).Hour
    foreach ($RHSTime in $RHSTimeArray){
        #if it's got no hour add the hour now (as it's a run every hour schedule)
        if ($RHSTime.Split(":")[0]){
            if ($Log) {Write-Logfile "$($RHSTime.Split(":")[0]) is not blank"}
            $DaySchedule += $RHSTime                    }
        else{
            if ($Log) {Write-Logfile "$($RHSTime.Split(":")[0]) is blank"}
            $RHSTime="$($HourNow)$($RHSTime)"
            $DaySchedule += $RHSTime
            }
        }
    
    
    ##Find the nearest but past time 
    ##Add the time now to the array, order it to find the last schedule prior to time now
    $TimeNow = (Get-Date).tostring("HH:mm")
    $DaySchedule += $TimeNow
    $DaySort = $DaySchedule | sort
    [INT]$TimeInArray = [array]::lastindexof($DaySort,$TimeNow)
    $LastRunInPast = $DaySort[$TimeInArray-1]#.tostring("dd/MM/yyyy HH:mm")
    if ($Log) {Write-Logfile "LastRunInPast is $($LastRunInPast)"}
    $LastRunHour = $DaySort[$TimeInArray-1].Hour
    if ($Log) {Write-Logfile "LastRunHour is $($LastRunHour)"}
    $RunHour = $DaySort[$TimeInArray-1].Hour
    if ($Log) {Write-Logfile "RunHour is $($RunHour)"}
    $LastRunMinute = $DaySort[$TimeInArray-1].Minute
    if ($Log) {Write-Logfile "LastRunMinute is $($LastRunMinute)"}
    $RunMinute = $DaySort[$TimeInArray-1].Minute
    if ($Log) {Write-Logfile "RunMinute is $($RunMinute)"}
    #[datetime]$LastScheduledTime = get-date "$($LastPreviousScheduledDate) $($LastRunHour):$($LastRunMinute):00" -Format "dd/MM/yyyy HH:mm:ss"
    $LastScheduledTime = get-date "$($LastPreviousScheduledDate) $($LastRunHour):$($LastRunMinute):00" #-Format "dd/MM/yyyy"
    #unless that gives us a time which is in the future
    #write-host "Comparing $LastScheduledTime and $TodaysDate"
    if ($LastScheduledTime -gt $TodaysDate){
        #write-host "$LastScheduledTime is after $TodaysDate"
        if ($Log) {Write-Logfile "$LastScheduledTime is after $TodaysDate"}
        #set the time to the previous schedule (day before in this case)
        ##write-host $LastScheduledTime.gettype()
        #$LastScheduledTime = (get-date $LastScheduledTime).AddHours(-1) #-Format "dd/MM/yyyy HH:mm:ss"
        #Find Previous Scheduled day in $PreviousScheduleDates
        [INT]$TodayInArray = [array]::indexof($SortedPreviousScheduledDate,$TimeNow)
        $PreviousScheduleToToday = $SortedPreviousScheduledDate[$TodayInArray-1].tostring("dd/MM/yyyy")
        #write-host "Previous schedule date is $($PreviousScheduleToToday)"
        $LastScheduledTime = get-date "$($PreviousScheduleToToday) $($LastRunHour):$($LastRunMinute):00"
        ##write-host $LastScheduledTime 
        }
    }
else{
    #if the schedule does not contain a comma on the RHS then it's a single schedule
    #write-host "Single schedule"
    $DailySchedule = $ScheduleRHS.Split(":")
    if ($DailySchedule[0]){
        #if there is something on the LHS of the schedule then that is the hour
        #write-host "Something on LHS of hourly schedule so let's find the hour"
        $LastRunHour = $DailySchedule[0]
        #write-host $LastRunHour
        if ($Log) {Write-Logfile "LastRunHour is $($LastRunHour)"}
        $RunHour = $DailySchedule[0]
        if ($Log) {Write-Logfile "RunHour is $($RunHour)"}
        $LastRunMinute = $DailySchedule[1]
        #write-host $LastRunMinute
        if ($Log) {Write-Logfile "LastRunMinute is $($LastRunMinute)"}
        $RunMinute = $DailySchedule[1]
        if ($Log) {Write-Logfile "RunMinute is $($RunMinute)"}
        #write-host $LastPreviousScheduledDate
        #unless that gives us a time which is in the future
        #[datetime]$LastScheduledTime = get-date "$($LastPreviousScheduledDate) $($LastRunHour):$($LastRunMinute):00" -Format "dd/MM/yyyy HH:mm:ss"
        $LastScheduledTime = get-date "$($LastPreviousScheduledDate) $($LastRunHour):$($LastRunMinute):00" #-Format "dd/MM/yyyy"
        #write-host "Comparing $LastScheduledTime and $TodaysDate"
        if ($LastScheduledTime -gt $TodaysDate){
            ##write-host "$LastScheduledTime is after $TodaysDate"
            if ($Log) {Write-Logfile "$LastScheduledTime is after $TodaysDate"}
            #set the time to the previous schedule (day before in this case)
            ##write-host $LastScheduledTime.gettype()
            $LastScheduledTime = (get-date $LastScheduledTime).AddHours(-24) #-Format "dd/MM/yyyy HH:mm:ss"
            ##write-host $LastScheduledTime 
            }
        }
    else{
        #if there is nothing on the LHS of the schedule then it's an every hour schedule
        #write-host "Nothing on LHS of hour schedule"
        if ($LastPreviousScheduledDate -notmatch $TodaysDate.tostring("dd/MM/yyyy")){
            #write-host "$($LastPreviousScheduledDate) and $($TodaysDate.tostring("dd/MM/yyyy")) are different -setting hour to 23"
            $LastRunHour = "23"
            }
        else{
            $LastRunHour = (Get-Date).Hour
            }
        #write-host $LastRunHour
        if ($Log) {Write-Logfile "LastRunHour is $($LastRunHour)"}
        $RunHour = "every hour"
        if ($Log) {Write-Logfile "RunHour is $($RunHour)"}
        $LastRunMinute = $DailySchedule[1]
        #write-host $LastRunMinute
        if ($Log) {Write-Logfile "LastRunMinute is $($LastRunMinute)"}
        $RunMinute = $DailySchedule[1]
        if ($Log) {Write-Logfile "RunMinute is $($RunMinute)"}
        #unless that gives us a time which is in the future
        #[datetime]$LastScheduledTime = get-date "$($LastPreviousScheduledDate) $($LastRunHour):$($LastRunMinute):00" -Format "dd/MM/yyyy HH:mm:ss"
        $LastScheduledTime = get-date "$($LastPreviousScheduledDate) $($LastRunHour):$($LastRunMinute):00" #-Format "dd/MM/yyyy"
        #write-host $LastScheduledTime
       #write-host "Comparing $LastScheduledTime and $TodaysDate"
        if ($LastScheduledTime -gt $TodaysDate){
            ##write-host "$LastScheduledTime is after $TodaysDate"
            if ($Log) {Write-Logfile "$LastScheduledTime is after $TodaysDate"}
            #set the time to the previous schedule (hour before in this case)
            ##write-host $LastScheduledTime.gettype()
            $LastScheduledTime = (get-date $LastScheduledTime).AddHours(-1) #-Format "dd/MM/yyyy HH:mm:ss"
            ##write-host $LastScheduledTime 
            }
        }
    }


return $LastScheduledTime



}

function Analyse_SnapMirrors{
param (
    $NodeList
)

#Get all the volumes for this node
$NetAppAggregates = Get-NcAggr |  where {$_.Nodes -match $NodeList}
$NetAppVolumes = Get-NcVol  | where {$_.VolumeStateAttributes.IsNodeRoot -eq $false -and $_.Aggregate -in $NetAppAggregates.Name}
$SnapShotResults = @()
foreach ($NetAppVolume in $NetAppVolumes){
    #Write-Host "Analysing snapmirrors on Volume is $($NetAppVolume.Name)"
       
    ##Run through each volume homed on this node and record policy, schedules and last snapshot details
    $NetAppSnapMirror = get-ncsnapmirror -DestinationVolume  $NetAppVolume.Name
    #$NetAppSnapMirror
    if ($NetAppSnapMirror){
        $NetAppSnapMirrorSchedule = $NetAppSnapMirror.Schedule
        if ($Log) {Write-Logfile "Snapmirror Schedule Name is $($NetAppSnapMirror.Schedule)"}
        $CronSchedule = Get-NcJobCronSchedule -Name $NetAppSnapMirrorSchedule
        $DaystoRun = $LastRunDay = $RunDay = $HourNow = $DailySchedule = $DailySort = $LastRunInPast =$LastRunHour = $RunHour = $LastRunMinute = $RunMinute = $null
        if ($Log) {Write-Logfile "Job Schedule Name is $($CronSchedule.JobScheduleName)"}
        if ($Log) {Write-Logfile "Job Schedule Description is $($CronSchedule.JobScheduleDescription)"}
        ##Find the last snapmirror snapshot for this volume 
        $LastSnapshotCreated = $null
        $LastSnapshotCreated = $NetAppSnapMirror.NewestSnapshotTimestampDT
        #Compare last snapshot taken to when the schedule says it should have been taken
                
        if ($LastSnapshotCreated){
            #if ($LastSnapshotCreated -lt (Get-date).AddMinutes(-$MaxMinutesSnapMirrorLag)){
            #        "SnapMirror $($NetAppSnapMirror.SourceVolume) - $($CronSchedule.JobScheduleName) schedule is lagging more than the configured maximum($($MaxMinutesSnapMirrorLag));"
            #        if ($Log) {Write-Logfile "SnapMirror $($NetAppSnapMirror.SourceVolume) - $($CronSchedule.JobScheduleName) schedule is lagging more than the configured maximum($($MaxMinutesSnapMirrorLag))"}
            #        }  
            #[datetime]$LastSnapshotCreated = $LastSnapshot.Created.tostring("MM/dd/yyyy HH:mm")
            $PreviousSchedule = Analyse_Schedule $CronSchedule.JobScheduleDescription $LastSnapshotCreated
            if($PreviousSchedule){
                if ($Log) {Write-Logfile "Previous schedule is: $($PreviousSchedule)"}
                if ($LastSnapshotCreated -lt $PreviousSchedule){
                        if ($Log) {Write-Logfile "Last snapshot created date $($LastSnapshotCreated) is before last scheduled snapshot $($PreviousSchedule) - missed schedule"}
                        "SnapMirror $($NetAppSnapMirror.SourceVolume) - $($CronSchedule.JobScheduleName) schedule has missed at least one snapshot;"
                        if ($Log) {Write-Logfile "SNapmirror for $($NetAppSnapMirror.SourceVolume) - $($CronSchedule.JobScheduleName) schedule has missed at least one snapshot"}
                        }
                    else{
                        #write-host "Last snapshot created date $($LastSnapshotCreated) is the same as or after last scheduled snapshot $($LastScheduleTime) - snapshots up-to-date" -ForegroundColor Yellow
                        if ($Log) {Write-Logfile "Last snapshot created date $($LastSnapshotCreated) is the same as or after last scheduled snapshot $($PreviousSchedule) - snapshots up-to-date"}
                        if ($Log) {Write-Logfile "Snapmirror for $($NetAppSnapMirror.SourceVolume) - $($CronSchedule.JobScheduleName) schedule has NOT missed a snapshot"}
                        }
                }
            }
            
        else {
            "SnapMirror $($NetAppSnapMirror.SourceVolume) - $($CronSchedule.JobScheduleName) does not have any snapshots;"
            if ($Log) {Write-Logfile "Snapmirror for $($NetAppSnapMirror.SourceVolume) - $($CronSchedule.JobScheduleName) does not have any snapshots;"}
            }
        } 
    }
   
}

function Analyse_SnapVaults{
param (
    $NodeList
)

$NetAppSnapVaults = Get-NcSnapmirror |Where-Object{($_.RelationshipType -eq "vault" -or $_.PolicyType -match "mirror_vault") -and $_.DestinationVolumeNode -match $NodeList }

foreach ($NetAppSnapVault in $NetAppSnapVaults){
    $NetAppActualTotalSnapshots = 0 
    #$NetAppPolicyTotalSnapshots = 0
    $NetAppSnapMirrorPolicy = Get-NcSnapmirrorPolicy -Name $NetAppSnapVault.Policy
    #$NetAppSnapMirrorPolicy | gm
    #exit
    foreach ($SnapmirrorPolicyRule in $NetAppSnapMirrorPolicy.SnapmirrorPolicyRules){
        if ($SnapmirrorPolicyRule.SnapmirrorLabel -ne "sm_created"){
            $NetAppPolicySnapshotsRetained = $SnapmirrorPolicyRule.Keep
            if ($Log) {Write-Logfile "$($NetAppSnapVault.Policy) $($SnapmirrorPolicyRule)"}                        
            #Find the snapshots with this prefix and check retention is correct
            if ($Log) {Write-Logfile "Find the snapshots with $($SnapmirrorPolicyRule.SnapmirrorLabel) and check retention is correct"}
            #$NetAppActualSnapshots = $NetAppSnapshots | where {$_.Volume -eq $NetAppSnapVault.DestinationVolume -and $_.Name -match $SnapmirrorPolicyRule.SnapmirrorLabel}
            $NetAppActualSnapshots = $NetAppSnapshots | where {$_.Volume -eq $NetAppSnapVault.DestinationVolume -and $_.Name.StartsWith($SnapmirrorPolicyRule.SnapmirrorLabel)}
            #write-host $NetAppActualSnapshots
            if ($NetAppActualSnapshots){
                $NetAppActualSnapshotsRetained = $NetAppActualSnapshots.Count
                if ($Log) {Write-Logfile "Actual snapshots retained for this policy rule is $($NetAppActualSnapshotsRetained)"}
                $NetAppActualTotalSnapshots += $NetAppActualSnapshotsRetained
                if ($Log) {Write-Logfile "Policy snapshots retained for this policy rule should be $($NetAppPolicySnapshotsRetained)"}
                #$NetAppPolicyTotalSnapshots += $NetAppPolicySnapshotsRetained
                if ($NetAppActualSnapshotsRetained -gt $NetAppPolicySnapshotsRetained){
                    "SnapVault $($NetAppSnapVault.DestinationVolume) has more retained copies ($($NetAppActualSnapshotsRetained)) than set in policy ($($NetAppPolicySnapshotsRetained));"
                    if ($Log) {Write-Logfile "SnapVault $($NetAppSnapVault.DestinationVolume) has more retained copies ($($NetAppActualSnapshotsRetained)) than set in policy ($($NetAppPolicySnapshotsRetained))"}
                    }
                }
            else{
                "SnapVault $($NetAppSnapVault.SourceVolume) - $($SnapmirrorPolicyRule) does not have any snapvaults on this node;"
                if ($Log) {Write-Logfile "SnapVault $($NetAppSnapVault.SourceVolume) - $($SnapmirrorPolicyRule) does not have any snapvaults on this node;"}
                }   
                                
                                
                                
            }
        }
                      
    $NetAppSnapMirrorSnapshotCount = ($NetAppSnapshots | where {$_.Volume -eq $NetAppSnapVault.DestinationVolume -and $_.Name.StartsWith("snapmirror")}).Count
    if ($Log) {Write-Logfile "SnapMirror retains $($NetAppSnapMirrorSnapshotCount) copies on $($NetAppSnapVault.DestinationVolume)"}
    
    if ($Log) {Write-Logfile "Comparing - total retained snapshots for $($NetAppSnapVault.Policy) is $($NetAppActualTotalSnapshots) and should be upto $($NetAppSnapMirrorPolicy.TotalKeep+$NetAppSnapMirrorSnapshotCount);"}
    if ($NetAppActualTotalSnapshots -gt ($NetAppSnapMirrorPolicy.TotalKeep+$NetAppSnapMirrorSnapshotCount)){
        #Allow for snapmirrors in calcs
        "Total retained snapshots for SnapVault Policy $($NetAppSnapVault.Policy) is $($NetAppActualTotalSnapshots) but should be $($NetAppSnapMirrorPolicy.TotalKeep+$NetAppSnapMirrorSnapshotCount);"
        if ($Log) {Write-Logfile "Total retained snapshots for $($NetAppSnapVault.Policy) is $($NetAppActualTotalSnapshots) but should be $($NetAppSnapMirrorPolicy.TotalKeep+$NetAppSnapMirrorSnapshotCount)"}
        }    
    #Now check the policy schedule timings and check that the last snapvault is within correct tolerance of that time
    foreach ($NetAppSnapVaultPolicyRule in $NetAppSnapMirrorPolicy.SnapmirrorPolicyRules){
        if ($NetAppSnapVaultPolicyRule.SnapmirrorLabel -ne "sm_created"){
            #So we need to take the snapmirrorLabel and ensure that we have pulled a snapshot within the specified time 
            $LastSnapshot = $null
            $LastSnapshot = $NetAppSnapshots | where {$_.Name -match $NetAppSnapVaultPolicyRule.SnapmirrorLabel} | select -Last 1
            $CronSchedule = Get-NcJobCronSchedule -Name $NetAppSnapVaultPolicyRule.SnapmirrorLabel
            $DaystoRun = $LastRunDay = $RunDay = $HourNow = $DailySchedule = $DailySort = $LastRunInPast =$LastRunHour = $RunHour = $LastRunMinute = $RunMinute = $null
            if ($Log) {Write-Logfile "Job Schedule Name is $($CronSchedule.JobScheduleName)"}
            if ($Log) {Write-Logfile "Job Schedule Description is $($CronSchedule.JobScheduleDescription)"}
            
            #write-host "Job Schedule Description is $($CronSchedule.JobScheduleDescription)"
            
            if ($LastSnapshot){
                #[datetime]$LastSnapshotCreated = $LastSnapshot.Created.tostring("MM/dd/yyyy HH:mm")
                $LastSnapshotCreated = $LastSnapshot.Created 
                #if ($Log) {Write-Logfile "LastSNapshot is $($LastSnapshotCreated)"}
                #if ($Log) {Write-Logfile "LagTime is $((Get-date).AddMinutes(-$MaxMinutesSnapMirrorLag)))"}
                #if ($LastSnapshotCreated -lt (Get-date).AddMinutes(-$MaxMinutesSnapMirrorLag)){
                #    "SnapVault $($NetAppSnapVault) - $($CronSchedule.JobScheduleName) schedule is lagging more than the configured maximum($($MaxMinutesSnapMirrorLag));"
                #    if ($Log) {Write-Logfile "SnapVault $($NetAppSnapVault) - $($CronSchedule.JobScheduleName) schedule is lagging more than the configured maximum($($MaxMinutesSnapMirrorLag))"}
                #    }    
                $PreviousSchedule = Analyse_Schedule $CronSchedule.JobScheduleDescription $LastSnapshotCreated
                if($PreviousSchedule){
                    if ($LastSnapshotCreated -lt $LastScheduleTime){
                        if ($Log) {Write-Logfile "Last snapshot created date $($LastSnapshotCreated) is before last scheduled snapshot $($PreviousSchedule) - missed schedule"}
                        #write-host "$($LastSnapshotCreated) is before $($LastScheduleTime) - missed schedule set at $($LastScheduleTime)" -ForegroundColor Red
                        "SnapVault $($NetAppSnapVault) - $($CronSchedule.JobScheduleName) schedule has missed at least one snapshot;"
                        if ($Log) {Write-Logfile "$($NetAppSnapVault) - $($CronSchedule.JobScheduleName) schedule has missed at least one snapshot"}
                        }
                    else{
                        #write-host "Last snapshot created date $($LastSnapshotCreated) is the same as or after last scheduled snapshot $($LastScheduleTime) - snapshots up-to-date" -ForegroundColor Yellow
                        if ($Log) {Write-Logfile "Last snapshot created date $($LastSnapshotCreated) is the same as or after last scheduled snapshot $($PreviousSchedule) - snapshots up-to-date"}
                        if ($Log) {Write-Logfile "SnapVault $($NetAppSnapVault) - $($CronSchedule.JobScheduleName) schedule has NOT missed a snapshot"}
                        }
                       
                    }
                }
            else {
                "SnapVault $($NetAppSnapVault) - $($CronSchedule.JobScheduleName) does not have any snapshots;"
                if ($Log) {Write-Logfile "SnapVault $($NetAppSnapVault) - $($CronSchedule.JobScheduleName) does not have any snapshots;"}
                }
                    
                    
            }
        }
    }
        
}

function Analyse_Snapshots{
param (
    $NodeList
)

#Get all the volumes for this node
$NetAppAggregates = Get-NcAggr |  where {$_.Nodes -match $NodeList}
$NetAppVolumes = Get-NcVol  | where {($_.VolumeStateAttributes.IsNodeRoot -eq $false) -and ($_.Aggregate -in $NetAppAggregates.Name) -and ($_.Name -notmatch "MDV_aud_")}



$SnapShotResults = @()
foreach ($NetAppVolume in $NetAppVolumes){
    if ($Log) {Write-Logfile "$($NetAppVolume.Name)"}
    #write-host $NetAppVolume -ForegroundColor Yellow      
    $NetAppVolumePolicyTotalSnapshots = 0  
    ##Run through each volume homed on this node and record policy, schedules and last snapshot details
    #See if it has protection turned on
    if ($NetAppVolume.VolumeIdAttributes.Type -eq "rw" -and (($NetAppVolume | Get-NcVolOption -Hashtable).value.nosnap -eq "on" -or $NetAppVolume.VolumeSnapshotAttributes.SnapshotPolicy -eq "none")){
        "No protection for volume $($NetAppVolume.Name);"
        if ($Log) {Write-Logfile "No protection for volume $($NetAppVolume.Name)"}
        }
    $VolumeSnapShotCount = $NetAppVolume.VolumeSnapshotAttributes.SnapshotCount
    $NetAppSnapshotPolicy = Get-NcSnapshotPolicy -Name $NetAppVolume.VolumeSnapshotAttributes.SnapshotPolicy
    $NetAppSnapshotSchedules = $NetAppSnapshotPolicy.SnapshotPolicySchedules
    ##Find policy for volume and work out retention and actual numbers of snapshots held
    ##Find total retained snapshots for this volume and then compare with how many we should have (adding up all schedules)
    
    foreach ($NetAppSnapshotSchedule in $NetAppSnapshotSchedules.Schedule){
        $CronSchedule = Get-NcJobCronSchedule -Name $NetAppSnapshotSchedule
        #write-host $CronSchedule.JobScheduleName
        $NetAppActualSnapshots = $NetAppSnapshots | where {$_.Volume -eq $NetAppVolume.Name -and $_.Name.StartsWith($CronSchedule.JobScheduleName)}
        $NetAppActualSnapshotsRetained = $($NetAppActualSnapshots.Count)
        if ($Log) {Write-Logfile "Actual snapshots retained for this schedule is $($NetAppActualSnapshotsRetained)"}
        #write-host "Actual snapshots retained for this schedule is $($NetAppActualSnapshotsRetained)"
        $NetAppPolicySnapshotsRetained = ($NetAppSnapshotSchedules | where{$_.Schedule -eq $NetAppSnapshotSchedule}).Count
        if ($Log) {Write-Logfile "Policy snapshots retained for this schedule should be $($NetAppPolicySnapshotsRetained)"}
        #write-host "Policy snapshots retained for this schedule should be $($NetAppPolicySnapshotsRetained)"
        $NetAppVolumePolicyTotalSnapshots += $NetAppPolicySnapshotsRetained
        if ($NetAppActualSnapshotsRetained -gt $NetAppPolicySnapshotsRetained){
            "$($NetAppVolume.Name) - $($CronSchedule.JobScheduleName) schedule has more retained copies ($($NetAppActualSnapshotsRetained)) than set in policy ($($NetAppPolicySnapshotsRetained));"
            if ($Log) {Write-Logfile "$($NetAppVolume.Name) - $($CronSchedule.JobScheduleName) schedule has more retained copies ($($NetAppActualSnapshotsRetained)) than set in policy ($($NetAppPolicySnapshotsRetained))"}
            }
        if ($Log) {Write-Logfile "Job Schedule Name is $($CronSchedule.JobScheduleName)"}
        if ($Log) {Write-Logfile "Job Schedule Description is $($CronSchedule.JobScheduleDescription)"}
        
        $LastSnapshot = $null
        $LastSnapshot = $NetAppSnapshots | where {$_.Volume -eq $NetAppVolume.Name -and $_.Name -match $CronSchedule.JobScheduleName} | select -Last 1 
        if ($LastSnapshot){
                [datetime]$LastSnapshotCreated = $LastSnapshot.Created.tostring("MM/dd/yyyy HH:mm")
                $PreviousSchedule = Analyse_Schedule $CronSchedule.JobScheduleDescription $LastSnapshotCreated
                if($PreviousSchedule){
                    if ($LastSnapshotCreated -lt $LastScheduleTime){
                        if ($Log) {Write-Logfile "Last snapshot created date $($LastSnapshotCreated) is before last scheduled snapshot $($PreviousSchedule) - missed schedule"}
                        #write-host "$($LastSnapshotCreated) is before $($LastScheduleTime) - missed schedule set at $($LastScheduleTime)" -ForegroundColor Red
                        "$($NetAppVolume.Name) - $($CronSchedule.JobScheduleName) schedule has missed at least one snapshot;"
                        if ($Log) {Write-Logfile "$($NetAppVolume.Name) - $($CronSchedule.JobScheduleName) schedule has missed at least one snapshot"}
                        }
                    else{
                        #write-host "Last snapshot created date $($LastSnapshotCreated) is the same as or after last scheduled snapshot $($LastScheduleTime) - snapshots up-to-date" -ForegroundColor Yellow
                        if ($Log) {Write-Logfile "Last snapshot created date $($LastSnapshotCreated) is the same as or after last scheduled snapshot $($PreviousSchedule) - snapshots up-to-date"}
                        if ($Log) {Write-Logfile "$($NetAppVolume.Name) - $($CronSchedule.JobScheduleName) schedule has NOT missed a snapshot"}
                        }
                       
                    }
                }
        else {
            "$($NetAppVolume.Name) - $($CronSchedule.JobScheduleName) does not have any snapshots;"
            if ($Log) {Write-Logfile "$($NetAppVolume.Name) - $($CronSchedule.JobScheduleName) does not have any snapshots;"}
            }
         
        
        } 
  
  if ($NetAppSnapshotSchedules){
      $NetAppSnapMirrorSnapshotCount = ($NetAppSnapshots | where {$_.Volume -eq $NetAppVolume.Name -and $_.Name.StartsWith("snapmirror")}).Count
      #$NetAppSnapMirrorSnapshotCount

      if ($NetAppVolume.VolumeSnapshotAttributes.SnapshotCount -gt $NetAppVolumePolicyTotalSnapshots+$NetAppSnapMirrorSnapshotCount){
        #Allow for snapmirrors in calcs
        "$($NetAppVolume.Name) - Total retained snapshots for volume is $($NetAppVolume.VolumeSnapshotAttributes.SnapshotCount) but should be $($NetAppVolumePolicyTotalSnapshots);"
        #write-host "Total retained snapshots for volume is $($NetAppVolume.VolumeSnapshotAttributes.SnapshotCount) but should be $($NetAppVolumePolicyTotalSnapshots) "
        }
    }
  }

}



#...................................
# Script
#...................................
#Find run directory 
$runDir = Split-Path -Parent $MyInvocation.MyCommand.Path
#$reportemailsubject = "NetApp Health Report"
$ignorelistfile = "$($runDir)\ignorelist.txt"

################################ Start a transcript log ####################################################

Start-Transcript -Path "$($runDir)\NetApp_health_transcript.log"

################################ Initialise some variables #################################################



# dot source the External variables PowerShell File

if (Test-Path "$($runDir)\Test-NetAppHealth-cfg.ps1"){
    . "$($runDir)\Test-NetAppHealth-cfg.ps1"
    }
else{
    write-host "Cannot find config file - please create $($runDir)\Test-NetAppHealth-cfg.ps1" -ForegroundColor Red
    exit
    }

#...................................
# Variables
#...................................

$now = Get-Date                                             #Used for timestamps
$date = $now.ToShortDateString()                            #Short date format for email message subject
#[array]$netappservers = @()                                #Array for the NetApp filers to check

#Maxima and minima
#$MaxMinutesSinceSnapshot = 60                               #Max minutes since last snapshot
#$MaxMinutesSnapMirrorLag = 60                               #Max minutes lag for snapmirrors
#$MaxHoursToScanLog = 24                                     #Max hours to go back and alert in logs
#$VolumeFullPercentageError = 95                             #Percentage full before Error
#$VolumeFullPercentageWarning = 85                           #Percentage full before Warning
#$VolumeSnapReserveFullPercentageError = 95                  #Percentage full before Error on snap reserve
#$AggregateFullPercentageError = 95                          #Percentage full before Error
#$AggregateFullPercentageWarning = 85                        #Percentage full before Warning


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
$myDir = Split-Path -Parent $MyInvocation.MyCommand.Path
#$reportemailsubject = "NetApp Health Report"
$ignorelistfile = "$myDir\ignorelist.txt"
#$logfile = "C:\Source\Scripts\netapp\netapp_health.log"
$ERRORS=$null
$OVC="Not Connected"
$netappHosts=$null
$OutputFolder = [System.IO.Path]::GetDirectoryName($ReportFile)
#$ReportURL = "http://BOH2-EUD-VMAN01\Monitor\netappreporterrors.html"

$SystemErrors = $false                                    #Variable to show whether system errors have been encountered on any node
$AlertSeverity = "error"                               #Variable to pick which system errors to pick up: warning, error, critical, debug, informational, notice


#...................................
# Email Settings
#...................................

$recipients = @("kevin.snook@cobham.com")
#$emailFrom = "netapphealth@cobham.com"
#$smtpServer = "smtp.eu.cobham.net"

#$smtpsettings = @{
    #To =  "kevin.snook@cobham.com"
    #To =  "ERoW-IT-Datacentre-Callout-Team@cobham.com"
    #From = "CMS-NETAPP-Alerts@cobham.com"
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

if (Test-Path "$($OutputFolder)\NetApp_Error_Status_Fail.txt"){
    del "$($OutputFolder)\NetApp_Error_Status_Fail.txt"
    }
 if (Test-Path "$($OutputFolder)\netappReportErrors.html"){
    del "$($OutputFolder)\netappReportErrors.html" 
    }  
      

#Log file is overwritten each time the script is run to avoid
#very large log files from growing over time
if ($Log) {
    $timestamp = Get-Date -DisplayHint Time
    "$($timestamp) =====================================" | Out-File $logfile
    Write-Logfile " NetApp Server Health Check"
    Write-Logfile "  $now"
    Write-Logfile "====================================="
}

Write-Host "Initializing..."
if ($Log) {Write-Logfile "Initializing..."}


#...................................
# Credentials
#...................................

#Login to monitoring user (RO user "monitoring-user" setup on NetApp clusters)
#$NetAppCredential = Import-CliXml -Path c:\source\scripts\netapp\monitoring-user.xml

#...................................
# NetApp controllers
#$NetAppControllers = "10.172.2.185","10.136.18.60"
#...................................


foreach($NetAppController in $NetAppControllers){ 
    Write-Host $NetAppController -ForegroundColor Blue
    $NetAppConnect1 = Connect-NcController $NetAppController -Credential $NetAppCredential
    if ($Log) {Write-Logfile "$($NetAppConnect1)"} 
    #Get all the snapshots ready for later analysis
    $NetAppSnapshots = get-ncsnapshot | Sort-Object -Property Created
    $NetAppClusterName = (Get-NcCluster -Controller $NetAppConnect1).ClusterName
    $NetAppNodes = Get-NcNode
    if ($Log) {Write-Logfile "Processing for $($NetAppNodes)"}
    foreach ($NetAppNode in $NetAppNodes){
        Write-Host $NetAppNode.Node -ForegroundColor Blue
        if ($Log) {Write-Logfile "Processing for $($NetAppNode)"}
    
        #Custom object properties
        $serverObj = New-Object PSObject
        $serverObj | Add-Member NoteProperty -Name "Node" -Value $NetAppNode.Node
        $serverObj | Add-Member NoteProperty -Name "Cluster" -Value $NetAppClusterName
                
        #Null and n/a the rest, will be populated as script progresses
        $serverObj | Add-Member NoteProperty -Name "DNS" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Ping" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Health" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Uptime (hrs)" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Snapmirrors" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Snapshots" -Value $null
        $serverObj | Add-Member NoteProperty -Name "SnapVaults" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Alerts" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Networks" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Hardware" -Value "n/a"
        $serverObj | Add-Member NoteProperty -Name "Volumes" -Value "n/a"
        $serverObj | Add-Member NoteProperty -Name "SVMs" -Value "n/a"
        $serverObj | Add-Member NoteProperty -Name "Shares" -Value "n/a"
        $serverObj | Add-Member NoteProperty -Name "Aggregates" -Value "n/a"

        $NetAppAggregates = Get-NcAggr | where {$_.Nodes -match $NetAppNode.Node} #We use this a lot to find volumes/shares etc located on this node
        if ($Log) {Write-Logfile "Aggregates on this node: $($NetAppAggregates)"}

#...................................
#DNS Check
#...................................
        Write-Host "DNS Check: " -NoNewline;
        if ($Log) {Write-Logfile "DNS Check: "}
        try {$ip = @([System.Net.Dns]::GetHostByName($NetAppController).AddressList | Select-Object IPAddressToString -ExpandProperty IPAddressToString)}
        catch {
            Write-Host -ForegroundColor $fail $_.Exception.Message
            if ($Log) {Write-Logfile "$_.Exception.Message"}
            $ip = $null
            }
        if ( $ip -ne $null ){
            Write-Host -ForegroundColor $pass "Pass"
            $serverObj | Add-Member NoteProperty -Name "DNS" -Value "Pass" -Force
            if ($Log) {Write-Logfile "DNS Success: $ip"}
            #Is server online
            Write-Host "Ping Check: " -NoNewline;
            if ($Log) {Write-Logfile "Ping check:"}
            $ping = $null
            try {$ping = Test-Connection $NetAppController -Quiet -ErrorAction Stop}
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
                    $serversummary += "$($NetAppController) - Ping Failed"
                    if ($Log) {Write-Logfile "Fail"}
                    }
                }
            }
 
 #...................................       
 #Health Check
 #...................................
        Write-Host "Node health: " -NoNewline
        if ($Log) {Write-Logfile "Node health: "}
        Switch ($NetAppNode.IsNodeHealthy) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj |Add-Member NoteProperty -Name "Health" -Value "Pass" -Force;if ($Log) {Write-Logfile "Pass"}}
            $false { Write-Host -ForegroundColor $fail "Fail"; $serversummary += "$($NetAppNode.Node) is unhealthy;";$serverObj |Add-Member NoteProperty -Name "Health" -Value "Fail" -Force;if ($Log) {Write-Logfile "Fail"}}
            default { Write-Host -ForegroundColor $fail "Fail"; $serversummary += "$($NetAppNode.Node) is unhealthy;";$serverObj |Add-Member NoteProperty -Name "Health" -Value "Fail" -Force;if ($Log) {Write-Logfile "Fail"}}
            }
        
#...................................       
#Uptime Check
#...................................       
 
        Write-Host "Uptime (hrs): " -NoNewline
        if ($Log) {Write-Logfile "Uptime (hrs): "}
        
        $uptimehours = ($NetAppNode.NodeUptime / 60 / 60) #convert seconds to hours
        Switch ($uptimehours -gt 23) {
            $true { Write-Host -ForegroundColor $pass $uptimehours;if ($Log) {Write-Logfile "Pass - uptime is $uptimehours"}}
            $false { Write-Host -ForegroundColor $warn $uptimehours; $serversummary += "$($NetAppNode.Node) - Uptime is less than 24 hours ($uptimehours);";if ($Log) {Write-Logfile "Fail - uptime is $uptimehours"}}
            default { Write-Host -ForegroundColor $warn $uptimehours; $serversummary += "$($NetAppNode.Node) - Uptime is less than 24 hours ($uptimehours);";if ($Log) {Write-Logfile "Fail - uptime is $uptimehours"}}
            }

        $serverObj | Add-Member NoteProperty -Name "Uptime (hrs)" -Value $uptimehours -Force 
#...................................
#Snapmirrors check
#...................................
        Write-Host "SnapMirrors: " -NoNewline
        if ($Log) {Write-Logfile "SnapMirrors: "}
        #$SnapMirrorResults = get-ncsnapmirror | select-Object @{Name="RPOMet";Expression={$_.Lagtime -lt 14400}} , IsHealthy, SourceVolume| where {(!$_.RPOMet) -or (!$_.IsHealthy)}
        $SnapMirrorResults = Analyse_SnapMirrors $NetAppNode.Node
        Switch (!$SnapMirrorResults) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "SnapMirrors" -Value "Pass" -Force;if ($Log) {Write-Logfile "Pass - snapmirrors are OK - no lags beyond scheduled times"}}
            $false { Write-Host -ForegroundColor $fail $SnapMirrorResults; $serversummary += "$($NetAppNode.Node) - $($SnapMirrorResults);";$serverObj | Add-Member NoteProperty -Name "SnapMirrors" -Value "Fail" -Force;if ($Log) {Write-Logfile "Fail - $($NetAppNode.Node) - $($SnapMirrorResults)"}}
            default { Write-Host -ForegroundColor $fail $SnapMirrorResults; $serversummary += "$($NetAppNode.Node) - $($SnapMirrorResults);";$serverObj | Add-Member NoteProperty -Name "SnapMirrors" -Value "Fail" -Force;if ($Log) {Write-Logfile "Fail - $($NetAppNode.Node) - $($SnapMirrorResults)"}}
            }

#...................................
#Snapshots check
#...................................
        Write-Host "SnapShots: " -NoNewline
        if ($Log) {Write-Logfile "SnapShots($($NetAppNode.Node)): "}
        
        $SnapshotResults = Analyse_Snapshots $NetAppNode.Node
        Switch (!$SnapshotResults) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Snapshots" -Value "Pass" -Force;if ($Log) {Write-Logfile "Pass - snapshots are OK - no lags beyond scheduled times"}}
            $false { Write-Host -ForegroundColor $fail $SnapshotResults; $serversummary += "$($NetAppNode.Node) - $($SnapshotResults);";$serverObj | Add-Member NoteProperty -Name "Snapshots" -Value "Fail" -Force;if ($Log) {Write-Logfile "Fail - snapshots have fallen behind - $($NetAppNode.Node) - $($SnapshotResults)"}}
            default { Write-Host -ForegroundColor $fail $SnapshotResults; $serversummary += "$($NetAppNode.Node) - $($SnapshotResults);";$serverObj | Add-Member NoteProperty -Name "Snapshots" -Value "Fail" -Force;if ($Log) {Write-Logfile "Fail - snapshots have fallen behind - $($NetAppNode.Node) - $($SnapshotResults)"}}
            }

#...................................
#SnapVaults check
#...................................
        Write-Host "SnapVaults: " -NoNewline
        if ($Log) {Write-Logfile "SnapVaults: "}
        $SnapVaultResults = Analyse_SnapVaults $NetAppNode.Node
        Switch (!$SnapVaultResults) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "SnapVaults" -Value "Pass" -Force;if ($Log) {Write-Logfile "Pass - snapvaults are OK - no lags beyond scheduled times"}}
            $false { Write-Host -ForegroundColor $fail $SnapVaultResults; $serversummary += "$($NetAppNode.Node) - $($SnapVaultResults);";$serverObj | Add-Member NoteProperty -Name "SnapVaults" -Value "Fail" -Force;if ($Log) {Write-Logfile "Fail - snapvaults have fallen behind -$($NetAppNode.Node) - $($SnapVaultResults)"}}
            default { Write-Host -ForegroundColor $fail $SnapVaultResults; $serversummary += "$($NetAppNode.Node) - $($SnapVaultResults);";$serverObj | Add-Member NoteProperty -Name "SnapVaults" -Value "Fail" -Forceif ($Log) {Write-Logfile "Fail - snapvaults have fallen behind -$($NetAppNode.Node) - $($SnapVaultResults)"}}
            }       
        
        
        #$serverObj | Add-Member NoteProperty -Name "SnapVaults" -Value "Pass" -Force

#...................................
#Controller Alarms check
#...................................
        Write-Host "Controller Alerts: " -NoNewline
        if ($Log) {Write-Logfile "Controller Alerts: "}
        
        $AlertResults = Get-NcEmsMessage -Severity $AlertSeverity | where{$_.Node -match $NetAppNode.Node -and $_.TimeDT -gt (get-date).AddHours(-$MaxHoursToScanLog) } | select Node,TimeDT,Event 
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
                
            $AlertResults | ConvertTo-HTML -head $errorhtmlhead| out-file "$($OutputFolder)\netappReportErrors.html" -append
            }
        Switch (!$AlertResults) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Alerts" -Value "Pass" -Force;if ($Log) {Write-Logfile "No controller alerts"}}
            $false { Write-Host -ForegroundColor $fail "Fail"; $serversummary += "$($NetAppNode.Node) - System Errors - Check log for errors (click link above);";$serverObj | Add-Member NoteProperty -Name "Alerts" -Value "Fail" -Force;$SystemErrors = $true;if ($Log) {Write-Logfile "There are controller alerts`n`r$AlertResults"}}
            default { Write-Host -ForegroundColor $fail "Fail"; $serversummary += "$($NetAppNode.Node) - System Errors - Check log for errors (click link above);";$serverObj | Add-Member NoteProperty -Name "Alerts" -Value "Fail" -Force;$SystemErrors = $true;if ($Log) {Write-Logfile "There are controller alerts`n`r$AlertResults"}}
            }
        
#...................................        
#Networks check
#...................................
        Write-Host "Network: " -NoNewline
        if ($Log) {Write-Logfile "Network: "}
        $NetworkOK = $true
        $NetAppNetworkInterfaces = Get-NcNetInterface | where {$_.HomeNode -match $NetAppNode.Node}
        foreach ($NetAppNetworkInterface in $NetAppNetworkInterfaces){
            if ($NetAppNetworkInterface.IsHome -eq $False){
                $NetworkOK = $false;$serversummary += "$($NetAppNode.Node) - $($NetAppNetworkInterface.InterfaceName) is not at Home;";if ($Log) {Write-Logfile "$($NetAppNode.Node) - $($NetAppNetworkInterface.InterfaceName) is not at Home"}
                }
            if ($NetAppNetworkInterface.AdministrativeStatus -ne "up" -or $NetAppNetworkInterface.OperationalStatus -ne "up" -or $NetAppNetworkInterface.OpStatus -ne "up"){
                $NetworkOK = $false;$serversummary += "$($NetAppNode.Node) - $($NetAppNetworkInterface.InterfaceName) is not at Home;";if ($Log) {Write-Logfile "$($NetAppNode.Node) - $($NetAppNetworkInterface.InterfaceName) is not at Home"}
                }
            #Ping all data and nodeMgmt interfaces
            if ($NetAppNetworkInterface.Role -eq "node_mgmt" -or $NetAppNetworkInterface.Role -eq "data"){
                if ($Log) {Write-Logfile "Ping check:"}
                $ping = $null
                try {$ping = Test-Connection $NetAppNetworkInterface.Address -Quiet -ErrorAction Stop -Count 4}
                catch {if ($Log) {Write-Logfile "$_.Exception.Message"}}

                switch ($ping)
                    {
                    $true {if ($Log) {Write-Logfile "Pass $($NetAppNetworkInterface.InterfaceName) at address $($NetAppNetworkInterface.Address) is pingable"}}
                    default {
                        $NetworkOK = $false
                        $serversummary += "$($NetAppNetworkInterface.Role) interface $($NetAppNetworkInterface.InterfaceName) at address $($NetAppNetworkInterface.Address) is not pingable;"
                        if ($Log) {Write-Logfile "$($NetAppNetworkInterface.Role) interface $($NetAppNetworkInterface.InterfaceName) at address $($NetAppNetworkInterface.Address) is not pingable"}
                        if ($Log) {Write-Logfile "Fail"}
                        }
                    }
                    
                }

            }
        #find peer SVM or interfaces
        $NetAppClusterPeer = Get-NcClusterPeer 
        if ($NetAppClusterPeer){
            $NetAppClusterPeerHealth = Get-NcClusterPeerHealth 
            foreach ($NetAppPeer in $NetAppClusterPeerHealth){
                $NetAppPeerLastUpdated = ([int][double]::Parse((Get-Date (get-date).touniversaltime() -UFormat %s)) - $NetAppPeer.LastUpdated)
                #write-host "Peer Updated $($NetAppPeerLastUpdated) seconds ago"
                if ($Log) {Write-Logfile "Peer Updated $($NetAppPeerLastUpdated) seconds ago"}
                if ($NetAppPeer.DataPing -ne "interface_reachable" -or $NetAppPeer.IsClusterHealthy -ne "True" -or $NetAppPeer.IsDestinationNodeAvailable -ne "True" -or $NetAppPeer.IsNodeHealthy -ne "True" -or $NetAppPeerLastUpdated -gt 9600){
                    $NetworkOK = $false
                    #write-host "Cluster Peer at $($NetAppPeer.DestinationNode) ($($NetAppPeer.DestinationCluster)) is not operational;"
                    $serversummary += "Cluster Peer at $($NetAppPeer.DestinationNode) ($($NetAppPeer.DestinationCluster)) is not operational;"
                    if ($Log) {Write-Logfile "Cluster Peer at $($NetAppPeer.DestinationNode) ($($NetAppPeer.DestinationCluster)) is not operational"}
                        
                    }
                }
            }
        Switch ($NetworkOK) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Networks" -Value "Pass" -Force}
            #$true { Write-Host -ForegroundColor $fail "Fail";$serverObj | Add-Member NoteProperty -Name "Networks" -Value "Fail" -Force}
            $false { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Networks" -Value "Fail" -Force}
            default { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Networks" -Value "Fail" -Force}
            }
#...................................        
#Hardware check
#...................................
        #SP,Controller, Disks,Shelves
        Write-Host "Hardware: " -NoNewline
        if ($Log) {Write-Logfile "Hardware: "}
        
        
        $HardwareOK = $true
        #Service Processor
        $NetAppSP = Get-NcServiceProcessor -Node $NetAppNode.Node
        if (!$NetAppSP.IsIpConfigured){
            $HardwareOK = $false;$serversummary += "$($NetAppNode.Node) - Service Processor IP not configured;";if ($Log) {Write-Logfile "$($NetAppNode.Node) - Service Processor IP not configured"}
            }
        if ($NetAppSP.Status -ne "online"){
            $HardwareOK = $false;$serversummary += "$($NetAppNode.Node) - Service Processor not online;";if ($Log) {Write-Logfile "$($NetAppNode.Node) - Service Processor not online"}
            }  
        #Service Processor
        if ($NetAppSP.IpAddress -ne $null ){
            $ping = $null
            try {$ping = Test-Connection $NetAppSP.IpAddress -Quiet -ErrorAction Stop}
            catch {$HardwareOK = $false
            $serversummary += "$($NetAppNode.Node) - Service Processor - $($NetAppSP.IpAddress) failed to respond to Ping;";if ($Log) {Write-Logfile "$($NetAppNode.Node) - Service Processor - $($NetAppSP.IpAddress) failed to respond to Ping"}
            }

            switch ($ping)
                {
                $fail {$HardwareOK = $false}
                }
            }
        $NetAppSPNetwork = Get-NcServiceProcessorNetwork -Node $NetAppNode.Node | where {$_.AddressType -eq "ipv4"}
        if ($NetAppSPNetwork.SetupStatus -ne "succeeded" -or $NetAppSPNetwork.Status -ne "online" -or $NetAppSPNetwork.IsEnabled -ne "True" -or $NetAppSPNetwork.LinkStatus -ne "up"){
            $HardwareOK = $false;$serversummary += "$($NetAppNode.Node) - Service Processor not setup or not online;";if ($Log) {Write-Logfile "$($NetAppNode.Node) - Service Processor not setup or not online"}
            }
        $NetAppSPAutoSupport = Get-NcServiceProcessorAutoSupport 
        if ($NetAppSPAutoSupport.IsEnabled -ne "True" ){
            $HardwareOK = $false;$serversummary += "$($NetAppNode.Node) - Service Processor not setup for autosupport;";if ($Log) {Write-Logfile "$($NetAppNode.Node) - Service Processor not setup for autosupport"}
            }

        
        
        #Shelves
        $ShelfResults = Get-NcShelf -NodeName $NetAppNode.Node | where {$_.ModuleState -ne "ok" -or $_.ShelfState -ne "online"} |  select ShelfName
        Switch (!$ShelfResults) {
            $true {$HardwareOK = $true }
            $false {$HardwareOK = $false;$serversummary += "$($NetAppNode.Node) - $($ShelfResults) not Online;";if ($Log) {Write-Logfile "$($NetAppNode.Node) - $($ShelfResults) not Online"}}
            default {$HardwareOK = $false;$serversummary += "$($NetAppNode.Node) - $($ShelfResults) not Online;";if ($Log) {Write-Logfile "$($NetAppNode.Node) - $($ShelfResults) not Online"}}
            }
        #Disks
        $DiskResults = Get-NcDiskOwner * | where {$_.Owner -eq $NetAppNode.Node -and $_.IsFailed -ne $false} | select Name
        Switch (!$DiskResults) {
            $true {$HardwareOK = $true }
            $false {$HardwareOK = $false;$serversummary += "$($NetAppNode.Node) - $($DiskResults) failed;";if ($Log) {Write-Logfile "$($NetAppNode.Node) - $($DiskResults) failed"}}
            default {$HardwareOK = $false;$serversummary += "$($NetAppNode.Node) - $($DiskResults) failed;";if ($Log) {Write-Logfile "$($NetAppNode.Node) - $($DiskResults) failed"}}
            }

        Switch ($HardwareOK) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Pass" -Force}
            $false { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Fail" -Force}
            default { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Fail" -Force}
            }
        
#...................................
#Volumes check
#...................................
        Write-Host "Volumes: " -NoNewline
        if ($Log) {Write-Logfile "Volumes: "}
        $VolumesOK = $pass
        $NetAppVolumes = Get-NcVol  | where {$_.VolumeStateAttributes.IsNodeRoot -eq $false -and $_.Aggregate -in $NetAppAggregates.Name}
        #$VolumeFullPercentageWarning = 65
        #$VolumeFullPercentageError = 75
        foreach ($NetAppVolume in $NetAppVolumes){
            #write-host $NetAppVolume -ForegroundColor Yellow
            #$NetAppVolume | fl
            #exit
            #$NetAppVolume.VolumeSpaceAttributes | fl
            #$NetAppVolume.VolumeSnapshotAttributes | fl
            #exit
            if ($Log) {Write-Logfile "$($NetAppNode.Node) - $($NetAppVolume) is $($NetAppVolume.VolumeSpaceAttributes.PercentageSizeUsed)% full"}
            switch ($NetAppVolume.VolumeSpaceAttributes.PercentageSizeUsed){
                {$_ -gt $VolumeFullPercentageWarning -and $_ -lt $VolumeFullPercentageError} {$VolumesOK = $warn;$serversummary += "Warning - $($NetAppNode.Node) - $($NetAppVolume) is $($NetAppVolume.VolumeSpaceAttributes.PercentageSizeUsed)% full;";if ($Log) {Write-Logfile "$($NetAppNode.Node) - $($NetAppVolume) is $($NetAppVolume.VolumeSpaceAttributes.PercentageSizeUsed)% full"}}
                {$_ -gt $VolumeFullPercentageError} {$VolumesOK = $fail;$serversummary += "Error - $($NetAppNode.Node) - $($NetAppVolume) is $($NetAppVolume.VolumeSpaceAttributes.PercentageSizeUsed)% full;";if ($Log) {Write-Logfile "$($NetAppNode.Node) - $($NetAppVolume) is $($NetAppVolume.VolumeSpaceAttributes.PercentageSizeUsed)% full"}}
                }
            #$NetAppVolume.VolumeSpaceAttributes.PercentageSnapshotReserveUsed 
            if ($Log) {Write-Logfile "$($NetAppNode.Node) - $($NetAppVolume) Snapshot Reserve is $($NetAppVolume.VolumeSpaceAttributes.PercentageSnapshotReserveUsed)% full"}
            if ($NetAppVolume.VolumeSpaceAttributes.PercentageSnapshotReserveUsed -gt $VolumeSnapReserveFullPercentageError){
                $VolumesOK = $fail
                #Dump autodelete settings to log file if enabled
                #$NetAppVolume | fl
                #$NetAppVolume.VolumeSpaceAttributes | fl
                #$NetAppVolume.VolumeSnapshotAutodeleteAttributes  | fl
                $serversummary += "$($NetAppNode.Node) - $($NetAppVolume) Snapshot Reserve is $($NetAppVolume.VolumeSpaceAttributes.PercentageSnapshotReserveUsed)% full;"
                if ($Log) {Write-Logfile "$($NetAppNode.Node) - $($NetAppVolume) Snapshot Reserve is $($NetAppVolume.VolumeSpaceAttributes.PercentageSnapshotReserveUsed)% full"
                    Write-Logfile "$($NetAppNode.Node) - $($NetAppVolume) FYI Autodelete attributes set to:"
                    Write-Logfile "Commitment : $($NetAppVolume.VolumeSnapshotAutodeleteAttributes.Commitment)"
                    Write-Logfile "DeferDelete : $($NetAppVolume.VolumeSnapshotAutodeleteAttributes.DeferDelete)"
                    Write-Logfile "DeleteOrder : $($NetAppVolume.VolumeSnapshotAutodeleteAttributes.DeleteOrder)"
                    Write-Logfile "DestroyList : $($NetAppVolume.VolumeSnapshotAutodeleteAttributes.DestroyList)"
                    Write-Logfile "IsAutodeleteEnabled : $($NetAppVolume.VolumeSnapshotAutodeleteAttributes.IsAutodeleteEnabled)"
                    Write-Logfile "Prefix : $($NetAppVolume.VolumeSnapshotAutodeleteAttributes.Prefix)"
                    Write-Logfile "TargetFreeSpace : $($NetAppVolume.VolumeSnapshotAutodeleteAttributes.TargetFreeSpace)"
                    Write-Logfile "Trigger : $($NetAppVolume.VolumeSnapshotAutodeleteAttributes.Trigger)"
                   }
            
                }
            
            }
        
        
        Switch ($VolumesOK) {
            $pass { Write-Host -ForegroundColor $pass "Pass"; $serverObj | Add-Member NoteProperty -Name "Volumes" -Value "Pass" -Force}
            $warn { Write-Host -ForegroundColor $warn "Warn";$serverObj | Add-Member NoteProperty -Name "Volumes" -Value "Warn" -Force}
            $fail { Write-Host -ForegroundColor $fail "Fail";$serverObj | Add-Member NoteProperty -Name "Volumes" -Value "Fail" -Force}
            }
            
#...................................       
#SVMs check
#...................................
        Write-Host "SVMs: " -NoNewline
        if ($Log) {Write-Logfile "SVMs: "}
        $SVMStatus = "Pass"
        #Check SVM DNS entries and Ping
        $NetAppSVMs = get-ncvserver | where{$_.VserverType -eq "data"} 
        foreach ($NetAppSVM in $NetAppSVMs){
            $NetAppCIFSServer = Get-NcCifsServer -Name $NetAppSVM.VserverName
            if ($NetAppCIFSServer.AdministrativeStatus -ne "Up"){
                $serversummary += "$($NetAppNode.Node) - $($NetAppSVM.VserverName) not Up;"
                }
            #$NetAppDomainControllers = Find-NcCifsDomainServer -VserverContext $NetAppSVM.VserverName | where {$_.Node -eq $NetAppNode.Node}
            $NetAppDomainControllers = Get-NcCifsDomainServer -VserverContext $NetAppSVM.VserverName | where {$_.Status -eq "ok"}
            if (!$NetAppDomainControllers){
                $serversummary += "$($NetAppNode.Node) - Could not find domain controller for $($NetAppSVM.VserverName);"
                if ($Log) {Write-Logfile "$($NetAppNode.Node) - Could not find domain controller for $($NetAppSVM.VserverName);"}
                $SVMStatus = "Fail"
                }

            
            #Find the interface for this SVM to get the domain info
            $NetAppSVMInterface = get-ncnetinterface -Vserver $NetAppSVM.VserverName | where {$_.HomeNode -eq $NetAppNode.Node -and $_.DnsDomainName -ne "none"}
            try {$ip = @([System.Net.Dns]::GetHostByName($NetAppSVMInterface.DnsDomainName).AddressList | Select-Object IPAddressToString -ExpandProperty IPAddressToString)}
            catch {
                $serversummary += "$($NetAppNode.Node) - Could not find $($NetAppSVMInterface.DnsDomainName) in DNS;"
                if ($Log) {Write-Logfile "$($NetAppNode.Node) - Could not find $($NetAppSVMInterface.DnsDomainName) in DNS"}
                $ip = $null
                $SVMStatus = "Fail"
                }
            if ( $ip -ne $null ){
                $ping = $null
                if ($Log) {Write-Logfile "DNS Success: $ip"}
                try {$ping = Test-Connection $NetAppSVMInterface.DnsDomainName -Quiet -ErrorAction Stop}
                catch {#Write-Host -ForegroundColor $warn $_.Exception.Message
                $serversummary += "$($NetAppNode.Node) - $($NetAppSVMInterface.DnsDomainName) failed to respond to Ping;"
                if ($Log) {Write-Logfile "$($NetAppNode.Node) - $($NetAppSVMInterface.DnsDomainName) failed to respond to Ping"}
                }

                switch ($ping)
                {
                    $true {
                        }
                    default {
                        $SVMStatus = "Fail"
                        }
                    }
                }
            }
        Switch ($SVMStatus) {
            "Pass" { Write-Host -ForegroundColor $pass "Pass"; $serverObj | Add-Member NoteProperty -Name "SVMs" -Value "Pass" -Force}
            "Warn" { Write-Host -ForegroundColor $fail "Fail";$serverObj | Add-Member NoteProperty -Name "SVMs" -Value "Warn" -Force}
            "Fail" { Write-Host -ForegroundColor $fail "Fail";$serverObj | Add-Member NoteProperty -Name "SVMs" -Value "Fail" -Force}
            }
#...................................        
#Shares check
#...................................
        Write-Host "Shares: " -NoNewline
        if ($Log) {Write-Logfile "Shares: "}
        $SharesStatus = "Pass"
        #Get all shares on this node (shares presenting volumes that are in aggregates on this node)
        $NetAppSVMShares = Get-NcCifsShare -CifsServer $NetAppSVM.VserverName | where {(get-ncvol $_.Volume).Aggregate -in $NetAppAggregates.Name -and $_.ShareName -notmatch "admin" -and $_.ShareName -notmatch "ipc" -and $_.ShareName -notmatch "c"}
        foreach ($NetAppSVMShare in $NetAppSVMShares){
             $NetAppSVMInterface = get-ncnetinterface -Vserver $NetAppSVM.VserverName | where {$_.HomeNode -eq $NetAppNode.Node -and $_.DnsDomainName -ne "none"}
             #Can I map to it?
             $NetAppUNCPath = "\\$($NetAppSVMInterface.DnsDomainName)\$($NetAppSVMShare.ShareName)"
             $NetAppUNCPathResult = Test-Path -Path $NetAppUNCPath
             Switch ($NetAppUNCPathResult) {
                $false {$SharesStatus = "Fail";$serversummary += "$($NetAppNode.Node) - $($NetAppUNCPath) mapping failed;";if ($Log) {Write-Logfile "$($NetAppNode.Node) - $($NetAppUNCPath) mapping failed"}}
                }
            }
        Switch ($SharesStatus) {
            "Pass" { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Shares" -Value "Pass" -Force}
            "Warn" { Write-Host -ForegroundColor $fail "Fail";$serverObj | Add-Member NoteProperty -Name "Shares" -Value "Warn" -Force}
            "Fail" { Write-Host -ForegroundColor $fail "Fail";$serverObj | Add-Member NoteProperty -Name "Shares" -Value "Fail" -Force}
            }
#...................................        
#Aggregates check
#...................................

        Write-Host "Aggregates: " -NoNewline
        if ($Log) {Write-Logfile "Aggregates: "}
        $AggregatesStatus = "Pass"
        $NetAppAggregates2 = $NetAppAggregates | where {$_.AggrSpaceAttributes.PercentageSizeUsed -gt $AggregateFullPercentageWarning -and $_.AggrSpaceAttributes.PercentageSizeUsed -lt $AggregateFullPercentageError}
        foreach ($NetAppAggregate in $NetAppAggregates2){
            $serversummary += "$($NetAppNode.Node) - $($NetAppAggregate) is $($NetAppAggregate.AggrSpaceAttributes.PercentageSizeUsed)% full;";if ($Log) {Write-Logfile "$($NetAppNode.Node) - $($NetAppAggregate) is $($NetAppAggregate.AggrSpaceAttributes.PercentageSizeUsed)% full"}
            $AggregateStatus = "Warn"
            if ((Get-NcAggrStatus -Aggregate $NetAppAggregate).AggrWaflStatus -ne "Online"){
                $serversummary += "$($NetAppNode.Node) - $($NetAppAggregate) is not Online;";if ($Log) {Write-Logfile "$($NetAppNode.Node) - $($NetAppAggregate) is not Online"}
                $AggregateStatus = "Fail"
            
                }
            }
        $NetAppAggregates2 = $NetAppAggregates | where {$_.AggrSpaceAttributes.PercentageSizeUsed -gt $AggregateFullPercentageError}
        foreach ($NetAppAggregate in $NetAppAggregates2){
            $serversummary += "$($NetAppNode.Node) - $($NetAppAggregate) is $($NetAppAggregate.AggrSpaceAttributes.PercentageSizeUsed)% full;";if ($Log) {Write-Logfile "$($NetAppNode.Node) - $($NetAppAggregate) is $($NetAppAggregate.AggrSpaceAttributes.PercentageSizeUsed)% full"}
            $AggregateStatus = "Fail"
            if ((Get-NcAggrStatus -Aggregate $NetAppAggregate).AggrWaflStatus -ne "Online"){
                $serversummary += "$($NetAppNode.Node) - $($NetAppAggregate) is not Online;";if ($Log) {Write-Logfile "$($NetAppNode.Node) - $($NetAppAggregate) is not Online"}
                }
            }
        
        Switch ($AggregatesStatus) {
            "Pass" { Write-Host -ForegroundColor $pass "Pass"; $serverObj | Add-Member NoteProperty -Name "Aggregates" -Value "Pass" -Force}
            "Warn" { Write-Host -ForegroundColor $fail "Fail";$serverObj | Add-Member NoteProperty -Name "Aggregates" -Value "Warn" -Force}
            "Fail" { Write-Host -ForegroundColor $fail "Fail";$serverObj | Add-Member NoteProperty -Name "Aggregates" -Value "Fail" -Force}
            }
       
    

    
        #Add this servers output to the $report array
        $report = $report + $serverObj
    
        }         
    }



### Begin report generation
if ($ReportMode -or $SendEmail)
{
    #Get report generation timestamp
    $reportime = (Get-Date).ToString("dd/MM/yyyy HH:mm")

    #Create HTML Report
    #Common HTML head and styles
    
    if ($SystemErrors){            
                $htmlhead += "<a href=""$ReportURL"">Error Report File</a>"
                }
    #Check if the server summary has 1 or more entries
    if ($($serversummary.count) -gt 0)
    {
        #Set alert flag to true
        $alerts = $true
        # Create the error status file (if not already there)
        Out-File -FilePath "$($OutputFolder)\NetApp_Error_Status_Fail.txt"
        #Generate the HTML
        $serversummaryhtml = "<h3>NetApp Health Details</h3>
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
        $serversummaryhtml = "<h3>NetApp Health Details</h3>
                        <p>No NetApp health errors or warnings.</p>"
    }
    
    $htmlhead="<html>
                <head><title>NetApp GreenScreen - $servicestatus</title></head>
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
                <h1 align=""center"">NetApp Health Check Report</h1>
                <h3 align=""center"">Generated: $reportime</h3>"
        
    #netapp Health Report Table Header
    $htmltableheader = "<h3>NetApp Health Summary</h3>
                        <p>
                        <table>
                        <tr>
                        <th>Node</th>
                        <th>Cluster</th>
                        <th>DNS</th>
                        <th>Ping</th>
                        <th>Uptime</th>
                        <th>SnapMirrors</th>
                        <th>Snapshots</th>
                        <th>SnapVaults</th>
                        <th>Alerts</th>
                        <th>Networks</th>
                        <th>Hardware</th>
                        <th>Volumes</th>
                        <th>SVMs</th>
                        <th>Shares</th>
                        <th>Aggregates</th>
                        </tr>"

    #netapp Health Report Table
    
    $serverhealthhtmltable = $null
    $serverhealthhtmltable = $serverhealthhtmltable + $htmltableheader  
    
    foreach ($line in $report){
        #Pop reportlines into separate arrays based on whether they have errors or not
        #write-host "report line is"
        #write-host $line
        if ($line -match "Fail" -or $line -match "Warn"){
            write-host "$($line.node) has failures/warnings" -ForegroundColor Red
            $failreport += $line
            }
        else{
            write-host "$($line.node) is OK" -ForegroundColor Green
            $passreport += $line
            }
        }                    
                        
    #Add failures to top of table so they show up first
    foreach ($reportline in $failreport)
    {
        $htmltablerow = "<tr>"
        $htmltablerow += "<td>$($reportline.node)</td>"
        $htmltablerow += "<td>$($reportline.cluster)</td>"
        $htmltablerow += (New-ServerHealthHTMLTableCell "DNS")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Ping")
        
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

        $htmltablerow += (New-ServerHealthHTMLTableCell "SnapMirrors")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Snapshots")
        $htmltablerow += (New-ServerHealthHTMLTableCell "SnapVaults")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Alerts")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Networks")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Hardware")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Volumes")
        $htmltablerow += (New-ServerHealthHTMLTableCell "SVMs")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Shares")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Aggregates")
        $htmltablerow += "</tr>"
        
        $serverhealthhtmltable = $serverhealthhtmltable + $htmltablerow
    }

    #Add passes to bottom of table so they show up last
    foreach ($reportline in $passreport)
    {
        $htmltablerow = "<tr>"
        $htmltablerow += "<td>$($reportline.node)</td>"
        $htmltablerow += "<td>$($reportline.cluster)</td>"
        $htmltablerow += (New-ServerHealthHTMLTableCell "DNS")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Ping")
        
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

        $htmltablerow += (New-ServerHealthHTMLTableCell "SnapMirrors")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Snapshots")
        $htmltablerow += (New-ServerHealthHTMLTableCell "SnapVaults")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Alerts")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Networks")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Hardware")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Volumes")
        $htmltablerow += (New-ServerHealthHTMLTableCell "SVMs")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Shares")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Aggregates")
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
                Send-MailMessage $smtpsettings -To $recipients -Subject "$servicestatus - $reportemailsubject - $reportime" -Body $htmlreport -BodyAsHtml -Encoding ([System.Text.Encoding]::UTF8)
                }
        }
    }
}
### End report generation


Write-Host "End"
if ($Log) {Write-Logfile "End"}
Stop-Transcript

