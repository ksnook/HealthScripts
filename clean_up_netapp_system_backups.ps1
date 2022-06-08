$LogPath = "c:\source\scripts\netapp\logs"
$BackupsPath = "C:\inetpub\ftproot\NetApp"
$NumberOfClusters = 2
$GlobalRetention = @{}
$GlobalRetention."Deleting_files" = 10 # log files of that script
$GlobalRetention."8hour" = 20 * $NumberOfClusters
$GlobalRetention."daily" = 14 *  $NumberOfClusters
$GlobalRetention."weekly" = 8 * $NumberOfClusters
$Files = (Get-ChildItem $BackupsPath -Recurse) + (Get-ChildItem $LogPath) | sort CreationTime -Descending
$Deletefiles =  $Files | ? FullName -NotIn ($GlobalRetention.keys | % {$Files | ? Name -match $_ | select -First $GlobalRetention.$_}).FullName | ? PSIsContainer -eq $False
$Deletefiles  | select fullname,CreationTime | ft -AutoSize >> "$LogPath\$(get-date -Format "dd_MM_yyyy_HH_mm_ss")_Deleting_files.txt"
$Deletefiles  | rm 