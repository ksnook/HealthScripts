Start-Transcript -Path "c:\source\scripts\vmware\run-rvtools.log"

if (!(Test-Path "C:\Program Files (x86)\Robware\RVTools\RVtools.exe")){
    write-host "Please install RVTools" -ForegroundColor Red
    exit
    }

$VCServer = "vcserver.domain.net"
$VCCredential = Import-CliXml -Path c:\source\scripts\admin@sso_boh2.xml
$Path = "c:\source\scripts\vmware\RVTools"
if (!(Test-Path $Path)){
    write-host "Output path $($path) does not exist - please create it" -ForegroundColor Red
    exit
    }
#Get each vCenter on this connection and print RVTools for it
$VCConnection = Connect-VIServer $VCServer -Credential $VCCredential -AllLinked
$VCServerList = $global:DefaultVIServers
foreach ($VCServer in $VCServerList){
    write-host "Processing vCenter $($VCServer.Name)" -ForegroundColor Yellow
    write-host "Exporting to $($Path)\$($VCServer.Name)"
    if (!(Test-Path "$($Path)\$($VCServer.Name)")){
        write-host "Directory does not exist - creating directory" -ForegroundColor Red
        New-Item -Path "$($Path)\$($VCServer.Name)" -ItemType Directory
        }
    $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($VCCredential.Password))
    $ArgumentList = @("-s $($VCServer.Name)", "-u $($VCCredential.UserName)","-p $($password)", "-c ExportAll2xls", "-d $($Path)\$($VCServer.Name)" )
    write-host $ArgumentList
    Start-Process -FilePath "C:\Program Files (x86)\Robware\RVTools\RVtools.exe" -ArgumentList $ArgumentList -Wait
    }
disconnect-viserver * -confirm:$false
# Delete all RVTools Files that are older than 30 day(s)
$Daysback = "-30"
$CurrentDate = Get-Date
$DatetoDelete = $CurrentDate.AddDays($Daysback)
Get-ChildItem $Path -Recurse | Where-Object { $_.LastWriteTime -lt $DatetoDelete } | Remove-Item -Confirm:$false -Force -Recurse

Stop-Transcript
