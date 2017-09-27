#targets for the initial ingesters, the target file for output, and a list of which processing phases to enable (defaults to all active)
param (
[string]$securityeventtarget = 0,
[string]$terminaltarget = 0,
[string]$termlocaltarget = 0,
[string]$dest = ".\",
[int[]]$phases = @(1,2,3,4,5),
[string]$wideangle="NO"
)


$start = get-date #little timing mechanism
$dest = resolve-path $dest
write-host "security $securityeventtarget `n terminal $terminaltarget `n terminal local $termlocaltarget"
$eventstart = [scriptblock]{
param (
[string]$target,
[string]$dest,
[string]$loc,
[string]$wideangle="NO"
)

& $loc -target $target -dest $dest -wideangle $wideangle
get-content "$dest\securityevents\ips.txt" | out-file -filepath "$dest\ips.txt" -append
}
$termstart = {
param (
[string]$target,
[string]$dest,
[string]$loc,
[string]$wideangle="NO"
)

& $loc -target $target -dest $dest -wideangle $wideangle
get-content "$dest\connectionattempts\ips.txt" | out-file -filepath "$dest\ips.txt" -append
}
$localstart = [scriptblock]{
param (
[string]$target,
[string]$dest,
[string]$loc,
[string]$wideangle="NO"
)

& $loc -target $target -dest $dest -wideangle $wideangle
get-content "$dest\localsessions\ips.txt" | out-file -filepath "$dest\ips.txt" -append
}

$OSINTstart = [scriptblock]{
param(
[string]$target,
[string]$dest,
[string]$loc,
[string]$hmerun)
cd $hmerun
& $loc -source $target -outputtarget $dest -waitflag "NO"

}
$Combistart = [scriptblock]{

 param(
[string]$target,
[string]$loc,
[string]$hmerun)
cd $hmerun
& $loc -source $target

}
$OSNAMEWEAVE = [scriptblock]{
param(
[string]$file,
[object]$osint,
[string]$loc,
[string]$hmerun)
cd $hmerun
$file
$osint
& $loc -targetfile $file -osinfo $osint
}
$OSIPWEAVE = [scriptblock]{
param(
[string]$file,
[object]$osint,
[string]$loc,
[string]$hmerun)
cd $hmerun
$file
$osint
& $loc -targetfile $file -osinfo $osint
}
#calling in heuristics scriptblocks
. .\corellationheuristics.ps1
. .\anomaloustime.ps1
#starting initial extractors
$totalsize = 0

if($phases -contains 1)
{
    if($securityeventtarget -ne "0")
    {
        write-host "spawning security event extraction job"
        $securityeventtarget = resolve-path $securityeventtarget
        $totalsize += (get-item $securityeventtarget).length
        $loc = resolve-path '.\securityeventlogextractor.ps1'
        start-job -name "Security Events extraction" -scriptblock $eventstart -argumentlist $securityeventtarget,$dest,$loc,$wideangle
    }
    if($termlocaltarget -ne "0")
    {
        write-host "spawning local rdp event extraction job"
        $terminallocaltarget = resolve-path $termlocaltarget
        $totalsize += (get-item $termlocaltarget).length
        $loc = resolve-path '.\rdplocaleventlogextractor.ps1'
        start-job -name "Terminal Services Local extraction" -scriptblock $localstart -argumentlist $terminallocaltarget,$dest,$loc,$wideangle
    }
    if($terminaltarget -ne "0")
    {
        write-host "spawning rdp connection extraction job"
        $terminaltarget = resolve-path $terminaltarget
        $totalsize += (get-item $terminaltarget).length
        $loc = resolve-path '.\rdpeventlogextractor.ps1'
        start-job -name "Terminal Services extraction" -scriptblock $termstart -argumentlist $terminaltarget,$dest,$loc,$wideangle
    }
    write-host "Initiating phase 1 processing"
    get-job | wait-job | receive-job | out-file -filepath "$dest\phase1log.txt"
}
if($phases -contains 2)
{
    #combining output and gathering OSINT
    $loc = resolve-path ".\OsintParser\Gopher.ps1"
    $hmerun = resolve-path ".\"
    start-job -name "OSINT" -scriptblock $OSINTstart -argumentlist "$dest\ips.txt",$dest,$loc,$hmerun
    $loc = resolve-path ".\combinator.ps1"
    start-job -name "Correlation" -scriptblock $Combistart -argumentlist $dest,$loc,$hmerun
    write-host "Initiating phase 2 processing"
    get-job | wait-job | receive-job | out-file -filepath "$dest\phase2log.txt"
    Copy-item (Resolve-Path ".\OsintParser\ips.txt") (join-path -path $hmerun -childpath "\ips.txt)
}
if($phases -contains 3)
{
    get-content -path "$dest\inteloutput.csv" | select -skip 1 | out-file -filepath "$dest\temp.csv"
    $OSinfo = import-csv -path "$dest\temp.csv" -delimiter "`t"
    remove-item -path "$dest\temp.csv"

    #weaving osint into combined results
    write-host "Initiating phase 3 processing`n Merging OSINT with name associated records"
    $namefiles = get-childitem (join-path -path $dest -childpath "\combined\byname")
    $namesbyip = @{}
    $count = 0
    $countrylist= @()
    foreach($item in $OSinfo)
    {
        $temp = ((($item.'Address:Type') -split ":")[-1]).trim()
        $count += 1
        $namesbyip.$temp = $item
        $countrylist += $item.CountryName
    }
    $countrylist = $countrylist | sort -unique
    $loc = resolve-path ".\osint2names.ps1"
    foreach($thing in $namefiles)
    {
        start-job -scriptblock $OSNAMEWEAVE -argumentlist $thing.fullname,$namesbyip,$loc,$hmerun
    }
    write-host "Merging OSINT with ip associated records"
    $loc = resolve-path ".\osint2ip.ps1"
    $ipfiles = get-childitem (join-path -path $dest -childpath "\combined\byip")
    foreach($thing in $ipfiles)
    {
        start-job -scriptblock $OSIPWEAVE -argumentlist $thing.fullname,$namesbyip,$loc,$hmerun

    }

    get-job | wait-job | receive-job | out-file -filepath "$dest\phase3log.txt"
}
if($phases -contains 4)
{
    write-host "Information Gathering and integration complete"
    #creating aggregate file and applying heuristics based logic for anomaly detection
    write-host "Initiating phase 4 processing and heuristics"
    md "$dest\combined\statistics"
    


    foreach($thing in $namefiles)
    {
        start-job -scriptblock $HEURNAME -argumentlist $thing.fullname,$hmerun,$dest
    }
    write-host "Generating aggregate event list"
    $countrycount= @()
    $namecount = @()
    $ipcount = @()
    $count = 1
    $agdest = join-path -path $dest -childpath "\combined\aggregate.csv"
    foreach($thing in $ipfiles)
    {
        write-progress -activity "Processing $thing" -status "$count" -percentcomplete (($count/$ipfiles.length)*100)
        $count += 1
        $fileinfo = import-csv -path $thing.fullname -delimiter "`t" 
        $addressname = ($thing.fullname -split "\\")[-1] -split "\."
        $addressname = ($addressname[0..($addressname.count - 2)]) -join "."
        $fileinfo = $fileinfo | select User,IP,EventID,Host,ID,Time,TimeElapsed,Notes,Country,Url,Rating,Duration,DurationAnomaly,Pass1Anomaly,Pass2Anomaly,Pass3Anomaly,AnomalyRating
        $innercount = 1
        foreach($line in $fileinfo)
        {
            write-progress -id 1 -activity "Processing line $innercount" -percentcomplete (($innercount/$fileinfo.count)*100)
            $innercount += 1
            $line.IP = $addressname
            $countrycount += $line.Country
            $namecount += $line.User
            $ipcount += $line.IP
        }
        $fileinfo | export-csv -path $agdest -delimiter "`t" -NoTypeInformation -append 
        start-job -scriptblock $HEURIP -argumentlist $thing.fullname,$hmerun,$dest
    }


    $aggregate = import-csv -path "$dest\combined\aggregate.csv" -delimiter "`t" | sort-object Time
    start-job -scriptblock $HEURIP -argumentlist "$dest\combined\aggregate.csv",$hmerun,$dest
    
    $countrycount | group | select Name,Count | sort-object count -descending | out-file -filepath "$dest\combined\countrylist.txt"
    $namecount | group | select Name,Count | sort-object count -descending | out-file -filepath "$dest\combined\namelist.txt"
    $ipcount | group | select Name,Count | sort-object count -descending | out-file -filepath "$dest\combined\iplist.txt"

    get-job | wait-job | receive-job | out-file -filepath "$dest\phase4log.txt"
}

$end = get-date
$times= $end - $start
write-host "Event aggregation and correlation complete"
write-host "$totalsize bytes of data processed"
write-host "Time taken:"
$times
