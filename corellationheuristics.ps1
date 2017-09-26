$HEURNAME = [scriptblock]{
param(
[string]$targetfile,
[string]$hmerun,
[string]$dest)
cd $hmerun
. .\anomaloustime.ps1
$targetfile
$flags = "Flags: | "
$fileinfo = import-csv -path $targetfile -delimiter "`t"
$filename = ($targetfile -split "\\")[-1]
$output
$fileinfo[1].Country
$filename

#time anomaly functions
$things = avganomaly $fileinfo $flags $dest
$fileinfo = $things[0]
$flags = $things[1]

$ratingaverage = 0
#rating check
foreach($line in $fileinfo)
{
    $ratingaverage += $line.rating
}
$ratingaverage = $ratingaverage / $fileinfo.length
$flags += "Average Rating: $ratingaverage | "

#multicountry check
for($i = 1; $i -le $fileinfo.length; $i++)
{
    if($fileinfo[$i-1].Country -ne $fileinfo[$i].Country)
    {
        $i = $fileinfo.length
        
        $flags += "multicountry | "
    }
}
$fileinfo | export-csv -path $targetfile -delimiter "`t" -notypeinformation
$filename = $filename -replace "csv","txt"
$flags | out-file -filepath "$dest\combined\heuristics\statistics\$filename"
$temp = [timespan]::fromseconds($timeaverage)
"Average session duration: `n$temp" | out-file -filepath "$dest\combined\statistics\$filename" -append
$temp = [timespan]::fromseconds($timedev)
"Standard deviation of session duration average: `n$temp" | out-file -filepath "$dest\combined\heuristics\statistics\$filename" -append


}
$HEURIP = [scriptblock]{
param(
[string]$targetfile,
[string]$hmerun,
[string]$dest)
cd $hmerun
. .\anomaloustime.ps1
$targetfile
$flags = "Flags: | "
$fileinfo = import-csv -path $targetfile -delimiter "`t"
$filename = ($targetfile -split "\\")[-1]
$output
$fileinfo[1].Country
$filename
#time anomaly functions   
$things = avganomaly $fileinfo $flags $dest
$fileinfo = $things[0]
$flags = $things[1]
#multiuser check
for($i = 1; $i -le $fileinfo.length; $i++)
{
    if($fileinfo[$i-1].user -ne $fileinfo[$i].user)
    {
        $i = $fileinfo.length
        $flags += "multiuser | "
    }
}
$ratingaverage = 0
#rating check
foreach($line in $fileinfo)
{
    $ratingaverage += $line.rating
}
$ratingaverage = $ratingaverage / $fileinfo.length
$flags += "Average Rating: $ratingaverage | "

$fileinfo | export-csv -path $targetfile -delimiter "`t" -notypeinformation

$filename = $filename -replace "csv","txt"
$flags | out-file -filepath "$dest\combined\statistics\$filename"


}


