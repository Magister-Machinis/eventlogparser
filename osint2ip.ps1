#weaving osint results into IP sorted data
param(
[parameter(mandatory = $true)][string]$targetfile,
[parameter(mandatory = $true)][object]$osinfo
)
$targetfile

$fileinfo = import-csv -path "$targetfile" -delimiter "`t"
$addressname = ($targetfile -split "\\")[-1] -split "\."
$addressname = ($addressname[0..($addressname.count - 2)]) -join "."
$osline = $osinfo.$addressname
$osline
$fileinfo = $fileinfo | select User,EventID,Host,ID,Time,TimeElapsed,Duration,Notes,Country,Url,Rating | sort-object Time 
for($i = 0; $i -lt $fileinfo.length; $i++)
{
    if($osline.url -ne $null)
    {
        $fileinfo[$i].url = $osline.url
    }
    if($osline.CountryName -ne $null)
    {
        $fileinfo[$i].Country = $osline.CountryName
    }
    $fileinfo[$i].Rating = $osline.Rating
    if($i -gt 0)
    {
        $fileinfo[$i].TimeElapsed = [datetime]$fileinfo[$i].Time - [datetime]$fileinfo[$i-1].Time
		if($fileinfo[$i}.TimeElapsed -le 0)
		{
			$fileinfo[$i}.TimeElapsed
		}
    }
}
$fileinfo | export-csv -path "$targetfile" -delimiter "`t" -NoTypeInformation