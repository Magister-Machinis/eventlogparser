#weaving osint results into name associated file
param(
[parameter(mandatory = $true)][string]$targetfile,
[parameter(mandatory = $true)][object]$osinfo
)

$fileinfo = import-csv -path "$targetfile" -delimiter "`t"
$fileinfo = $fileinfo | select Address,EventID,Host,ID,Time,TimeElapsed,Duration,Notes,Country,URL,Rating | sort-object Time

for($i = 0; $i -lt $fileinfo.length; $i++)
{
    $addressholder = $fileinfo[$i].Address
    if($osinfo.$addressholder.URL -ne $null)
    {
        $fileinfo[$i].URL = $osinfo.$addressholder.URL
        #$osinfo.$addressholder.URL
    }
    if($osinfo.$addressholder.CountryName -ne $null)
    {
        $fileinfo[$i].Country = $osinfo.$addressholder.CountryName
    }
    $fileinfo[$i].Rating = $osinfo.$addressholder.Rating
    if($i -gt 0)
    {
        $fileinfo[$i].TimeElapsed = [datetime]$fileinfo[$i].Time - [datetime]$fileinfo[$i-1].Time
		if($fileinfo[$i].TimeElapsed -le 0)
		{
			$fileinfo[$i].TimeElapsed
		}
    }
}
$fileinfo | export-csv -path "$targetfile" -delimiter "`t" -NoTypeInformation