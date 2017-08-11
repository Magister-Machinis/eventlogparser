#experimental adfs log extractor
param (
[parameter(mandatory = $true)][string]$target = $(throw "input target adfs event evtx for ip address extraction/analysis, quotation not needed "),
[string]$dest = ".\"
)

$target = resolve-path $target
$dest = $dest + "\adfs"
md $dest
$dest = resolve-path $dest

#regex voodoo for extracting email addresses
$emaddress = "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}"
$ipv4 = "\b((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b"

#string of interest
$interested = @("*The password for this account has expired*", "*The user's account has expired*","*saml*", "*The user name or password is incorrect*", "*InvalidOldPassword*", "*The referenced account is currently locked out and may not be logged on to*", "*wsfed*", "*Not all SAML session participants logged out properly*")
$unusual = @("*Relying party trust*", "*The SSL certificate does not contain all UPN suffix values that exist in the enterprise. Users with UPN suffix values not represented in the certificate will not be able to*", "*Workplace-Join their devices. For more information*", "*The same client browser session has made*")
write-host "extracting events from $target"
start-sleep -s 1
$EVEE = get-winevent -path $target | where {$_.id -ne "1000"}
$EVHASHlist = @()
$sizecount = 0
write-host "Processing ingested events"
start-sleep -s 1
$Names = @()
$CorIDs = @()
$IP = @()
#format juggling to sift out desired info
foreach($item in $EVEE)
{
    $EVXML = [xml]$item.toxml()
    $EVHASHlist += @{ID = $EVXML.event.system.eventid; TIME = [datetime]$EVXML.event.system.timecreated.systemtime; Host=$EVXML.event.system.Computer; CorellationID=$EVXML.event.system.correlation.activityid}
    
    
    $emaillist = @()
    $iplist = @()
    $Interesting = $null
    $strange = @()
    
    foreach($line in $EVXML.event.userdata.event.eventdata.data)
    {
        $emails = ([regex]::match($line, $emaddress)).value
        $Names += $emails
        foreach($items in $emails)
        {
            $emaillist += [string]$items
        }
        $ips = ([regex]::match($line, $ipv4)).value
        foreach($items in $ips)
        {
            $iplist += [string]$items
        }
        $IP += $iplist
        foreach($item2 in $interested)
        {
            if($line -like $item2)
            {
                $Interesting += (" | " + [string]$item2 + ", | ")
            }
        }
       
        foreach($item2 in $unusual)
        {
            if($line -like $item2)
            {
                $strange += [string](($line -join " ") -replace "`n", " ") + ", "
            }
        }
    }
    $Interesting = ((((($Interesting -split " | ") | where {$_ -ne ""} | select -unique) -join " ")))
    if($Interesting[0] -eq "|")
    {
        $Interesting = $Interesting -replace "^."
    }
    if($Interesting[-1] -eq "|")
    {
        $Interesting = $Interesting -replace ".$"
    }
    $Interesting = ($Interesting -replace "\*").trim()
    #$Interesting
    $EVHASHlist[-1].add("unusualitems", ($strange | sort -unique))
    $EVHASHlist[-1].add("interestingitems", $Interesting)
    $EVHASHlist[-1].add("extractedIPs", ($iplist | sort -unique))
    $EVHASHlist[-1].add("extractedemails", ($emaillist | sort -unique))
    $EVHASHlist[-1].add("rawdata", $EVXML.event.userdata.event.eventdata.data)
    foreach($item21 in $EVHASHlist[-1].keys)
    {
        if($EVHASHlist[-1].$item21 -eq "" -or $EVHASHlist[-1].$item21 -eq $null)
        {
            $EVHASHlist[-1].$item21 = "=|="
        }
    }
    $CorIDs += $EVHASHlist[-1].CorellationID
}
remove-variable EVEE
$CorIDs = $CorIDs | sort -unique
$Names | group | select-object Name,Count | sort Count -descending | out-file -filepath "$dest\emailtally.txt"
$Names | sort -unique | out-file -filepath "$dest\emaillist.txt"
$IP | group | select-object Name,Count | sort Count -descending | out-file -filepath "$dest\iptally.txt"
$IP | sort -unique | out-file -filepath "$dest\iplist.txt"

write-host "writing results"

$headers = "EventID`t Time`t Host`t CorellationID`t Extracted Emails`t Extracted IPs`t items of interest"
$headers | out-file -filepath "$dest\findings.csv"
foreach($item in $EVHASHlist)
{
    if($item.interestingitems -eq "" -or $item.interestingitems -eq $null)
    {
        [string]$temp = $item.id + "`t" + $item.time + "`t" + $item.host + "`t" + $item.CorellationID + "`t" + $item.extractedemails + "`t" + $item.extractedIPs + "`t" + $item.unusualitems
    }
    else
    {
        [string]$temp = $item.id + "`t" + $item.time + "`t" + $item.host + "`t" + $item.CorellationID + "`t" + $item.extractedemails + "`t" + $item.extractedIPs + "`t" + $item.interestingitems + ", " + $item.unusualitems
    }
   $temp = $temp.trim()
   
   while($temp[-1] -eq "|" -or $temp[-1] -eq ",")
   {
       $temp = $temp -replace ".$"
   }
   while($temp[0] -eq "|" -or $temp[0] -eq ",")
   {
       $temp = $temp -replace "^."
   }
   $temp.trim() | out-file -filepath "$dest\findings.csv" -append
}

write-host "results recorded, refining"
start-sleep -s 1
$CORlist= @{}
foreach($item in $CorIDs)
{
    $CORlist.add('$item', @("EventID`t Time`t Host`t CorellationID`t Extracted Emails`t Extracted IPs`t items of interest"))
}
$mainlist = import-csv -path "$dest\findings.csv" -delimiter "`t"
foreach($item in $mainlist)
{
    $line.CorellationID
    $CORlist.('$line.CorellationID') +=[string]@($item.EventID + "`t" + $item.Time + "`t" + $item.Host + "`t" + $item.CorellationID + "`t" + $item.'Extracted Emails' + "`t" + $item.'Extracted IPs' + "`t" + $item.'items of interest')
    $CORlist.'$item.CorellationID'
}
md "$dest\corellated"
foreach($item in $CorIDs)
{
    $pathname = [string]($item + ".csv")
    $CORlist.'$item' | out-file -filepath "$dest\corellated\$pathname"
}