#target security event evtx file, extractes logins and logouts and outputs analysis to dest folder

param (
[parameter(mandatory = $true)][string]$target = $(throw "input target security event evtx for ip address extraction/analysis, quotation not needed "),
[string]$dest = ".\"
)

$target = resolve-path $target
$dest = $dest + "\securityevents"
md $dest
$dest = resolve-path $dest

write-host "extracting events from $target"
start-sleep -s 1
$EVEE = get-winevent -path $target | where {$_.id -eq "4624" -or $_.id -eq "4634"}
$EVHASHlist = @()
$sizecount = 0
write-host "Processing ingested events"
start-sleep -s 1
#format juggling to sift out desired info
foreach($item in $EVEE)
{
    $EVXML = [xml]$item.toxml()
    $EVHASHlist += @{ID = $EVXML.event.system.eventid; TIME = [datetime]$EVXML.event.system.timecreated.systemtime; Host=$EVXML.event.system.Computer}
    foreach($particle in $EVXML.event.eventdata.data)
    {
        $EVHASHlist[-1].add($particle.name, $particle."#text")
    }
    write-progress -activity "Process Item#: " -status "$sizecount"
    $sizecount += 1
}
remove-variable EVEE

#EVHASHlist is now list of hashtables with: ID#, TIME, and contents of ITEM.event.eventdata.data

write-host "Eventlog ingested, processing"
start-sleep -s 1
write-host "..."
start-sleep -s 1
$IP = @()
$UserName = @()
$count = 0
foreach($item in $EVHASHlist)
{
    $perc= (($count/$EVHASHlist.length)*100)
    write-progress -activity "Processing item#: $count" -status "=][= $perc" -percentcomplete $perc
    $count += 1
    if($item.ContainsKey('IpAddress'))
    {
        $IP += $item.IpAddress
    }
    $UserName += $item.TargetUserName
}
$IP | sort -unique | out-file -filepath "$dest\ips.txt" 
$IP | group | select Name,Count | sort Count -descending | export-csv "$dest\iptally.csv"
$UserName2 = @()
foreach($name in $UserName)
{
    $UserName2 += ($name -split "\\")[-1]
}
$UserName2 | group | select Name,Count | sort Count -descending | export-csv "$dest\usernametally.csv"

#ditching unneeded variables and prepping for associations
remove-variable IP
$UserName = $UserName | sort -unique
$UserNameList = @{}
write-host "Preparing for Username/LogIO correlation"
start-sleep -s 1
foreach($name in $UserName)
{
    $UserNameList.add($name, @("Address:Port`t EventID`t Host`t ID`t Time`t Duration"))
    write-progress -activity "Preparing List of Usernames" -status "=][= " -percentcomplete (($UserNameList.count)/($UserName.length)*100)
}

write-host "associating usernames with logins/logouts and addresses, this may be slow"
start-sleep -s 1

$count = 0
$assoc = [string]([string]$dest + "\associations")
md $assoc

foreach($item in $EVHASHlist)
{
    $perc = (($count/$sizecount)*100)
    $UserNameList.($item.TargetUserName) += @($item.ipaddress + ":" +$item.IPPort + "`t" + $item.ID + "`t" + $item.Host + "`t" + $item.TargetLogonID + "`t" + $item.TIME)
    write-progress -activity "Correlating logs to usernames" -status "=][= $perc" -percentcomplete $perc
    $count += 1
}
remove-variable EVHASHlist
write-host "writing findings to file"
start-sleep -s 1
$count = 0
foreach($name in $UserName)
{
    [string]$namepath = $assoc + "\" + ($name -split "\\")[-1] + ".csv"
    $UserNameList.($name) | out-file -filepath $namepath
    write-progress "writing to files" -status "=][= $name" -percentcomplete (($count/($Username.length))*100)
    $count += 1
}
remove-variable UserNameList
remove-variable UserName

write-host "Associations recorded, processing times"
start-sleep -s 1

$files = get-childitem "$assoc"
$count = 0
foreach($file in $files)
{
    $subject = get-content $file.fullname
    $events = @()
    write-progress -activity "Processing $file" -status "=][= " -percentcomplete (($count/$files.length) *100)
    $count += 1
    for($i=0; $i -lt $subject.count; $i++)
    {
        $temp = $subject[$i] -split "`t"
        $subject[$i] = $temp
        $events += $temp[3]
    }
    $events = $events | sort -unique
    $subject = $subject | sort-object @{Expression={$_[3],$_[4]}}
    write-host "Event ids are: `n$events"
    $innercount = 0
    foreach($item in $events)
    {
        write-progress -id 1 -activity "Processing event id $item" -status "=][=" -percentcomplete (($innercount/$events.length)*100)
        $innercount += 1
        $first = $null
        $second = $null
        $line = 0
        $addressholder = $null
        for($i=1; $i -lt $subject.count; $i++)
        {
            if($subject[$i][3] -eq $item)
            {
                if([string]$subject[$i][1] -eq "4624")
                {
                    $first = [datetime]$subject[$i][4]
                    $addressholder = $subject[$i][0]
                }
                elseif(([string]$subject[$i][1] -eq "4634") -and ($first -ne $null))
                {
                    $second = [datetime]$subject[$i][4]
                    $line = $i
                }
            }
            if(($first -ne $null) -and ($second -ne $null))
            {
                $subject[$line] += ([datetime]$second - [datetime]$first)
                $subject[$i][0] = $addressholder
                $addressholder = $null
                $first = $null
                $second = $null
                $line = 0
            }
        }
    }
    
    for($i=0; $i -lt $subject.count; $i++)
    {
        $temp = $subject[$i] -join "`t"
        $subject[$i] = $temp
    }
    $subject | out-file -filepath $file.fullname
}
