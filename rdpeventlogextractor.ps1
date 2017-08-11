#rdp logs processing

param (
[parameter(mandatory = $true)][string]$target = $(throw "input target terminal services local evtx for ip address extraction/analysis, quotation not needed "),
[string]$dest = ".\"
)

$target = resolve-path $target
$dest = $dest + "\connectionattempts"
md $dest
$dest = resolve-path $dest

write-host "extracting events from $target"
start-sleep -s 1
$EVEE = get-winevent -path $target | where {$_.id -eq "1149"}
$EVHASHlist = @()
$sizecount = 0
write-host "Processing ingested events"
start-sleep -s 1
#format juggling to sift out desired info
foreach($item in $EVEE)
{
    $EVXML = [xml]$item.toxml()
    $EVHASHlist += @{ID = $EVXML.event.system.eventid; TIME = [datetime]$EVXML.event.system.timecreated.systemtime; Host=$EVXML.event.system.Computer}
        foreach($particle in ($EVXML.event.userdata.eventxml.childnodes.tostring() -split " "))
    {
        if($particle -eq "Param1")
        {
            $EVHASHlist[-1].add("User", $EVXML.event.userdata.eventxml.($particle))
        }
        elseif($particle -eq "Param2")
        {
            $EVHASHlist[-1].add("Domain", $EVXML.event.userdata.eventxml.($particle))
        }
        elseif($particle -eq "Param3")
        {
            $EVHASHlist[-1].add("address", $EVXML.event.userdata.eventxml.($particle))
        }
        else
        {
            $EVHASHlist[-1].add($particle, $EVXML.event.userdata.eventxml.($particle))
        }
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
    if($item.ContainsKey('Address'))
    {
        $IP += $item.Address
    }
    $UserName += $item.User
}
$IP | sort -unique | out-file -filepath "$dest\ips.txt" -append
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
    $UserNameList.add($name, @("Address`t EventID`t Host`t ][`t Time"))
    write-progress -activity "Preparing List of Usernames" -status "=][= " -percentcomplete (($UserNameList.count)/($UserName.length)*100)
}
write-host "associating usernames with activity, this may be slow"
start-sleep -s 1

$count = 0
$assoc = [string]([string]$dest + "\associations")
md $assoc
write-host "List of names is $UserName"
foreach($item in $EVHASHlist)
{
    $perc = (($count/$sizecount)*100)
    $UserNameList.($item.User) += @($item.address + "`t" + $item.ID + "`t" + $item.Host + "`t ][`t" + $item.TIME)
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
    
    $UserNameList.$name | out-file -filepath $namepath
    write-progress "writing to files" -status "=][= $name" -percentcomplete (($count/($Username.length))*100)
    $count += 1
}