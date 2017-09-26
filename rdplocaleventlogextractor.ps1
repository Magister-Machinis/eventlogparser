#localsesssions rdp logs processing

param (
[parameter(mandatory = $true)][string]$target = $(throw "input target terminal services evtx for ip address extraction/analysis, quotation not needed "),
[string]$dest = ".\",
[string]$wideangle="NO"
)

function Test-FileLock {
  param (
    [parameter(Mandatory=$true)][string]$Path
  )

  $oFile = New-Object System.IO.FileInfo $Path

  if ((Test-Path -Path $Path) -eq $false) {
    return $false
  }

  try {
    $oStream = $oFile.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)

    if ($oStream) {
      $oStream.Close()
    }
    $false
  } catch {
    # file is locked by a process.
    return $true
  }
}
$target = resolve-path $target
$dest = $dest + "\localsessions"
md $dest
$dest = resolve-path $dest
$target
$dest
write-host "extracting events from $target"
start-sleep -s 1
$EVEE = @()
if($wideangle -eq "NO")
{
    $EVEE = get-winevent -path $target | where {$_.id -eq "21" -or $_.id -eq "22" -or $_.id -eq "23" -or $_.id -eq "24" -or $_.id -eq "25"}
}
else
{
    cd $target
	$templist = get-childitem $target -filter "*.evtx"
    #$templist = $templist | sort-object {get-random}
    foreach($item in $templist)
    {
		$item = resolve-path $item
		write-host "$item"
        while((Test-FileLock $item) -eq $true)
        {
            start-sleep -s 5
        }
        $EVEE += get-winevent -path $item | where {$_.id -eq "21" -or $_.id -eq "22" -or $_.id -eq "23" -or $_.id -eq "24" -or $_.id -eq "25"}
    }
}

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
        $EVHASHlist[-1].add($particle, $EVXML.event.userdata.eventxml.($particle))
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

while((Test-FileLock "$dest\ips.txt") -eq $true)
{
    start-sleep -s 5
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
    $UserNameList.add($name, @("Address `t EventID `t Host `t ID `t Time `t Duration"))
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
    if($item.containskey("address"))
    {
        $UserNameList.($item.User) += @($item.address + "`t" + $item.ID + "`t" + $item.Host + "`t" + $item.SessionID + "`t" + $item.TIME)
    }
    else
    {
        $UserNameList.($item.User) += @("`t" + $item.ID + "`t" + $item.Host + "`t" + $item.SessionID + "`t" + $item.TIME)
    }
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
    $subject = $subject | select -skip 1 | sort-object @{Expression={$_[3],$_[4]}}
    write-host "Event ids are: `n$events"
    $innercount = 0
    foreach($item in $events)
    {
        write-progress -id 1 -activity "Processing event id $item" -status "=][=" -percentcomplete (($innercount/$events.length)*100)
        $innercount += 1
        $first = $null
        $second = $null
        $addressholder = $null
        $line = 0
        for($i=0; $i -lt $subject.count; $i++)
        {
            if($subject[$i][3] -eq $item)
            {
                if([string]$subject[$i][1] -eq "21")
                {
                    $first = [datetime]$subject[$i][4]
                    $addressholder = $subject[$i][0]
                }
                elseif((([string]$subject[$i][1] -eq "23") -or ([string]$subject[$i][1] -eq "24") -and ($first -ne $null)))
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
        $temp = [string]($subject[$i] -join "`t")
        $subject[$i] = $temp + "`n"
    }
    $subject = ("Address`t EventID`t Host`t ID`t Time`t Duration`n") + $subject
    $subject | out-file -filepath $file.fullname
}

    