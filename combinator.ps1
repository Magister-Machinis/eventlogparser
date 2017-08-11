param(
[string]$source = ".\"
)

$source = resolve-path $source
$rdplocal = join-path -path $source -childpath "\localsessions"
$rdpcon = join-path -path $source -childpath "\connectionattempts"
$secevents = join-path -path $source -childpath "\securityeventresults"
$combinated = join-path -path $source -childpath "\combined"
$filelist = @()
$nameslist = @()
$iplist = @()
if(test-path $rdplocal)
{
    $filelist += get-childitem (join-path -path $rdplocal -childpath "\associations")
    $nameslist += (import-csv (join-path -path $rdplocal -childpath "\usernametally.csv")).name
    $iplist += (get-content (join-path -path $rdplocal -childpath "\ips.txt"))
}
if(test-path $rdpcon)
{
    $filelist += get-childitem (join-path -path $rdpcon -childpath "\associations")
    $nameslist += (import-csv (join-path -path $rdpcon -childpath "\usernametally.csv")).name
    $iplist += (get-content (join-path -path $rdpcon -childpath "\ips.txt"))
}
if(test-path $secevents)
{
    $filelist += get-childitem (join-path -path $secevents -childpath "\associations")
    $nameslist += (import-csv (join-path -path $secevents -childpath "\usernametally.csv")).name
    $iplist += (get-content (join-path -path $secevents -childpath "\ips.txt"))
}
$nameslist = $nameslist | sort -unique
$iplist = $iplist | sort -unique
write-host "List of names:`n $nameslist"
write-host "List of IP:`n $iplist"
write-host "List of Files: `n $filelist"
$namesdic= @{}
$ipdic= @{}
foreach($ip in $iplist)
{
    $ipdic.add($ip, @("User`t EventID`t Host`t ID`t Time`t Duration`t Notes"))
}
$ipdic.add("no-address", @("Address`t EventID`t Host`t ID`t Time`t Duration`t Notes"))
foreach($name in $nameslist)
{
    $namesdic.add($name, @("Address`t EventID`t Host`t ID`t Time`t Duration`t Notes"))
}
md $combinated
md (join-path -path $combinated -childpath "\byip")
md (join-path -path $combinated -childpath "\byname")

write-host "correlating by username"
start-sleep -s 1
$count = 0
foreach($file in $filelist)
{
    write-progress -activity  "Correlating $file" -status $count -percentcomplete $count
    $count += 1
    $bits = get-content $file.fullname
    $name = ([string]($file.name) -split "\.")[0]
    $innercount = 0
    for($i =1; $i -le $bits.length; $i++)
    {
        write-progress -id 1 -activity "Detailing $bits[$i]" -status $innercount
        $innercount += 1
        ($namesdic.($name)) += $bits[$i]
    }
}

write-host "correlation complete, writing data to files"
start-sleep -s 1
$count = 0
foreach($name in $nameslist)
{
    write-progress -activity  "Writing to $name" -status $count
    $count += 1
    $namepath = $name + ".csv"
    $namesdic.($name) | out-file (join-path -path $combinated -childpath "\byname\$namepath")
}
write-host "recording complete, processing"
start-sleep -s 1
$count = 0
$filelist = get-childitem (join-path -path $combinated -childpath "\byname")
$iddic = @{"21" = "Rdp session connect"; "22" = "Rdp Shell initiated"; "23" = "Rdp session logoff"; "24" = "Rdp session disconnect"; "25" = "Rdp session reconnect"; "1149" = "Rdp connection attempt"; "4624" = "General Login"; "4634" = "General Logoff"; "][" = "no ID"}
foreach($file in $filelist)
{
    write-progress -activity  "Processing $file" -status $count
    $count += 1
    $subject = import-csv -path $file.fullname -delimiter "`t" | sort-object @{expression={$_.time}}
    $innercount = 0
    foreach($line in $subject)
    {
        write-progress -id 1 -activity "Detailing $line" -status $innercount
        $innercount += 1
        $line.notes = $iddic.($line.eventid)
    }
    $subject | export-csv -path $file.fullname -delimiter "`t"
    $innercount = 0
    $filename = ([string]($file.name) -split "\.")[0]
    foreach($line in $subject)
    {
        write-progress -id 1 -activity  "Processing $line" -status $innercount
        $innercount += 1
        if($line.address -eq $null)
        {
            $ipdic.("no-address") += @($filename + "`t" + $line.EventID + "`t" + $line.host + "`t" + $line.id + "`t" + $line.time + "`t" + $line.duration + "`t" + $line.notes)
        }
        else
        {
            $ipdic.($line.address) += @($filename + "`t" + $line.EventID + "`t" + $line.host + "`t" + $line.id + "`t" + $line.time + "`t" + $line.duration + "`t" + $line.notes)
        }
    }
}
foreach($ip in $iplist)
{
    $ipname = $ip +".csv"
    $temp = @($ipdic.($ip))
    
    $temp | out-file -filepath (join-path -path $combinated -childpath "\byip\$ipname")
}