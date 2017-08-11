#calculating average session duration for user and average rating
function avganomaly($fileinfo, $flags, $dest)
{
    $fileinfo = $fileinfo | select *,DurationAnomaly,Pass1Anomaly,Pass2Anomaly,Pass3Anomaly,AnomalyRating
    $timetotal = 0
    $counttotal = 0
    $ratingaverage = 0
    #calculating rating and duration averages
    foreach($line in $fileinfo)
    {
        if($line.duration -ne "")
        {
            $timetotal += [int32]([timespan]::parse($line.duration).totalseconds)
            $counttotal += 1
        }
        $ratingaverage += $line.rating

    }
    $timeaverage = $timetotal / $counttotal
    $ratingaverage = $ratingaverage / $fileinfo.length
    $flags += "Average Rating: $ratingaverage | "
    if($ratingaverage -gt 5)
    {
        $fileinfo | export-csv -path "$dest\combined\heuristics\averagerisk\$filename" -delimiter "`t"
    }
    #calculating standard deviation for duration
    $timetotal = 0
    foreach($line in $fileinfo)
    {
        if($line.duration -ne "")
        {
            $timetotal += ((([int32]([timespan]::parse($line.duration).totalseconds)) -$timeaverage) * (([int32]([timespan]::parse($line.duration).totalseconds)) -$timeaverage))
        }
    }
    $timedev = [math]::sqrt($timetotal / ($counttotal))
    $flags += "Number of sessions : $counttotal | "
    #outside of average check
    $counttotal = 0
    foreach($line in $fileinfo)
    {
        if($line.duration -ne ""){
            if([math]::abs(([int32]([timespan]::parse($line.duration).totalseconds))-$timeaverage) -ge $timedev)
            {
                $counttotal +=1
                $line.DurationAnomaly = "X"
            }
        }
    }
    
    #calculating first pass average and std dev elapsed time between events 
    $elapsedtime1 = 0
    $elapsedcount1 = 0
    $elapsedavg1 = 0
    $elapsedstddev1 = 0
    foreach($line in $fileinfo)
    {
        if([int32]([timespan]::parse($line.timeelapsed).totalseconds) -ne 0)
        {
            $elapsedtime1 += [int32]([timespan]::parse($line.timeelapsed).totalseconds)
            $elapsedcount1 += 1
        }
    }
    $elapsedavg1 = $elapsedtime1 / $elapsedcount1
    $flags += "First pass average elapsed time between events: $elapsedavg1 |"
    #std dev calculations
    foreach($line in $fileinfo)
    {
        if([int32]([timespan]::parse($line.timeelapsed).totalseconds) -ne 0)
        {
            $elapsedstddev1 += ((([int32]([timespan]::parse($line.timeelapsed).totalseconds)) -$elapsedavg1) * (([int32]([timespan]::parse($line.timeelapsed).totalseconds)) -$elapsedavg1))
        }
    }
    $elapsedstddev1 = [math]::sqrt($elapsedstddev1 / $elapsedcount1)
    $flags += "First pass std dev is : $elapsedstddev1"
    #first pass anomaly check
    foreach($line in $fileinfo)
    {
        if([int32]([timespan]::parse($line.timeelapsed).totalseconds) -ne 0)
        {
            if([math]::abs(([int32]([timespan]::parse($line.timeelapsed).totalseconds))-$elapsedavg1) -ge $elapsedstddev1)
            {
                $line.Pass1Anomaly = "X"
            }
        }
    }
    #calculating 2nd pass anomaly check, avg results from clusters, as determined from first pass check
    $pass2arrays = @()
    $temparray = @()
    $tempcount = 0
    #initial cluster identification, last values of each subarray is the avg
    foreach($line in $fileinfo)
    {
        if($line.Pass1Anomaly -eq "X")
        {
            $temparray.add(($tempcount / ($temparray.length)))
            $pass2arrays.add($temparray)
            $temparray = @()
            $tempcount = 0
        }
        else
        {
            $temparray.add([int32]([timespan]::parse($line.timeelapsed).totalseconds))
            $tempcount += [int32]([timespan]::parse($line.timeelapsed).totalseconds)
        }
    }
    #weighted avg for pass 2 
    $pass2avg = 0
    foreach($item in $pass2arrays)
    {
        $pass2avg += $item[-1]
    }
    #pass 2 std dev
    $pass2stddev = 0
    $tempcount = 0
    foreach($array in $pass2arrays)
    {
        for($i = 0; $i -lt $array.length; $i++)
        {
            $pass2stddev += [math]::abs($array[$i]-$pass2avg)*[math]::abs($array[$i]-$pass2avg)
            $tempcount += 1
        }
    }
    $pass2stddev = [math]::sqrt($pass2stddev / $tempcount)
    #pass 2 cluster identification
    foreach($line in $fileinfo)
    {
        if([math]::abs($line.timeelapsed - $pass2avg) -ge $pass2stddev)
        {
            $line.Pass2Anomaly = "X"
        }
    }
    if($counttotal -ne 0)
    {
        $output = join-path -path $dest -childpath "combined\heuristics\UnusualSessionDurations\$filename"
        $fileinfo | export-csv -path $output -delimiter "`t"
    }
    $flags += "Number of anomolously lengthed sessions: $counttotal | "
    return @($fileinfo, $flags)
}
