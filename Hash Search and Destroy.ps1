#Lines 2 through 14 are used to establish multiple, networked computer searchs.
if (!(Test-Path "$home\hostlist.txt")){
	New-Item -Path $home -Name "hostlist.txt" -ItemType File
	Get-ADComputer -Filter * | Select-Object -ExpandProperty Name | Out-File -FilePath "$home\hostlist.txt"
	if ((Get-Item "$home\hostlist.txt").length -eq 0kb){
		Write-Host "`nSomething is Going Wring Accessing the Active Diresctory. please Try to Solve this Issue Before Trying Again" - BackgroundColor Red
		Remove-Item "$home\hostlist.txt"; sleep 8
		Write-Host "";break
	}
}

$targets = Get-Content "$home\hostlist.txt"

ForEach ($target in $targets){

Invoke-Command -cn $target -ScriptBlock {
    $hashs = $null
    #Checks all possible routes for Windows Disk Drives.
    [byte]$Alp = [char]'Z'
    Do {$Alpa = [char]$Alp
        #Adds hashs of all files recurisely from the root folder. Include keywords in the -Include section to filter on files for Interest.
        $hashs += Get-Childitem -path "$Alpa`:\" -Include "*1*","*.lnk" -ErrorAction SilentlyContinue -Recurse -Force | Get-FileHash 
        #Change Algorithm from MD5 to another one if desired.
        -Algorithm MD5 -ErrorAction SilentlyContinue
        $Alp--}
    Until ($Alp -lt 65)

    ForEach ($hash in $hashs){    
        #Place any hash\es below to match on. Either a single one "<HASH>" or multiple "((<HASH1>)|(<HASH2>)|(<HASH3>))"
        if ($hash -match "((<HASH1>)|(<HASH2>))") {
        $path = $hash | Select -Property path
        #If you don't want to delete a file, change the below line to specify what you want the scrip to do with hash matched files.
        Remove-Item -Path $path.Path -Force
        Write-Host "Found a malicious hash on $target, deleted $($path.Path)"
        }
    }}
}

Remove-Item -Path "$home\hostlist.txt" -Force
[System.Windows.MessageBox]::Show("`t`tScript has completed!")