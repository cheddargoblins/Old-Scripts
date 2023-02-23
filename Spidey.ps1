#This ps1 has been developed for use in Incident Response in a PowerShell enabled enviroment.

#region FolderCheck
Function CheckPullFolder {
#Checks to see if the Pull folder exists, if it doesn't the Pull folder is created
if (!(Test-Path "C:\Pull")) {
    New-Item -Path C:\ -Name "Pull" -Itemtype "directory"
    }
}

Function CheckReferenceMaterial {
#Checks to see if the Ref folder exists, if it doesn't the Ref folder is created
if (!(Test-Path C:\Pull\Ref)) {
	mkdir C:\Pull\Ref
    }
#Checks to see if the host refernce file exists, if it doesn't the below commands will attempt to create it
if (!(Test-Path C:\Pull\Ref\allhostlist.txt)){
	New-Item -Path C:\Pull\Ref -Name "allhostlist.txt" -Itemtype "file"
    Get-ADComputer -Filter * | Select-Object -ExpandProperty Name | Out-File -FilePath C:\Pull\Ref\allhostlist.txt
    if (!(Test-Path C:\Pull\ADUsers.txt)){
        Get-ADUser -Filter * -Properties Name,BadLogonCount,badPwdCount,CanonicalName,Created,DistinguishedName,Enabled,LogonWorkstations,MemberOf,PasswordLastSet,PasswordNeverExpires,PasswordNotRequired,SID,SIDHistory,LastBadPasswordAttempt,lastLogoff,lastLogon  | Out-file -filepath C:\Pull\ADUsers.txt
        }
    }
if ((Get-Item C:\Pull\Ref\allhostlist.txt).length -eq 0kb){
    Get-ADComputer -Filter * -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Out-File -FilePath C:\Pull\Ref\allhostlist.txt
    if ((Get-Item C:\Pull\Ref\allhostlist.txt).length -eq 0kb){
        Write-Host "`nSomething is Going Wrong Accessing the Active Directory. Please Try to Solve This Issue Before Trying Again" -BackgroundColor Red
        Remove-Item C:\Pull\Ref\allhostlist.txt; sleep 8
        Write-Host "";break
        }
    }

Write-Host "Please either manually check or enable the code comment within this scirpt to remove undesired computers from the the pull file located at 'C:\Pull\Ref\allhostlist.txt'"
#The Below command can filter out any computer naming schemes not want, just uncomment the command and replace the "REPLACE" portion below.
##(Get-Content C:\Pull\Ref\allhostlist.txt) -replace "REPLACE.*","" | sort | ? {$_.trim() -ne "" } | Set-Content C:\Pull\Ref\allhostlist.txt
}
#endregion FolderCheck

#region Startup
Function CheckWinRM {
#This function is used to check WinRM's status. This service is important because you need it for remoting with PowerShell.
#This portion checks the host computer to see if WinRM is Running
$winrm = Get-Service -Name WinRM | Select-Object Status
if ($winrm.Status -eq "Stopped") {
        Write-Host "`n`n`n`n`n`n`n`n`n`n`n`n`t`t`t`t`t" -NoNewline;Write-Host "Uh Oh, WinRM is NOT RUNNING on your host so this Script will not run remotely!`n`n"-BackgroundColor DarkRed;sleep 4; Continue
   }
CheckPullFolder
CheckReferenceMaterial
sleep 8
}

Function FixShell {
#This function is purely cosmetic as it changes the shell title, adjuzts the shells windows size and memory, and changes the shell's color scheme.
$ErrorActionPreference = "silentlycontinue"
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force -ErrorAction SilentlyContinue
$Host.UI.RawUI.WindowTitle = “Incident Response Pull Script"
$pshost = Get-Host

$psWindow = $pshost.UI.RawUI

$newSize =$psWindow.BufferSize

$newSize.Height = 4000
$newSize.Width = 170

$psWindow.BufferSize = $newSize

$newSize = $psWindow.WindowSize
$newSize.Height = 54
$newSize.Width = 160

$psWindow.WindowSize= $newSize

cmd /c color 17
$ErrorActionPreference = "continue"}
#endregion Startup

#Menu to Choose what comptuers to interact with
Function cho {
[string]$choimenu = @'
  From How Many Boxes Do You Want to Interact With?   
                                                      
      Will you be pulling from:                       
                                                      
      1.  All Reachable Boxes in the AD?              
      2.  Specific Multiple Hosts?                    
      3.  A Single Box?                               
                                                      
                  or                                  
                                                      
          Type Back to Go Back                        
'@
    Write-Host $choimenu -BackgroundColor Black    
    $cinput = Read-Host "Selection #"
    Write-Host ""

#This switch uses the 'cinput' (aka Choice Input) input from 2 lines up and directs the script to the next portion of the script that it needs to go to.
    switch ($cinput){
        1 {Multi}
        2 {Mutichoice}
        3 {Single}
        "Back"{Clear-Host; Write-Host "Going Back";sleep 2}
        default{Clear-Host; Write-Host "Invalid Choice... Try Again" -BackgroundColor Red}
		}
}

#region Choices
Function Multi{
#This Function is used to access the Active Directory and pull all reachable computers into a reference file called 'allhostlist.txt' because of how the computer names are pulled, the function also trims the non-computer name elements.
CheckPullFolder
CheckReferenceMaterial
$targets = Get-Content C:\Pull\Ref\allhostlist.txt
(&$prevprog)
}

Function Mutichoice {
#This function lists computer names in the 'hostlist.txt' file if avaible, if there are no names or if the names need to change it further asks if you want to change.
CheckPullFolder
if (!(Test-Path C:\Pull\Ref)) {
    New-Item -Path C:\Pull -Name "Ref" -Itemtype "directory"
    }
if (!(Test-Path C:\Pull\Ref\hostlist.txt)) {
    New-Item -Path C:\Pull\Ref -Name "hostlist.txt" -Itemtype "file"
    }
if ((Get-Item C:\Pull\Ref\hostlist.txt).length -gt 0){
      Write-Host " List of Hosts found. The following Hosts are on the list:`n"  -BackgroundColor Black
      Get-Content C:\Pull\Ref\hostlist.txt
      $keep = Read-Host "`nDo You Want to keep this list Y/N?"
        if ($keep -like "N*") {
            Remove-Item  C:\Pull\Ref\hostlist.txt
            New-Item -Path C:\Pull\Ref -Name "hostlist.txt" -Itemtype "file"
            }
      }
    
    Write-Host "`t`t`tWhen Entering Hosts, Please Use The Complete Hostnames. NO IPs.`t`t`t`nAfter Each Input, Confirm The New Addition.  When Typing Done, DO NOT CONFIRM OUTPUT" -BackgroundColor Black
	Do {$box = Read-Host "Enter Host or type Done to Exit "
        $box | Out-File -Append -FilePath C:\Pull\Ref\hostlist.txt -Confirm
        }
	until ($box -like "Do*")

#This section checks and removes any input that might be an accidental confrimed 'done'.
(Get-Content C:\Pull\Ref\hostlist.txt) -replace "Don.*","" | ? {$_.trim() -ne "" } | Set-Content C:\Pull\Ref\hostlist.txt

$targets = Get-Content C:\Pull\Ref\hostlist.txt
(&$prevprog)
}

Function Single {
#This Function is used only for a single computer.
CheckPullFolder

Write-Host " When Entering Host Please Use The Complete Host Name, No IP." ''  -BackgroundColor Black
Write-Host "`t`t`t`t" -NoNewline; Write-Host " Type Quit to Go Back" '' -BackgroundColor Black
$targets = Read-Host "Enter Host "
if ($targets -like "Qu*") {continue}
(&$prevprog)	
}

#endregion Choices

#region Pull
Function everything {
Write-Host "`t`t`t`t`t`t`t" -NoNewline;Write-Host " Welcome to the Pull Everything Script" '' -BackgroundColor Black
Write-Host "`t" -NoNewline;Write-Host " Everything being a pull of the Tasklist, Netstat, Services, System32, SysWOW64, Prefetch, Program Files, Jobs and the Temp Folder." -BackgroundColor Black

ForEach ($target in $targets) {
#The following IF statement will check to see if a folder for the computer target already exists and if it does, will rename the contents inside to the time it was last written to. This is done to keep the pull text files distinguished from one another.
If (Test-Path C:\Pull\$target){
	Get-ChildItem C:\Pull\$target -Include *txt -Exclude *_* -Recurse -Force | Rename-Item -newname {$_.BaseName + "_" + $_.LastWriteTime.toString("HH.mm") + ".txt"}}
else {
    mkdir C:\Pull\$target}

Write-Host "`n`t" -NoNewline;Write-Host " Beginning Pull of the Tasklist, Netstat, Services, System32, and Program Files for $target. All files will be saved in C:\Pull\$target"'' -BackgroundColor DarkGray

Write-Host "`n=======================Starting Tasklist==========================" -BackgroundColor DarkYellow
Invoke-Command -cn $target -ScriptBlock {Get-Process | Select-Object -ExpandProperty Path} | Out-File -FilePath C:\Pull\$target\$target-Tasklist.txt
Write-Host "=======================Tasklist Finished=========================="-BackgroundColor DarkYellow

Write-Host "`n=======================Starting NetStat===========================" -BackgroundColor DarkYellow
Invoke-Command -cn $target -ScriptBlock {netstat -anob} | Out-File -FilePath C:\Pull\$target\$target-Netstat.txt
Write-Host "=======================NetStat Finished==========================="-BackgroundColor DarkYellow

Write-Host "`n=======================Starting Services=========================="-BackgroundColor DarkYellow
Invoke-Command -cn $target -ScriptBlock {reg query HKLM\System\CurrentControlSet\Services} | Out-File -FilePath C:\Pull\$target\$target-Services.txt
(Get-Content C:\Pull\$target\$target-Services.txt) -replace "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\" | Set-Content C:\Pull\$target\$target-Services.txt
Write-Host "=======================Services Finished=========================="-BackgroundColor DarkYellow

Write-Host "`n======================Starting Program Files======================"-BackgroundColor DarkYellow
Invoke-Command -cn $target -ScriptBlock {Get-ChildItem "C:\Program Files" -Force | Format-Table -Property Name} | Out-File -FilePath C:\Pull\$target\$target-PF.txt
(Get-Content C:\Pull\$target\$target-PF.txt) -replace '   +', "          " | ? {$_.trim() -ne "" } | Set-Content C:\Pull\$target\$target-PF.txt
Write-Host "======================Program Files Finished======================"-BackgroundColor DarkYellow

Write-Host "`n======================Starting Prefetch==========================="-BackgroundColor DarkYellow
Invoke-Command -cn $target -ScriptBlock {Get-ChildItem C:\Windows\Prefetch -Force | Format-Table -Property Name} | Out-File -FilePath C:\Pull\$target\$target-PreFetch.txt
(Get-Content C:\Pull\$target\$target-PreFetch.txt) -replace '   +', "          " | ? {$_.trim() -ne "" } | Set-Content C:\Pull\$target\$target-PreFetch.txt
Write-Host "======================Prefetch Finished==========================="-BackgroundColor DarkYellow

Write-Host "`n======================Starting System32==========================="-BackgroundColor DarkYellow
Invoke-Command -cn $target -ScriptBlock {Get-ChildItem C:\Windows\System32 -Force | Format-Table -Property Name}  | Out-File -FilePath C:\Pull\$target\$target-S32.txt
(Get-Content C:\Pull\$target\$target-S32.txt) -replace '   +', "          " | ? {$_.trim() -ne "" } | Set-Content C:\Pull\$target\$target-S32.txt
Write-Host "======================System32 Finished==========================="-BackgroundColor DarkYellow

Write-Host "`n======================Starting SysWOW64==========================="-BackgroundColor DarkYellow
Invoke-Command -cn $target -ScriptBlock {Get-ChildItem C:\Windows\SysWOW64 -Force | Format-Table -Property Name}  | Out-File -FilePath C:\Pull\$target\$target-SW64.txt
(Get-Content C:\Pull\$target\$target-SW64.txt) -replace '   +', "          " | ? {$_.trim() -ne "" } | Set-Content C:\Pull\$target\$target-SW64.txt
Write-Host "======================SysWOW64 Finished==========================="-BackgroundColor DarkYellow

<#Write-Host '';Write-Host "======================Starting Command History===================="-BackgroundColor DarkYellow
Invoke-Command -cn $target -ScriptBlock {cmd /c "doskey /history"} -WarningAction SilentlyContinue | Out-File -FilePath C:\Pull\$target\$target-Commands.txt
Invoke-Command -cn $target -ScriptBlock {Get-History} -WarningAction SilentlyContinue | Out-File -Append -FilePath C:\Pull\$target\$target-Commands.txt
Write-Host "======================Command History Finished===================="-BackgroundColor DarkYellow#>

Write-Host "`n======================Starting Jobs==============================="-BackgroundColor DarkYellow
Invoke-Command -cn $target -ScriptBlock {schtasks;at} | Out-File -FilePath C:\Pull\$target\$target-Jobs.txt
Write-Host "======================Jobs Finished==============================="-BackgroundColor DarkYellow
<#$tasks = schtasks.exe /query /fo CSV | ConvertFrom-CSV;$myTask = $tasks | Select-Object {$_.TaskName} | Out-File -FilePath C:\Pull\$target\$target-Jobs.txt
(Get-Content C:\Pull\$target\$target-Jobs.txt) -replace "TaskName","" | out-file -FilePath C:\Pull\$target\$target-Jobs.txt#>

Write-Host "`n======================Starting Temp==============================="-BackgroundColor DarkYellow
Invoke-Command -cn $target -ScriptBlock {gci C:\Users\*\AppData\Local\Temp -Force -Recurse | Format-Table -Property Name}  | Out-File -FilePath C:\Pull\$target\$target-Temp.txt
(Get-Content C:\Pull\$target\$target-Temp.txt) -replace '   +', "          " | ? {$_.trim() -ne "" } | Set-Content C:\Pull\$target\$target-Temp.txt
Write-Host "======================Temp Finished==============================="-BackgroundColor DarkYellow

Write-Host "`n======================Starting Users==============================="-BackgroundColor DarkYellow
Invoke-Command -cn $target -ScriptBlock {Get-LocalUser | sort Enabled | Format-Table -Property Name,Enabled,Description} | Out-file -filepath C:\Pull\$target\$target-Users.txt
(Get-Content C:\Pull\$target\$target-Users.txt) -replace '   +', "          " | ? {$_.trim() -ne "" } | Set-Content C:\Pull\$target\$target-Users.txt
Write-Host "======================Users Finished==============================="-BackgroundColor DarkYellow

Write-Host "`n============================  Got Em   ===========================`n" -BackgroundColor DarkGray

$files = (Get-Childitem C:\Pull\$target -Recurse).FullName
ForEach ($file in $files) {
    if ((Get-Item $file).length -eq 0kb){
        sleep 3
        Write-Host "$file is empty. Either there was nothing to pull or something has gone wrong." -BackgroundColor Red
        remove-item $file
    }}
Get-ChildItem C:\Pull -recurse | Where {$_.PSIsContainer -and `
@(Get-ChildItem -Lit $_.Fullname -r | Where {!$_.PSIsContainer}).Length -eq 0} | Remove-Item -recurse -Force
}}

Function nettask {
Write-Host "`t`t`t`t`t`t" -NoNewline;Write-Host " Welcome to the Short Pulling Script for Tasklist and Netstat" ''  -BackgroundColor Black

ForEach ($target in $targets) {
If (Test-Path C:\Pull\s$target){
	Get-ChildItem C:\Pull\s$target -Include *txt -Exclude *_* -Recurse -Force | Rename-Item -newname {$_.BaseName + "_" + $_.LastWriteTime.toString("HH.mm") + ".txt"}}
else {
    mkdir C:\Pull\s$target}

Write-Host "`n`t`t`t" -NoNewline;Write-Host " Beginning Pull of the Tasklist and Netstat for $target. All files will be saved in C:\Pull\s$target"'' -BackgroundColor DarkGray

Write-Host "`n=======================Starting Tasklist========================="-BackgroundColor DarkYellow
Invoke-Command -cn $target -ScriptBlock {Get-Process | Select-Object -ExpandProperty Path} | Out-File -FilePath C:\Pull\s$target\s$target-Tasklist.txt -width 180
Write-Host "=======================Tasklist Finished========================="-BackgroundColor DarkYellow

Write-Host "`n=========================Starting NetStat========================"-BackgroundColor DarkYellow
Invoke-Command -cn $target -ScriptBlock {netstat -anob} | Out-File -FilePath C:\Pull\s$target\s$target-Netstat.txt -width 180
Write-Host "=========================NetStat Finished========================"-BackgroundColor DarkYellow

Write-Host "`n============================  Got Em   ==========================`n" -BackgroundColor DarkGray

if (Test-Path C:\Pull\s) {Remove-Item C:\Pull\s}

$files = (Get-Childitem C:\Pull\s$target).FullName
ForEach ($file in $files) {
    if ((Get-Item $file).length -eq 0kb){
        sleep 5
        Write-Host "$file is empty. Either there was nothing to pull or something has gone wrong." -BackgroundColor Red
        remove-item $file
    }}
#Recursively searches the Pull folder for empty folders and deletes them when found.
Get-ChildItem C:\Pull -recurse | Where {$_.PSIsContainer -and `
@(Get-ChildItem -Lit $_.Fullname -r | Where {!$_.PSIsContainer}).Length -eq 0} |Remove-Item -recurse

<##Recursively searches the Pull folder for empty folders and deletes them when found. Messier version than the section above.
(gci C:\Pull -r | ? {$_.PSIsContainer -eq $True}) | ? {$_.GetFiles().Count -eq 0} | select FullName |Out-File -FilePath C:\Pull\Empty.txt
(Get-Content C:\Pull\Empty.txt) -replace "FullName" -replace "--------" -replace " +" | ? {$_.trim() -ne "" } | Out-File -FilePath C:\Pull\Empty.txt
$folders = Get-Content C:\Pull\Empty.txt
ForEach ($folder in $folders) {
    Write-Host "$folder is empty. Either there was nothing to pull or something has gone wrong." -BackgroundColor Red
    Remove-Item $folder
}#>
}}

Function s32pf {
Write-Host "`t`t`t" -NoNewline;Write-Host " Welcome to the Detailed Pulling Script for System32, Prefetch, SysWOW64, Services and Program Files" -BackgroundColor Black

ForEach ($target in $targets) {
    If (Test-Path C:\Pull\s$target){
	Get-ChildItem C:\Pull\s$target -Include *txt -Exclude *_* -Recurse -Force | Rename-Item -newname {$_.BaseName + "_" + $_.LastWriteTime.toString("HH.mm") + ".txt"}}
    else {
        mkdir C:\Pull\s$target}

Write-Host "`n`t  " -NoNewline;Write-Host " Beginning Pull of the Names of System32, Prefetch, and Program Files for $target. All files will be saved in C:\Pull\s$target" -BackgroundColor DarkGray

Write-Host "`n======================Starting Program Files====================="-BackgroundColor DarkYellow
Invoke-Command -cn $target -ScriptBlock {Get-ChildItem "C:\Program Files" -Force | Format-Table -Property Name, Length, LastWriteTime -HideTableHeader} | Out-File -FilePath C:\Pull\s$target\s$target-PF.txt #-width 180
(Get-Content C:\Pull\s$target\s$target-PF.txt) -replace '   +', "          " | ? {$_.trim() -ne "" } | Set-Content C:\Pull\s$target\s$target-PF.txt
Write-Host "======================Program Files Finished====================="-BackgroundColor DarkYellow
    
Write-Host "`n=========================Starting System32======================="-BackgroundColor DarkYellow
Invoke-Command -cn $target -ScriptBlock {Get-ChildItem C:\Windows\System32 -Force | Format-Table -Property Name, Length, LastWriteTime -HideTableHeader}  | Out-File -FilePath C:\Pull\s$target\s$target-S32.txt  #-width 180
(Get-Content C:\Pull\s$target\s$target-S32.txt) -replace '   +', "          " | ? {$_.trim() -ne "" } | Set-Content C:\Pull\s$target\s$target-S32.txt
Write-Host "=========================System32 Finished======================="-BackgroundColor DarkYellow
    
Write-Host "`n======================Starting Prefetch=========================="-BackgroundColor DarkYellow
Invoke-Command -cn $target -ScriptBlock {Get-ChildItem C:\Windows\Prefetch -Force | Format-Table -Property Name, Length, LastWriteTime -HideTableHeader} | Out-File -FilePath C:\Pull\s$target\s$target-PreFetch.txt
(Get-Content C:\Pull\s$target\s$target-PreFetch.txt) -replace '   +', "          " | ? {$_.trim() -ne "" } | Set-Content C:\Pull\s$target\s$target-PreFetch.txt
Write-Host "======================Prefetch Finished=========================="-BackgroundColor DarkYellow
    
Write-Host "`n======================Starting SysWOW64=========================="-BackgroundColor DarkYellow
Invoke-Command -cn $target -ScriptBlock {Get-ChildItem C:\Windows\SysWOW64 -Force | Format-Table -Property Name, Length, LastWriteTime -HideTableHeader}  | Out-File -FilePath C:\Pull\s$target\s$target-SW64.txt
(Get-Content C:\Pull\s$target\s$target-SW64.txt) -replace '   +', "          " | ? {$_.trim() -ne "" } | Set-Content C:\Pull\s$target\s$target-SW64.txt
Write-Host "======================SysWOW64 Finished=========================="-BackgroundColor DarkYellow
    
Write-Host "`n=======================Starting Services========================="-BackgroundColor DarkYellow
Invoke-Command -cn $target -ScriptBlock {reg query HKLM\System\CurrentControlSet\Services} | Out-File -FilePath C:\Pull\s$target\s$target-Services.txt
(Get-Content C:\Pull\s$target\s$target-Services.txt) -replace "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\" | Set-Content C:\Pull\s$target\s$target-Services.txt
Write-Host "=======================Services Finished========================="-BackgroundColor DarkYellow
    
Write-Host "`n============================  Got Em   ==========================`n" -BackgroundColor DarkGray

$files = (Get-Childitem C:\Pull\s$target).FullName
ForEach ($file in $files) {
    if ((Get-Item $file).length -eq 0kb){
        sleep 5
        Write-Host "$file is empty. Either there was nothing to pull or something has gone wrong." -BackgroundColor Red
        remove-item $file 
        }}
Get-ChildItem C:\Pull -recurse | Where {$_.PSIsContainer -and `
@(Get-ChildItem -Lit $_.Fullname -r | Where {!$_.PSIsContainer}).Length -eq 0} | Remove-Item -recurse
}}

Function runkeys {
if (!(Test-Path C:\Pull\Ref)) {
   New-Item -Path C:\Pull -Name Ref -Itemtype "Directory"}

ForEach ($target in $targets) {
If (Test-Path C:\Pull\$target){
	Get-ChildItem C:\Pull\$target -Include *txt -Exclude *_* -Recurse -Force | Rename-Item -newname {$_.BaseName + "_" + $_.LastWriteTime.toString("HH.mm") + ".txt"}}
else {
    mkdir C:\Pull\$target}

If (Test-Path C:\Pull\$target\$target-runkeys.txt){
	Get-ChildItem C:\Pull\$target\$target-runkeys.txt -Include *txt -Exclude *_* -Recurse -Force | Rename-Item -newname {$_.BaseName + "_" + $_.LastWriteTime.toString("HH.mm") + ".txt"}}
if (!(Test-Path C:\Pull\Ref\userlists-$target.txt)) {
    Invoke-Command -cn $target -ScriptBlock {Get-ChildItem "C:\Users" | Format-Table -Property Name} | Out-file -Encoding ascii -filepath C:\Pull\Ref\userlists-$target.txt
    (Get-Content C:\Pull\Ref\userlists-$target.txt) -replace "Name" -replace "----" | Set-Content C:\Pull\Ref\userlists-$target.txt
    $(foreach ($line in Get-Content C:\Pull\Ref\userlists-$target.txt) {$line.tolower().split(" ")}) | Get-Unique | sort | ? {$_.trim() -ne "" } | Set-Content C:\Pull\Ref\userlists-$target.txt}
$users = Get-Content C:\Pull\Ref\userlists-$target.txt

Write-Host "`t`t`t" -NoNewline;Write-Host "Start searching for $target run keys"  -BackgroundColor DarkGray

Write-Host "`n=============Starting looking for the HKLM\\\Run Key============="-BackgroundColor DarkYellow
echo "--HKLM Run------------------------------------------------------------------------------------------"| Out-File -FilePath C:\Pull\$target\$target-runkeys.txt
Invoke-Command -ComputerName $target -ScriptBlock {reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run} | Out-File -FilePath C:\Pull\$target\$target-runkeys.txt.txt
Write-Host "=============Stopped looking for the HKLM\\\Run Key=============="-BackgroundColor DarkYellow

Write-Host "`n===========Starting looking for the HKLM\\\RunOnce Key==========="-BackgroundColor DarkYellow
echo "--HKLM RunOnce--------------------------------------------------------------------------------------"| Out-File -Append -FilePath C:\Pull\$target\$target-runkeys.txt
Invoke-Command -ComputerName $target -ScriptBlock {reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce} | Out-File -Append -FilePath C:\Pull\$target\$target-runkeys.txt.txt
Write-Host "===========Stopped looking for the HKLM\\\RunOnce Key============"-BackgroundColor DarkYellow

Write-Host "`n=============Starting looking for the HKCU\\\Run Key============="-BackgroundColor DarkYellow
echo "--HKCU Run------------------------------------------------------------------------------------------"| Out-File -Append -FilePath C:\Pull\$target\$target-runkeys.txt
Invoke-Command -ComputerName $target -ScriptBlock {reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run} | Out-File -Append -FilePath C:\Pull\$target\$target-runkeys.txt
Write-Host "=============Stopped looking for the HKCU\\\Run Key=============="-BackgroundColor DarkYellow

Write-Host "`n===========Starting looking for the HKCU\\\RunOnce Key==========="-BackgroundColor DarkYellow
echo "--HKCU RunOnce--------------------------------------------------------------------------------------"| Out-File -Append -FilePath C:\Pull\$target\$target-runkeys.txt
Invoke-Command -ComputerName $target -ScriptBlock {reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce} | Out-File -Append -FilePath C:\Pull\$target\$target-runkeys.txt
Write-Host "===========Stopped looking for the HKCU\\\RunOnce Key============"-BackgroundColor DarkYellow

ForEach ($user in $users) {
Write-Host "`n===========Starting looking for the HKCU\$user\\Startup==========="-BackgroundColor DarkYellow
echo "--$user Startup-------------------------------------------------------------------------------------"| Out-File -Append -FilePath C:\Pull\$target\$target-runkeys.txt
Invoke-Command -ComputerName $target -ScriptBlock {Get-ChildItem "C:\Users\$using:user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" -Force -ErrorAction SilentlyContinue} | Out-File -Append -FilePath C:\Pull\$target\$target-runkeys.txt
Write-Host "===========Stopped looking for the HKCU\$user\\Startup============"}-BackgroundColor DarkYellow

Write-Host "`n============================  Got Em   ===========================`n"-BackgroundColor DarkGray}

$files = (Get-Childitem C:\Pull\$target).FullName
ForEach ($file in $files) {
    if ((Get-Item $file).length -eq 0kb){
        sleep 5
        Write-Host "$file is empty. Either there was nothing to pull or something has gone wrong." -BackgroundColor Red
        remove-item $file 
}}
Get-ChildItem C:\Pull -recurse | Where {$_.PSIsContainer -and `
@(Get-ChildItem -Lit $_.Fullname -r | Where {!$_.PSIsContainer}).Length -eq 0} | Remove-Item -recurse}

Function logs {
Write-Host "`t`t`t" -NoNewline;Write-Host " Lincoln Logs" -BackgroundColor Black

If (Test-Path C:\Pull\Logs){
	Get-ChildItem C:\Pull\Logs -Include *txt -Exclude *_* -Recurse -Force | Rename-Item -newname {$_.BaseName + "_" + $_.LastWriteTime.toString("HH.mm") + ".txt"}}
else {
    mkdir C:\Pull\Logs}

ForEach ($target in $targets) {
$date= [datetime]::Today.AddDays(-1)
Invoke-Command -cn $target -ScriptBlock {Get-EventLog -LogName Security -InstanceId 4672,4624,4634,4647,4673,4674,4697,4720,4738,4781,4728,4727,4764,4737,4735,4732 -After $date | Select-Object -Property Index,TimeGenerated,EntryType,InstanceId,Message |Sort-Object -Property InstanceId | Format-Table -AutoSize -Wrap} | Out-File -FilePath C:\Pull\$target\$target-SpecificLogs.txt
}

$box = $env:COMPUTERNAME

ForEach ($target in $targets) {
if (!(Get-PSSession -ComputerName $target -State Opened)){
        $ses = New-PSSession -ComputerName $target}
else {$ses = Get-PSSession -ComputerName $target -State Opened}

Invoke-Command -Session $ses -ScriptBlock {
if (Test-Path C:\Windows\System32\winevt\Logs) {
	Copy-item C:\Windows\System32\winevt\Logs -Destination \\$using:box\C$\Pull\Logs\$using:target-Logs -Recurse -Force
}
  
Write-Host "`n============================  Got Em   =========================="-BackgroundColor DarkGray


Write-Host "`n======================== Starting Logparser ====================="-BackgroundColor DarkYellow
if (Test-Path C:\windows\system32\logparser.exe){
    ForEach ($target in $targets) {
    cmd /c cd C:\Pull\Logs\$target-Logs
    cmd /c C:\windows\system32\logparser.exe "SELECT * INTO *.csv FROM *.evtx`" -i:evt -o:csv"}
    Write-Host "======================== Logparser Finished =====================`n"-BackgroundColor DarkYellow
    }
else{Write-Host "======================== Logparser Program Not Found! Please locate and place in the C:\windows\system32 folder! =====================`n"-BackgroundColor Red}
}}}

#endregion Pull

#region custom
Function taskl {
Write-Host "`t`t`t`t" -NoNewline; Write-Host "Tasklist Pull"'' -BackgroundColor Black
Write-Host "Enter ''Full'' or ''Short'' for pull type" -NoNewline -BackgroundColor Black; $choice = Read-Host " "
	
ForEach ($target in $targets) {	
if (!(Test-Path C:\Pull\Custom\$target)){
    mkdir C:\Pull\Custom\$target}

if ($choice -like "F*"){
        Write-Host "------------------------------Full-------------------------------"-BackgroundColor DarkGray
   		Write-Host "=======================Starting Tasklist========================="-BackgroundColor DarkYellow
		Invoke-Command -cn $target -ScriptBlock {Get-Process | Select-Object -ExpandProperty Path} | Out-File -FilePath C:\Pull\Custom\$target\$target-Tasklist.txt
		Write-Host "=======================Tasklist Finished========================="-BackgroundColor DarkYellow}
else {
		Write-Host "-----------------------------Short-------------------------------"-BackgroundColor DarkGray
		Write-Host "=======================Starting Tasklist========================="-BackgroundColor DarkYellow
		Invoke-Command -cn $target -ScriptBlock {Get-Process | Format-Table -Property ProcessName, OriginalFilename, Name} | Out-File -FilePath C:\Pull\Custom\$target\s$target-Tasklist.txt
		Write-Host "=======================Tasklist Finished========================="-BackgroundColor DarkYellow
}}}

Function netat {
Write-Host "`t`t`t`t" -NoNewline; Write-Host "Netstat Pull"'' -BackgroundColor Black
Write-Host "Enter ''Full'' or ''Short'' for pull type" -NoNewline -BackgroundColor Black; $choice = Read-Host " "
	
ForEach ($target in $targets) {	
if (!(Test-Path C:\Pull\Custom\$target)){
    mkdir C:\Pull\Custom\$target}

if ($choice -like "F*"){
        Write-Host "------------------------------Full-------------------------------"-BackgroundColor DarkGray
		Write-Host "=========================Starting NetStat========================"-BackgroundColor DarkYellow
		Invoke-Command -cn $target -ScriptBlock {netstat -anob} | Out-File -FilePath C:\Custom\$target\$target-Netstat.txt
		Write-Host "=========================NetStat Finished========================"-BackgroundColor DarkYellow}
else{
		Write-Host "-----------------------------Short-------------------------------"-BackgroundColor DarkGray
        Write-Host "=========================Starting NetStat========================"-BackgroundColor DarkYellow
		Invoke-Command -cn $target -ScriptBlock {netstat -no} | Out-File -FilePath C:\Custom\$target\s$target-Netstat.txt
		Write-Host "=========================NetStat Finished========================"-BackgroundColor DarkYellow
}}}

Function servi {
ForEach ($target in $targets) {
if (!(Test-Path C:\Pull\Custom\$target)){
    mkdir C:\Pull\Custom\$target}

Write-Host "=========================Starting Services======================="-BackgroundColor DarkYellow
Invoke-Command -cn $target -ScriptBlock {reg query HKLM\System\CurrentControlSet\Services;Get-Service | sort -property Status} | Out-File -FilePath C:\Pull\Custom\$target\$target-Services.txt
(Get-Content C:\Pull\Custom\$target\$target-Services.txt) -replace "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\" | Set-Content C:\Pull\Custom\$target\$target-Services.txt
Write-Host "=========================Services Finished======================="-BackgroundColor DarkYellow
Write-Host "`nPlease Check C:\Pull\Custom\$target for Results"
}}

Function PF {
Write-Host "`t`t`t`t" -NoNewline; Write-Host "Program Files Pull"'' -BackgroundColor Black
Write-Host "Enter ''Full'' or ''Short'' for pull type" -NoNewline -BackgroundColor Black; $choice = Read-Host " "
	
ForEach ($target in $targets) {	
if (!(Test-Path C:\Pull\Custom\$target)){
    mkdir C:\Pull\Custom\$target}

if ($choice -like "F*"){
    Write-Host "------------------------------Full-------------------------------"-BackgroundColor DarkGray
	Write-Host "======================Starting Program Files====================="-BackgroundColor DarkYellow
	Invoke-Command -cn $target -ScriptBlock {Get-ChildItem "C:\Program Files" | Format-Table -Property Name, Length, LastWriteTime -HideTableHeader} | Out-File -FilePath C:\Pull\Custom\$target\$target-PF.txt
	(Get-Content C:\Pull\Custom\$target\$target-PF.txt) -replace '   +', "          " | ? {$_.trim() -ne "" } | Set-Content C:\Pull\Custom\$target\$target-PF.txt
    Write-Host "======================Program Files Finished====================="-BackgroundColor DarkYellow}
else {
	Write-Host "-----------------------------Short-------------------------------"-BackgroundColor DarkGray
    Write-Host "======================Starting Program Files====================="-BackgroundColor DarkYellow
	Invoke-Command -cn $target -ScriptBlock {Get-ChildItem "C:\Program Files" | Format-Table -Property Name} | Out-File -FilePath C:\Pull\Custom\$target\s$target-PF.txt #-width 180
	(Get-Content C:\Pull\Custom\$target\s$target-PF.txt) -replace '   +', "          " | ? {$_.trim() -ne "" } | Set-Content C:\Pull\Custom\$target\s$target-PF.txt
    Write-Host "======================Program Files Finished====================="-BackgroundColor DarkYellow}
}}

Function sy32 {
Write-Host "`t`t`t`t" -NoNewline; Write-Host "Tasklist Pull"'' -BackgroundColor Black
Write-Host "Enter ''Full'' or ''Short'' for pull type" -NoNewline -BackgroundColor Black; $choice = Read-Host " "
	
ForEach ($target in $targets) {	
if (!(Test-Path C:\Pull\Custom\$target)){
    mkdir C:\Pull\Custom\$target}

if ($choice -like "F*"){
    Write-Host "------------------------------Full-------------------------------"-BackgroundColor DarkGray
    Write-Host "=========================Starting System32======================="-BackgroundColor DarkYellow
	Invoke-Command -cn $target -ScriptBlock {Get-ChildItem C:\Windows\System32 | Format-Table -Property Name, Length, LastWriteTime -HideTableHeader}  | Out-File -FilePath C:\Pull\Custom\$target\$target-S32.txt
	(Get-Content C:\Pull\Custom\$target\$target-S32.txt) -replace '   +', "          " | ? {$_.trim() -ne "" } | Set-Content C:\Pull\Custom\$target\$target-S32.txt
    Write-Host "=========================System32 Finished======================="-BackgroundColor DarkYellow}
else {
	Write-Host "-----------------------------Short-------------------------------"-BackgroundColor DarkGray
	Write-Host "=========================Starting System32======================="-BackgroundColor DarkYellow
	Invoke-Command -cn $target -ScriptBlock {Get-ChildItem C:\Windows\System32 | Format-Table -Property Name}  | Out-File -FilePath C:\Pull\Custom\$target\s$target-S32.txt  #-width 180
	(Get-Content C:\Pull\Custom\$target\s$target-S32.txt) -replace '   +', "          " | ? {$_.trim() -ne "" } | Set-Content C:\Pull\Custom\$target\s$target-S32.txt
    Write-Host "=========================System32 Finished======================="-BackgroundColor DarkYellow}
}}

Function Jabs {
Write-Host "`t`t`t`t" -NoNewline; Write-Host "Jobs Pull"'' -BackgroundColor Black
	
ForEach ($target in $targets) {
if (!(Test-Path C:\Pull\Custom\$target)){
    mkdir C:\Pull\Custom\$target}

Write-Host "`n======================Starting Jobs==============================="-BackgroundColor DarkYellow
Invoke-Command -cn $target -ScriptBlock {schtasks;at} | Out-File -FilePath C:\Pull\Custom\$target\$target-Jobs.txt
Write-Host "======================Jobs Finished==============================="-BackgroundColor DarkYellow}}

Function apdata {
	Write-Host "`t`t`t`t" -NoNewline; Write-Host "AppData Pull" -BackgroundColor Black
	
ForEach ($target in $targets) {	
if (!(Test-Path C:\Pull\Custom\$target)){
    mkdir C:\Pull\Custom\$target}

if (!(Test-Path C:\Pull\Ref\cuserlists-$target.txt)) {
    Invoke-Command -cn $target -ScriptBlock {Get-LocalUser | Format-Table Name} | Out-file -filepath C:\Pull\Ref\cuserlists-$target.txt
    (Get-Content C:\Pull\Ref\cuserlists-$target.txt) -replace "Name" -replace "----" | Set-Content C:\Pull\Ref\cuserlists-$target.txt
    $(foreach ($line in Get-Content C:\Pull\Ref\cuserlists-$target.txt) {$line.tolower().split(" ")}) | Get-Unique | sort | ? {$_.trim() -ne "" } | Set-Content C:\Pull\Ref\cuserlists-$target.txt
}
$usars = Get-Content C:\Pull\Ref\cuserlists-$target.txt

ForEach ($usar in $usars) {
	Write-Host "======================Starting $usar AppData Pull======================"-BackgroundColor DarkYellow
	Invoke-Command -cn $target -ScriptBlock {Get-ChildItem "C:\Users\$using:usar\AppData" -Recurse -ErrorAction SilentlyContinue | Format-Table -Property FullName -HideTableHeader -Wrap} | Out-File -FilePath C:\Pull\Custom\$target\$usar-AppData.txt #-Force
	(Get-Content C:\Pull\Custom\$target\$usar-AppData.txt) -replace ".*AppData\\", "" | Set-Content C:\Pull\Custom\$target\$usar-AppData.txt
    Write-Host "======================$usar AppData Pull Finished======================"-BackgroundColor DarkYellow
}}}

Function download{
Write-Host "`t`t`t`t" -NoNewline; Write-Host "Download Pull" -BackgroundColor Black
$targets = gc C:\Pull\Ref\hostlist.txt
	
ForEach ($target in $targets) {	
if (!(Test-Path C:\Pull\Ref\cuserlists-$target.txt)) {
    Invoke-Command -cn $target -ScriptBlock {Get-LocalUser | Format-Table Name} | Out-file -filepath C:\Pull\Ref\cuserlists-$target.txt
    (Get-Content C:\Pull\Ref\cuserlists-$target.txt) -replace "Name" -replace "----" | Set-Content C:\Pull\Ref\cuserlists-$target.txt
    $(foreach ($line in Get-Content C:\Pull\Ref\cuserlists-$target.txt) {$line.tolower().split(" ")}) | Get-Unique | sort | ? {$_.trim() -ne "" } | Set-Content C:\Pull\Ref\cuserlists-$target.txt
}
$usars = Get-Content C:\Pull\Ref\cuserlists-$target.txt

ForEach ($usar in $usars) {
	Write-Host "======================Starting $usar Download Pull======================"-BackgroundColor DarkYellow
	Invoke-Command -cn $target -ScriptBlock {hostname;Get-ChildItem "C:\Users\$using:usar\Downloads" -Recurse -Force -ErrorAction SilentlyContinue | Format-Table -Property FullName -HideTableHeader -Wrap} | Out-File -append -FilePath C:\Pull\Custom\download.txt #-Force
    Write-Host "======================$usar Download Pull Finished======================"-BackgroundColor DarkYellow
}}}

Function Tempa{
Write-Host "`t`t`t`t" -NoNewline; Write-Host "Temp Pull" -BackgroundColor Black

ForEach ($target in $targets) {
if (!(Test-Path C:\Pull\Ref\cuserlists-$target.txt)) {
    Invoke-Command -cn $target -ScriptBlock {Get-LocalUser | Format-Table Name} | Out-file -filepath C:\Pull\Ref\cuserlists-$target.txt
    (Get-Content C:\Pull\Ref\cuserlists-$target.txt) -replace "Name" -replace "----" | Set-Content C:\Pull\Ref\cuserlists-$target.txt
    $(foreach ($line in Get-Content C:\Pull\Ref\cuserlists-$target.txt) {$line.tolower().split(" ")}) | Get-Unique | sort | ? {$_.trim() -ne "" } | Set-Content C:\Pull\Ref\cuserlists-$target.txt
}
$usars = Get-Content C:\Pull\Ref\cuserlists-$target.txt

Write-Host "`n============================== Starting $target ==================================" -BackgroundColor DarkYellow

ForEach ($usar in $usars) {
Write-Host "`n======================Starting $usar Temp===============================" -BackgroundColor DarkGray
Invoke-Command -cn $target -ScriptBlock {hostname;gci C:\Users\$using:usar\AppData\Local\Temp -Force -Recurse | Format-Table -Property Name}  | Out-File -Encoding ascii -Append -FilePath C:\Pull\Temp.txt
Write-Host "======================$usar Temp Finished==============================="-BackgroundColor DarkGray}
(Get-Content C:\Pull\Temp.txt) -replace '   +', "          " | ? {$_.trim() -ne "" } | Set-Content C:\Pull\Temp.txt
}}

Function usars{
Write-Host "`t`t`t`t" -NoNewline; Write-Host "Temp Pull" -BackgroundColor Black

ForEach ($target in $targets) {
Write-Host "`n============================== Starting $target ==================================" -BackgroundColor DarkYellow
Invoke-Command -cn $target -Scriptblock {hostname;Get-LocalUser | sort Enabled | Format-Table -Property Name,Enabled,Description} | Out-File -FilePath C:\Pull\Custom\Users.txt}}

Function adusars{
Write-Host "`n============================ Getting Active Directory Users ================================" -BackgroundColor DarkYellow
If (Test-Path C:\Pull\ADUsers.txt){
	Get-Item C:\Pull\ADUsers.txt | Rename-Item -NewName {"ADUsers_" + $_.LastWriteTime.toString("HH.mm") + ".txt"}}
Get-ADUser -Filter * -Properties Name,BadLogonCount,badPwdCount,CanonicalName,Created,DistinguishedName,Enabled,LogonWorkstations,MemberOf,PasswordLastSet,PasswordNeverExpires,PasswordNotRequired,SID,SIDHistory,LastBadPasswordAttempt,lastLogoff,lastLogon  | Out-file -filepath C:\Pull\ADUsers.txt
}

Function custom { 
[string]$cmenu = @'
            Custom Pulling Script                       
 Enter the number you wish to execute or Quit to exit   
                                                        
  1. Tasklist                                           
  2. Netstat                                            
  3. Services                                           
  4. Program Files                                      
  5. System32                                           
  6. Jobs                                               
  7. AppData                                            
  8. Downloads Folder                                   
  9. Temp Folder                                        
  10. List of Users                                     
  11. List of Active Directory Users                    
                                                        
'@

If (!(Test-Path C:\Pull)){
    mkdir C:\Pull}
If (Test-Path C:\Pull\Custom){
	Get-Item C:\Pull\Custom  -Include *txt -Exclude *_* -Recurse -Force | Rename-Item -newname {$_.BaseName + "_" + $_.LastWriteTime.toString("HH.mm") + ".txt"}}
else {
    New-Item -Path C:\Pull -Name Custom -Itemtype "Directory"}

	Do{
		Write-Host $cmenu -BackgroundColor Black
		$input = Read-Host "Selection "
        Write-Host ""
		
		switch ($input){
			1{taskl}
			2{netat}
			3{servi}
			4{PF}
			5{sy32}
            6{Jabs}
            7{apdata}
            8{download}
            9{Tempa}
            10{usars}
            11{adusars}
			"Quit"{Clear-Host; Write-Host "Thank You For Using This IR Script!";sleep 3}
            default{Clear-Host; Write-Host "Invalid Choice... Try Again" -BackgroundColor Red}}
	
    } while ($input -like "Q*")
}

#sort -Property LastWriteTimesort -Property LastWriteTime
#endregion custom

#region RemoteCommands
Function hash {
CheckPullFolder
CheckReferenceMaterial
if (!(Test-Path C:\Pull\Remote)){
    mkdir C:\Pull\Remote}

Write-Host "`t`t`t`t`t`t`t" -NoNewline;Write-Host " Get That Hash " -BackgroundColor Black
Write-Host " When Entering The Target Host, Please Use The Complete Hostname, No IPs. " -BackgroundColor Black
Write-Host "`t`t`t`t`t`t" -NoNewline; Write-Host " Type Quit to Go Back `n" -BackgroundColor Black

$target = Read-Host "`nEnter Host Name "
if ($target -like "Qu*") {return}
$choie = Read-Host "Single File or Multiple? "
if ($choie -like "Multi*") {    
    Write-Host "Write the Full Path if Possible, If Not Put the Base Name"
    Do {$box = Read-Host "Enter Files to be Hashed or type Done to Exit "
            $box | Out-File -Encoding ascii -append -FilePath C:\Pull\Ref\hashlist.txt -Confirm
            }
	    until ($box -like "Do*")}
else {
    Write-Host "`nWrite the Full Path if Possible, If Not Put the Base Name" -BackgroundColor Black
    Read-Host "Enter File to be Hashed " | Out-File -FilePath C:\Pull\Ref\hashlist.txt}    
(Get-Content C:\Pull\Ref\hashlist.txt) -replace "Don.*","" | ? {$_.trim() -ne "" } | Set-Content C:\Pull\Ref\hashlist.txt
$hfiles = Get-Content C:\Pull\Ref\hashlist.txt

ForEach ($hfile in $hfiles){
Invoke-Command -cn $target -ScriptBlock {
Write-Host "Looking for $using:hfile Now"
if (!(Test-Path $using:hfile)){
    Get-ChildItem -Path C:\ -include "*$using:hfile*" -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -Property FullName}} | Out-File -Append -FilePath C:\Pull\Ref\hashlist.txt}
(Get-Content C:\Pull\Ref\hashlist.txt) -replace "FullName" -replace "-+" | ? {$_.trim() -ne "" } | Set-Content C:\Pull\Ref\hashlist.txt
$hfiles = Get-Content C:\Pull\Ref\hashlist.txt
Write-Host "File(s) have been found! There was $(($hfiles | Measure).count) results"

ForEach ($hfile in $hfiles){
Invoke-Command -cn $target -ScriptBlock {
hostname;Get-FileHash $using:hfile -Algorithm md5} | Out-File -Encoding ascii -Append -FilePath C:\Pull\Remote\Hashes.txt -width 180}

(Get-Content C:\Pull\Remote\Hashes.txt) -replace "Algorithm" -replace "PSComputerName" -replace "Hash" -replace "Path" -replace "-+" -replace ' +', "    " | ? {$_.trim() -ne "" } | Set-Content C:\Pull\Remote\Hashes.txt
#Remove-Item C:\Pull\Ref\hashlist.txt

<#	If (Test-Path C:\$hfile) {
		Write-Host 'Found $hfile its in C:\'
		$hafile =  C:\$hfile
		Get-FileHash $hafile -Algorithm MD5 | Out-File -Append -FilePath C:\Pull\Hashes.txt
		Write-Host 'File has been hashed, please check C:\Hashes.txt'
		}
	elseif (Test-Path C:\Windows\$hfile) {
		Write-Host 'Found $hfile its in C:\'
		$hafile =  C:\Windows\$hfile
		Get-FileHash $hafile -Algorithm MD5 | Out-File -Append -FilePath C:\Pull\Hashes.txt
		Write-Host 'File has been hashed, please check C:\Hashes.txt'
		}
	elseif (Test-Path C:\Windows\System32\$hfile) { 
		Write-Host 'Found $hfile its in C:\'
		$hafile =  C:\Windows\System32\$hfile
		Get-FileHash $hafile -Algorithm MD5 | Out-File -Append -FilePath C:\Pull\Hashes.txt
		Write-Host 'File has been hashed, please check C:\Hashes.txt'
		}
	elseif (Test-Path 'C:\Program Files\$hfile') { 
		Write-Host 'Found $hfile its in C:\'
		$hafile =  'C:\Program Files\$hfile'
		Get-FileHash $hafile -Algorithm MD5 | Out-File -Append -FilePath C:\Pull\Hashes.txt       
		Write-Host 'File has been hashed, please check C:\Hashes.txt'
		}
	else {
		Write-Host 'Couldnt find $hash in any of the main directories, searching for it now'
		if (dir /s $hfile) {
				else Write-Host 'Found $hash, please wait as its being hashed'
				$hafile =  Read-Host "Please Look at above results and type in full path of the desired file "
				Get-FileHash $hafile -Algorithm MD5 | Out-File -Append -FilePath C:\Pull\Hashes.txt
				Write-Host 'File has been hashed, please check C:\Hashes.txt'
							}
		else Write-Host 'Cound not find $hash'
		}#>
}

Function share {
Write-Host "`t`t`t`t" -NoNewline;Write-Host " Welcome to Create-A-Share " -BackgroundColor Black
Write-Host "`t`t`t`t  " -NoNewline; Write-Host " Type Quit to Go Back `n" -BackgroundColor Black

$ip = Read-Host "Input Your Box's IP "
$user = Read-Host "Enter User "
$passw = Read-Host "Enter Password " #-AsSecureString
#$Encrypted = ConvertFrom-SecureString -SecureString $passw

ForEach ($target in $targets) {
if (!(Get-PSSession -ComputerName $target -State Opened)){
        $ses = New-PSSession -ComputerName $target}
else {$ses = Get-PSSession -ComputerName $target -State Opened}

Invoke-Command -Session $ses -ScriptBlock {
Write-Host "Starting Seach For Share Location in $using:target"
$lane = "False"
[byte]$Alp = [char]'Z'
Do {$Alpa = [char]$Alp
    $lane = Test-Path "$Alpa`:\"
    $let = [char]$Alp
    if ($lane -like "True") {
        write-host $let":/ is taken"
        $Alp--}
}Until (($lane -like "False") -or ($Alp -lt 68))
if ($lane -like "False"){
    write-host $let":/ is availble"
    }
else{write-host "Either ALL Share letters are taken or Something has gone wrong...Probably the latter" -BackgroundColor Red
    Write-Host "`nTry this command for yourself: net use <LETTER>: \\<IP>\c$ <PASSWORD> /user:<USER>" -BackgroundColor Red}

Write-Host "$let`: \\$using:ip\c$ $using:passw /user:$using:user /persistent:yes"
net use $let`: \\$using:ip\c$ $using:passw /user:$using:user
}}}

Function autoruns {
CheckPullFolder
if (!(Test-Path C:\Pull\Remote)) {
    mkdir C:\Pull\Remote}

Write-Host "`t`t`t`t`t`t" -NoNewline;Write-Host " Welcome to AUTOruns " -BackgroundColor Black
Write-Host " When Entering The Target Host, Please Use The Complete Hostname, No IPs." -BackgroundColor Black
Write-Host "`t`t`t`t`t`t" -NoNewline; Write-Host " Type Quit to Go Back `n" -BackgroundColor Black

$target = Read-Host "Input Target Host "
if ($target -like "Qu*") {return}
$ses = Get-PSSession -ComputerName $target -State Opened

Invoke-Command -Session $ses -ScriptBlock {
Write-Host "Starting Seach for Share and Folder Location"
$lane = "True"
[byte]$Alp = [char]'Z'
Do {$Alpa = [char]$Alp
    $lane = Test-Path "$Alpa`:\autoruns.exe"
    $let = [char]$Alp
    if ($lane -like "False") {
        write-host $let":/ is not a share or cannot access share"
        $Alp--}
}Until (($lane -like "True") -or ($Alp -lt 68))
if ($lane -like "True"){
    write-host "Found autoruns.exe, it's avalible at $let`:/"
    }
else {write-host "Could not find autoruns.exe. There may be a problem with the share." -BackgroundColor Red; break}

$target = Read-Host "Input Target Host "
echo "$let`:\autoruns.exe -a $let`:\Pull\Remote\$using:target.arn  /accepteula"
$comman = "$let`:\autoruns.exe -a $let`:\Pull\Remote\$using:target.arn /accepteula"
Invoke-Expression $comman
}}

Function strings {
CheckPullFolder
if (!(Test-Path C:\Pull\Remote)) {
    mkdir C:\Pull\Remote}

Write-Host "`t`t`t`t`t" -NoNewline;Write-Host " Welcome to String-A-Ling-A-Lings" -BackgroundColor Black
Write-Host " When Entering The Target Host Please Use The Complete Host Name, No IPs." -BackgroundColor Black
Write-Host "`t`t`t`t`t`t" -NoNewline; Write-Host " Type Quit to Go Back `n" -BackgroundColor Black

$target = Read-Host "Input Target Host "
if ($target -like "Qu*") {return}
$ses = Get-PSSession -ComputerName $target -State Opened

Invoke-Command -Session $ses -ScriptBlock {
Write-Host "Starting Seach for Share and Folder Location"
$lane = "True"
[byte]$Alp = [char]'Z'
Do {$Alpa = [char]$Alp
    $lane = Test-Path "$Alpa`:\strings.exe"
    $let = [char]$Alp
    if ($lane -like "False") {
        write-host $let":/ is not a share or cannot access share"
        $Alp--}
}Until (($lane -like "True") -or ($Alp -lt 68))
if ($lane -like "True"){
    write-host "Found strings.exe, it's avalible at $let`:/"}
else {write-host "Have Searched all locations and cannot access the share or find its location" -BackgroundColor Red; break}

$loc = Read-Host "Enter Full Path of File "
$loca = [io.path]::GetFileNameWithoutExtension($loc)

echo "$let`:\strings.exe $loc /accepteula"
$comman = "$let`:\strings.exe $loc /accepteula"
Invoke-Expression $comman | Out-File -FilePath "$let`:\Pull\Remote\$loca.txt"
Write-Host "Strings have been runned on $loc. Unless it didn't it..."}}

Function procmon {
#This Function is used for remotely access the procmon.exe
CheckPullFolder
if (!(Test-Path C:\Pull\Remote)) {
    mkdir C:\Pull\Remote}

Write-Host "`t`t`t`t" -NoNewline;Write-Host " Welcome to Procmon" -BackgroundColor Black
Write-Host "`t`t" -NoNewline; Write-Host " Type Quit to Go Back `n" -BackgroundColor Black

$target = Read-Host "Input Target IP"
$user = Read-Host "Enter User "
$passw = Read-Host "Enter Password " #-AsSecureString

echo "psexec \\$target -u site\$user -p $passw cmd.exe"
psexec \\$target -u site\$user -p $passw cmd.exe

Write-Host "Starting Seach for Share and Folder Location"
$lane = "True"
[byte]$Alp = [char]'Z'
Do {$Alpa = [char]$Alp
    $lane = Test-Path "$Alpa`:\procmon.exe"
    $let = [char]$Alp
    if ($lane -like "False") {
        write-host $let":/ is taken or cannot access share"
        $Alp--}
}Until (($lane -like "True") -or ($Alp -lt 68))
if ($lane -like "True"){
    write-host "Found procmon.exe, it's avalible at $let`:/"}
else {write-host "Have Searched all locations and cannot access the share or find its location" -BackgroundColor Red; break}

echo "$let`:\procmon.exe /backingfile $let`:\Pull\Remote\log.pml /quiet /accepteula"
$comman = "$let`:\procmon.exe /backingfile $let`:\Pull\Remote\log.pml /quiet /accepteula"
Invoke-Expression $comman
Invoke-Expression $comman
exit
}

Function scour {
Write-Host "`t`t" -NoNewline;Write-Host " Welcome to the File Searcher " -BackgroundColor Black
CheckPullFolder
if (!(Test-Path "C:\Pull\Search")) {
   New-Item -Path C:\Pull -Name Search -Itemtype "Directory"
    }

foreach ($target in $targets){
$scour = Read-Host "Enter File to be searched "
$cour = [System.Io.Path]::GetFileNameWithoutExtension("$scour")

Invoke-Command -cn $target -ScriptBlock {cmd /c dir /s $using:scour} | Out-File -Append -FilePath C:\Pull\Search\$cour.txt
#Below is the previous command used
<#Write-Host "Looking for File Now, Please look at C:\Pull\Search\$using:cour.txt for update"
Get-ChildItem -Path C:\ -include "*$using:scour*" -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -Property FullName} | Out-File -Append -FilePath C:\Pull\Search\$cour.txt#>

if ((Get-Item C:\Pull\Search\$cour.txt).length -eq 0kb){
    Write-Host "$cour.txt is empty. Either there was nothing to find or something has gone wrong." -BackgroundColor Red
    remove-item C:\Pull\Search\$cour.txt}
else {Write-Host "File(s) Found! Results will be Displayed Below and will be sent to C:\Pull\Search\$cour.txt for further inspection"
}
if (Test-Path C:\Pull\Search\$cour.txt) {
Get-Content C:\Pull\Search\$cour.txt
}}}

Function newfiles {
Write-Host "`t`t`t`t" -NoNewline;Write-Host " Welcome to the Newly Created Files Search " -BackgroundColor Black
CheckPullFolder
if (!(Test-Path C:\Pull\Search)) {
   New-Item -Path C:\Pull -Name "Search" -Itemtype "Directory"
    }

ForEach ($target in $targets) {
Write-Host "Getting $target directory and sorting it by newest files and folders first. Please look at C:\Pull\Search\$target-New.txt file for the results"
Invoke-Command -cn $target -ScriptBlock {cmd /c "dir /S /O:-D *"} | Out-File -FilePath C:\Pull\Search\$target-New.txt
}

#Previous command used, was limited by the 248 character limit. Robocopy is a potential solution.
<#ForEach ($target in $targets) {
$ho = Read-Host "Input the Number of Hours to search back (in two digits)"
if ($ho -like "Qu*") {return}

Invoke-Command -cn $target -ScriptBlock {Get-ChildItem -Path C:\ -Recurse -Force | Where-Object {$_.CreationTime -gt (Get-Date).AddHours(-$ho)}} | select -ExpandProperty Fullname | Out-File -FilePath C:\Pull\Search\$target-New.txt
}

Write-Host "Search for new files created within the past $ho hours is done. Please look at C:\Pull\Search\$target-New.txt file for the results"#>

$files = (Get-Childitem C:\Pull\Comparison\Search -Recurse).FullName
ForEach ($file in $files) {
    if ((Get-Item $file).length -eq 0kb){
        sleep 3
        Write-Host "$file is empty. Either there was nothing to pull or something has gone wrong." -BackgroundColor Red
        remove-item $file 
        }
    }
}

Function anycommand {
Write-Host "`t`t" -NoNewline;Write-Host " Welcome to the Any Command, Where You Can Use Any Command (Most Likely) " -BackgroundColor Black
Write-Host "`t`t`t`t" -NoNewline; Write-Host " Type Quit to Go Back `n" -BackgroundColor Black

ForEach ($target in $targets) {
$cmd = Read-Host "Enter Command "
if ($cmd -like "Qu*") {return}
#$addo = Read-Host "Enter Command's arguments "
$cmdo = [System.Io.Path]::GetFileNameWithoutExtension("$cmd")

CheckPullFolder
if (!(Test-Path "C:\Pull\Remote")) {
    New-Item -Path C:\Pull -Name "Remote" -Itemtype "directory"
    }
if (!(Test-Path "C:\Pull\Remote\$cmdo.txt")) {
    New-Item -Path C:\Pull\Remote -Name "$cmdo.txt" -Itemtype "file"
    }

Write-Host "Invoking Command $cmd on $target ... will send output to C:\Pull\Remote\$cmdo.txt"
Invoke-Command -cn $target -ScriptBlock {hostname; Invoke-Expression $using:cmd} | Out-File -append -FilePath "C:\Pull\Remote\$using:cmdo.txt"
#Invoke-Command -cn $target -ScriptBlock {Invoke-Expression $cmd} | Out-File -append -FilePath "C:\Pull\Remote\$cmd.txt"
} #& $cmd &aggo might work remotely
}

Function deleted {
if (!(Test-Path C:\Pull\MFT)) {
    mkdir C:\Pull\MFT}
if (!(Test-Path C:\Pull\Ref)) {
    mkdir C:\Pull\Ref}

Write-Host "`t`t`t`t`t`t " -NoNewline;Write-Host " Searching the `$MFT " -BackgroundColor Black
Write-Host " When Entering the Target Host, Please Use The Complete Hostname, No IPs. " -BackgroundColor Black
Write-Host "`t`t`t`t`t`t" -NoNewline; Write-Host " Type Quit to Go Back `n" -BackgroundColor Black

ForEach ($target in $targets) {
$ses = Get-PSSession -ComputerName $target -State Opened

If (Test-Path C:\Pull\MFT\$target.txt){
	Get-ChildItem C:\Pull\MFT -Include *txt -Exclude *_* -Recurse -Force | Rename-Item -newname {$_.BaseName + "_" + $_.LastWriteTime.toString("HH.mm") + ".txt"}
        }

Invoke-Command -Session $ses -ScriptBlock {
Write-Host "Starting Seach for share and folder location"
$lane = "True"
[byte]$Alp = [char]'Z'
Do {$Alpa = [char]$Alp
    $lane = Test-Path "$Alpa`:\mftf.exe"
    $let = [char]$Alp
    if ($lane -like "False") {
        write-host $let":/ is taken or cannot access share"
        $Alp--}
}Until (($lane -like "True") -or ($Alp -le 64))
if ($lane -like "True"){
    write-host "Found mftf.exe, it's avalible at $let`:/"
    }
else {write-host "Could not find mftf.exe. There may be a problem with the share." -BackgroundColor Red; break}

$ErrorActionPreference = "silentlycontinue"
echo "Cmd /c $let`:\mftf.exe -cp c:\`$MFT -n $let`:\Pull\Ref\$using:target`_mft.bin"
Cmd /c $let`:\mftf.exe -cp c:\`$MFT -n $let`:\Pull\Ref\$using:target`_mft.bin

echo "Cmd /c $let`:\mftf.exe -o $let`:\Pull\Ref\$uing:target`_mft.bin -l2t -tf 2017/08/14 -tt 2017/08/20 `>$let`:\Pull\MFT\$using:target.txt 2`>`&1"
Cmd /c $let`:\mftf.exe -o $let`:\Pull\Ref\$uing:target`_mft.bin -l2t -tf 2017/08/14 -tt 2017/08/20 `>$let`:\Pull\MFT\$using:target.txt 2`>`&1
}

Get-Content C:\Pull\MFT\$target.txt -ReadCount 1000 | foreach { $_ -match "Deleted file"  } | Out-File -FilePath C:\Pull\MFT\$target`-del.txt
Get-Content C:\Pull\MFT\$target.txt -ReadCount 1000 | foreach { $_ -match "Deleted directory"  } | Out-File -Append -FilePath C:\Pull\MFT\$target`-del.txt
Remove-Item -Path C:\Pull\Ref\$target`_mft.bin
}}

Function deleteshare {
Write-Host "`t`t`t`t`t" -NoNewline;Write-Host " Delete a Share Remotely `n" -BackgroundColor Black
Write-Host " When Entering The Target Host, Please Use The Complete Hostname, No IPs."  -BackgroundColor Black
Write-Host "`t`t`t`t`t  " -NoNewline; Write-Host " Type Quit to Go Back `n" -BackgroundColor Black

$target = Read-Host "Input Target Host "
if ($target -like "Qu*") {return}

Invoke-Command -cn $target -ScriptBlock {
$opti = Read-Host "Would you like to Remove Shares or Sessions? "
	if ($opti -like "Sessi.*"){
		net use
		$let = Read-Host "Enter Letter of the Share to be Deleted "
		net use $let`: /delete /y}
	else {
		Get-Pssesion
		$ids = Read-Host "Enter Session ID to be Deleted "
		Remove-PSSession -Id $ids}}
}

Function Remote {
Write-Host " Welcome to the So Simple a Baby Can Do It Remoting`n" -BackgroundColor Black

$choic = Read-Host "Do you want to use psexec or PowerShell to remote?"

if ($choic -like "psex*") {
    $target = Read-Host "Input Target IP"
    $user = Read-Host "Enter User "
    $passw = Read-Host "Enter Password " #-AsSecureString

    echo "psexec \\$target -u site\$user -p $passw cmd.exe"
    psexec \\$target -u site\$user -p $passw cmd.exe
}
else {
    cmd /c start powershell -NoExit -Command {
    $Host.UI.RawUI.WindowTitle = “Remote Session"
    $pshost = Get-Host

    $psWindow = $pshost.UI.RawUI

    $newSize =$psWindow.BufferSize

    $newSize.Height = 4000
    $newSize.Width = 170

    $psWindow.BufferSize = $newSize

    $newSize = $psWindow.WindowSize
    $newSize.Height = 54
    $newSize.Width = 160

    $psWindow.WindowSize= $newSize

    cmd /c color 80
    Write-Host " When Entering The Target Host Please Use The Complete Host Name, No IPs." ''  -BackgroundColor Black -ForegroundColor White
    $target = Read-Host "Input Target Host "
    if (!(Get-PSSession -ComputerName $target -State Opened)){
        $ses = New-PSSession -ComputerName $target}
    else {$ses = Get-PSSession -ComputerName $target -State Opened}
    Enter-PSSession -Session $ses
    $Host.UI.RawUI.WindowTitle = “Remote Session $target"
    }}
}

#endregion RemoteCommands

#region diff
#This area of functions is to compare files of either the same computer, different computers, or see simalarities.
Function diff {
Write-Host "`t`t`t`t`t`t`t`t`t`t`t" -NoNewline;Write-Host " Welcome to the Diff Jam " -BackgroundColor Black
Write-Host "`n`t" -NoNewline;Write-Host " When inputting boxes, the difference between full and short pulls is that short pulls start with `"s`" " -BackgroundColor Black
Write-Host "`t`t`t`t`t" -NoNewline;Write-Host " example: Full Pull: C:\Pull\Host     Short Pull: C:\Pull\sHost" -BackgroundColor Black
Write-Host "`t`t`t`t`t`t`t`t`t`t`t"-NoNewline;Write-Host "Type Quit to Go Back `n" -BackgroundColor Black

$knowngood = Read-Host "The Known Good Box "
if ($knowngood -like "Qu*") {return}
if (!(Test-Path C:\Pull\Comparison)){
   New-Item -Path C:\Pull -Name Comparison -Itemtype "Directory"}

	ForEach ($target in $targets) {
		$knownbad = $target
        If (Test-Path C:\Pull\Comparison\$knowngood){
	        If (Test-Path C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt) {
                Get-Item C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt -Include *txt -Exclude *_* -Force | Rename-Item -newname {$_.BaseName + "_" + $_.LastWriteTime.toString("HH.mm") + ".txt"}
                }}
        else {
            mkdir C:\Pull\Comparison\$knowngood
        }
					
		echo "-------------------------$knowngood---------------------------------------------------------------------$knownbad----------------------"''  | Out-File -FilePath C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt
        echo "-------------------------Tasklist------------------------------------------------------------------------------------------------------"''  | Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"
        if ((Test-Path "C:\Pull\$knowngood\$knowngood-Tasklist.txt") -And (Test-Path C:\Pull\$knownbad\$knownbad-Tasklist.txt)) {
            $ht = @{};Compare-Object -ReferenceObject $(Get-Content C:\Pull\$knowngood\$knowngood-Tasklist.txt) -DifferenceObject $(Get-Content C:\Pull\$knownbad\$knownbad-Tasklist.txt) | ForEach-Object {
          $value = $_.InputObject
          switch ($_.SideIndicator) {
            '<=' { $ht["$knowngood"] += @($value) }
            '=>' { $ht["$knownbad"] += @($value) }}}

        $cnt  = $ht.Values | ForEach-Object { $_.Count } | Sort-Object | Select-Object -Last 1
        $keys = $ht.Keys | Sort-Object

        0..($cnt-1) | ForEach-Object {$props = [ordered]@{}
          foreach ($key in $keys) {$props[$key] = $ht[$key][$_]}
          New-Object -Type PSObject -Property $props} | Format-Table -AutoSize | Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"}
        echo "Both Tasklists have been compared, only differences will be listed."'' | Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"

		echo "-------------------------Services-----------------------------------------------------------------------------------------------------"'' | Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"
            if ((Test-Path C:\Pull\$knowngood\$knowngood-Services.txt) -and (Test-Path C:\Pull\$knownbad\$knownbad-Services.txt)) {
			$ht = @{};Compare-Object -ReferenceObject $(Get-Content C:\Pull\$knowngood\$knowngood-Services.txt) -DifferenceObject $(Get-Content C:\Pull\$knownbad\$knownbad-Services.txt) | ForEach-Object {
          $value = $_.InputObject
          switch ($_.SideIndicator) {
            '<=' { $ht["$knowngood"] += @($value) }
            '=>' { $ht["$knownbad"] += @($value) }}}

        $cnt  = $ht.Values | ForEach-Object { $_.Count } | Sort-Object | Select-Object -Last 1
        $keys = $ht.Keys | Sort-Object

        0..($cnt-1) | ForEach-Object {$props = [ordered]@{}
          foreach ($key in $keys) {$props[$key] = $ht[$key][$_]}
          New-Object -Type PSObject -Property $props} | Format-Table -AutoSize | Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"}
        echo "Both Services have been compared, only differences will be listed."'' | Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"

		echo "----------------------Program Files---------------------------------------------------------------------------------------------------"'' | Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"
            if ((Test-Path C:\Pull\$knowngood\$knowngood-PF.txt) -and (Test-Path C:\Pull\$knownbad\$knownbad-PF.txt)) {
			$ht = @{};Compare-Object -ReferenceObject $(Get-Content C:\Pull\$knowngood\$knowngood-PF.txt) -DifferenceObject $(Get-Content C:\Pull\$knownbad\$knownbad-PF.txt) | ForEach-Object {
          $value = $_.InputObject
          switch ($_.SideIndicator) {
            '<=' { $ht["$knowngood"] += @($value) }
            '=>' { $ht["$knownbad"] += @($value) }}}

        $cnt  = $ht.Values | ForEach-Object { $_.Count } | Sort-Object | Select-Object -Last 1
        $keys = $ht.Keys | Sort-Object

        0..($cnt-1) | ForEach-Object {$props = [ordered]@{}
          foreach ($key in $keys) {$props[$key] = $ht[$key][$_]}
          New-Object -Type PSObject -Property $props} | Format-Table -AutoSize | Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"}
		echo "Both Program Files have been compared, only differences will be listed."'' | Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"

		echo "-------------------------PreFetch-----------------------------------------------------------------------------------------------------"'' | Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"
            if ((Test-Path "C:\Pull\$knowngood\$knowngood-PreFetch.txt") -and (Test-Path C:\Pull\$knownbad\$knownbad-PreFetch.txt)) {
			$ht = @{};Compare-Object -ReferenceObject $(Get-Content C:\Pull\$knowngood\$knowngood-PreFetch.txt) -DifferenceObject $(Get-Content C:\Pull\$knownbad\$knownbad-PreFetch.txt) | ForEach-Object {
          $value = $_.InputObject
          switch ($_.SideIndicator) {
            '<=' { $ht["$knowngood"] += @($value) }
            '=>' { $ht["$knownbad"] += @($value) }}}

        $cnt  = $ht.Values | ForEach-Object { $_.Count } | Sort-Object | Select-Object -Last 1
        $keys = $ht.Keys | Sort-Object

        0..($cnt-1) | ForEach-Object {$props = [ordered]@{}
          foreach ($key in $keys) {$props[$key] = $ht[$key][$_]}
          New-Object -Type PSObject -Property $props} | Format-Table -AutoSize | Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"}
		echo "Both PreFetchs have been compared, only differences will be listed."'' | Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"

		echo "-------------------------System32----------------------------------------------------------------------------------------------------"''| Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"
            if ((Test-Path C:\Pull\$knowngood\$knowngood-S32.txt) -and (Test-Path C:\Pull\$knownbad\$knownbad-S32.txt)) {
			$ht = @{};Compare-Object -ReferenceObject $(Get-Content C:\Pull\$knowngood\$knowngood-S32.txt) -DifferenceObject $(Get-Content C:\Pull\$knownbad\$knownbad-S32.txt) |ForEach-Object {
          $value = $_.InputObject
          switch ($_.SideIndicator) {
            '<=' { $ht["$knowngood"] += @($value) }
            '=>' { $ht["$knownbad"] += @($value) }}}

        $cnt  = $ht.Values | ForEach-Object { $_.Count } | Sort-Object | Select-Object -Last 1
        $keys = $ht.Keys | Sort-Object

        0..($cnt-1) | ForEach-Object {$props = [ordered]@{}
          foreach ($key in $keys) {$props[$key] = $ht[$key][$_]}
          New-Object -Type PSObject -Property $props} | Format-Table -AutoSize | Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"}
		echo "Both System32s have been compared, only differences will be listed."'' | Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"

		echo "-------------------------SysWOW64----------------------------------------------------------------------------------------------------"''| Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"
            if ((Test-Path C:\Pull\$knowngood\$knowngood-SW64.txt) -and (Test-Path C:\Pull\$knownbad\$knownbad-SW64.txt)) {
			$ht = @{};Compare-Object -ReferenceObject $(Get-Content C:\Pull\$knowngood\$knowngood-SW64.txt) -DifferenceObject $(Get-Content C:\Pull\$knownbad\$knownbad-SW64.txt) |ForEach-Object {
          $value = $_.InputObject
          switch ($_.SideIndicator) {
            '<=' { $ht["$knowngood"] += @($value) }
            '=>' { $ht["$knownbad"] += @($value) }}}

        $cnt  = $ht.Values | ForEach-Object { $_.Count } | Sort-Object | Select-Object -Last 1
        $keys = $ht.Keys | Sort-Object

        0..($cnt-1) | ForEach-Object {$props = [ordered]@{}
          foreach ($key in $keys) {$props[$key] = $ht[$key][$_]}
          New-Object -Type PSObject -Property $props} | Format-Table -AutoSize | Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"}
		echo "Both SysWOW64s have been compared, only differences will be listed."'' | Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"

		echo "-------------------------Jobs--------------------------------------------------------------------------------------------------------"''| Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"
            if ((Test-Path "C:\Pull\$knowngood\$knowngood*-Jobs.txt") -and (Test-Path C:\Pull\$knownbad\$knownbad-Jobs.txt)) {
			$ht = @{};Compare-Object -ReferenceObject $(Get-Content C:\Pull\$knowngood\$knowngood-Jobs.txt) -DifferenceObject $(Get-Content C:\Pull\$knownbad\$knownbad-Jobs.txt) |ForEach-Object {
          $value = $_.InputObject
          switch ($_.SideIndicator) {
            '<=' { $ht["$knowngood"] += @($value) }
            '=>' { $ht["$knownbad"] += @($value) }}}

        $cnt  = $ht.Values | ForEach-Object { $_.Count } | Sort-Object | Select-Object -Last 1
        $keys = $ht.Keys | Sort-Object

        0..($cnt-1) | ForEach-Object {$props = [ordered]@{}
          foreach ($key in $keys) {$props[$key] = $ht[$key][$_]}
          New-Object -Type PSObject -Property $props} | Format-Table -AutoSize | Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"}
		echo "Both Jobs have been compared, only differences will be listed."'' | Out-File -Append -FilePath "C:\Pull\Comparison\$knowngood\Comparison-$knownbad.txt"

			Write-Host "The Comparison of $knowngood and $knownbad has completed, please check C:\Pull\Comparison\$knowngood for the results"''
	}
	
$files = (Get-Childitem C:\Pull\Comparison\$knowngood -Recurse).FullName
ForEach ($file in $files) {
    if ((Get-Item $file).length -le 3kb){
        sleep 3
        Write-Host "$file is empty. Either there was nothing to pull or something has gone wrong." -BackgroundColor Red
        remove-item $file 
            }
        }
}

Function samediff {
Write-Host "`t`t`t`t`t`t`t`t" -NoNewline;Write-Host " Here's your Chance to do a Diff on the Same Box" -BackgroundColor Black
Write-Host "`n`t" -NoNewline;Write-Host " When inputting boxes, the difference between full and short pulls is that short pulls start with `"s`" " -BackgroundColor Black
Write-Host "`t`t`t`t`t" -NoNewline;Write-Host " example: Full Pull: C:\Pull\Host     Short Pull: C:\Pull\sHost" -BackgroundColor Black
Write-Host "`t`t`t`t`t`t`t`t`t`t`t"-NoNewline;Write-Host "Type Quit to Go Back `n" -BackgroundColor Black

if (!(Test-Path C:\Pull\Comparison)) {
   New-Item -Path C:\Pull -Name Comparison -Itemtype "Directory"}
	
    ForEach ($target in $targets) {
		$known = $target
        if ($known -like "Qu*") {return}
        If (Test-Path C:\Pull\Comparison\$known){
	        If (Test-Path C:\Pull\Comparison\$known\Comparison-$known.txt) {
                Get-Item C:\Pull\Comparison\$known\Comparison-$known.txt -Include *txt -Exclude *_* -Force | Rename-Item -newname {$_.BaseName + "_" + $_.LastWriteTime.toString("HH.mm") + ".txt"}
                }}
        else {
            mkdir C:\Pull\Comparison\$known
        }
					
		$knowns = (Gi C:\Pull\$known\$known-Tasklist_*.txt | sort LastWriteTime | select -last 1| select -expand Name);$knownss = $knowns -replace "-Tasklist";$knownbad = $knownss -replace ".txt"

		echo "---------------------------------$known--------------------------------------------------------------------------$knownbad----------------------------------"''  | Out-File -FilePath C:\Pull\Comparison\$known\Comparison-$knownbad.txt
        echo "-------------------------Tasklist-------------------------------------------------------------------------------------------------------------------------"''  | Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"
        $known2 = Gi C:\Pull\$known\$known-Tasklist_*.txt | sort LastWriteTime | select -last 1
        if ((Test-Path "C:\Pull\$known\$known-Tasklist.txt") -And (Test-Path $known2)) {
            $ht = @{};Compare-Object -ReferenceObject $(Get-Content C:\Pull\$known\$known-Tasklist.txt) -DifferenceObject $(Get-Content $known2) | ForEach-Object {
          $value = $_.InputObject
          switch ($_.SideIndicator) {
            '<=' { $ht["$known"] += @($value) }
            '=>' { $ht["$knownbad"] += @($value) }}}

        $cnt  = $ht.Values | ForEach-Object { $_.Count } | Sort-Object | Select-Object -Last 1
        $keys = $ht.Keys | Sort-Object

        0..($cnt-1) | ForEach-Object {$props = [ordered]@{}
          foreach ($key in $keys) {$props[$key] = $ht[$key][$_]}
          New-Object -Type PSObject -Property $props} | Format-Table -AutoSize | Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"}
        echo "Both Tasklists have been compared, only differences will be listed."'' | Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"

		echo "-------------------------Services-----------------------------------------------------------------------------------------------------"'' | Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"
        $known2 = Gi C:\Pull\$known\$known-Services_*.txt | sort LastWriteTime | select -last 1
        if ((Test-Path C:\Pull\$known\$known-Services.txt) -and (Test-Path $known2)) {
			$ht = @{};Compare-Object -ReferenceObject $(Get-Content C:\Pull\$known\$known-Services.txt) -DifferenceObject $(Get-Content $known2) | ForEach-Object {
          $value = $_.InputObject
          switch ($_.SideIndicator) {
            '<=' { $ht["$known"] += @($value) }
            '=>' { $ht["$knownbad"] += @($value) }}}

        $cnt  = $ht.Values | ForEach-Object { $_.Count } | Sort-Object | Select-Object -Last 1
        $keys = $ht.Keys | Sort-Object

        0..($cnt-1) | ForEach-Object {$props = [ordered]@{}
          foreach ($key in $keys) {$props[$key] = $ht[$key][$_]}
          New-Object -Type PSObject -Property $props} | Format-Table -AutoSize | Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"}
        echo "Both Services have been compared, only differences will be listed."'' | Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"

		echo "----------------------Program Files---------------------------------------------------------------------------------------------------"'' | Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"
        $known2 = Gi C:\Pull\$known\$known-PF_*.txt | sort LastWriteTime | select -last 1
        if ((Test-Path C:\Pull\$known\$known-PF.txt) -and (Test-Path $known2)) {
			$ht = @{};Compare-Object -ReferenceObject $(Get-Content C:\Pull\$known\$known-PF.txt) -DifferenceObject $(Get-Content $known2) | ForEach-Object {
          $value = $_.InputObject
          switch ($_.SideIndicator) {
            '<=' { $ht["$known"] += @($value) }
            '=>' { $ht["$knownbad"] += @($value) }}}

        $cnt  = $ht.Values | ForEach-Object { $_.Count } | Sort-Object | Select-Object -Last 1
        $keys = $ht.Keys | Sort-Object

        0..($cnt-1) | ForEach-Object {$props = [ordered]@{}
          foreach ($key in $keys) {$props[$key] = $ht[$key][$_]}
          New-Object -Type PSObject -Property $props} | Format-Table -AutoSize | Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"}
        echo "Both Program Files have been compared, only differences will be listed."'' | Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"

		echo "-------------------------PreFetch-----------------------------------------------------------------------------------------------------"'' | Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"
        $known2 = Gi C:\Pull\$known\$known-PreFetch_*.txt | sort LastWriteTime | select -last 1
        if ((Test-Path "C:\Pull\$known\$known-PreFetch.txt") -and (Test-Path $known2)) {
			$ht = @{};Compare-Object -ReferenceObject $(Get-Content C:\Pull\$known\$known-PreFetch.txt) -DifferenceObject $(Get-Content $known2) | ForEach-Object {
          $value = $_.InputObject
          switch ($_.SideIndicator) {
            '<=' { $ht["$known"] += @($value) }
            '=>' { $ht["$knownbad"] += @($value) }}}

        $cnt  = $ht.Values | ForEach-Object { $_.Count } | Sort-Object | Select-Object -Last 1
        $keys = $ht.Keys | Sort-Object

        0..($cnt-1) | ForEach-Object {$props = [ordered]@{}
          foreach ($key in $keys) {$props[$key] = $ht[$key][$_]}
          New-Object -Type PSObject -Property $props} | Format-Table -AutoSize | Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"}
        echo "Both PreFetchs have been compared, only differences will be listed."'' | Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"

		echo "-------------------------System32----------------------------------------------------------------------------------------------------"''| Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"
        $known2 = Gi C:\Pull\$known\$known-S32_*.txt | sort LastWriteTime | select -last 1
        if ((Test-Path C:\Pull\$known\$known-S32.txt) -and (Test-Path C:\Pull\$known\$known-S32_*.txt)) {
			$ht = @{};Compare-Object -ReferenceObject $(Get-Content C:\Pull\$known\$known-S32.txt) -DifferenceObject $(Get-Content $known2) |ForEach-Object {
          $value = $_.InputObject
          switch ($_.SideIndicator) {
            '<=' { $ht["$known"] += @($value) }
            '=>' { $ht["$knownbad"] += @($value) }}}

        $cnt  = $ht.Values | ForEach-Object { $_.Count } | Sort-Object | Select-Object -Last 1
        $keys = $ht.Keys | Sort-Object

        0..($cnt-1) | ForEach-Object {$props = [ordered]@{}
          foreach ($key in $keys) {$props[$key] = $ht[$key][$_]}
          New-Object -Type PSObject -Property $props} | Format-Table -AutoSize | Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"}
        echo "Both System32s have been compared, only differences will be listed."'' | Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"

		echo "-------------------------SysWOW64----------------------------------------------------------------------------------------------------"''| Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"
        $known2 = Gi C:\Pull\$known\$known-SW64_*.txt | sort LastWriteTime | select -last 1
        if ((Test-Path C:\Pull\$known\$known-SW64.txt) -and (Test-Path $known2)) {
			$ht = @{};Compare-Object -ReferenceObject $(Get-Content C:\Pull\$known\$known-SW64.txt) -DifferenceObject $(Get-Content $known2) |ForEach-Object {
          $value = $_.InputObject
          switch ($_.SideIndicator) {
            '<=' { $ht["$known"] += @($value) }
            '=>' { $ht["$knownbad"] += @($value) }}}

        $cnt  = $ht.Values | ForEach-Object { $_.Count } | Sort-Object | Select-Object -Last 1
        $keys = $ht.Keys | Sort-Object

        0..($cnt-1) | ForEach-Object {$props = [ordered]@{}
          foreach ($key in $keys) {$props[$key] = $ht[$key][$_]}
          New-Object -Type PSObject -Property $props} | Format-Table -AutoSize | Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"}
        echo "Both SysWOW64s have been compared, only differences will be listed."'' | Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"

		echo "-------------------------Jobs--------------------------------------------------------------------------------------------------------"''| Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"
        $known2 = Gi C:\Pull\$known\$known-Jobs_*.txt | sort LastWriteTime | select -last 1
        if ((Test-Path "C:\Pull\\$known\$known-Jobs.txt") -and (Test-Path $known2)) {
			$ht = @{};Compare-Object -ReferenceObject $(Get-Content C:\Pull\$known\$known-Jobs.txt) -DifferenceObject $(Get-Content $known2) |ForEach-Object {
          $value = $_.InputObject
          switch ($_.SideIndicator) {
            '<=' { $ht["$known"] += @($value) }
            '=>' { $ht["$knownbad"] += @($value) }}}

        $cnt  = $ht.Values | ForEach-Object { $_.Count } | Sort-Object | Select-Object -Last 1
        $keys = $ht.Keys | Sort-Object

        0..($cnt-1) | ForEach-Object {$props = [ordered]@{}
          foreach ($key in $keys) {$props[$key] = $ht[$key][$_]}
          New-Object -Type PSObject -Property $props} | Format-Table -AutoSize | Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"}
        echo "Both Jobs have been compared, only differences will be listed."'' | Out-File -Append -FilePath "C:\Pull\Comparison\$known\Comparison-$knownbad.txt"

		Write-Host "`nThe Comparison of $known and $knownbad has completed, please check C:\Pull\Comparison\$known for the results."''

$files = (Get-Childitem C:\Pull\Comparison\$known -Recurse).FullName
ForEach ($file in $files) {
    if ((Get-Item $file).length -le 3kb){
        sleep 3
        Write-Host "$file is empty. Either there was nothing to pull or something has gone wrong." -BackgroundColor Red
        remove-item $file 
            }
        }
Get-ChildItem C:\Pull\Comparison -recurse | Where {$_.PSIsContainer -and `
@(Get-ChildItem -Lit $_.Fullname -r | Where {!$_.PSIsContainer}).Length -eq 4kb} |
Remove-Item -recurse
}}

Function shortdiff {
Write-Host "`t`t`t`t`t`t`t`t`t`t" -NoNewline;Write-Host " Welcome to the Short Diff Jam " -BackgroundColor Black
Write-Host "`n`t" -NoNewline;Write-Host " When inputting boxes, the difference between full and short pulls is that short pulls start with `"s`" " -BackgroundColor Black
Write-Host "`t`t`t`t`t" -NoNewline;Write-Host " example: Full Pull: C:\Pull\Host     Short Pull: C:\Pull\sHost" -BackgroundColor Black
Write-Host "`t`t`t`t`t`t`t`t`t`t`t"-NoNewline;Write-Host "Type Quit to Go Back `n" -BackgroundColor Black

$knowngood = Read-Host "The Known Good Box "
if ($knowngood -like "Qu*") {return}
if (!(Test-Path C:\Pull\Comparison)){
   New-Item -Path C:\Pull -Name Comparison -Itemtype "Directory"}
Write-Host "`nWhat Do you Specifically want to diff?"'' -BackgroundColor Black
    Write-Host "Options: Tasklist, PF, Jobs, Netstat, PF, Pretech, S32, Services, SW64, Temp, runkeys, AppData"'' -BackgroundColor Black
    $picka = Read-Host "Selection "

ForEach ($target in $targets) {
	$knownbad = $target

    If (Test-Path C:\Pull\Comparison\Specific){
	    If (Test-Path C:\Pull\Comparison\Specific\$picka-$knownbad.txt) {
                Get-Item C:\Pull\Comparison\Specific\$picka-$knownbad.txt -Include *txt -Exclude *_* -Force | Rename-Item -newname {$_.BaseName + "_" + $_.LastWriteTime.toString("HH.mm") + ".txt"}}}
    else {
        mkdir C:\Pull\Comparison\Specific}
					
	echo "-------------------------$knowngood---------------------------------------------------------------------$knownbad----------------------"''  | Out-File -FilePath C:\Pull\Comparison\Specific\$picka-$knownbad.txt
    echo "-------------------------$picka------------------------------------------------------------------------------------------------------"''  | Out-File -Append -FilePath "C:\Pull\Comparison\Specific\$picka-$knownbad.txt"
    if ((Test-Path "C:\Pull\$knowngood\$knowngood-$picka.txt") -And (Test-Path C:\Pull\$knownbad\$knownbad-$picka.txt)) {
            $ht = @{};Compare-Object -ReferenceObject $(Get-Content C:\Pull\$knowngood\$knowngood-$picka.txt) -DifferenceObject $(Get-Content C:\Pull\$knownbad\$knownbad-$picka.txt) | ForEach-Object {
          $value = $_.InputObject
          switch ($_.SideIndicator) {
            '<=' { $ht["$knowngood"] += @($value) }
            '=>' { $ht["$knownbad"] += @($value) }}}

        $cnt  = $ht.Values | ForEach-Object { $_.Count } | Sort-Object | Select-Object -Last 1
        $keys = $ht.Keys | Sort-Object

        0..($cnt-1) | ForEach-Object {$props = [ordered]@{}
          foreach ($key in $keys) {$props[$key] = $ht[$key][$_]}
          New-Object -Type PSObject -Property $props} | Format-Table -AutoSize | Out-File -Append -FilePath "C:\Pull\Comparison\Specific\$picka-$knownbad.txt"}
    echo "Both $picka`s have been compared, only differences will be listed."'' | Out-File -Append -FilePath "C:\Pull\Comparison\Specific\$picka-$knownbad.txt"

		Write-Host "The Comparison of $knowngood and $knownbad $picka has completed, please check C:\Pull\Comparison\Specific for the results"''
}
	
$files = (Get-Childitem C:\Pull\Comparison\Specific -Recurse).FullName
ForEach ($file in $files) {
    if ((Get-Item $file).length -le 3kb){
        sleep 3
        Write-Host "$file is empty. Either there was nothing to pull or something has gone wrong." -BackgroundColor Red
        remove-item $file 
            }
        }
}

Function sameshortdiff {
Write-Host "`t`t`t`t`t`t`t" -NoNewline;Write-Host " Here's your Chance do a Selective Diff on the Same Box" -BackgroundColor Black
Write-Host "`n`t" -NoNewline;Write-Host " When inputting boxes, the difference between full and short pulls is that short pulls start with `"s`" " -BackgroundColor Black
Write-Host "`t`t`t`t`t" -NoNewline;Write-Host " example: Full Pull: C:\Pull\Host     Short Pull: C:\Pull\sHost" -BackgroundColor Black
Write-Host "`t`t`t`t`t`t`t`t`t`t`t"-NoNewline;Write-Host "Type Quit to Go Back `n" -BackgroundColor Black

if (!(Test-Path C:\Pull\Comparison)) {
   New-Item -Path C:\Pull -Name Comparison -Itemtype "Directory"}
Write-Host "`nWhat Do you Specifically want to diff on the Same Box?" -BackgroundColor Black
Write-Host "Options: Tasklist, PF, Jobs, Netstat, PF, Pretech, S32, Services, SW64, Temp, runkeys, AppData" -BackgroundColor Black
$pick = Read-Host "Selection "

ForEach ($target in $targets) {
	$known = $target
    if ($known -like "Qu*") {return}

    If (Test-Path C:\Pull\Comparison\ASpecific){
	    If (Test-Path C:\Pull\Comparison\ASpecific\$pick-$known.txt) {
                Get-Item C:\Pull\Comparison\ASpecific\$pick-$known.txt -Include *txt -Exclude *_* -Force | Rename-Item -newname {$_.BaseName + "_" + $_.LastWriteTime.toString("HH.mm") + ".txt"}
                }}
    else {
            mkdir C:\Pull\Comparison\ASpecific
        }
					
	$knowns = (Gi C:\Pull\$known\$known-$pick*.txt | sort LastWriteTime | select -last 1| select -expand Name);$knownss = $knowns -replace "-$pick";$knownbad = $knownss -replace ".txt"

	echo "---------------------------------$known--------------------------------------------------------------------------$knownbad----------------------------------"''  | Out-File -FilePath C:\Pull\Comparison\ASpecific\$pick-$knownbad.txt
    echo "-------------------------$pick-------------------------------------------------------------------------------------------------------------------------"''  | Out-File -Append -FilePath "C:\Pull\Comparison\ASpecific\$pick-$knownbad.txt"
    $known2 = Gi C:\Pull\$known\$known-$pick.txt | sort LastWriteTime | select -last 1
    if ((Test-Path "C:\Pull\$known\$known-$pick.txt") -And (Test-Path $known2)) {
            $ht = @{};Compare-Object -ReferenceObject $(Get-Content C:\Pull\$known\$known-$pick.txt) -DifferenceObject $(Get-Content $known2) | ForEach-Object {
          $value = $_.InputObject
          switch ($_.SideIndicator) {
            '<=' { $ht["$known"] += @($value) }
            '=>' { $ht["$knownbad"] += @($value) }}}

        $cnt  = $ht.Values | ForEach-Object { $_.Count } | Sort-Object | Select-Object -Last 1
        $keys = $ht.Keys | Sort-Object

        0..($cnt-1) | ForEach-Object {$props = [ordered]@{}
          foreach ($key in $keys) {$props[$key] = $ht[$key][$_]}
          New-Object -Type PSObject -Property $props} | Format-Table -AutoSize | Out-File -Append -FilePath "C:\Pull\Comparison\ASpecific\$pick-$knownbad.txt"}
    echo "Both $pick`s have been compared, only differences will be listed."'' | Out-File -Append -FilePath "C:\Pull\Comparison\ASpecific\$pick-$knownbad.txt"

	Write-Host "`nThe Comparison of $known and $knownbad $pick has completed, please check C:\Pull\Comparison\ASpecific for the results."

$files = (Get-Childitem C:\Pull\Comparison\$known -Recurse).FullName
ForEach ($file in $files) {
    if ((Get-Item $file).length -le 3kb){
        sleep 3
        Write-Host "$file is empty. Either there was nothing to pull or something has gone wrong." -BackgroundColor Red
        remove-item $file 
            }
        }
Get-ChildItem C:\Pull\Comparison -recurse | Where {$_.PSIsContainer -and `
@(Get-ChildItem -Lit $_.Fullname -r | Where {!$_.PSIsContainer}).Length -eq 4kb} | Remove-Item -recurse}}

Function samesimilar {
Write-Host "`t`t`t`t`t`t`t`t`t`t`t" -NoNewline;Write-Host " Welcome to the Same Jam " -BackgroundColor Black
Write-Host "`n`t" -NoNewline;Write-Host " When inputting boxes, the difference between full and short pulls is that short pulls start with `"s`" " -BackgroundColor Black
Write-Host "`t`t`t`t`t" -NoNewline;Write-Host " example: Full Pull: C:\Pull\Host     Short Pull: C:\Pull\sHost" -BackgroundColor Black
Write-Host "`t`t`t`t`t`t`t`t`t`t`t"-NoNewline;Write-Host "Type Quit to Go Back `n" -BackgroundColor Black

$knowngood = Read-Host "The Known Good Box "
if ($knowngood -like "Qu*") {return}
if (!(Test-Path C:\Pull\Comparison)){
   New-Item -Path C:\Pull -Name Comparison -Itemtype "Directory"}
Write-Host "`nWhat Do you Specifically want to see is the same?" -BackgroundColor Black
Write-Host "Options: Tasklist, PF, Jobs, Netstat, PF, Pretech, S32, Services, SW64, Temp, runkeys, AppData" -BackgroundColor Black
$picka = Read-Host "Selection "

ForEach ($target in $targets) {
	$knownbad = $target

    If (Test-Path C:\Pull\Comparison\Same){
	    If (Test-Path C:\Pull\Comparison\Same\$picka-$knownbad.txt) {
                Get-Item C:\Pull\Comparison\Same\$picka-$knownbad.txt -Include *txt -Exclude *_* -Force | Rename-Item -newname {$_.BaseName + "_" + $_.LastWriteTime.toString("HH.mm") + ".txt"}}}
    else {
        mkdir C:\Pull\Comparison\Same}
					
	echo "-------------------------$knowngood---------------------------------------------------------------------$knownbad----------------------"  | Out-File -FilePath C:\Pull\Comparison\Same\$picka-$knownbad.txt
    echo "-------------------------$picka------------------------------------------------------------------------------------------------------";Write-Host""  | Out-File -Append -FilePath "C:\Pull\Comparison\Same\$picka-$knownbad.txt"
    if ((Test-Path "C:\Pull\$knowngood\$knowngood-$picka.txt") -And (Test-Path C:\Pull\$knownbad\$knownbad-$picka.txt)) {
        Compare-Object -ReferenceObject $(Get-Content C:\Pull\$knowngood\$knowngood-$picka.txt) -DifferenceObject $(Get-Content C:\Pull\$knownbad\$knownbad-$picka.txt) -ExcludeDifferent -IncludeEqual | Out-File -Append -FilePath "C:\Pull\Comparison\Same\$picka-$knownbad.txt"
        (gc C:\Pull\Comparison\Same\$picka-$knownbad.txt) -replace "InputObject" -replace "SideIndicator" -replace "----+" -replace "==" -replace "    +" | sort | ? {$_.trim() -ne "" } |  sc C:\Pull\Comparison\Same\$picka-$knownbad.txt}

    echo "Both $picka`s have been compared, only similarities will be listed." | Out-File -Append -FilePath "C:\Pull\Comparison\Same\$picka-$knownbad.txt"

		Write-Host "The Comparison of $knowngood and $knownbad $picka has completed, please check C:\Pull\Comparison\Same for the results"
}
	
$files = (Get-Childitem C:\Pull\Comparison\Same -Recurse).FullName
ForEach ($file in $files) {
    if ((Get-Item $file).length -le 3kb){
        sleep 3
        Write-Host "$file is empty. Either there was nothing to pull or something has gone wrong." -BackgroundColor Red
        remove-item $file 
            }
        }
}

Function sameshortsimilar {
Write-Host "`t`t`t`t`t`t`t" -NoNewline;Write-Host " Here's Your Chance to do a Selective Same on the Same Box " -BackgroundColor Black
Write-Host "`n`t" -NoNewline;Write-Host " When inputting boxes, the difference between full and short pulls is that short pulls start with `"s`" " -BackgroundColor Black
Write-Host "`t`t`t`t`t" -NoNewline;Write-Host " example: Full Pull: C:\Pull\Host     Short Pull: C:\Pull\sHost" -BackgroundColor Black
Write-Host "`t`t`t`t`t`t`t`t`t`t`t"-NoNewline;Write-Host "Type Quit to Go Back `n" -BackgroundColor Black

if (!(Test-Path C:\Pull\Comparison)) {
   New-Item -Path C:\Pull -Name Comparison -Itemtype "Directory"}
Write-Host "`t`t`t" -NoNewline; Write-host " What Do you Specifically want to Selectivly Same on the Same Box?" -BackgroundColor Black
Write-Host "Options: Tasklist, PF, Jobs, Netstat, PF, Pretech, S32, Services, SW64, Temp, runkeys, AppData" -BackgroundColor Black
$pick = Read-Host "Selection "

ForEach ($target in $targets) {
	$known = $target
    if ($known -like "Qu*") {return}

    If (Test-Path C:\Pull\Comparison\ASame){
	    If (Test-Path C:\Pull\Comparison\ASame\$pick-$known.txt) {
                Get-Item C:\Pull\Comparison\ASame\$pick-$known.txt -Include *txt -Exclude *_* -Force | Rename-Item -newname {$_.BaseName + "_" + $_.LastWriteTime.toString("HH.mm") + ".txt"}
                }}
    else {
            mkdir C:\Pull\Comparison\ASame
        }
					
	$knowns = (Gi C:\Pull\$known\$known-$pick*.txt | sort LastWriteTime | select -last 1| select -expand Name);$knownss = $knowns -replace "-$pick";$knownbad = $knownss -replace ".txt"

	echo "---------------------------------$known--------------------------------------------------------------------------$knownbad----------------------------------"''  | Out-File -FilePath C:\Pull\Comparison\ASame\$pick-$knownbad.txt
    echo "-------------------------$pick-------------------------------------------------------------------------------------------------------------------------"''  | Out-File -Append -FilePath "C:\Pull\Comparison\ASame\$pick-$knownbad.txt"
    $known2 = Gi C:\Pull\$known\$known-$pick.txt | sort LastWriteTime | select -last 1
    if ((Test-Path "C:\Pull\$known\$known-$pick.txt") -And (Test-Path $known2)) {
            Compare-Object -ReferenceObject $(Get-Content C:\Pull\$knowngood\$knowngood-$pick.txt) -DifferenceObject $(Get-Content C:\Pull\$knownbad\$knownbad-$pick.txt) -ExcludeDifferent -IncludeEqual | Out-File -Append -FilePath "C:\Pull\Comparison\ASame\$pick-$knownbad.txt"
        (gc C:\Pull\Comparison\ASame\$pick-$knownbad.txt) -replace "InputObject" -replace "SideIndicator" -replace "----+" -replace "==" -replace "    +" | sort | ? {$_.trim() -ne "" } |  sc C:\Pull\Comparison\ASame\$pick-$knownbad.txt}

    echo "Both $pick have been compared, only similarities will be listed."'' | Out-File -Append -FilePath "C:\Pull\Comparison\ASame\$pick-$knownbad.txt"

	Write-Host "`nThe Comparison of $known and $knownbad $pick has completed, please check C:\Pull\Comparison\ASame for the results."

$files = (Get-Childitem C:\Pull\Comparison\ASame -Recurse).FullName
ForEach ($file in $files) {
    if ((Get-Item $file).length -le 3kb){
        sleep 3
        Write-Host "$file is empty. Either there was nothing to pull or something has gone wrong." -BackgroundColor Red
        remove-item $file 
        }}
Get-ChildItem C:\Pull\Comparison\ASame -recurse | Where {$_.PSIsContainer -and `
@(Get-ChildItem -Lit $_.Fullname -r | Where {!$_.PSIsContainer}).Length -eq 4kb} | Remove-Item -recurse}}

Function adusersdiff {
Write-Host "`t`t`t`t`t`t`t" -NoNewline;Write-Host " What AD Users Have Been Added??" -BackgroundColor Black

if (!(Test-Path C:\Pull\Comparison)) {
   New-Item -Path C:\Pull -Name Comparison -Itemtype "Directory"}
If (Test-Path C:\Pull\Comparison\ADUsers.txt){
	Get-Item C:\Pull\Comparison\ADUsers.txt | Rename-Item -NewName {"ADUsers_" + $_.LastWriteTime.toString("HH.mm") + ".txt"}}

$knownbad = (Gi "C:\Pull\ADUsers_*.txt" | sort LastWriteTime | select -last 1| select -expand BaseName)

echo "---------------------------------ADUsers--------------------------------------------------------------------------$knownbad----------------------------------"''  | Out-File -FilePath C:\Pull\Comparison\ADUsers.txt
if ((Test-Path "C:\Pull\ADUsers.txt") -And (Test-Path $knownbad)) {
        $ht = @{};Compare-Object -ReferenceObject $(Get-Content "C:\Pull\ADUsers.txt") -DifferenceObject $(Get-Content $knownbad) | ForEach-Object {
        $value = $_.InputObject
        switch ($_.SideIndicator) {
        '<=' { $ht["$known"] += @($value) }
        '=>' { $ht["$knownbad"] += @($value) }}}

    $cnt  = $ht.Values | ForEach-Object { $_.Count } | Sort-Object | Select-Object -Last 1
    $keys = $ht.Keys | Sort-Object

    0..($cnt-1) | ForEach-Object {$props = [ordered]@{}
        foreach ($key in $keys) {$props[$key] = $ht[$key][$_]}
        New-Object -Type PSObject -Property $props} | Format-Table -AutoSize | Out-File -Append -FilePath "C:\Pull\Comparison\ADUsers.txt"}
echo "Both AD Users have been compared, only differences will be listed."'' | Out-File -Append -FilePath "C:\Pull\Comparison\ADUsers.txt"

Write-Host "`nThe Comparison of Old and New AD Users has completed, please check C:\Pull\Comparison\ADUsers.txt for the results."

if ((Get-Item C:\Pull\Comparison\ADUsers.txt).length -le 1kb){
    sleep 3
    Write-Host "C:\Pull\Comparison\ADUsers.txt is empty. Either there was nothing to pull or something has gone wrong." -BackgroundColor Red
    remove-item C:\Pull\Comparison\ADUsers.txt}
}
#endregion diff

#region extra
#The following portion of script is of no actual use. Namely it was used for fun/cleaning up the mess this script leaves on a computer.
Function bolin {
#This function is used as a joke whenever someone complains/requests something of the script.
Clear-Host
Write-Host "`n`n`n`n`n`n`n`n`n`n`n`t`t`t`t`t`t`t`t" -NoNewline;Write-Host "Expecting More?" -BackgroundColor DarkGreen
Write-Host "`n`n`t`t`t`t`t`t" -NoNewline;Write-Host "Well Write Your Own Damn Script Next Time"-BackgroundColor DarkGreen;sleep 7
Clear-Host
}

Function buehl {
#This function is to be used by CTN1 Buehl as it is designed to his forensics abilities aka DumpIt.
Write-Host "Pulling Memory"
if (!(Test-Path C:\Pull\Remote)) {
    mkdir C:\Pull\Remote}
if (!(Test-Path C:\Pull\Ref)) {
    mkdir C:\Pull\Ref}

$target = Read-Host "Input Target Host "
$ses = Get-PSSession -ComputerName $target -State Opened

If (Test-Path C:\Pull\Remote\$target.txt){
	Get-ChildItem C:\Pull\Remote -Include *txt -Exclude *_* -Recurse -Force | Rename-Item -newname {$_.BaseName + "_" + $_.LastWriteTime.toString("HH.mm") + ".txt"}
        }

Invoke-Command -Session $ses -ScriptBlock {
Write-Host "Starting Search for share and folder location"
$lane = "True"
[byte]$Alp = [char]'Z'
Do {$Alpa = [char]$Alp
    $lane = Test-Path "$Alpa`:\dumpit.exe"
    $let = [char]$Alp
    if ($lane -like "False") {
        write-host $let":/ is taken or cannot access share"
        $Alp--}
}Until (($lane -like "True") -or ($Alp -le 64))
if ($lane -like "True"){
    write-host "Found dumpit.exe, it's avalible at $let`:/"
    }
else {write-host "Could not find dumpit.exe or there is a problem access the share." -BackgroundColor Red;break}

$target = Read-Host "Input Target Host "
echo "Cmd /c $let`:\dumpit.exe"
$comma = "Cmd /c $let`:\dumpit.exe" #$let`:\Pull\Remote\$target-dump.txt 2`>`&1
Invoke-Expression $comma
}

Get-Content C:\Pull\Remote\$target.txt -ReadCount 1000 | foreach { $_ -match "Deleted file"  } | Out-File -FilePath C:\Pull\Remote\$target`-del.txt
Get-Content C:\Pull\Remote\$target.txt -ReadCount 1000 | foreach { $_ -match "Deleted directory"  } | Out-File -Append -FilePath C:\Pull\Remote\$target`-del.txt
Remove-Item -Path C:\Pull\Ref\$target`_mft.bin
}

Function trace {
#This function is used to clean up the mess this script causes with the abundant files it creates.
Write-Host "`t`t`t`t" -NoNewline;Write-Host " Welcome to Remove All Trace" -BackgroundColor Black

ForEach ($target in $targets) {
Invoke-Command -cn $target -ScriptBlock {
net user | Out-File C:\Pull\Ref\userlists-$target.txt
(Get-Content C:\Pull\Ref\userlists-$target.txt) -replace "The command completed successfully." -replace "User accounts for \\.*" -replace '\W+',"`r`n" | ? {$_.trim() -ne "" } | Set-Content C:\Pull\Ref\userlists-$target.txt
Get-ChildItem "C:\Users" -Force | Format-Table -Property Name | Out-file -Encoding ascii -append -filepath C:\Pull\Ref\userlists-$target.txt
(Get-Content C:\Pull\Ref\userlists-$target.txt) -replace "Name" -replace "----" | Set-Content C:\Pull\Ref\userlists-$target.txt
$(foreach ($line in Get-Content C:\Pull\Ref\userlists-$target.txt) {$line.tolower().split(" ")}) | sort | Get-Unique | ? {$_.trim() -ne "" } | Set-Content C:\Pull\Ref\userlists-$target.txt
$users = Get-Content C:\Pull\Ref\userlists-$target.txt

Write-Host "`n=======================Searchinig $target========================="

Write-Host "`nLooking for Files Now"
if (Test-Path C:\Pull){
    Write-Host "`nFound the Pull Folder. Deleting Now"
    Remove-Item -Path C:\Pull -Recurse -Force -Confirm}
else {Write-Host "`nPull is not Present" -BackgroundColor Red}
Write-Host "`nLooking for Spidey in C:\ Now"
if (Test-Path C:\*Spidey*){
    Write-Host "`nFound Spidey in C:\. Deleting Now"
    Remove-Item -Path C:\*Spidey* -Include *ps1 -Force -Confirm}
else {Write-Host "`nSpidey is not Present in C:\" -BackgroundColor Red}
Write-Host "`nLooking for Spidey in Downloads Now"
ForEach ($user in $users) {
if (Test-Path C:\Users\$user\Downloads\Spidey*){
    Write-Host "`nFound Spidey in C:\Users\$user\Downloads. Deleting Now"
    Remove-Item -Path C:\Users\$user\Downloads\Spidey* -Include *ps1 -Force -Confirm}
else {Write-Host "`nSpidey is not Present in  $user\Downloads" -BackgroundColor Red}}
Write-Host "`n=======================Done With $target=========================="
Write-Host "`nRemove all Trace Has Finsihed`n"
}}}

Function gpupdate {
#This function lists computer names in the 'hostlist.txt' file if avaible, and then uses the PSEXEC tool to push an Group Policy Update to all computers in the hostlist.txt. This is mostly used to turn WinRM On.
CheckPullFolder
if (!(Test-Path C:\Pull\Ref)) {
    New-Item -Path C:\Pull -Name "Ref" -Itemtype "directory"
    }
if (!(Test-Path C:\Pull\Ref\hostlist.txt)) {
    New-Item -Path C:\Pull\Ref -Name "hostlist.txt" -Itemtype "file"
    }
if ((Get-Item C:\Pull\Ref\hostlist.txt).length -gt 0){
      Write-Host " List of Hosts found. The following Hosts are on the list:`n"  -BackgroundColor Black
      Get-Content C:\Pull\Ref\hostlist.txt
      $keep = Read-Host "`nDo You Want to keep this list Y/N?"
        if ($keep -like "N*") {
            Remove-Item  C:\Pull\Ref\hostlist.txt
            New-Item -Path C:\Pull\Ref -Name "hostlist.txt" -Itemtype "file"
            }
      }
    
    Write-Host "`t`t`tWhen Entering Hosts, Please Use The Complete Hostnames. NO IPs.`t`t`t`nAfter Each Input, Confirm The New Addition.  When Typing Done, DO NOT CONFIRM OUTPUT" -BackgroundColor Black
	Do {$box = Read-Host "Enter Host or type Done to Exit "
        $box | Out-File -Append -FilePath C:\Pull\Ref\hostlist.txt -Confirm
        }
	until ($box -like "Do*")

#This section checks and removes any input that might be an accidental confrimed 'done'.
(Get-Content C:\Pull\Ref\hostlist.txt) -replace "Don.*","" | ? {$_.trim() -ne "" } | Set-Content C:\Pull\Ref\hostlist.txt

$user = Read-Host "Enter User "
$passw = Read-Host "Enter Password " #-AsSecureString

echo "psexec -@C:\Pull\Ref\hostlist.txt -u site\$user -p $passw Gpupdate.exe"
psexec -@C:\Pull\Ref\hostlist.txt -u site\$user -p $passw Gpupdate.exe
}
#endregion extra

[string]$menu = @'
____________________________________________________________________________________________________________
|                                                                                                          |
|                              Welcome to the Incident Response Script                                     |
|                                  ------------------------------                                          |
|                      Enter the Number You Wish to Execute or Quit to Exit                                |
|                                                                                                          |
|  Pull Commands                                                                                           |
|  -------------                                                                                           |
|   1. Main Pull                                                                                           |
|        -Tasklist, Netstat, Services, Program Files, Prefetch, System32, SysWOW64, Jobs, and Temp         |
|   2. Pull Simplified Tasklist and Netstat                                                                |
|   3. Pull Detailed System32, Prefetch, SysWOW64, Services, and Program Files                             |
|   4. Custom Single Pull                                                                                  |
|        -Tasklist, Netstat, Services, Program Files, System32, Jobs, AppData, Downloads, Users and Temp   |
|   5. Pull Run Keys                                                                                       |
|   6. Pull Logs                                                                                           |
|        -Logparser Program Required, Must Be Located in C:\windows\system32                               |
|                                                                                                          |
|  Remote Commands                                                                                         |
|  ---------------                                                                                         |
|   7. Create a Remote Session                                                                             |
|        -Either Through PsExec or PSSesion                                                                |
|   8. Any One Command on Any Box                                                                          |
|                                                                                                          |
|   9. Create Shares                                                                                       |
|        -Must Run before Running Selections 9, 10, and 13                                                 |
|  10. Pull Autoruns                                                                                       |
|  11. Conduct Strings on a Remote File                                                                    |
|                                                                                                          |
|  12. Search on Remote Boxes                                                                              |
|  13. Search for Newly Created Files                                                                      |
|  14. Search Files and Deleted Files                                                                      |
|        -MFT Program Required, Must Be Located in C:\                                                     |
|                                                                                                          |
|  15. Get MD5 Hashes                                                                                      |
|                                                                                                          |
|  Compare Commands                                                                                        |
|  ----------------                                                                                        |
|  16. Compare Different Boxes Pulls                                                                       |
|        -Recommend that Main Pull is Ran Beforehand.                                                      |
|  17. Compare the Same Box's Pulls                                                                        |
|        -Recommend that at least two of the same Pull have been Ran Beforehand.                           |
|                                                                                                          |
|  18. Compare A Single Option From Different Boxes                                                        |
|        -Options: Tasklist, PF, Jobs, Netstat, PF, Pretech, S32, Services, SW64, Temp, runkeys, AppData   |
|  19. Compare A Single Option From the Same Boxes                                                         |
|        -Options: Tasklist, PF, Jobs, Netstat, PF, Pretech, S32, Services, SW64, Temp, runkeys, AppData   |
|                                                                                                          |
|  20. Show the Similarities of A Single Option From Different Boxes                                       |
|        -Options: Tasklist, PF, Jobs, Netstat, PF, Pretech, S32, Services, SW64, Temp, runkeys, AppData   |
|  21. Show the Similarities of A Single Option From the Same Boxes                                        |
|        -Options: Tasklist, PF, Jobs, Netstat, PF, Pretech, S32, Services, SW64, Temp, runkeys, AppData   |
|                                                                                                          |
|__________________________________________________________________________________________________________|
'@

#These two functions run first to set up the script enviroment and checks to see if PS remoting is possible. Further info can be found in the comments of each function.
FixShell
CheckWinRM

Do {
Write-Host $menu -BackgroundColor Black
$input = Read-Host "Selection "
Write-Host ""

#This is the table for functions the are reliant on a reference file made from the 'cho' (aka choice) function and sets the 'prevprog' (aka previous program) variable to the desired function for future use.
if ($input -like "1") {$prevprog = "everything"}
if ($input -like "2") {$prevprog = "nettask"}
if ($input -like "3") {$prevprog = "s32pf"}
if ($input -like "4") {$prevprog = "custom"}
if ($input -like "5") {$prevprog = "runkeys"}
if ($input -like "6") {$prevprog = "logs"}
if ($input -like "8") {$prevprog = "anycommand"}
if ($input -like "9") {$prevprog = "share"}
if ($input -like "12") {$prevprog = "scour"}
#if ($input -like "13") {$prevprog = "newfiles"}
if ($input -like "14") {$prevprog = "deleted"}
if ($input -like "16") {$prevprog = "diff"}
if ($input -like "17") {$prevprog = "samediff"}
if ($input -like "18") {$prevprog = "shortdiff"}
if ($input -like "19") {$prevprog = "sameshortdiff"}
if ($input -like "20") {$prevprog = "samesimilar"}
if ($input -like "21") {$prevprog = "sameshortsimilar"}
if ($input -like "62") {$prevprog = "trace"}

#This is the switch table for the users' input from the start of this function. Most functions use the 'cho' function to create a reference file. 
    switch ($input){
        1{cho}
        2{cho}
        3{cho}
        4{cho}
        5{cho}
        6{cho}
        7{remote}
        8{cho}
        9{cho}
        10{autoruns}
        11{strings}
        12{cho}
        13{newfiles}
        14{cho}
        15{hash}
        16{cho}
        17{cho}
        18{cho}
        19{cho}
        20{cho}
        21{cho}
        22{bolin}
        25{procmon}
        26{deleteshare}
        27{buehl}
        28{adusersdiff}
        29{gpupdate}
        62{cho}
        "Quit"{Clear-Host; Write-Host "Thank You For Using This IR Script!";sleep 3}
        default{Clear-Host; Write-Host "Invalid Choice... Try Again" -BackgroundColor Red}
		}
}
Until ($input -like "Q*")