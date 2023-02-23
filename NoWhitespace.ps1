#The Purpose of this script is to Cut out writespace within a text file.

Write-Host "Remove All Whitespace from a file"
$file = Read-Host "Input the full file path:"
if ((Get-Item $file).length -ge 1000kb){
        Write-Host " This file may have a lot of whitespaces, please be patient " -BackgroundColor Yellow -ForegroundColor Black
}

(Get-Content "$file") -replace " +","" | ? {$_.trim() -ne "" } | Set-Content "$file"

<#
If you want to copy the core command, please see below:
(Get-Content 'replace this text with the full filepath') -replace " +","" | ? {$_.trim() -ne "" } | Set-Content 'replace this text with the full filepath'
#>