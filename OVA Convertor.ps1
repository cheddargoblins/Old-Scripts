$src_vms = @()
$global:dest_ovas = @()
$global:external_ovas = @()
$menu = $true

function OVAName {
$global:dest_name = Read-Host "Type in OVA name to save as"
$global:external_ovas += "$global:dest_name.ova"
$global:dest_ovas += "`"<PATH_TO_EXPORT_FOLDER>\$global:dest_name.ova`""}

Do {
[string]$menu = @'
                    VM Options:                     
                                                    
            -VM1_NAME                                  
            -VM2_NAME                                 
            -VM3_NAME                                 
            -Custom                                 
                                                    
        Once Done with Selections, type 'done'      
                                                    
               Or type 'exit' to exit               
                                                    
'@
    Write-Host $menu -BackgroundColor Black 

    $vm_input = Read-Host "Type in VM to convert"

    if ($vm_input -like "VM1_NAME*") {
        $src_vms += '"<PATH_TO_VM1>.vmx"';OVAName}
    elseif ($vm_input -like "VM2_NAME*") {
        $src_vms += '"<PATH_TO_VM1>"';OVAName}
    elseif ($vm_input -like "VM3_NAME*") {
        $src_vms += '"<PATH_TO_VM1>"';OVAName}
    elseif ($vm_input -like "Cus*") {
        $comeon = $true
        Do {
            $custom_vm = Read-Host "Type in the FULL path to custom vmx"
            if ($custom_vm -like "don*"){
                $comeon = $false}
            elseif (!(Test-Path $custom_vm)){
                Write-Host "Sorry not a valid path" -BackgroundColor Red -ForegroundColor White}
            else {$src_vms += "`"$custom_vm`"";OVAName
            $comeon = $false}}
        until ($comeon -eq $false)
            }
    elseif ($vm_input -like "don*") {
        $menu = $false
    }
    else {exit}
}
until ($menu -eq $false)

if (Test-Path '<PATH_TO_EXTERNAL_DRIVE>') {
$copy = Read-Host "Do you wanna save to external? y/n"}

$shut = Read-Host "Do you want to shutdown the computer afterwards? y/n"

cd "C:\Program Files\VMware\VMware OVF Tool"

For ($i = 0; $i -lt $global:dest_ovas.count; $i++) {

if (Test-Path $global:dest_ovas[$i]) {
    Write-Host "$($global:dest_ovas[$i]) already exists, deleting now..." -BackgroundColor Red -ForegroundColor White
    Remove-Item -Path $global:dest_ovas[$i] -Force
    Write-Host "$($global:dest_ovas[$i]) was deleted" -BackgroundColor Red -ForegroundColor White
}

cmd /c Ovftool.exe $src_vms[$i] $global:dest_ovas[$i]


if ($copy -like "y*") {
    if (Test-Path '<PATH_TO_EXTERNAL_DRIVE>') {
        if (Test-Path "<PATH_TO_EXTERNAL_DRIVE>\$($global:external_ovas[$i])") {
            Write-Host "$($global:external_ovas[$i]) already exists, deleting now..." -BackgroundColor Red -ForegroundColor White
            Remove-Item -Path "<PATH_TO_EXTERNAL_DRIVE>\$($global:external_ovas[$i])" -Force
            Write-Host "$($global:external_ovas[$i]) was deleted" -BackgroundColor Red -ForegroundColor White
        }
        Write-Host "copying $($global:external_ovas[$i]) now..." -BackgroundColor Red -ForegroundColor White
        Copy-Item $global:dest_ovas[$i].Replace("`"","") -Destination '<PATH_TO_EXTERNAL_DRIVE>'
        Write-Host "$($global:external_ovas[$i]) copied" -BackgroundColor Red -ForegroundColor White
        }
    }
else {exit}

}

if ($shut -like "y*") {
    Stop-Computer -ComputerName localhost
}
else {
    exit}