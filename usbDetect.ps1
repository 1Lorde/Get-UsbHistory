$InformationPreference = 'Continue'
Write-Warning "Use 'Import-Module .\usbDetect.ps1' to load commandlet Get-UsbHistory."


function Get-UsbHistory {
 <#
    .SYNOPSIS
	Отримує історію підключень до комп'тера USB-носіїв.

	.DESCRIPTION
	Виводить серійний номер, часові мітки використання (Install, LastArrival, LastRemoval)
    та WEL-повідомлення, що підтверджують останнє підключення до комп'ютера зовнішнього USB-носія.

	.PARAMETER SerialNum
	Серійний номер шуканого носія.

	.PARAMETER Init
	Ввімкнення логування подій Windows, пов'язаних з USB.

    .PARAMETER AllProps
	Виведення всіх полів.

    .PARAMETER File
	Збереження звіту у results.csv.

    .PARAMETER Silent
	Не відображати повідомлення в ході виконання.

	.EXAMPLE
	Get-UsbHistory -Init

    .EXAMPLE
	Get-UsbHistory -SerialNum "60A44C413DF8F191798C01CB"

    .EXAMPLE
	Get-UsbHistory -File -AllProps -Silent

	.EXAMPLE
	"60A44C413DF8F191798C01CB","E0D55EA5741B1711F93F1449" | Get-UsbHistory

	.NOTES
	NAME: Get-UsbHistory
	AUTHOR: Vladyslav Savchuk
	VERSION: 1.0
	LASTEDIT: 04.10.2023

	#>  
   
    [CmdletBinding()] 

    PARAM(
        [Parameter(HelpMessage="Initialize Windows USB events logging")]
        [switch]$Init = $False,

        [Parameter(HelpMessage="Show more properties of USB-device")]
        [switch]$AllProps = $False,

        [Parameter(HelpMessage="Save report to result.csv")]
        [switch]$File = $False,

        [Parameter(HelpMessage="Silent mode")]
        [switch]$Silent = $False,

        [Parameter(            
            ValueFromPipeline=$true,            
            ValueFromPipelineByPropertyName=$true,
            HelpMessage="Search only specific serial number")]
        [string]$SerialNum
    )

    BEGIN {
        $isAdmin = checkAdminRights
        if (!$isAdmin){
            Write-Warning "Please Run this Commandlet as Administrator!"
            Read-Host -Prompt "Press [Enter] for exit..."
            exit
        }

        if ($Silent){
            $InformationPreference = 'SilentlyContinue'
        } else {
            $InformationPreference = 'Continue'
        }

        if ($Init){
            enableLogging
            Write-Information "USB Event Logging (DriverFrameworks-UserMode) enabled."
            Read-Host -Prompt "Press [Enter] for exit..."
            exit
        }

        
        if (!(checkLoggingEnabled)) {
            Write-Warning "USB Event Logging (DriverFrameworks-UserMode) disabled. Run 'Get-UsbHistory -Init' to enable."
        }
        elevateToLocalSystem
    }

    PROCESS {
        $objs1 = checkRegHiveUSBSTOR
        $objs2 = checkRegHiveUSB
        $objs3 = checkRegHive53f56307
        $objs4 = checkWel

        $objs = @($objs1) + @($objs2) + @($objs3) + @($objs4)
        $serialNumbers = $objs | Select-Object -ExpandProperty "Serial" -Unique
        $uniqCount = $serialNumbers.Count
        Write-Information "Totally found $uniqCount unique USB-device(s) in all places."

        $final = @()
       
        foreach ($serial in $serialNumbers) {
            $obj1 = $objs1 | Where-Object -Property Serial -EQ $serial | Write-Output
            $obj2 = $objs2 | Where-Object -Property Serial -EQ $serial | Write-Output
            $obj3 = $objs3 | Where-Object -Property Serial -EQ $serial | Write-Output
            $obj4 = $objs4 | Where-Object -Property Serial -EQ $serial | Write-Output
        
            $obj = mergeObjects($obj1, $obj2, $obj3, $obj4)
            $final += $obj;
        }

        if (!$AllProps){
            $final | Format-Table -Property Serial, Install, LastArrival, LastRemoval, InstallAlternative, LastArrivalAlternative -AutoSize
        } else {
            $final | Format-Table -Property Serial, DisplayName, PID, VID, REV, Install, 
                                            LastArrival, LastRemoval, InstallAlternative, LastArrivalAlternative -AutoSize
        } 
    }


    END {
        if ($File){
            $final | Export-CSV -Path "$PSScriptRoot\result_$((get-date).ToString("yyyyMMddHHmmss")).csv" -NoTypeInformation
            Write-Information "Report saved into the report.csv file."
        } 
        Remove-Variable * -ErrorAction SilentlyContinue
    }

}


function checkAdminRights(){
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function enableLogging() {
    $welName = 'Microsoft-Windows-DriverFrameworks-UserMode/Operational'

    $wel = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $welName
    $wel.IsEnabled=$true
    $wel.SaveChanges()
}

function checkLoggingEnabled() {
    $welName = 'Microsoft-Windows-DriverFrameworks-UserMode/Operational'

    $wel = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $welName
    return $wel.IsEnabled
}

function elevateToLocalSystem() { 
    Remove-Variable * -ea 0

    $ErrorActionPreference = "stop"

$signature = @"
    [DllImport("advapi32.dll")]
    public static extern bool OpenProcessToken(IntPtr Thread, UInt32 Access, out IntPtr Handle);

    [DllImport("advapi32.dll")]
    public extern static bool DuplicateToken(IntPtr Handle, int Level, out IntPtr Copy);

    [DllImport("advapi32.dll")]
    public static extern bool SetThreadToken(IntPtr Thread, IntPtr Token);
"@ 

    $advApi = Add-Type -MemberDefinition $signature -Name advApi -PassThru
    $ServicePID = (get-wmiobject win32_service | where { $_.name -eq 'SamSs'}).processID
    $process = (Get-Process -Id $ServicePID)
    $otherToken = [IntPtr]0
    $null = $advApi::OpenProcessToken($process.Handle, 6, [ref]$otherToken)
    $tokenCopy = [IntPtr]0
    $null = $advApi::DuplicateToken($otherToken, 2, [ref]$tokenCopy)
    $null = $advApi::SetThreadToken([IntPtr]0, $tokenCopy)
}

function getRegTime($regPath) {
add-type @"
    using System;
    using System.Text;
    using System.Runtime.InteropServices;

    public class advapi32 {
        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern Int32 RegQueryInfoKey(
            Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey,
            StringBuilder lpClass,
            Int32 lpCls, Int32 spare, Int32 subkeys,
            Int32 skLen, Int32 mcLen, Int32 values,
            Int32 vNLen, Int32 mvLen, Int32 secDesc,
            out System.Runtime.InteropServices.ComTypes.FILETIME lpftLastWriteTime
        );
    }
"@

    $reg = get-item $regPath -force
    if ($reg.handle) {
        $time = New-Object System.Runtime.InteropServices.ComTypes.FILETIME
        $result = [advapi32]::RegQueryInfoKey($reg.Handle, $null, 0,0,0,0,0,0,0,0,0, [ref]$time)

        if ($result -eq 0) {
            $timeValue = [uint64]$time.dwHighDateTime -shl 32 -bor ($time.dwLowDateTime -bor [uint32]0)
            return [datetime]::FromFileTime($timeValue)
        }
    }
}

function getRegKeyLastWriteTime($regPath) { 
add-type @"
    using System;
    using System.Text;
    using System.Runtime.InteropServices;

    public class advapi32 {
        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern Int32 RegQueryInfoKey(
            Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey,
            StringBuilder lpClass,
            Int32 lpCls, Int32 spare, Int32 subkeys,
            Int32 skLen, Int32 mcLen, Int32 values,
            Int32 vNLen, Int32 mvLen, Int32 secDesc,
            out System.Runtime.InteropServices.ComTypes.FILETIME lpftLastWriteTime
        );
    }
"@ 


    $reg = get-item $regPath -force

    if ($reg.handle) {
        $time = New-Object System.Runtime.InteropServices.ComTypes.FILETIME
        $result = [advapi32]::RegQueryInfoKey($reg.Handle, $null, 0,0,0,0,0,0,0,0,0, [ref]$time)

        if ($result -eq 0) {
            $low = [uint32]0 -bor $time.dwLowDateTime
            $high = [uint32]0 -bor $time.dwHighDateTime
            $timeValue = ([int64]$high -shl 32) -bor $low
            return [datetime]::FromFileTime($timeValue)
        }
    }
}


function checkRegHiveUSBSTOR() {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
    $propertiesHiveGuid = "{83da6326-97a6-4088-9453-a1923f573b29}"

    $outObjs = @()

    foreach ($device in get-Item "$regPath\*\*") {
        $displayName = $device.GetValue("FriendlyName")
        $service = $device.GetValue('Service')
        if ($service -ne 'disk') {
            Continue
        }

        $serial = $device.Name.Split('\')[6].Split('&')[0]
        if ($SerialNum) {
            if ($serial -ne $SerialNum) {
                Continue
            }
        }
        
        $propertiesHive = $device.psPath + "\Properties\$propertiesHiveGuid"
        $install = getRegTime "$propertiesHive\0064"
        $lastArrival = getRegTime "$propertiesHive\0066"
        $isLastRemovalExist = Test-Path "$propertiesHive\0067"
        $lastRemoval = ''
        if($isLastRemovalExist){
            $lastRemoval = getRegTime "$propertiesHive\0067"
            if ($lastRemoval -eq $lastArrival) {$lastRemoval = "connected now"}
        }

        $outObj = "" | Select DisplayName, Serial, Install, LastArrival, LastRemoval
        $outObj.DisplayName = $displayName
        $outObj.Serial = $serial
        $outObj.Install = $install
        $outObj.LastArrival = $lastArrival
        $outObj.LastRemoval = $lastRemoval
        $outObjs += $outObj
    }

    $outCount = ($outObjs).Length
    Write-Information "Found $outCount USB-device(s) in registry hive [HKLM:\...\Enum\USBSTOR]"
    return $outObjs
}

function checkRegHiveUSB() {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USB"
    $propertiesHiveGuid = "{83da6326-97a6-4088-9453-a1923f573b29}"

    $outObjs = @()

    foreach ($device in get-Item "$regPath\*\*") {
        $service = $device.GetValue('Service')
        if ($service -eq 'USBSTOR') {
            $harwareId = $device.GetValue("HardwareID").Split('\')[1].Split('&')
            $vendorId = $harwareId[0]
            $productId = $harwareId[1]
            $revision = $harwareId[2]

            $serial = $device.Name.Split('\')[6].Split('&')[0]
            if ($SerialNum) {
                if ($serial -ne $SerialNum) {
                    Continue
                }
            }
            $propertiesHive = $device.psPath + "\Properties\$propertiesHiveGuid"
            $install = getRegTime "$propertiesHive\0064"
            $lastArrival = getRegTime "$propertiesHive\0066"
            $lastRemoval = ''
            if($isLastRemovalExist){
                $lastRemoval = getRegTime "$propertiesHive\0067"
                if ($lastRemoval -eq $lastArrival) {$lastRemoval = "connected now"}
            }
       
            $outObj = "" | Select VID, PID, REV, Serial, Install, LastArrival, LastRemoval
            $outObj.VID = $vendorId
            $outObj.PID = $productId
            $outObj.REV = $revision
            $outObj.Serial = $serial
            $outObj.Install = $install
            $outObj.LastArrival = $lastArrival
            $outObj.LastRemoval = $lastRemoval
            $outObjs += $outObj
          }
    }

    $outCount = ($outObjs).Length
    Write-Information "Found $outCount USB-device(s) in registry hive [HKLM:\...\Enum\USB]"
    return $outObjs
}

function checkRegHive53f56307() {
    $regPath = "HKLM:\SYSTEM\ControlSet001\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
    $outObjs = @()

    foreach ($device in get-Item "$regPath\*") {
    
        if ($device.GetValue('DeviceInstance') -like '*USBSTOR*') {
            $deviceInstance = $device.GetValue("DeviceInstance").Split('\')
            $vendorId = $deviceInstance[1].Split('&')[1]
            $productId = $deviceInstance[1].Split('&')[2]
            $serial = $deviceInstance[2].Split('&')[0]
            if ($SerialNum) {
                if ($serial -ne $SerialNum) {
                    Continue
                }
            }
            $LastWriteTime = getRegKeyLastWriteTime($device.PsPath)
            

            $outObj = "" | Select FriendlyVID, FriendlyPID, Serial, InstallAlternative
            $outObj.FriendlyVID = $vendorId
            $outObj.FriendlyPID = $productId
            $outObj.Serial = $serial
            $outObj.InstallAlternative = $LastWriteTime
            $outObjs += $outObj
          }
    }
    $outCount = ($outObjs).Length
    Write-Information "Found $outCount USB-device(s) in registry hive [HKLM:\...\DeviceClasses\{53f56307-...}]"
    return $outObjs
}

function checkWEL() {
    $Filter = @{
        logname='Microsoft-Windows-DriverFrameworks-UserMode/Operational' 
        id=2003
    }

    $events = Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue
    $outObjs = @()

    foreach ($event in $events) {
        if ($event.Message -like '*USBSTOR*') {
            $messageRegex = $event.Message | Select-String -Pattern 'USBSTOR#DISK&(.*)&0#{' -CaseSensitive -AllMatches 
            $deviceInstance = ($messageRegex.Matches.Groups | Where-Object -Property Name -EQ 1 | Select-Object -ExpandProperty Value).Split('&')

            $serial = $deviceInstance[2].Split('#')[1]
            if ($SerialNum) {
                if ($serial -ne $SerialNum) {
                        Continue
                    }
            }
            if ($outObjs.Serial -cnotcontains $serial) {
                $vendorId = $deviceInstance[0]
                $productId = $deviceInstance[1]
                $lastArrival = $event.TimeCreated
            
                $outObj = "" | Select FriendlyVID, FriendlyPID, Serial, LastArrivalAlternative
                $outObj.FriendlyVID = $vendorId
                $outObj.FriendlyPID = $productId
                $outObj.Serial = $serial
                $outObj.LastArrivalAlternative = $lastArrival
                $outObjs += $outObj
            } 
         }
    }

    $outCount = ($outObjs).Length
    Write-Information "Found $outCount USB-device(s) in Windows Event Logs [DriverFrameworks-UserMode/Operational]"
    return $outObjs
}


function mergeObjects($objects){
    if (!$objects[0]){
       $objects[0] = New-Object -TypeName PSObject
    }
    $propertyList1 = @(Get-Member -InputObject $objects[0] -MemberType Properties).Name;
    For ($i=1; $i -le $objects.Count-1; $i++) {
        if (!$objects[$i]){
           $objects[$i] = New-Object -TypeName PSObject
        }

        $propertyList2 = Get-Member -InputObject $objects[$i] -MemberType Properties | Where-Object -FilterScript { $propertyList1 -notcontains $PSItem.Name; };
        

        foreach ($property in $propertyList2) {
            Add-Member -Force -InputObject $objects[0] -Name $property.Name -MemberType NoteProperty -Value $objects[$i].$($property.Name);
        }
    }
    
    return $objects[0]
}