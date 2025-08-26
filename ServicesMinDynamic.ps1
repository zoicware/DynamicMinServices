If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	
}

#idea credits
#https://github.com/djdallmann/GamingPCSetup/blob/master/CONTENT/SCRIPTS/SafeMode.ps1
#get minimal services by comparing running services in normal mode and safe mode with networking



function Get-ServicesDrivers {
    param(
        [ValidateSet('Normal', 'Safe')]
        $Mode
    )
    #get services and drivers
    $serviceNames = sc.exe query type=all | findstr /i SERVICE_NAME | ForEach-Object { $_.replace('SERVICE_NAME: ', '') }

    #exclude services and drivers that are not from microsoft
    $services = Get-WmiObject Win32_Service | Where-Object { $serviceNames -contains $_.Name }
    $DriverNameList = $services | ForEach-Object {
        $path = $_.PathName
    
        #get exe path
        if ($path -match '"([^"]+)"') {
            $exePath = $matches[1]
        }
        else {
            $exePath = $path.Split(' ')[0].Trim()
        }
    
        if (-not (Test-Path $exePath -ErrorAction SilentlyContinue)) {
            return
        }
    
        try {
            $fileVersionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exePath)
            if ($fileVersionInfo.CompanyName -like '*Microsoft*') {
                return $_.Name
            }
        }
        catch {
            #cant get version info
        }
    } | Where-Object { $_ -ne $null }

   

    if ($Mode -eq 'Safe') {
        #clear xml files just incase
        Remove-Item "$env:TEMP\SafeModeSCQuery.xml" -ErrorAction SilentlyContinue
        #export list to xml
        $DriverNameList | Export-Clixml -Path "$env:TEMP\SafeModeSCQuery.xml"
    }
    else {
        #clear xml files just incase
        Remove-Item "$env:TEMP\SCQuery.xml" -ErrorAction SilentlyContinue
        #export list to xml
        $DriverNameList | Export-Clixml -Path "$env:TEMP\SCQuery.xml"
    }
    
}

function Get-SafeBootServiceData {
    $safeModeDriverNameList = Import-Clixml -Path "$env:TEMP\SafeModeSCQuery.xml"
    return $safeModeDriverNameList
}

function Get-NormalBootServiceData {
    $normalDriverNameList = Import-Clixml -Path "$env:TEMP\SCQuery.xml"
    return $normalDriverNameList
}

function Compare-ServiceData {
    $safeModeSvcData = Get-SafeBootServiceData
    $normalModeSvcData = Get-NormalBootServiceData
    #compare data and return services running in normal mode but not in safemode
    $livesvccompare = Compare-Object -ReferenceObject $normalModeSvcData -DifferenceObject $safeModeSvcData -IncludeEqual
    $livenotrunning = @()
    foreach ( $i in $livesvccompare ) {
        if ( $i.SideIndicator -eq '<=' ) {
            $livenotrunning += $i.InputObject
        }
    }
    return $livenotrunning
}


function Disable-Services {
    #create log to track services disabled
    $outLog = "$env:USERPROFILE\ServicesMinResultLog.txt"
    Remove-Item $outLog -ErrorAction SilentlyContinue
    New-Item $outLog | Out-Null

    #exclude some services
    $excludedSvcs = @(
        'AudioEndpointBuilder', 
        'Audiosrv', 
        'SysMain',
        'HdAudAddService',
        'MMCSS',
        'ksthunk',
        #uncomment themes (remove #) if you want to change your background/theme
        #'Themes', 
        'camsvc',
        'Schedule',
        'iphlpsvc',
        'Appinfo',
        'DispBrokerDesktopSvc'
    )

    $normalModeSvcs = Compare-ServiceData
    foreach ($svc in $normalModeSvcs) {
        if ($excludedSvcs -notcontains $svc) {
            $ogStartType = (Get-Service -Name $svc).StartType
            try {
                Set-Service -Name $svc -StartupType Disabled -ErrorAction Ignore
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
                Set-ItemProperty -Path $regPath -Name 'Start' -Value 4 -ErrorAction Stop
                Add-Content $outLog -Value "Disabled [$svc] Successfully! Original StartType : $ogStartType"
            }
            catch {
                Add-Content $outLog -Value "Unable to Disable $svc!"
            }
        }
    }
}

function Set-BootMode {
    param(
        [ValidateSet('Normal', 'Safe')]
        $Mode
    )
    if ($Mode -eq 'Safe') {
        #boot to safemode with networking
        Start-process bcdedit.exe -ArgumentList '/set {current} safeboot network'
        Restart-Computer
    }
    else {
        #boot back to normal
        Start-process bcdedit.exe -ArgumentList '/deletevalue safeboot'
        Restart-Computer
    }
    
}


function Revert-Services {
    $StartTypeTable = @{
        'Boot'      = 0
        'System'    = 1
        'Automatic' = 2
        'Manual'    = 3
        'Disabled'  = 4
    }

    try {
        $resultContent = Get-Content "$env:USERPROFILE\ServicesMinResultLog.txt" -ErrorAction Stop
    }
    catch {
        return 1
    }

    foreach ($line in $resultContent) {
        if ($line -like 'Disabled*') {
            #get service name
            $start = $line.indexof('[') + 1
            $end = $line.indexof(']')
            $length = $end - $start
            $svcName = $line.substring($start, $length)
            #get og start type
            $junk, $startType = $line -split ':'
            #apply start type
            Set-Service -Name $svcName -StartupType $startType.Trim() -ErrorAction Ignore
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
            Set-ItemProperty -Path $regPath -Name 'Start' -Value $StartTypeTable[$startType.Trim()] -ErrorAction Ignore
        }
    }


}



$bootState = (Get-CimInstance win32_computersystem).BootupState

if ($bootState -like '*Fail-safe*') {
    Write-Host '[+] Safe Mode Detected...' -ForegroundColor Green
    Write-Host '[+] Collecting Services and Drivers...' -ForegroundColor Green
    Get-ServicesDrivers -Mode Safe
    Write-Host '[+] Press Any Key to Boot Back to Normal Mode...' -NoNewline -ForegroundColor Green
    [void][System.Console]::ReadKey($true)
    Set-BootMode -Mode Normal
}
else {
    Write-Host '[+] Safe Mode NOT Detected...' -ForegroundColor Green
    Write-Host
    do {
        Write-Host '[1] Enter Safe Mode with Networking to Collect Services' -ForegroundColor Cyan
        Write-Host '[2] Collect Normal Mode Services and Disable' -ForegroundColor Cyan
        Write-Host '[3] Revert Disabled Services' -ForegroundColor Cyan
        Write-Host 'Enter Option 1,2,3: ' -ForegroundColor Cyan -NoNewline
        $option = Read-Host
        switch ($option) {
            '1' { 
                Set-BootMode -Mode Safe
                break
            }
            '2' {
                Get-ServicesDrivers -Mode Normal
                Disable-Services
                Write-Host '[+] Services Disabled...' -ForegroundColor Green
                Write-Host "[+] Result Log Created at [$env:USERPROFILE\ServicesMinResultLog.txt]" -ForegroundColor Green
                Write-Host '[!] Keep This Log If You Need to Revert Later' -ForegroundColor Yellow
                Write-Host '[+] Restart To Apply Changes...' -NoNewline -ForegroundColor Green
                [void][System.Console]::ReadKey($true)
                Restart-Computer
                break
            }
            '3' {
                $result = Revert-Services
                if ($result -eq 1) {
                    Write-Host '[!] Unable To Get Result Log...' -ForegroundColor Red -NoNewline
                    [void][System.Console]::ReadKey($true)
                }
                else {
                    Write-Host '[+] Services Reverted...' -ForegroundColor Green
                    Write-Host '[+] Restart To Apply...' -ForegroundColor Green
                    [void][System.Console]::ReadKey($true)
                    Restart-Computer
                }
                break
            }
            Default {
                Write-Host '[!] Invalid Option...' -ForegroundColor Red
                $invalid = $true
                break
            }
        }
   
    }while ($invalid)


}

