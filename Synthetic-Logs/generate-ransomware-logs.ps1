<#
.SYNOPSIS
Simulates DarkSide ransomware behavioral telemetry for Splunk JSON ingestion.

.DESCRIPTION
Generates synthetic Windows Event Logs (Event ID 4688) as JSON objects matching the Splunk Common Information Model (CIM), enabling SIEM correlation rule testing.
#>

$OutputFile = "d:\CyberSecurityRuleBook\githubprojects\CyberSecurity RuleBook - Governance Platform\public\data\splunk_darkside_telemetry.json"
if (Test-Path $OutputFile) { Remove-Item $OutputFile }

function Write-SplunkJson {
    param (
        [string]$EventCode,
        [string]$ProcessName,
        [string]$CommandLine,
        [string]$Message
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $log = @{
        time = $timestamp
        source = "WinEventLog:Security"
        sourcetype = "XmlWinEventLog"
        host = "OT-HMI-01"
        EventCode = $EventCode
        ProcessName = $ProcessName
        CommandLine = $CommandLine
        Message = $Message
    }
    $log | ConvertTo-Json -Depth 3 -Compress | Out-File -FilePath $OutputFile -Append -Encoding utf8
}

Write-Host "[*] Simulating T1489: Service Stop..." -ForegroundColor Yellow
Write-SplunkJson -EventCode "4688" -ProcessName "C:\Windows\System32\cmd.exe" -CommandLine "cmd.exe /c net stop mpssvc" -Message "A new process has been created."

Write-Host "[*] Simulating T1490: Inhibit System Recovery..." -ForegroundColor Red
Write-SplunkJson -EventCode "4688" -ProcessName "C:\Windows\System32\vssadmin.exe" -CommandLine "vssadmin.exe Delete Shadows /All /Quiet" -Message "A new process has been created."

Write-Host "[*] Simulating File Encryption..." -ForegroundColor DarkRed
Write-SplunkJson -EventCode "4663" -ProcessName "C:\Users\Public\darkside.exe" -CommandLine "N/A" -Message "An attempt was made to access an object. File: C:\SCADA\Config\HMI_layout.ini.darkside"

Start-Sleep -Seconds 2

Write-Host "[*] Simulating EDR Containment: Process Termination..." -ForegroundColor Cyan
Write-SplunkJson -EventCode "4689" -ProcessName "C:\Users\Public\darkside.exe" -CommandLine "N/A" -Message "A process has exited. Status: 0x0"

Write-Host "[*] Simulating EDR Containment: WFP Network Block..." -ForegroundColor Cyan
Write-SplunkJson -EventCode "5156" -ProcessName "System" -CommandLine "N/A" -Message "The Windows Filtering Platform has blocked a connection."

Write-Host "[+] Splunk JSON telemetry generated at $OutputFile" -ForegroundColor Green
