<#
.SYNOPSIS
Simulates DarkSide ransomware behavioral telemetry for SIEM ingestion.

.DESCRIPTION
This script generates synthetic Windows Event Logs (Event ID 4688 - Process Creation) to simulate the tactics used in the Colonial Pipeline breach, specifically:
- Disabling security services
- Deleting Volume Shadow Copies
- Encrypting OT/ICS interface files

.NOTES
Run this only in a controlled lab environment. This does NOT execute real malware; it only writes log entries to the Application event log.
#>

$Source = "DarkSide-Simulation"
if ([System.Diagnostics.EventLog]::SourceExists($Source) -eq $false) {
    New-EventLog -LogName Application -Source $Source
}

Write-Host "[*] Simulating T1489: Service Stop..." -ForegroundColor Yellow
$msg1 = "Process Creation: cmd.exe /c net stop mpssvc"
Write-EventLog -LogName Application -Source $Source -EntryType Warning -EventId 4688 -Message $msg1

Write-Host "[*] Simulating T1490: Inhibit System Recovery..." -ForegroundColor Red
$msg2 = "Process Creation: vssadmin.exe Delete Shadows /All /Quiet"
Write-EventLog -LogName Application -Source $Source -EntryType Error -EventId 4688 -Message $msg2

Write-Host "[*] Simulating OT Environment Impact..." -ForegroundColor DarkRed
$msg3 = "File Modified: C:\SCADA\Config\HMI_layout.ini.darkside"
Write-EventLog -LogName Application -Source $Source -EntryType Error -EventId 4663 -Message $msg3

Write-Host "[+] Synthetic telemetry injected successfully." -ForegroundColor Green
