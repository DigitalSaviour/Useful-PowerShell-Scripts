
<#
Author: Lee Burridge (patched by Copilot)
Date: January 16, 2026
Description: Analyze Windows event logs (last 24h) and log issues with suggested solutions.
Adds DMEDP/WUfB error-code extraction (hex & decimal) + common code hints.
Patched to match solutions by Channel (LogName) OR Source (ProviderName),
with a heuristic that maps Windows Update Client events logged in System
to the Operational channel mappings.
#>

$logPath = Join-Path -Path "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs" -ChildPath "EventLogAnalysis.log"

# --- Helper: case-insensitive hashtable ---
function New-CaseInsensitiveHashtable {
    param([hashtable]$Seed)
    $ht = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($Seed) { $Seed.GetEnumerator() | ForEach-Object { $ht[$_.Key] = $_.Value } }
    return $ht
}

# --- Known event solutions (case-insensitive keys) ---
$solutions = New-CaseInsensitiveHashtable @{}

# System
$solutions["System:41"]   = "Unexpected system shutdown. Check power supply, hardware connections, and for overheating issues. For more information: https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/event-id-41-restart"
$solutions["System:6008"] = "Unexpected shutdown. Investigate power-related problems or system crashes. For more information: https://support.microsoft.com/en-us/topic/event-id-6008-is-unexpectedly-logged-to-the-system-event-log-after-you-shut-down-and-restart-your-computer-2e517ea0-e592-b3ad-d572-501c033f4567"
$solutions["System:7000"] = "Service failed to start. Verify service dependencies, permissions, and configuration. For more information: https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/system-log-event-id-7000-7026"
$solutions["System:7026"] = "Driver failed to load. Update or reinstall the problematic driver. For more information: https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/system-log-event-id-7000-7026"
$solutions["System:1001"] = "Blue Screen of Death (BSOD). Analyze memory dump, update drivers, or check hardware. For more information: https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs"
$solutions["System:1074"] = "System shutdown or restart initiated. Check for unexpected restarts or user-initiated actions. For more information: https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs"
$solutions["System:7031"] = "Service terminated unexpectedly. Investigate the specific service mentioned in the event details. For more information: https://learn.microsoft.com/en-us/answers/questions/4076280/event-id-7031-the-dns-client-service-terminated-un"
$solutions["System:7034"] = "Service Control Manager error - service terminated unexpectedly. Review service logs and dependencies. For more information: https://learn.microsoft.com/en-us/answers/questions/2591479/event-id-7034"
$solutions["System:6006"] = "Event log service stopped. This may indicate system shutdown; check for related events. For more information: https://learn.microsoft.com/en-us/answers/questions/3864277/when-are-windows-events-6006-and-6005-logged(apart"
$solutions["System:7036"] = "Service entered the running or stopped state. Normal operation, but monitor if unexpected. For more information: https://www.eventid.net/display.asp?eventid=7036"
$solutions["System:7001"] = "Service Control Manager - dependency service or group failed to start. Check dependencies and related services. For more information: https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/system-log-event-id-7000-7026"
$solutions["System:6005"] = "Event log service started. Indicates system startup. For more information: https://www.eventid.net/display.asp?eventid=6005"
$solutions["System:6009"] = "Microsoft Windows version. Indicates system startup details. For more information: https://www.eventid.net/display.asp?eventid=6009"
$solutions["System:1076"] = "Unexpected shutdown due to power failure or other reasons. Check power supply. For more information: https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs"

# Application
$solutions["Application:1000"] = "Application crash. Try reinstalling the application, checking for updates, or verifying compatibility. For more information: https://learn.microsoft.com/en-us/troubleshoot/outlook/performance/outlook-crashes-and-returns-event-id-1000-crash-signatures"
$solutions["Application:1002"] = "Application hang. Close unresponsive apps, check system resources, or update the application. For more information: https://learn.microsoft.com/en-us/answers/questions/5227473/how-do-i-resolve-event-id-1002"
$solutions["Application:1026"] = ".NET Runtime error. Update .NET Framework, check application logs, or ensure compatibility. For more information: https://learn.microsoft.com/en-us/answers/questions/2792445/net-runtime-error-1026-application-crashes-immedia"
$solutions["Application:1001"] = "Application fault reported by Windows Error Reporting. Review fault bucket details and update the app. For more information: https://learn.microsoft.com/en-us/windows-server/performance/troubleshoot-application-service-crashing-behavior"
$solutions["Application:11708"] = "MSI installation failed. Check MSI logs for detailed error codes and resolve dependencies. For more information: https://learn.microsoft.com/en-us/troubleshoot/windows-server/admin-development/windows-installer-reconfigured-all-applications"
$solutions["Application:10005"] = "DCOM error. Verify component permissions and registration. For more information: https://learn.microsoft.com/en-us/answers/questions/3934476/windows-keeps-crashing-keep-getting-event-id-10005"
$solutions["Application:8198"] = "License activation scheduler error. Check activation status and retry. For more information: https://learn.microsoft.com/en-us/answers/questions/163997/event-id-8198-security-spp-error"
$solutions["Application:1020"] = "Updates to the .NET Framework failed. Reinstall or repair .NET Framework. For more information: https://learn.microsoft.com/en-us/dotnet/framework/install/troubleshoot-blocked-installations-and-uninstallations"
$solutions["Application:1004"] = "Application error in Windows Error Reporting. Investigate the reported fault. For more information: https://learn.microsoft.com/en-us/windows-server/performance/troubleshoot-application-service-crashing-behavior"

# Security
$solutions["Security:4625"] = "An account failed to log on. This could indicate incorrect credentials, account lockout, or potential security threats like brute force attempts. Check the failure reason in the event details. For more information: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625"
$solutions["Security:4740"] = "A user account was locked out. This may be due to multiple failed logon attempts. Review account lockout policies and investigate potential attacks. For more information: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4740"
$solutions["Security:4771"] = "Kerberos pre-authentication failed. Often related to bad passwords or clock skew. Verify user credentials and system time synchronization. For more information: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4771"
$solutions["Security:4769"] = "A Kerberos service ticket was requested. If failure, check for account issues or network problems. For more information: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769"
$solutions["Security:1102"] = "The audit log was cleared. This could be a security incident; investigate who cleared the log and why. For more information: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102"
$solutions["Security:4618"] = "A monitored security event pattern has occurred. Review security policies and potential threats. For more information: https://www.eventid.net/display.asp?eventid=4618"
$solutions["Security:4648"] = "A logon was attempted using explicit credentials. Monitor for unusual activity. For more information: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4648"
$solutions["Security:4672"] = "Special privileges assigned to new logon. Normal for admins, but monitor for elevation attempts. For more information: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672"
$solutions["Security:4720"] = "A user account was created. Verify if this was authorized. For more information: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720"
$solutions["Security:4726"] = "A user account was deleted. Check for unauthorized deletions. For more information: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4726"

# AppLocker
$solutions["Microsoft-Windows-AppLocker/EXE and DLL:8003"] = "AppLocker would have prevented the app from running if enforced. This is an audit mode finding; consider updating policies if enforcement is planned. For more information: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker"
$solutions["Microsoft-Windows-AppLocker/EXE and DLL:8004"] = "AppLocker prevented an EXE or DLL from running. Review AppLocker policies and add an exception if the application is trusted. For more information: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker"
$solutions["Microsoft-Windows-AppLocker/MSI and Script:8006"] = "AppLocker would have prevented the MSI or script from running if enforced. Audit mode finding. For more information: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker"
$solutions["Microsoft-Windows-AppLocker/MSI and Script:8007"] = "AppLocker prevented an MSI or script from running. Check policies and whitelist if necessary. For more information: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker"
$solutions["Microsoft-Windows-AppLocker/EXE and DLL:8000"] = "AppID policy conversion failed. Verify the AppLocker policy configuration and syntax. For more information: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker"
$solutions["Microsoft-Windows-AppLocker/EXE and DLL:8025"] = "Packaged app was not allowed to run. Review AppLocker rules for packaged apps. For more information: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker"
$solutions["Microsoft-Windows-AppLocker/MSI and Script:8024"] = "Packaged app installation blocked. Check AppLocker policies for installers. For more information: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker"
$solutions["Microsoft-Windows-AppLocker/EXE and DLL:8005"] = "AppLocker would have allowed the EXE or DLL if enforced, but it's in audit mode. No action needed unless planning enforcement. For more information: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker"
$solutions["Microsoft-Windows-AppLocker/EXE and DLL:8001"] = "The AppLocker policy was applied successfully to this computer. Normal operation. For more information: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker"
$solutions["Microsoft-Windows-AppLocker/EXE and DLL:8002"] = "EXE or DLL was allowed to run. Normal operation under policy. For more information: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker"

# DMEDP / Intune & WUfB
$solutions["Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin:76"]  = "Auto MDM Enrollment failed. Check the error code (e.g., 0x8018002b might indicate licensing issues, network problems, or enrollment restrictions). Verify user licenses and device limits in Intune. For more information: https://learn.microsoft.com/en-us/troubleshoot/mem/intune/device-enrollment/windows10-enroll-error-80180002b"
$solutions["Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin:201"] = "MDM enrollment attempted but may have issues. Check subsequent events for success or failure details. For more information: https://learn.microsoft.com/en-us/answers/questions/377729/device-enrollment-failing"
$solutions["Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin:305"] = "Device join attempt failed. Investigate connectivity, credentials, or Azure AD configuration. For more information: https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-hybrid-join-windows-current"
$solutions["Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin:109"] = "MDM Enroll failed. Review the Win32 error code and check network connectivity or authentication. For more information: https://learn.microsoft.com/en-us/troubleshoot/mem/intune/device-enrollment/troubleshoot-windows-enrollment-errors"
$solutions["Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin:401"] = "MDM Session failed to get AAD Token. Ensure proper authentication and check for 401 unauthorized errors. For more information: https://www.reddit.com/r/Intune/comments/yoz78u/new_intune_setup_error_code_401"
$solutions["Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin:454"] = "MDM Policy failed to apply. Verify policy settings and device compliance. For more information: https://learn.microsoft.com/en-us/answers/questions/4294708/device-management-enterprise-diagnostic-provider-e"
$solutions["Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin:204"] = "Hybrid AAD join started but may have issues. Monitor for completion events. For more information: https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-hybrid-join-windows-current"
$solutions["Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin:208"] = "MDM policy refresh session. If failed, check network or server issues. For more information: https://learn.microsoft.com/en-us/answers/questions/377729/device-enrollment-failing"
$solutions["Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin:301"] = "MDM enrollment successful. Normal operation. For more information: https://learn.microsoft.com/en-us/troubleshoot/mem/intune/device-enrollment/troubleshoot-windows-enrollment-errors"
$solutions["Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin:404"] = "Enrollment error. Check detailed error codes in the event message. For more information: https://learn.microsoft.com/en-us/troubleshoot/mem/intune/device-enrollment/troubleshoot-windows-enrollment-errors"
$solutions["Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin:500"] = "Internal service error. Retry enrollment or check Intune service health. For more information: https://learn.microsoft.com/en-us/troubleshoot/mem/intune/device-enrollment/troubleshoot-windows-enrollment-errors"
$solutions["Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin:600"] = "MDM session error. Investigate the specific error code provided. For more information: https://learn.microsoft.com/en-us/troubleshoot/mem/intune/device-enrollment/troubleshoot-windows-enrollment-errors"
$solutions["Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin:813"] = "MDM policy applied successfully. Normal operation. For more information: https://www.anoopcnair.com/intune-logs-event-ids-ime-logs-troubleshooting"
$solutions["Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin:814"] = "MDM client received and applied policy update. Normal operation. For more information: https://www.anoopcnair.com/intune-logs-event-ids-ime-logs-troubleshooting"

# Windows Update Client
$solutions["Microsoft-Windows-WindowsUpdateClient/Operational:20"] = "Installation Failure: Windows failed to install the following update. Check the error code in the message for specific issues, such as 0x8024200D (retry download) or 0x80070643 (repair .NET Framework). For more information: https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/common-windows-update-errors"
$solutions["Microsoft-Windows-WindowsUpdateClient/Operational:24"] = "Download Failure: Windows failed to download an update. Check network connectivity, proxy settings, or error code like 0x8024402C (invalid characters in proxy list). For more information: https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/common-windows-update-errors"
$solutions["Microsoft-Windows-WindowsUpdateClient/Operational:25"] = "General Failure: Windows Update encountered an unknown error. Review the error code and WindowsUpdate.log for details. Common fixes include running Windows Update Troubleshooter. For more information: https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-troubleshooting"
$solutions["Microsoft-Windows-WindowsUpdateClient/Operational:31"] = "Invalid Metadata: Windows Update Agent found invalid information in the update's metadata. Retry the update or check for corrupted files. For more information: https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-logs"
$solutions["Microsoft-Windows-WindowsUpdateClient/Operational:40"] = "Update Suspended: Update operation was suspended, possibly due to metered connection or policy. Resume when conditions allow. For more information: https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-troubleshooting"
$solutions["Microsoft-Windows-WindowsUpdateClient/Operational:43"] = "Update Detection: Information about a new update. If error, check detection process. For more information: https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-logs"
$solutions["Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin:1006"] = "Windows Update for Business policy failure. Check Intune policies and device compliance for update rings. For more information: https://learn.microsoft.com/en-us/mem/intune/protect/windows-update-for-business-configure"
$solutions["Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin:1007"] = "Windows Update for Business scan failure. Verify network and update service status. For more information: https://learn.microsoft.com/en-us/mem/intune/protect/windows-update-for-business-configure"

# --- ALIASES: Map common WU IDs when they are logged in the System channel ---
$solutions["System:20"] = $solutions["Microsoft-Windows-WindowsUpdateClient/Operational:20"]
$solutions["System:24"] = $solutions["Microsoft-Windows-WindowsUpdateClient/Operational:24"]
$solutions["System:25"] = $solutions["Microsoft-Windows-WindowsUpdateClient/Operational:25"]
$solutions["System:31"] = $solutions["Microsoft-Windows-WindowsUpdateClient/Operational:31"]
$solutions["System:40"] = $solutions["Microsoft-Windows-WindowsUpdateClient/Operational:40"]
$solutions["System:43"] = $solutions["Microsoft-Windows-WindowsUpdateClient/Operational:43"]

# --- Common error-code hints (case-insensitive) ---
$errorCodeHints = New-CaseInsensitiveHashtable @{
    "0x8018002b" = "AAD/MDM enrollment restriction, licensing, or device limit"
    "0x801c03f3" = "Azure AD device limit exceeded"
    "0x801c0003" = "Azure AD server error (transient); retry or check service health"
    "0x801c001d" = "Conditional access or policy blocked enrollment"
    "0x8024200D" = "Download incomplete; retry download"
    "0x8024402C" = "WU proxy list / name resolution issue"
    "0x8024A105" = "WU service/registration issue; reset WU components"
    "0x80070643" = "MSI install failure; often .NET repair helps"
    "0x80072EE2" = "Network timeout; proxy/firewall connectivity"
    "0x80070002" = "File not found; content missing/corrupted"
}

# --- Helper: extract error codes from an event (DMEDP & WU) ---
function Get-ErrorCodesFromEvent {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Eventing.Reader.EventRecord] $Event
    )
    $codes = New-Object System.Collections.Generic.List[string]
    $rx = '(?i)0x[0-9a-f]{6,8}|-?2147\d{6}'  # hex HRESULTs and negative decimal HRESULTs

    # From properties (structured) first
    foreach ($prop in $Event.Properties) {
        $val = [string]$prop.Value
        if ([string]::IsNullOrWhiteSpace($val)) { continue }
        foreach ($m in [regex]::Matches($val, $rx)) { $codes.Add($m.Value) }
    }
    # From message text
    $msg = $Event.Message
    if ($msg) {
        foreach ($m in [regex]::Matches($msg, $rx)) { $codes.Add($m.Value) }
    }

    # Normalize: convert negative decimal HRESULTs to hex and annotate
    $normalized = foreach ($c in ($codes | Select-Object -Unique)) {
        if ($c -match '^-?\d+$') {
            try {
                $i  = [int32]$c
                $u  = [uint32]$i
                $hx = ('0x{0:X8}' -f $u)
                "$hx (dec $c)"
            } catch { $c }
        } else {
            if ($c -like '0x*') { $c.ToUpperInvariant() } else { $c }
        }
    }

    # Append hints inline when known
    $withHints = foreach ($n in $normalized) {
        $lookup = $n -replace '\s*\(dec.*\)$',''
        if ($errorCodeHints.ContainsKey($lookup)) {
            "$n ($($errorCodeHints[$lookup]))"
        } else {
            $n
        }
    }

    return ($withHints | Select-Object -Unique)
}

# --- Build candidate keys for solution lookup (Channel + Source + heuristic) ---
function Get-SolutionKeyCandidates {
    param([System.Diagnostics.Eventing.Reader.EventRecord] $Event)

    $candidates = New-Object System.Collections.Generic.List[string]
    # Channel-based
    $candidates.Add("$($Event.LogName):$($Event.Id)")
    # Source-based
    $candidates.Add("$($Event.ProviderName):$($Event.Id)")

    # Heuristic: for Windows Update Client, also try its Operational channel mapping
    if ($Event.ProviderName -eq "Microsoft-Windows-WindowsUpdateClient") {
        $candidates.Add("Microsoft-Windows-WindowsUpdateClient/Operational:$($Event.Id)")
    }

    # Return unique in insertion order
    return ($candidates | Select-Object -Unique)
}

# --- Header ---
"Event Log Analysis Report" | Out-File -FilePath $logPath -Append -Encoding utf8
"Run on: $(Get-Date)"       | Out-File -FilePath $logPath -Append -Encoding utf8
"------------------------"  | Out-File -FilePath $logPath -Append -Encoding utf8

$logs = @(
    "System",
    "Application",
    "Security",
    "Microsoft-Windows-AppLocker/EXE and DLL",
    "Microsoft-Windows-AppLocker/MSI and Script",
    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
    "Microsoft-Windows-WindowsUpdateClient/Operational"
)

$hasIssues = $false

foreach ($log in $logs) {
    $filter = @{
        LogName   = $log
        StartTime = (Get-Date).AddHours(-240) # Last 10 days
        Level     = 2,3     # 2=Error, 3=Warning
    }

    # Force array to avoid single-object pitfalls
    $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue)

    if ($events.Count -gt 0) {
        $hasIssues = $true
        "Issues found in $log log:" | Out-File -FilePath $logPath -Append -Encoding utf8

        foreach ($event in $events) {
            # Try multiple keys for solution lookup
            $solution = $null
            foreach ($candidateKey in (Get-SolutionKeyCandidates -Event $event)) {
                if ($solutions.ContainsKey($candidateKey)) {
                    $solution = $solutions[$candidateKey]
                    break
                }
            }
            if (-not $solution) {
                $solution = "No specific solution available. Investigate the error message further or search for the Event ID online."
            }

            # Extract codes for WU events even if they appear in System
            $shouldExtractCodes =
                ($event.LogName -eq "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin") -or
                ($event.LogName -eq "Microsoft-Windows-WindowsUpdateClient/Operational") -or
                ($event.ProviderName -eq "Microsoft-Windows-WindowsUpdateClient")

            $errorCodesText = ""
            if ($shouldExtractCodes) {
                $codes = Get-ErrorCodesFromEvent -Event $event
                if ($codes -and $codes.Count -gt 0) {
                    $errorCodesText = "Error Codes: " + ($codes -join ", ")
                } else {
                    $errorCodesText = "Error Codes: None detected"
                }
            }

            $output = @"
Event ID: $($event.Id)
Time: $($event.TimeCreated)
Source: $($event.ProviderName)
Channel: $($event.LogName)
Message: $($event.Message)
$($errorCodesText)
Solution: $solution
------------------------
"@

            $output | Out-File -FilePath $logPath -Append -Encoding utf8
        }
    }
}

if (-not $hasIssues) {
    "No issues found in the last 24 hours." | Out-File -FilePath $logPath -Append -Encoding utf8
}

"End of Report" | Out-File -FilePath $logPath -Append -Encoding utf8
"=========================" | Out-File -FilePath $logPath -Append -Encoding utf8
