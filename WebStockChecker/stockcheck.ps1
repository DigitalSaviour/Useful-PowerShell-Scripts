<#
.SYNOPSIS
    Product Stock Checker v2 - WinForms GUI with background checks and notifications.

.DESCRIPTION
    Add multiple product URLs and check their page content for stock keywords.
    Checks run in the background using a RunspacePool so the GUI stays responsive.

.NOTES
    Save path: ProductStockChecker-v2.ps1
    Run with: powershell.exe -ExecutionPolicy Bypass -STA -File .\ProductStockChecker-v2.ps1
    Tested syntax style for Windows PowerShell 5.1 compatibility.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ------------------------------------------------------------
# Global state
# ------------------------------------------------------------

$Script:ConfigPath = Join-Path -Path $PSScriptRoot -ChildPath "ProductStockChecker-v2.json"
$Script:CsvDefaultPath = Join-Path -Path $PSScriptRoot -ChildPath "ProductStockChecker-products.csv"
$Script:DefaultIntervalMinutes = 60
$Script:IsSchedulerRunning = $false
$Script:IsChecking = $false
$Script:MaxThreads = 8
$Script:ResultQueue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
$Script:ActiveChecks = New-Object System.Collections.ArrayList
$Script:RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Script:MaxThreads)
$Script:RunspacePool.ApartmentState = 'MTA'
$Script:RunspacePool.Open()

# ------------------------------------------------------------
# Background stock checker code
# ------------------------------------------------------------

$Script:StockCheckScriptBlock = {
    param(
        [string]$Id,
        [string]$Name,
        [string]$Url,
        [string]$InStockTerms,
        [string]$OutOfStockTerms,
        [int]$TimeoutSec,
        [object]$Queue
    )

    function Split-Terms {
        param([string]$Terms)

        if ([string]::IsNullOrWhiteSpace($Terms)) {
            return @()
        }

        return @(
            $Terms -split ',' |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
    }

    function Add-Result {
        param(
            [string]$Status,
            [string]$MatchedTerm,
            [string]$ErrorMessage,
            [int]$HttpStatusCode
        )

        $Queue.Enqueue([PSCustomObject]@{
            Id             = $Id
            Name           = $Name
            Url            = $Url
            Status         = $Status
            MatchedTerm    = $MatchedTerm
            ErrorMessage   = $ErrorMessage
            HttpStatusCode = $HttpStatusCode
            CheckedAt      = Get-Date
        })
    }

    try {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
        }
        catch {
            # Ignore protocol assignment errors on older hosts.
        }

        $headers = @{
            'User-Agent'      = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShellStockChecker/2.0'
            'Accept'          = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            'Accept-Language' = 'en-GB,en;q=0.9'
            'Cache-Control'   = 'no-cache'
            'Pragma'          = 'no-cache'
        }

        $requestParams = @{
            Uri         = $Url
            Headers     = $headers
            TimeoutSec  = $TimeoutSec
            ErrorAction = 'Stop'
        }

        if ($PSVersionTable.PSVersion.Major -lt 6) {
            $requestParams['UseBasicParsing'] = $true
        }

        $response = Invoke-WebRequest @requestParams
        $content = [string]$response.Content
        $httpStatus = 0

        try {
            $httpStatus = [int]$response.StatusCode
        }
        catch {
            $httpStatus = 0
        }

        if ([string]::IsNullOrWhiteSpace($content)) {
            Add-Result -Status 'Unknown' -MatchedTerm '' -ErrorMessage 'Page returned no readable content.' -HttpStatusCode $httpStatus
            return
        }

        $outTerms = Split-Terms -Terms $OutOfStockTerms
        $inTerms = Split-Terms -Terms $InStockTerms

        foreach ($term in $outTerms) {
            if ($content -match [regex]::Escape($term)) {
                Add-Result -Status 'Out of stock' -MatchedTerm $term -ErrorMessage '' -HttpStatusCode $httpStatus
                return
            }
        }

        foreach ($term in $inTerms) {
            if ($content -match [regex]::Escape($term)) {
                Add-Result -Status 'In stock' -MatchedTerm $term -ErrorMessage '' -HttpStatusCode $httpStatus
                return
            }
        }

        Add-Result -Status 'Unknown' -MatchedTerm '' -ErrorMessage 'No configured stock keywords matched the page content.' -HttpStatusCode $httpStatus
    }
    catch {
        Add-Result -Status 'Error' -MatchedTerm '' -ErrorMessage $_.Exception.Message -HttpStatusCode 0
    }
}

# ------------------------------------------------------------
# Data table
# ------------------------------------------------------------

$table = New-Object System.Data.DataTable
[void]$table.Columns.Add('Id', [string])
[void]$table.Columns.Add('Enabled', [bool])
[void]$table.Columns.Add('Name', [string])
[void]$table.Columns.Add('Url', [string])
[void]$table.Columns.Add('InStockTerms', [string])
[void]$table.Columns.Add('OutOfStockTerms', [string])
[void]$table.Columns.Add('Status', [string])
[void]$table.Columns.Add('LastChecked', [string])
[void]$table.Columns.Add('LastMatch', [string])
[void]$table.Columns.Add('LastError', [string])
[void]$table.Columns.Add('LastNotified', [string])

# ------------------------------------------------------------
# GUI
# ------------------------------------------------------------

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Product Stock Checker v2'
$form.Size = New-Object System.Drawing.Size(1320, 860)
$form.MinimumSize = New-Object System.Drawing.Size(1120, 740)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Location = New-Object System.Drawing.Point(10, 10)
$grid.Size = New-Object System.Drawing.Size(1280, 330)
$grid.Anchor = 'Top,Left,Right'
$grid.DataSource = $table
$grid.AutoSizeColumnsMode = 'Fill'
$grid.AllowUserToAddRows = $false
$grid.SelectionMode = 'FullRowSelect'
$grid.MultiSelect = $true
$grid.RowHeadersVisible = $false
$form.Controls.Add($grid)

$lblName = New-Object System.Windows.Forms.Label
$lblName.Text = 'Product name'
$lblName.Location = New-Object System.Drawing.Point(10, 355)
$lblName.Size = New-Object System.Drawing.Size(100, 20)
$form.Controls.Add($lblName)

$txtName = New-Object System.Windows.Forms.TextBox
$txtName.Location = New-Object System.Drawing.Point(120, 352)
$txtName.Size = New-Object System.Drawing.Size(240, 24)
$form.Controls.Add($txtName)

$lblUrl = New-Object System.Windows.Forms.Label
$lblUrl.Text = 'URL'
$lblUrl.Location = New-Object System.Drawing.Point(380, 355)
$lblUrl.Size = New-Object System.Drawing.Size(40, 20)
$form.Controls.Add($lblUrl)

$txtUrl = New-Object System.Windows.Forms.TextBox
$txtUrl.Location = New-Object System.Drawing.Point(420, 352)
$txtUrl.Size = New-Object System.Drawing.Size(870, 24)
$txtUrl.Anchor = 'Top,Left,Right'
$form.Controls.Add($txtUrl)

$lblIn = New-Object System.Windows.Forms.Label
$lblIn.Text = 'In stock terms'
$lblIn.Location = New-Object System.Drawing.Point(10, 390)
$lblIn.Size = New-Object System.Drawing.Size(100, 20)
$form.Controls.Add($lblIn)

$txtIn = New-Object System.Windows.Forms.TextBox
$txtIn.Location = New-Object System.Drawing.Point(120, 387)
$txtIn.Size = New-Object System.Drawing.Size(520, 24)
$txtIn.Text = 'in stock,add to basket,add to cart,available,buy now,add to trolley,available online'
$form.Controls.Add($txtIn)

$lblOut = New-Object System.Windows.Forms.Label
$lblOut.Text = 'Out terms'
$lblOut.Location = New-Object System.Drawing.Point(660, 390)
$lblOut.Size = New-Object System.Drawing.Size(80, 20)
$form.Controls.Add($lblOut)

$txtOut = New-Object System.Windows.Forms.TextBox
$txtOut.Location = New-Object System.Drawing.Point(740, 387)
$txtOut.Size = New-Object System.Drawing.Size(550, 24)
$txtOut.Anchor = 'Top,Left,Right'
$txtOut.Text = 'out of stock,sold out,currently unavailable,unavailable,notify me,email me when back in stock,no longer available'
$form.Controls.Add($txtOut)

$btnAdd = New-Object System.Windows.Forms.Button
$btnAdd.Text = 'Add URL'
$btnAdd.Location = New-Object System.Drawing.Point(10, 425)
$btnAdd.Size = New-Object System.Drawing.Size(100, 32)
$form.Controls.Add($btnAdd)

$btnRemove = New-Object System.Windows.Forms.Button
$btnRemove.Text = 'Remove selected'
$btnRemove.Location = New-Object System.Drawing.Point(119, 425)
$btnRemove.Size = New-Object System.Drawing.Size(130, 32)
$form.Controls.Add($btnRemove)

$btnCheckNow = New-Object System.Windows.Forms.Button
$btnCheckNow.Text = 'Check now'
$btnCheckNow.Location = New-Object System.Drawing.Point(258, 425)
$btnCheckNow.Size = New-Object System.Drawing.Size(110, 32)
$form.Controls.Add($btnCheckNow)

$btnStartStop = New-Object System.Windows.Forms.Button
$btnStartStop.Text = 'Start scheduler'
$btnStartStop.Location = New-Object System.Drawing.Point(377, 425)
$btnStartStop.Size = New-Object System.Drawing.Size(130, 32)
$form.Controls.Add($btnStartStop)

$btnSave = New-Object System.Windows.Forms.Button
$btnSave.Text = 'Save'
$btnSave.Location = New-Object System.Drawing.Point(516, 425)
$btnSave.Size = New-Object System.Drawing.Size(80, 32)
$form.Controls.Add($btnSave)

$btnLoad = New-Object System.Windows.Forms.Button
$btnLoad.Text = 'Load'
$btnLoad.Location = New-Object System.Drawing.Point(605, 425)
$btnLoad.Size = New-Object System.Drawing.Size(80, 32)
$form.Controls.Add($btnLoad)

$btnExportCsv = New-Object System.Windows.Forms.Button
$btnExportCsv.Text = 'Export CSV'
$btnExportCsv.Location = New-Object System.Drawing.Point(694, 425)
$btnExportCsv.Size = New-Object System.Drawing.Size(90, 32)
$form.Controls.Add($btnExportCsv)

$btnImportCsv = New-Object System.Windows.Forms.Button
$btnImportCsv.Text = 'Import CSV'
$btnImportCsv.Location = New-Object System.Drawing.Point(793, 425)
$btnImportCsv.Size = New-Object System.Drawing.Size(90, 32)
$form.Controls.Add($btnImportCsv)

$lblInterval = New-Object System.Windows.Forms.Label
$lblInterval.Text = 'Interval minutes'
$lblInterval.Location = New-Object System.Drawing.Point(900, 432)
$lblInterval.Size = New-Object System.Drawing.Size(100, 20)
$form.Controls.Add($lblInterval)

$nudInterval = New-Object System.Windows.Forms.NumericUpDown
$nudInterval.Location = New-Object System.Drawing.Point(1005, 429)
$nudInterval.Size = New-Object System.Drawing.Size(70, 24)
$nudInterval.Minimum = 1
$nudInterval.Maximum = 1440
$nudInterval.Value = $Script:DefaultIntervalMinutes
$form.Controls.Add($nudInterval)

$lblTimeout = New-Object System.Windows.Forms.Label
$lblTimeout.Text = 'Timeout sec'
$lblTimeout.Location = New-Object System.Drawing.Point(1095, 432)
$lblTimeout.Size = New-Object System.Drawing.Size(80, 20)
$form.Controls.Add($lblTimeout)

$nudTimeout = New-Object System.Windows.Forms.NumericUpDown
$nudTimeout.Location = New-Object System.Drawing.Point(1175, 429)
$nudTimeout.Size = New-Object System.Drawing.Size(70, 24)
$nudTimeout.Minimum = 5
$nudTimeout.Maximum = 300
$nudTimeout.Value = 30
$form.Controls.Add($nudTimeout)

$lblNextRun = New-Object System.Windows.Forms.Label
$lblNextRun.Text = 'Next automatic check: stopped'
$lblNextRun.Location = New-Object System.Drawing.Point(10, 465)
$lblNextRun.Size = New-Object System.Drawing.Size(420, 20)
$form.Controls.Add($lblNextRun)

$grpNotify = New-Object System.Windows.Forms.GroupBox
$grpNotify.Text = 'Notifications'
$grpNotify.Location = New-Object System.Drawing.Point(10, 492)
$grpNotify.Size = New-Object System.Drawing.Size(1280, 150)
$grpNotify.Anchor = 'Top,Left,Right'
$form.Controls.Add($grpNotify)

$chkDesktop = New-Object System.Windows.Forms.CheckBox
$chkDesktop.Text = 'Desktop alert'
$chkDesktop.Checked = $true
$chkDesktop.Location = New-Object System.Drawing.Point(15, 25)
$chkDesktop.Size = New-Object System.Drawing.Size(120, 24)
$grpNotify.Controls.Add($chkDesktop)

$chkSound = New-Object System.Windows.Forms.CheckBox
$chkSound.Text = 'Sound'
$chkSound.Checked = $true
$chkSound.Location = New-Object System.Drawing.Point(140, 25)
$chkSound.Size = New-Object System.Drawing.Size(80, 24)
$grpNotify.Controls.Add($chkSound)

$chkTeams = New-Object System.Windows.Forms.CheckBox
$chkTeams.Text = 'Teams webhook'
$chkTeams.Location = New-Object System.Drawing.Point(240, 25)
$chkTeams.Size = New-Object System.Drawing.Size(130, 24)
$grpNotify.Controls.Add($chkTeams)

$txtTeamsWebhook = New-Object System.Windows.Forms.TextBox
$txtTeamsWebhook.Location = New-Object System.Drawing.Point(380, 25)
$txtTeamsWebhook.Size = New-Object System.Drawing.Size(880, 24)
$txtTeamsWebhook.Anchor = 'Top,Left,Right'
$grpNotify.Controls.Add($txtTeamsWebhook)

$chkEmail = New-Object System.Windows.Forms.CheckBox
$chkEmail.Text = 'Email'
$chkEmail.Location = New-Object System.Drawing.Point(15, 65)
$chkEmail.Size = New-Object System.Drawing.Size(80, 24)
$grpNotify.Controls.Add($chkEmail)

$lblSmtpServer = New-Object System.Windows.Forms.Label
$lblSmtpServer.Text = 'SMTP server'
$lblSmtpServer.Location = New-Object System.Drawing.Point(100, 69)
$lblSmtpServer.Size = New-Object System.Drawing.Size(80, 20)
$grpNotify.Controls.Add($lblSmtpServer)

$txtSmtpServer = New-Object System.Windows.Forms.TextBox
$txtSmtpServer.Location = New-Object System.Drawing.Point(185, 66)
$txtSmtpServer.Size = New-Object System.Drawing.Size(220, 24)
$grpNotify.Controls.Add($txtSmtpServer)

$lblSmtpPort = New-Object System.Windows.Forms.Label
$lblSmtpPort.Text = 'Port'
$lblSmtpPort.Location = New-Object System.Drawing.Point(420, 69)
$lblSmtpPort.Size = New-Object System.Drawing.Size(35, 20)
$grpNotify.Controls.Add($lblSmtpPort)

$nudSmtpPort = New-Object System.Windows.Forms.NumericUpDown
$nudSmtpPort.Location = New-Object System.Drawing.Point(460, 66)
$nudSmtpPort.Size = New-Object System.Drawing.Size(70, 24)
$nudSmtpPort.Minimum = 1
$nudSmtpPort.Maximum = 65535
$nudSmtpPort.Value = 25
$grpNotify.Controls.Add($nudSmtpPort)

$lblFrom = New-Object System.Windows.Forms.Label
$lblFrom.Text = 'From'
$lblFrom.Location = New-Object System.Drawing.Point(545, 69)
$lblFrom.Size = New-Object System.Drawing.Size(40, 20)
$grpNotify.Controls.Add($lblFrom)

$txtSmtpFrom = New-Object System.Windows.Forms.TextBox
$txtSmtpFrom.Location = New-Object System.Drawing.Point(590, 66)
$txtSmtpFrom.Size = New-Object System.Drawing.Size(250, 24)
$grpNotify.Controls.Add($txtSmtpFrom)

$lblTo = New-Object System.Windows.Forms.Label
$lblTo.Text = 'To'
$lblTo.Location = New-Object System.Drawing.Point(855, 69)
$lblTo.Size = New-Object System.Drawing.Size(25, 20)
$grpNotify.Controls.Add($lblTo)

$txtSmtpTo = New-Object System.Windows.Forms.TextBox
$txtSmtpTo.Location = New-Object System.Drawing.Point(885, 66)
$txtSmtpTo.Size = New-Object System.Drawing.Size(375, 24)
$txtSmtpTo.Anchor = 'Top,Left,Right'
$grpNotify.Controls.Add($txtSmtpTo)

$lblNote = New-Object System.Windows.Forms.Label
$lblNote.Text = 'Notifications trigger only when product status changes to In stock.'
$lblNote.Location = New-Object System.Drawing.Point(15, 110)
$lblNote.Size = New-Object System.Drawing.Size(730, 20)
$grpNotify.Controls.Add($lblNote)

$txtLog = New-Object System.Windows.Forms.TextBox
$txtLog.Location = New-Object System.Drawing.Point(10, 655)
$txtLog.Size = New-Object System.Drawing.Size(1280, 155)
$txtLog.Anchor = 'Top,Bottom,Left,Right'
$txtLog.Multiline = $true
$txtLog.ScrollBars = 'Vertical'
$txtLog.ReadOnly = $true
$form.Controls.Add($txtLog)

$notifyIcon = New-Object System.Windows.Forms.NotifyIcon
$notifyIcon.Icon = [System.Drawing.SystemIcons]::Information
$notifyIcon.Text = 'Product Stock Checker v2'
$notifyIcon.Visible = $true

$scheduleTimer = New-Object System.Windows.Forms.Timer
$scheduleTimer.Interval = $Script:DefaultIntervalMinutes * 60 * 1000

$uiTimer = New-Object System.Windows.Forms.Timer
$uiTimer.Interval = 1000

# ------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------

function Add-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $txtLog.AppendText("[$timestamp] $Message`r`n")
}

function New-ProductId {
    return [guid]::NewGuid().ToString()
}

function Get-DisplayNameFromRow {
    param([System.Data.DataRow]$Row)
    $displayName = [string]$Row.Name
    if ([string]::IsNullOrWhiteSpace($displayName)) {
        $displayName = [string]$Row.Url
    }
    return $displayName
}

function Save-Config {
    try {
        $products = foreach ($row in $table.Rows) {
            [PSCustomObject]@{
                Id              = [string]$row.Id
                Enabled         = [bool]$row.Enabled
                Name            = [string]$row.Name
                Url             = [string]$row.Url
                InStockTerms    = [string]$row.InStockTerms
                OutOfStockTerms = [string]$row.OutOfStockTerms
                Status          = [string]$row.Status
                LastChecked     = [string]$row.LastChecked
                LastMatch       = [string]$row.LastMatch
                LastError       = [string]$row.LastError
                LastNotified    = [string]$row.LastNotified
            }
        }

        $config = [PSCustomObject]@{
            Settings = [PSCustomObject]@{
                IntervalMinutes    = [int]$nudInterval.Value
                TimeoutSeconds     = [int]$nudTimeout.Value
                TeamsWebhookUrl    = [string]$txtTeamsWebhook.Text
                EnableTeamsWebhook = [bool]$chkTeams.Checked
                EnableDesktopAlert = [bool]$chkDesktop.Checked
                EnableSound        = [bool]$chkSound.Checked
                EnableEmail        = [bool]$chkEmail.Checked
                SmtpServer         = [string]$txtSmtpServer.Text
                SmtpPort           = [int]$nudSmtpPort.Value
                SmtpFrom           = [string]$txtSmtpFrom.Text
                SmtpTo             = [string]$txtSmtpTo.Text
            }
            Products = @($products)
        }

        $config | ConvertTo-Json -Depth 7 | Set-Content -Path $Script:ConfigPath -Encoding UTF8
        Add-Log "Configuration saved to $Script:ConfigPath"
    }
    catch {
        Add-Log "Failed to save configuration: $($_.Exception.Message)"
    }
}

function Load-Config {
    if (-not (Test-Path -Path $Script:ConfigPath)) {
        return
    }

    try {
        $config = Get-Content -Path $Script:ConfigPath -Raw | ConvertFrom-Json
        $table.Rows.Clear()

        if ($null -ne $config.Settings) {
            if ($null -ne $config.Settings.IntervalMinutes) { $nudInterval.Value = [decimal]$config.Settings.IntervalMinutes }
            if ($null -ne $config.Settings.TimeoutSeconds) { $nudTimeout.Value = [decimal]$config.Settings.TimeoutSeconds }
            $txtTeamsWebhook.Text = [string]$config.Settings.TeamsWebhookUrl
            $chkTeams.Checked = [bool]$config.Settings.EnableTeamsWebhook
            $chkDesktop.Checked = [bool]$config.Settings.EnableDesktopAlert
            $chkSound.Checked = [bool]$config.Settings.EnableSound
            $chkEmail.Checked = [bool]$config.Settings.EnableEmail
            $txtSmtpServer.Text = [string]$config.Settings.SmtpServer
            if ($null -ne $config.Settings.SmtpPort) { $nudSmtpPort.Value = [decimal]$config.Settings.SmtpPort }
            $txtSmtpFrom.Text = [string]$config.Settings.SmtpFrom
            $txtSmtpTo.Text = [string]$config.Settings.SmtpTo
        }

        foreach ($item in @($config.Products)) {
            if ([string]::IsNullOrWhiteSpace([string]$item.Url)) { continue }
            $row = $table.NewRow()
            if ([string]::IsNullOrWhiteSpace([string]$item.Id)) { $row.Id = New-ProductId } else { $row.Id = [string]$item.Id }
            $row.Enabled = [bool]$item.Enabled
            $row.Name = [string]$item.Name
            $row.Url = [string]$item.Url
            $row.InStockTerms = [string]$item.InStockTerms
            $row.OutOfStockTerms = [string]$item.OutOfStockTerms
            if ([string]::IsNullOrWhiteSpace([string]$item.Status)) { $row.Status = 'Not checked' } else { $row.Status = [string]$item.Status }
            $row.LastChecked = [string]$item.LastChecked
            $row.LastMatch = [string]$item.LastMatch
            $row.LastError = [string]$item.LastError
            $row.LastNotified = [string]$item.LastNotified
            $table.Rows.Add($row)
        }

        Add-Log "Configuration loaded from $Script:ConfigPath"
    }
    catch {
        Add-Log "Failed to load configuration: $($_.Exception.Message)"
    }
}

function Get-ProductRowById {
    param([string]$Id)
    foreach ($row in $table.Rows) {
        if ([string]$row.Id -eq $Id) { return $row }
    }
    return $null
}

function Show-DesktopNotification {
    param([string]$Title, [string]$Message)

    if (-not $chkDesktop.Checked) { return }

    try {
        $notifyIcon.BalloonTipTitle = $Title
        $notifyIcon.BalloonTipText = $Message
        $notifyIcon.ShowBalloonTip(10000)
    }
    catch {
        Add-Log "Desktop notification failed: $($_.Exception.Message)"
    }
}

function Send-TeamsNotification {
    param([string]$Message)

    if (-not $chkTeams.Checked) { return }
    if ([string]::IsNullOrWhiteSpace($txtTeamsWebhook.Text)) {
        Add-Log 'Teams notification skipped because no webhook URL is configured.'
        return
    }

    try {
        $body = @{ text = $Message } | ConvertTo-Json -Depth 3
        Invoke-RestMethod -Uri $txtTeamsWebhook.Text -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 20 -ErrorAction Stop | Out-Null
        Add-Log 'Teams notification sent.'
    }
    catch {
        Add-Log "Teams notification failed: $($_.Exception.Message)"
    }
}

function Send-EmailNotification {
    param([string]$Subject, [string]$Body)

    if (-not $chkEmail.Checked) { return }

    if ([string]::IsNullOrWhiteSpace($txtSmtpServer.Text) -or [string]::IsNullOrWhiteSpace($txtSmtpFrom.Text) -or [string]::IsNullOrWhiteSpace($txtSmtpTo.Text)) {
        Add-Log 'Email notification skipped because SMTP settings are incomplete.'
        return
    }

    try {
        Send-MailMessage -SmtpServer $txtSmtpServer.Text -Port ([int]$nudSmtpPort.Value) -From $txtSmtpFrom.Text -To $txtSmtpTo.Text -Subject $Subject -Body $Body -ErrorAction Stop
        Add-Log 'Email notification sent.'
    }
    catch {
        Add-Log "Email notification failed: $($_.Exception.Message)"
    }
}

function Send-InStockNotifications {
    param([System.Data.DataRow]$Row)

    $name = Get-DisplayNameFromRow -Row $Row
    $url = [string]$Row.Url
    $message = "Product appears to be in stock: $name`r`n$url"

    Show-DesktopNotification -Title 'Product in stock' -Message $message
    Send-TeamsNotification -Message $message
    Send-EmailNotification -Subject "Product in stock: $name" -Body $message

    if ($chkSound.Checked) {
        try { [System.Media.SystemSounds]::Exclamation.Play() } catch { Add-Log "Sound alert failed: $($_.Exception.Message)" }
    }

    $Row.LastNotified = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
}

function Add-ProductRow {
    param([string]$Name, [string]$Url, [string]$InTerms, [string]$OutTerms)

    if ([string]::IsNullOrWhiteSpace($Url)) {
        [System.Windows.Forms.MessageBox]::Show('Enter a URL first.', 'Missing URL', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        return
    }

    if ($Url -notmatch '^https?://') {
        [System.Windows.Forms.MessageBox]::Show('URL must start with http:// or https://', 'Invalid URL', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
        return
    }

    $row = $table.NewRow()
    $row.Id = New-ProductId
    $row.Enabled = $true
    $row.Name = $Name
    $row.Url = $Url
    $row.InStockTerms = $InTerms
    $row.OutOfStockTerms = $OutTerms
    $row.Status = 'Not checked'
    $row.LastChecked = ''
    $row.LastMatch = ''
    $row.LastError = ''
    $row.LastNotified = ''
    $table.Rows.Add($row)

    $txtName.Clear()
    $txtUrl.Clear()
    Save-Config
    Add-Log "Added product URL: $Url"
}

function Remove-SelectedRows {
    if ($grid.SelectedRows.Count -eq 0) { return }

    foreach ($selectedRow in $grid.SelectedRows) {
        if ($null -ne $selectedRow.DataBoundItem) {
            $dataRowView = [System.Data.DataRowView]$selectedRow.DataBoundItem
            $table.Rows.Remove($dataRowView.Row)
        }
    }

    Save-Config
    Add-Log 'Removed selected product(s).'
}

function Start-ProductCheck {
    param([System.Data.DataRow]$Row)

    $ps = [powershell]::Create()
    $ps.RunspacePool = $Script:RunspacePool
    [void]$ps.AddScript($Script:StockCheckScriptBlock.ToString())
    [void]$ps.AddArgument([string]$Row.Id)
    [void]$ps.AddArgument([string]$Row.Name)
    [void]$ps.AddArgument([string]$Row.Url)
    [void]$ps.AddArgument([string]$Row.InStockTerms)
    [void]$ps.AddArgument([string]$Row.OutOfStockTerms)
    [void]$ps.AddArgument([int]$nudTimeout.Value)
    [void]$ps.AddArgument($Script:ResultQueue)

    $handle = $ps.BeginInvoke()
    [void]$Script:ActiveChecks.Add([PSCustomObject]@{
        PowerShell = $ps
        Handle = $handle
        Id = [string]$Row.Id
        StartedAt = Get-Date
    })
}

function Start-AllProductChecks {
    if ($Script:IsChecking) {
        Add-Log 'Check skipped because another check is already running.'
        return
    }

    $enabledRows = @()
    foreach ($row in $table.Rows) {
        if ([bool]$row.Enabled -and -not [string]::IsNullOrWhiteSpace([string]$row.Url)) {
            $enabledRows += $row
        }
    }

    if ($enabledRows.Count -eq 0) {
        Add-Log 'No enabled products with URLs to check.'
        return
    }

    $Script:IsChecking = $true
    $btnCheckNow.Enabled = $false
    Add-Log "Starting background check for $($enabledRows.Count) product(s)."

    foreach ($row in $enabledRows) {
        $row.Status = 'Checking...'
        $row.LastError = ''
        Start-ProductCheck -Row $row
    }
}

function Complete-FinishedRunspaces {
    if ($Script:ActiveChecks.Count -eq 0) { return }

    for ($i = $Script:ActiveChecks.Count - 1; $i -ge 0; $i--) {
        $check = $Script:ActiveChecks[$i]
        if ($check.Handle.IsCompleted) {
            try { $null = $check.PowerShell.EndInvoke($check.Handle) }
            catch { Add-Log "Background check failed to close cleanly: $($_.Exception.Message)" }
            finally {
                $check.PowerShell.Dispose()
                $Script:ActiveChecks.RemoveAt($i)
            }
        }
    }

    if ($Script:ActiveChecks.Count -eq 0 -and $Script:IsChecking) {
        $Script:IsChecking = $false
        $btnCheckNow.Enabled = $true
        Save-Config
        Add-Log 'Background stock check completed.'
    }
}

function Process-ResultQueue {
    $item = $null

    while ($Script:ResultQueue.TryDequeue([ref]$item)) {
        $row = Get-ProductRowById -Id ([string]$item.Id)
        if ($null -eq $row) { continue }

        $previousStatus = [string]$row.Status
        $row.Status = [string]$item.Status
        $row.LastChecked = $item.CheckedAt.ToString('yyyy-MM-dd HH:mm:ss')
        $row.LastMatch = [string]$item.MatchedTerm
        $row.LastError = [string]$item.ErrorMessage

        if ($item.HttpStatusCode -gt 0) {
            if ([string]::IsNullOrWhiteSpace([string]$row.LastError)) {
                $row.LastError = "HTTP $($item.HttpStatusCode)"
            }
            else {
                $row.LastError = "$($row.LastError) HTTP $($item.HttpStatusCode)"
            }
        }

        $displayName = Get-DisplayNameFromRow -Row $row

        switch ([string]$item.Status) {
            'In stock' {
                Add-Log "IN STOCK: $displayName. Matched: $($item.MatchedTerm)"
                if ($previousStatus -ne 'In stock') { Send-InStockNotifications -Row $row }
            }
            'Out of stock' { Add-Log "Out of stock: $displayName. Matched: $($item.MatchedTerm)" }
            'Unknown' { Add-Log "Unknown: $displayName. $($item.ErrorMessage)" }
            'Error' { Add-Log "Error: $displayName. $($item.ErrorMessage)" }
            default { Add-Log "$($item.Status): $displayName" }
        }
    }
}

function Update-NextRunLabel {
    if ($Script:IsSchedulerRunning) {
        $next = (Get-Date).AddMilliseconds($scheduleTimer.Interval)
        $lblNextRun.Text = "Next automatic check: $($next.ToString('yyyy-MM-dd HH:mm'))"
    }
    else {
        $lblNextRun.Text = 'Next automatic check: stopped'
    }
}

function Set-SchedulerState {
    param([bool]$Enabled)

    if ($Enabled) {
        $minutes = [int]$nudInterval.Value
        $scheduleTimer.Interval = $minutes * 60 * 1000
        $scheduleTimer.Start()
        $Script:IsSchedulerRunning = $true
        $btnStartStop.Text = 'Stop scheduler'
        Add-Log "Scheduler started. Interval: $minutes minute(s)."
    }
    else {
        $scheduleTimer.Stop()
        $Script:IsSchedulerRunning = $false
        $btnStartStop.Text = 'Start scheduler'
        Add-Log 'Scheduler stopped.'
    }

    Update-NextRunLabel
}

function Export-ProductsCsv {
    try {
        $export = foreach ($row in $table.Rows) {
            [PSCustomObject]@{
                Enabled = [bool]$row.Enabled
                Name = [string]$row.Name
                Url = [string]$row.Url
                InStockTerms = [string]$row.InStockTerms
                OutOfStockTerms = [string]$row.OutOfStockTerms
            }
        }

        $export | Export-Csv -Path $Script:CsvDefaultPath -NoTypeInformation -Encoding UTF8
        Add-Log "Exported products to $Script:CsvDefaultPath"
    }
    catch {
        Add-Log "CSV export failed: $($_.Exception.Message)"
    }
}

function Import-ProductsCsv {
    try {
        if (-not (Test-Path -Path $Script:CsvDefaultPath)) {
            [System.Windows.Forms.MessageBox]::Show("CSV file not found:`r`n$Script:CsvDefaultPath", 'CSV not found', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            return
        }

        $items = Import-Csv -Path $Script:CsvDefaultPath
        foreach ($item in $items) {
            if ([string]::IsNullOrWhiteSpace([string]$item.Url)) { continue }
            $row = $table.NewRow()
            $row.Id = New-ProductId
            $row.Enabled = [bool]::Parse(([string]$item.Enabled))
            $row.Name = [string]$item.Name
            $row.Url = [string]$item.Url
            $row.InStockTerms = [string]$item.InStockTerms
            $row.OutOfStockTerms = [string]$item.OutOfStockTerms
            $row.Status = 'Not checked'
            $row.LastChecked = ''
            $row.LastMatch = ''
            $row.LastError = ''
            $row.LastNotified = ''
            $table.Rows.Add($row)
        }
        Save-Config
        Add-Log "Imported products from $Script:CsvDefaultPath"
    }
    catch {
        Add-Log "CSV import failed: $($_.Exception.Message)"
    }
}

# ------------------------------------------------------------
# Events
# ------------------------------------------------------------

$grid.Add_DataBindingComplete({
    if ($grid.Columns.Contains('Id')) { $grid.Columns['Id'].Visible = $false }
    if ($grid.Columns.Contains('Url')) { $grid.Columns['Url'].FillWeight = 180 }
    if ($grid.Columns.Contains('Name')) { $grid.Columns['Name'].FillWeight = 90 }
    if ($grid.Columns.Contains('Status')) { $grid.Columns['Status'].FillWeight = 75 }
    if ($grid.Columns.Contains('LastError')) { $grid.Columns['LastError'].FillWeight = 130 }
})

$grid.Add_CellFormatting({
    param($sender, $e)
    if ($e.RowIndex -lt 0) { return }
    if (-not $grid.Columns.Contains('Status')) { return }
    $statusColumnIndex = $grid.Columns['Status'].Index
    if ($e.ColumnIndex -ne $statusColumnIndex) { return }

    $value = [string]$e.Value
    if ($value -eq 'In stock') {
        $e.CellStyle.BackColor = [System.Drawing.Color]::PaleGreen
        $e.CellStyle.ForeColor = [System.Drawing.Color]::Black
    }
    elseif ($value -eq 'Out of stock') {
        $e.CellStyle.BackColor = [System.Drawing.Color]::MistyRose
        $e.CellStyle.ForeColor = [System.Drawing.Color]::Black
    }
    elseif ($value -eq 'Error') {
        $e.CellStyle.BackColor = [System.Drawing.Color]::LightYellow
        $e.CellStyle.ForeColor = [System.Drawing.Color]::Black
    }
    elseif ($value -eq 'Checking...') {
        $e.CellStyle.BackColor = [System.Drawing.Color]::LightBlue
        $e.CellStyle.ForeColor = [System.Drawing.Color]::Black
    }
})

$btnAdd.Add_Click({ Add-ProductRow -Name $txtName.Text -Url $txtUrl.Text -InTerms $txtIn.Text -OutTerms $txtOut.Text })
$btnRemove.Add_Click({ Remove-SelectedRows })
$btnCheckNow.Add_Click({ Start-AllProductChecks })
$btnStartStop.Add_Click({ if ($Script:IsSchedulerRunning) { Set-SchedulerState -Enabled $false } else { Set-SchedulerState -Enabled $true } })
$btnSave.Add_Click({ Save-Config })
$btnLoad.Add_Click({ Load-Config })
$btnExportCsv.Add_Click({ Export-ProductsCsv })
$btnImportCsv.Add_Click({ Import-ProductsCsv })

$scheduleTimer.Add_Tick({
    Start-AllProductChecks
    Update-NextRunLabel
})

$uiTimer.Add_Tick({
    Process-ResultQueue
    Complete-FinishedRunspaces
})

$nudInterval.Add_ValueChanged({
    if ($Script:IsSchedulerRunning) {
        $scheduleTimer.Interval = [int]$nudInterval.Value * 60 * 1000
        Update-NextRunLabel
        Add-Log "Scheduler interval changed to $([int]$nudInterval.Value) minute(s)."
    }
})

$form.Add_Shown({
    Load-Config
    $uiTimer.Start()
    Set-SchedulerState -Enabled $true
    Add-Log 'Product Stock Checker v2 started.'
})

$form.Add_FormClosing({
    try { Save-Config } catch { }
    try { $scheduleTimer.Stop(); $uiTimer.Stop() } catch { }

    try {
        foreach ($check in @($Script:ActiveChecks)) {
            try { $check.PowerShell.Stop(); $check.PowerShell.Dispose() } catch { }
        }
        $Script:RunspacePool.Close()
        $Script:RunspacePool.Dispose()
    }
    catch { }

    try { $notifyIcon.Visible = $false; $notifyIcon.Dispose() } catch { }
})

# ------------------------------------------------------------
# Start GUI
# ------------------------------------------------------------

[void]$form.ShowDialog()
