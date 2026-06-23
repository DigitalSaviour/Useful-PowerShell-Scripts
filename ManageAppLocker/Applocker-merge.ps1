#requires -version 5.1
<#
.DESCRIPTION
    AppLocker Policy Builder for Intune

    - Scans a selected folder for AppLocker-relevant files
    - Shows each eligible file as a separate row
    - Lets you choose Publisher / Path / Hash / Ignore per row
    - Generates one AppLocker XML rule per selected row
    - Does not use New-AppLockerPolicy to generate the final XML, avoiding AppLocker cmdlet de-duping
    - Publisher rules use PublisherName, ProductName and binary only:
        BinaryVersionRange LowSection="*" HighSection="*"
    - Rule names begin with the selected scan folder name
    - After creating XML, allows the generated XML to be merged into an existing AppLocker XML
    - Reports merge clashes by RuleCollection, Id, Name, and effective rule condition

.NOTES
    Recommended launch:
        powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File .\AppLocker-Merge.ps1
#>

#region Host checks
if ($PSVersionTable.PSEdition -ne 'Desktop') {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show(
        'This script is designed for Windows PowerShell 5.1 Desktop edition. Please run it with powershell.exe.',
        'Unsupported host',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    ) | Out-Null
    return
}

if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    try {
        if ($PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath)) {
            Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-STA','-File',"`"$PSCommandPath`"") | Out-Null
            return
        }
        Write-Warning 'Please re-run this script with -STA.'
        return
    }
    catch {
        Write-Warning 'Unable to relaunch in STA mode. Please run the script manually with -STA.'
        return
    }
}
#endregion

#region Assemblies / module
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

try { Import-Module AppLocker -ErrorAction Stop }
catch {
    [System.Windows.Forms.MessageBox]::Show(
        "The built-in AppLocker PowerShell module could not be loaded.`r`n`r`nError: $($_.Exception.Message)",
        'AppLocker module not available',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    return
}
#endregion

#region Script variables
$script:AppTitle = 'AppLocker Policy Builder for Intune'
$script:SelectedFolderName = 'AppLocker'
$script:ScanResults = New-Object System.Collections.Generic.List[object]
$script:LastGeneratedXmlPath = $null
$script:LastGeneratedXmlDoc = $null
$script:LastMergedXmlPath = $null
$script:LastMergedXmlDoc = $null

$script:EligibleExtensions = @('.exe','.com','.dll','.ocx','.ps1','.vbs','.js','.bat','.cmd','.msi','.msp','.mst','.msc')

$script:ColourPublisher = [System.Drawing.Color]::FromArgb(220,245,220)
$script:ColourPath      = [System.Drawing.Color]::FromArgb(255,230,204)
$script:ColourHash      = [System.Drawing.Color]::FromArgb(220,235,255)
$script:ColourNeutral   = [System.Drawing.Color]::FromArgb(245,245,245)
#endregion

#region General helpers
function Show-InfoMessage { param([Parameter(Mandatory)][string]$Message,[string]$Title=$script:AppTitle) [System.Windows.Forms.MessageBox]::Show($Message,$Title,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information)|Out-Null }
function Show-WarningMessage { param([Parameter(Mandatory)][string]$Message,[string]$Title=$script:AppTitle) [System.Windows.Forms.MessageBox]::Show($Message,$Title,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)|Out-Null }
function Show-ErrorMessage { param([Parameter(Mandatory)][string]$Message,[string]$Title=$script:AppTitle) [System.Windows.Forms.MessageBox]::Show($Message,$Title,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error)|Out-Null }

function Get-CollectionTypeFromExtension {
    param([Parameter(Mandatory)][string]$Extension)
    switch ($Extension.ToLowerInvariant()) {
        '.exe' { 'Exe' } '.com' { 'Exe' }
        '.dll' { 'Dll' } '.ocx' { 'Dll' }
        '.ps1' { 'Script' } '.bat' { 'Script' } '.cmd' { 'Script' } '.vbs' { 'Script' } '.js' { 'Script' }
        '.msi' { 'Msi' } '.msp' { 'Msi' } '.mst' { 'Msi' }
        '.msc' { 'Exe' }
        default { 'Exe' }
    }
}

function Get-AppLockerClipboardSourceXmlDocument {
    param(
        [Parameter(Mandatory)]
        [System.Windows.Forms.DataGridView]$Grid
    )

    if ($script:LastMergedXmlDoc) {
        return [pscustomobject]@{
            XmlDocument = $script:LastMergedXmlDoc
            Source      = 'merged XML'
            SourcePath  = $script:LastMergedXmlPath
        }
    }

    if ($script:LastGeneratedXmlDoc) {
        return [pscustomobject]@{
            XmlDocument = $script:LastGeneratedXmlDoc
            Source      = 'generated XML from this run'
            SourcePath  = $script:LastGeneratedXmlPath
        }
    }

    $selectedItems = Get-SelectedItemsFromGrid -Grid $Grid

    if ($selectedItems.Count -eq 0) {
        throw "No rules are selected. Change one or more rows from 'Ignore' to Publisher, Path or Hash."
    }

    $xmlDoc = Build-AppLockerPolicyXml -SelectedItems $selectedItems

    return [pscustomobject]@{
        XmlDocument = $xmlDoc
        Source      = 'current unsaved grid selection'
        SourcePath  = $null
    }
}

function Get-FriendlyPublisherName { param([string]$Subject) if ([string]::IsNullOrWhiteSpace($Subject)) { return $null }; if ($Subject -match 'CN=([^,]+)') { return $matches[1].Trim() }; return $Subject.Trim() }
function Get-ShortHash { param([string]$Hash) if ([string]::IsNullOrWhiteSpace($Hash)) { return '' }; if ($Hash.Length -le 20) { return $Hash }; return ($Hash.Substring(0,20)+'...') }

function Save-XmlUtf8 {
    param([Parameter(Mandatory)][xml]$XmlDocument,[Parameter(Mandatory)][string]$Path)
    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.Indent = $true
    $settings.IndentChars = '  '
    $settings.NewLineChars = "`r`n"
    $settings.NewLineHandling = [System.Xml.NewLineHandling]::Replace
    $settings.Encoding = New-Object System.Text.UTF8Encoding($true)
    $writer = [System.Xml.XmlWriter]::Create($Path,$settings)
    try { $XmlDocument.Save($writer) } finally { $writer.Close() }
}

function Get-ObjectPropertyValue {
    param([Parameter(Mandatory)]$Object,[Parameter(Mandatory)][string[]]$PropertyNames)
    if ($null -eq $Object) { return $null }
    foreach ($propertyName in $PropertyNames) {
        if ($Object.PSObject.Properties.Name -contains $propertyName) {
            $value = $Object.$propertyName
            if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) { return [string]$value }
        }
    }
    return $null
}

function Set-SelectedFolderNameFromPath {
    param([Parameter(Mandatory)][string]$FolderPath)
    $folderName = Split-Path -Path $FolderPath -Leaf
    if ([string]::IsNullOrWhiteSpace($folderName)) { $folderName = 'AppLocker' }
    $folderName = $folderName -replace '[^\w\.\-]','_'
    if ($folderName.Length -gt 60) { $folderName = $folderName.Substring(0,60) }
    $script:SelectedFolderName = $folderName
}

function Get-RuleName {
    param([Parameter(Mandatory)][string]$RuleType,[Parameter(Mandatory)][string]$FileName,[Parameter(Mandatory)][int]$Index)
    $safeFolder = [string]$script:SelectedFolderName
    if ([string]::IsNullOrWhiteSpace($safeFolder)) { $safeFolder = 'AppLocker' }
    $safeFolder = $safeFolder -replace '[^\w\.\-]','_'
    if ($safeFolder.Length -gt 60) { $safeFolder = $safeFolder.Substring(0,60) }
    $safeFile = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
    if ([string]::IsNullOrWhiteSpace($safeFile)) { $safeFile = 'File' }
    $safeFile = $safeFile -replace '[^\w\.\-]','_'
    if ($safeFile.Length -gt 40) { $safeFile = $safeFile.Substring(0,40) }
    return '{0}-{1:0000}-{2}-{3}' -f $safeFolder,$Index,$RuleType,$safeFile
}
#endregion

#region Scan functions
function Get-ScanItem {
    param([Parameter(Mandatory)][System.IO.FileInfo]$File)

    $appInfo = Get-AppLockerFileInformation -Path $File.FullName -ErrorAction Stop
    if ($appInfo -is [array]) { $appInfo = $appInfo | Select-Object -First 1 }
    $sha256 = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256 -ErrorAction Stop).Hash

    $signature = Get-AuthenticodeSignature -LiteralPath $File.FullName -ErrorAction SilentlyContinue
    $certificateSubject = ''
    $friendlyPublisherName = ''
    $isSigned = $false
    if ($signature -and $signature.SignerCertificate) {
        $certificateSubject = $signature.SignerCertificate.Subject
        $friendlyPublisherName = Get-FriendlyPublisherName -Subject $certificateSubject
        $isSigned = $true
    }

    $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
    $productName = if ([string]::IsNullOrWhiteSpace($versionInfo.ProductName)) { $File.BaseName } else { $versionInfo.ProductName }
    $binaryName = $File.Name
    $version = if (-not [string]::IsNullOrWhiteSpace($versionInfo.FileVersion)) { $versionInfo.FileVersion } elseif (-not [string]::IsNullOrWhiteSpace($versionInfo.ProductVersion)) { $versionInfo.ProductVersion } else { '*' }

    $publisherRuleAvailable = $false
    $appLockerPublisherName = $null
    $appLockerProductName = $null
    if ($appInfo.PSObject.Properties.Name -contains 'Publisher') {
        $publisherObject = $appInfo.Publisher
        $appLockerPublisherName = Get-ObjectPropertyValue -Object $publisherObject -PropertyNames @('PublisherName','Publisher','Name')
        $appLockerProductName = Get-ObjectPropertyValue -Object $publisherObject -PropertyNames @('ProductName','Product')
        if (-not [string]::IsNullOrWhiteSpace([string]$appLockerPublisherName)) { $publisherRuleAvailable = $true }
        elseif (-not [string]::IsNullOrWhiteSpace([string]$appInfo.Publisher)) { $publisherRuleAvailable = $true; $appLockerPublisherName = [string]$appInfo.Publisher }
    }

    if ([string]::IsNullOrWhiteSpace($friendlyPublisherName) -and -not [string]::IsNullOrWhiteSpace($appLockerPublisherName)) { $friendlyPublisherName = $appLockerPublisherName }
    if ([string]::IsNullOrWhiteSpace($appLockerProductName)) { $appLockerProductName = $productName }

    $publisherSummary = if ($publisherRuleAvailable) { if ([string]::IsNullOrWhiteSpace($appLockerProductName)) { $friendlyPublisherName } else { '{0} / {1}' -f $friendlyPublisherName,$appLockerProductName } } else { 'Not signed' }
    $pathRule = if ($appInfo.PSObject.Properties.Name -contains 'Path' -and -not [string]::IsNullOrWhiteSpace([string]$appInfo.Path)) { [string]$appInfo.Path } else { $File.FullName }

    $details = @(
        "File name: $($File.Name)",
        "Full path: $($File.FullName)",
        "Extension: $($File.Extension)",
        "File length: $($File.Length)",
        "Collection type: $(Get-CollectionTypeFromExtension -Extension $File.Extension)",
        "Publisher rule available: $(if ($publisherRuleAvailable) { 'Yes' } else { 'No' })",
        "Display publisher name: $friendlyPublisherName",
        "AppLocker publisher name: $appLockerPublisherName",
        "AppLocker product name: $appLockerProductName",
        "Product name: $productName",
        "Binary name: $binaryName",
        "Version: $version",
        "Publisher certificate string: $certificateSubject",
        "Path rule: $pathRule",
        "SHA256 hash: $sha256",
        "Hash file name: $($File.Name)",
        "Rule name prefix: $script:SelectedFolderName",
        "Publisher XML scope: PublisherName, ProductName and BinaryName ; Version=*"
    ) -join "`r`n"

    return [pscustomobject]@{
        FileName                 = $File.Name
        FullPath                 = $File.FullName
        FileLength               = [int64]$File.Length
        Extension                = $File.Extension
        CollectionType           = Get-CollectionTypeFromExtension -Extension $File.Extension
        AppLockerFileInformation = $appInfo
        PublisherRuleAvailable   = $publisherRuleAvailable
        PublisherName            = $friendlyPublisherName
        AppLockerPublisherName   = $appLockerPublisherName
        AppLockerProductName     = $appLockerProductName
        ProductName              = $productName
        BinaryName               = $binaryName
        Version                  = $version
        PublisherCertificate     = $certificateSubject
        PublisherSummary         = $publisherSummary
        PathRule                 = $pathRule
        HashRule                 = $sha256
        HashFileName             = $File.Name
        SelectedRule             = if ($publisherRuleAvailable) { 'Publisher' } else { 'Hash' }
        RuleDetails              = $details
        IsSigned                 = $isSigned
    }
}
#endregion

#region AppLocker XML generation
function New-AppLockerXmlDocumentSkeleton {
    $xml = New-Object System.Xml.XmlDocument
    $decl = $xml.CreateXmlDeclaration('1.0','utf-8',$null)
    [void]$xml.AppendChild($decl)
    $root = $xml.CreateElement('AppLockerPolicy')
    $root.SetAttribute('Version','1')
    [void]$xml.AppendChild($root)
    foreach ($type in @('Exe','Msi','Script','Dll')) {
        $collection = $xml.CreateElement('RuleCollection')
        $collection.SetAttribute('Type',$type)
        $collection.SetAttribute('EnforcementMode','NotConfigured')
        [void]$root.AppendChild($collection)
    }
    return $xml
}

function Get-AppLockerRuleCollectionNode {
    param([Parameter(Mandatory)][xml]$XmlDocument,[Parameter(Mandatory)][string]$CollectionType)
    foreach ($collection in $XmlDocument.AppLockerPolicy.RuleCollection) { if ($collection.Type -eq $CollectionType) { return $collection } }
    $collection = $XmlDocument.CreateElement('RuleCollection')
    $collection.SetAttribute('Type',$CollectionType)
    $collection.SetAttribute('EnforcementMode','NotConfigured')
    [void]$XmlDocument.AppLockerPolicy.AppendChild($collection)
    return $collection
}

function Get-PublisherConditionValues {
    param([Parameter(Mandatory)]$Item)
    $publisherName = $null
    $productName = $null
    if (-not [string]::IsNullOrWhiteSpace([string]$Item.AppLockerPublisherName)) { $publisherName = [string]$Item.AppLockerPublisherName }
    if (-not [string]::IsNullOrWhiteSpace([string]$Item.AppLockerProductName)) { $productName = [string]$Item.AppLockerProductName }
    if ([string]::IsNullOrWhiteSpace($publisherName) -and $Item.AppLockerFileInformation) {
        $publisherObject = $null
        if ($Item.AppLockerFileInformation.PSObject.Properties.Name -contains 'Publisher') { $publisherObject = $Item.AppLockerFileInformation.Publisher }
        $publisherName = Get-ObjectPropertyValue -Object $publisherObject -PropertyNames @('PublisherName','Publisher','Name')
        $productName = Get-ObjectPropertyValue -Object $publisherObject -PropertyNames @('ProductName','Product')
    }
    if ([string]::IsNullOrWhiteSpace($publisherName)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$Item.PublisherCertificate)) { $publisherName = [string]$Item.PublisherCertificate }
        elseif (-not [string]::IsNullOrWhiteSpace([string]$Item.PublisherName)) { $publisherName = [string]$Item.PublisherName }
    }
    if ([string]::IsNullOrWhiteSpace($productName)) { $productName = [string]$Item.ProductName }
    if ([string]::IsNullOrWhiteSpace($publisherName)) { throw "Publisher name could not be determined for '$($Item.FileName)'." }
    if ([string]::IsNullOrWhiteSpace($productName)) { $productName = '*' }
    return [pscustomobject]@{ PublisherName = $publisherName; ProductName = $productName }
}

function New-AppLockerFilePublisherRuleNode {
    param([Parameter(Mandatory)][xml]$XmlDocument,[Parameter(Mandatory)]$Item,[Parameter(Mandatory)][int]$Index)
    $publisherValues = Get-PublisherConditionValues -Item $Item
    $rule = $XmlDocument.CreateElement('FilePublisherRule')
    $rule.SetAttribute('Id',([guid]::NewGuid().Guid))
    $rule.SetAttribute('Name',(Get-RuleName -RuleType 'PublisherProduct' -FileName $Item.FileName -Index $Index))
    $rule.SetAttribute('Description',('Generated from row {0}: {1}. Publisher,Product,BinaryName and Version=*.' -f $Index,$Item.FullPath))
    $rule.SetAttribute('UserOrGroupSid','S-1-1-0')
    $rule.SetAttribute('Action','Allow')
    $conditions = $XmlDocument.CreateElement('Conditions')
    $condition = $XmlDocument.CreateElement('FilePublisherCondition')
    $condition.SetAttribute('PublisherName',$publisherValues.PublisherName)
    $condition.SetAttribute('ProductName',$publisherValues.ProductName)
    $condition.SetAttribute('BinaryName', $Item.BinaryName)
    $versionRange = $XmlDocument.CreateElement('BinaryVersionRange')
    $versionRange.SetAttribute('LowSection','*')
    $versionRange.SetAttribute('HighSection','*')
    [void]$condition.AppendChild($versionRange)
    [void]$conditions.AppendChild($condition)
    [void]$rule.AppendChild($conditions)
    return $rule
}

function New-AppLockerFilePathRuleNode {
    param([Parameter(Mandatory)][xml]$XmlDocument,[Parameter(Mandatory)]$Item,[Parameter(Mandatory)][int]$Index)
    $path = [string]$Item.PathRule
    if ([string]::IsNullOrWhiteSpace($path)) { $path = [string]$Item.FullPath }
    $rule = $XmlDocument.CreateElement('FilePathRule')
    $rule.SetAttribute('Id',([guid]::NewGuid().Guid))
    $rule.SetAttribute('Name',(Get-RuleName -RuleType 'Path' -FileName $Item.FileName -Index $Index))
    $rule.SetAttribute('Description',('Generated from row {0}: {1}' -f $Index,$Item.FullPath))
    $rule.SetAttribute('UserOrGroupSid','S-1-1-0')
    $rule.SetAttribute('Action','Allow')
    $conditions = $XmlDocument.CreateElement('Conditions')
    $condition = $XmlDocument.CreateElement('FilePathCondition')
    $condition.SetAttribute('Path',$path)
    [void]$conditions.AppendChild($condition)
    [void]$rule.AppendChild($conditions)
    return $rule
}

function New-AppLockerFileHashRuleNode {
    param([Parameter(Mandatory)][xml]$XmlDocument,[Parameter(Mandatory)]$Item,[Parameter(Mandatory)][int]$Index)
    if ([string]::IsNullOrWhiteSpace([string]$Item.HashRule)) { throw "Hash value is missing for '$($Item.FileName)'." }
    $hashValue = ([string]$Item.HashRule).Trim()
    if (-not $hashValue.StartsWith('0x',[System.StringComparison]::OrdinalIgnoreCase)) { $hashValue = '0x' + $hashValue }
    $fileLength = 0
    if ($Item.PSObject.Properties.Name -contains 'FileLength' -and $null -ne $Item.FileLength) { $fileLength = [int64]$Item.FileLength }
    $rule = $XmlDocument.CreateElement('FileHashRule')
    $rule.SetAttribute('Id',([guid]::NewGuid().Guid))
    $rule.SetAttribute('Name',(Get-RuleName -RuleType 'Hash' -FileName $Item.FileName -Index $Index))
    $rule.SetAttribute('Description',('Generated from row {0}: {1}' -f $Index,$Item.FullPath))
    $rule.SetAttribute('UserOrGroupSid','S-1-1-0')
    $rule.SetAttribute('Action','Allow')
    $conditions = $XmlDocument.CreateElement('Conditions')
    $condition = $XmlDocument.CreateElement('FileHashCondition')
    $fileHash = $XmlDocument.CreateElement('FileHash')
    $fileHash.SetAttribute('Type','SHA256')
    $fileHash.SetAttribute('Data',$hashValue.ToUpperInvariant())
    $fileHash.SetAttribute('SourceFileName',[string]$Item.HashFileName)
    $fileHash.SetAttribute('SourceFileLength',[string]$fileLength)
    [void]$condition.AppendChild($fileHash)
    [void]$conditions.AppendChild($condition)
    [void]$rule.AppendChild($conditions)
    return $rule
}

function Get-AppLockerXmlRuleCount {
    param([Parameter(Mandatory)][xml]$XmlDocument)
    $count = 0
    foreach ($collection in $XmlDocument.AppLockerPolicy.RuleCollection) {
        foreach ($child in $collection.ChildNodes) { if ($child.NodeType -eq [System.Xml.XmlNodeType]::Element) { $count++ } }
    }
    return $count
}

function Set-AppLockerCollectionEnforcementModes {
    param([Parameter(Mandatory)][xml]$XmlDocument)
    foreach ($collection in $XmlDocument.AppLockerPolicy.RuleCollection) {
        $collectionRuleCount = 0
        foreach ($child in $collection.ChildNodes) { if ($child.NodeType -eq [System.Xml.XmlNodeType]::Element) { $collectionRuleCount++ } }
        if ($collectionRuleCount -gt 0) { $collection.SetAttribute('EnforcementMode','Enabled') } else { $collection.SetAttribute('EnforcementMode','NotConfigured') }
    }
}

function Convert-XmlNodeToFormattedString {
    param(
        [Parameter(Mandatory)]
        [System.Xml.XmlNode]$Node
    )

    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.Indent = $true
    $settings.IndentChars = '  '
    $settings.NewLineChars = "`r`n"
    $settings.NewLineHandling = [System.Xml.NewLineHandling]::Replace
    $settings.OmitXmlDeclaration = $true
    $settings.Encoding = New-Object System.Text.UTF8Encoding($false)

    $stringBuilder = New-Object System.Text.StringBuilder
    $writer = [System.Xml.XmlWriter]::Create($stringBuilder, $settings)

    try {
        $Node.WriteTo($writer)
        $writer.Flush()
        return $stringBuilder.ToString().Trim()
    }
    finally {
        $writer.Close()
    }
}

function Get-AppLockerRuleCollectionRuleCount {
    param(
        [Parameter(Mandatory)]
        [System.Xml.XmlElement]$CollectionNode
    )

    $count = 0

    foreach ($child in $CollectionNode.ChildNodes) {
        if ($child.NodeType -eq [System.Xml.XmlNodeType]::Element) {
            $count++
        }
    }

    return $count
}

function Get-AppLockerRuleCollectionClipboardText {
    param(
        [Parameter(Mandatory)]
        [xml]$XmlDocument,

        [Parameter(Mandatory)]
        [ValidateSet('Exe','Msi','Script','Dll')]
        [string]$CollectionType
    )

    if (-not $XmlDocument.AppLockerPolicy) {
        throw 'The generated XML does not appear to be an AppLocker policy. Root node AppLockerPolicy was not found.'
    }

    $collectionNode = $null

    foreach ($collection in $XmlDocument.AppLockerPolicy.RuleCollection) {
        if ($collection.Type -eq $CollectionType) {
            $collectionNode = $collection
            break
        }
    }

    if (-not $collectionNode) {
        throw "RuleCollection '$CollectionType' was not found in the generated AppLocker policy."
    }

    $ruleCount = Get-AppLockerRuleCollectionRuleCount -CollectionNode $collectionNode

    if ($ruleCount -eq 0) {
        throw "The '$CollectionType' RuleCollection does not contain any rules to copy."
    }

    return [pscustomobject]@{
        CollectionType = $CollectionType
        RuleCount      = $ruleCount
        Xml            = Convert-XmlNodeToFormattedString -Node $collectionNode
    }
}

function Copy-AppLockerRuleCollectionToClipboard {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Exe','Msi','Script','Dll')]
        [string]$CollectionType,

        [Parameter(Mandatory)]
        [System.Windows.Forms.DataGridView]$Grid
    )

    $source = Get-AppLockerClipboardSourceXmlDocument -Grid $Grid

    $copyResult = Get-AppLockerRuleCollectionClipboardText `
        -XmlDocument $source.XmlDocument `
        -CollectionType $CollectionType

    [System.Windows.Forms.Clipboard]::SetText(
        $copyResult.Xml,
        [System.Windows.Forms.TextDataFormat]::UnicodeText
    )

    $omaSegment = switch ($CollectionType) {
        'Exe'    { 'EXE' }
        'Msi'    { 'MSI' }
        'Script' { 'Script' }
        'Dll'    { 'DLL' }
    }

    $sourcePathText = ''
    if (-not [string]::IsNullOrWhiteSpace([string]$source.SourcePath)) {
        $sourcePathText = "`r`n`r`nSource file:`r`n$($source.SourcePath)"
    }

    Show-InfoMessage -Message (
        "Copied $CollectionType RuleCollection to clipboard." +
        "`r`n`r`nSource: $($source.Source)" +
        $sourcePathText +
        "`r`n`r`nRules copied: $($copyResult.RuleCount)" +
        "`r`n`r`nPaste this XML into the Intune OMA-URI Policy value for:" +
        "`r`n./Vendor/MSFT/AppLocker/ApplicationLaunchRestrictions/{Grouping}/$omaSegment/Policy"
    )

    return [pscustomobject]@{
        CollectionType = $CollectionType
        RuleCount      = $copyResult.RuleCount
        Source         = $source.Source
        SourcePath     = $source.SourcePath
        Xml            = $copyResult.Xml
    }
}

function Build-AppLockerPolicyXml {
    param([Parameter(Mandatory)][System.Collections.Generic.List[object]]$SelectedItems)
    $itemsToWrite = @($SelectedItems | Where-Object { $_.SelectedRule -and $_.SelectedRule -ne 'Ignore' })
    if ($itemsToWrite.Count -eq 0) { throw 'No rules were selected.' }
    $invalidPublisherSelections = @($itemsToWrite | Where-Object { $_.SelectedRule -eq 'Publisher' -and -not $_.PublisherRuleAvailable } | Select-Object -ExpandProperty FileName)
    if ($invalidPublisherSelections.Count -gt 0) { throw "The following files were set to Publisher but do not have usable publisher metadata:`r`n - $($invalidPublisherSelections -join "`r`n - ")" }

    $xmlDoc = New-AppLockerXmlDocumentSkeleton
    $index = 0
    foreach ($item in $itemsToWrite) {
        $index++
        switch ($item.SelectedRule) {
            'Publisher' { $ruleNode = New-AppLockerFilePublisherRuleNode -XmlDocument $xmlDoc -Item $item -Index $index }
            'Path'      { $ruleNode = New-AppLockerFilePathRuleNode -XmlDocument $xmlDoc -Item $item -Index $index }
            'Hash'      { $ruleNode = New-AppLockerFileHashRuleNode -XmlDocument $xmlDoc -Item $item -Index $index }
            default     { throw "Unsupported selected rule type '$($item.SelectedRule)' for '$($item.FileName)'." }
        }
        $targetCollection = Get-AppLockerRuleCollectionNode -XmlDocument $xmlDoc -CollectionType $item.CollectionType
        [void]$targetCollection.AppendChild($ruleNode)
    }
    Set-AppLockerCollectionEnforcementModes -XmlDocument $xmlDoc
    $actualRuleCount = Get-AppLockerXmlRuleCount -XmlDocument $xmlDoc
    if ($actualRuleCount -ne $itemsToWrite.Count) { throw "Rule count mismatch. Expected $($itemsToWrite.Count) rule(s), but generated $actualRuleCount rule(s)." }
    return $xmlDoc
}
#endregion

#region Merge functions
function Get-AppLockerRuleKey {
    param([Parameter(Mandatory)][System.Xml.XmlElement]$RuleNode)
    $action = $RuleNode.GetAttribute('Action')
    $sid = $RuleNode.GetAttribute('UserOrGroupSid')
    $conditionXml = ''
    foreach ($child in $RuleNode.ChildNodes) {
        if ($child.NodeType -eq [System.Xml.XmlNodeType]::Element -and $child.Name -eq 'Conditions') {
            $conditionXml = $child.OuterXml
            break
        }
    }
    return ('{0}|{1}|{2}|{3}' -f $RuleNode.Name,$action,$sid,$conditionXml)
}

function Merge-AppLockerPolicyWithExistingXml {
    param(
        [Parameter(Mandatory)][xml]$ExistingXml,
        [Parameter(Mandatory)][xml]$GeneratedXml
    )

    if (-not $ExistingXml.AppLockerPolicy) { throw 'The existing XML does not appear to be an AppLocker policy. Root node AppLockerPolicy was not found.' }
    if (-not $GeneratedXml.AppLockerPolicy) { throw 'The generated XML does not appear to be an AppLocker policy. Root node AppLockerPolicy was not found.' }

    $report = New-Object System.Collections.Generic.List[string]
    $added = 0
    $skipped = 0

    foreach ($generatedCollection in $GeneratedXml.AppLockerPolicy.RuleCollection) {
        $collectionType = [string]$generatedCollection.Type
        if ([string]::IsNullOrWhiteSpace($collectionType)) { continue }

        $targetCollection = Get-AppLockerRuleCollectionNode -XmlDocument $ExistingXml -CollectionType $collectionType

        $existingIds = @{}
        $existingNames = @{}
        $existingKeys = @{}
        foreach ($existingRule in $targetCollection.ChildNodes) {
            if ($existingRule.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            $id = $existingRule.GetAttribute('Id')
            $name = $existingRule.GetAttribute('Name')
            $key = Get-AppLockerRuleKey -RuleNode $existingRule
            if (-not [string]::IsNullOrWhiteSpace($id)) { $existingIds[$id.ToLowerInvariant()] = $true }
            if (-not [string]::IsNullOrWhiteSpace($name)) { $existingNames[$name.ToLowerInvariant()] = $true }
            if (-not [string]::IsNullOrWhiteSpace($key)) { $existingKeys[$key] = $true }
        }

        foreach ($generatedRule in $generatedCollection.ChildNodes) {
            if ($generatedRule.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }

            $ruleId = $generatedRule.GetAttribute('Id')
            $ruleName = $generatedRule.GetAttribute('Name')
            $ruleKey = Get-AppLockerRuleKey -RuleNode $generatedRule
            $clashes = New-Object System.Collections.Generic.List[string]

            if (-not [string]::IsNullOrWhiteSpace($ruleId) -and $existingIds.ContainsKey($ruleId.ToLowerInvariant())) { $clashes.Add('Id') | Out-Null }
            if (-not [string]::IsNullOrWhiteSpace($ruleName) -and $existingNames.ContainsKey($ruleName.ToLowerInvariant())) { $clashes.Add('Name') | Out-Null }
            if (-not [string]::IsNullOrWhiteSpace($ruleKey) -and $existingKeys.ContainsKey($ruleKey)) { $clashes.Add('Effective condition') | Out-Null }

            if ($clashes.Count -gt 0) {
                $skipped++
                $report.Add(('SKIPPED [{0}] {1} - clash: {2}' -f $collectionType,$ruleName,($clashes -join ', '))) | Out-Null
                continue
            }

            $imported = $ExistingXml.ImportNode($generatedRule,$true)
            [void]$targetCollection.AppendChild($imported)
            $added++

            if (-not [string]::IsNullOrWhiteSpace($ruleId)) { $existingIds[$ruleId.ToLowerInvariant()] = $true }
            if (-not [string]::IsNullOrWhiteSpace($ruleName)) { $existingNames[$ruleName.ToLowerInvariant()] = $true }
            if (-not [string]::IsNullOrWhiteSpace($ruleKey)) { $existingKeys[$ruleKey] = $true }
        }
    }

    Set-AppLockerCollectionEnforcementModes -XmlDocument $ExistingXml

    return [pscustomobject]@{
        MergedXml = $ExistingXml
        AddedRules = $added
        SkippedRules = $skipped
        ClashReport = @($report)
    }
}
#endregion

#region Grid helpers
function Set-RowColours {
    param([Parameter(Mandatory)][System.Windows.Forms.DataGridViewRow]$Row)
    if (-not $Row.Tag) { return }
    $selectedRule = [string]$Row.Cells['SelectedRule'].Value
    if ($Row.Tag.PublisherRuleAvailable) { $Row.Cells['PublisherRule'].Style.BackColor = $script:ColourPublisher; $Row.Cells['PublisherRule'].Style.SelectionBackColor = $script:ColourPublisher }
    else { $Row.Cells['PublisherRule'].Style.BackColor = $script:ColourNeutral; $Row.Cells['PublisherRule'].Style.SelectionBackColor = $script:ColourNeutral }
    $Row.Cells['PathRule'].Style.BackColor = $script:ColourPath
    $Row.Cells['PathRule'].Style.SelectionBackColor = $script:ColourPath
    $Row.Cells['HashRule'].Style.BackColor = $script:ColourHash
    $Row.Cells['HashRule'].Style.SelectionBackColor = $script:ColourHash
    switch ($selectedRule) {
        'Publisher' { $Row.Cells['SelectedRule'].Style.BackColor = $script:ColourPublisher; $Row.Cells['SelectedRule'].Style.SelectionBackColor = $script:ColourPublisher }
        'Path'      { $Row.Cells['SelectedRule'].Style.BackColor = $script:ColourPath; $Row.Cells['SelectedRule'].Style.SelectionBackColor = $script:ColourPath }
        'Hash'      { $Row.Cells['SelectedRule'].Style.BackColor = $script:ColourHash; $Row.Cells['SelectedRule'].Style.SelectionBackColor = $script:ColourHash }
        default     { $Row.Cells['SelectedRule'].Style.BackColor = $script:ColourNeutral; $Row.Cells['SelectedRule'].Style.SelectionBackColor = $script:ColourNeutral }
    }
    foreach ($cell in $Row.Cells) { $cell.Style.SelectionForeColor = [System.Drawing.Color]::Black }
}

function Add-ResultRow {
    param([Parameter(Mandatory)][System.Windows.Forms.DataGridView]$Grid,[Parameter(Mandatory)]$Item)
    $rowIndex = $Grid.Rows.Add($Item.FileName,$Item.PublisherSummary,$Item.PathRule,(Get-ShortHash -Hash $Item.HashRule),$Item.SelectedRule,$Item.RuleDetails)
    $row = $Grid.Rows[$rowIndex]
    $row.Tag = $Item
    $row.Cells['FileName'].ToolTipText = $Item.FullPath
    $row.Cells['PublisherRule'].ToolTipText = $Item.PublisherSummary
    $row.Cells['PathRule'].ToolTipText = $Item.PathRule
    $row.Cells['HashRule'].ToolTipText = ('{0} ({1})' -f $Item.HashRule,$Item.HashFileName)
    $row.Cells['RuleDetails'].ToolTipText = $Item.RuleDetails
    Set-RowColours -Row $row
}

function Update-DetailsPane {
    param([Parameter(Mandatory)][System.Windows.Forms.DataGridView]$Grid,[Parameter(Mandatory)][System.Windows.Forms.TextBox]$TextBox)
    if ($Grid.CurrentRow -and $Grid.CurrentRow.Tag) { $TextBox.Text = [string]$Grid.CurrentRow.Tag.RuleDetails } else { $TextBox.Text = '' }
}

function Get-SelectedItemsFromGrid {
    param([Parameter(Mandatory)][System.Windows.Forms.DataGridView]$Grid)
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($row in $Grid.Rows) {
        if ($row.IsNewRow) { continue }
        if (-not $row.Tag) { continue }
        $item = $row.Tag
        $item.SelectedRule = [string]$row.Cells['SelectedRule'].Value
        if ($item.SelectedRule -and $item.SelectedRule -ne 'Ignore') { $items.Add($item) | Out-Null }
    }
    return $items
}
#endregion

#region Build UI
$form = New-Object System.Windows.Forms.Form
$form.Text = $script:AppTitle
$form.StartPosition = 'CenterScreen'
$form.Size = New-Object System.Drawing.Size(1570,900)
$form.MinimumSize = New-Object System.Drawing.Size(1280,700)

$topPanel = New-Object System.Windows.Forms.Panel
$topPanel.Dock = 'Top'
$topPanel.Height = 105
$topPanel.Padding = New-Object System.Windows.Forms.Padding(10)

$topLayout = New-Object System.Windows.Forms.TableLayoutPanel
$topLayout.Dock = 'Fill'
$topLayout.ColumnCount = 1
$topLayout.RowCount = 2
$topLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,34)))
$topLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,42)))

$folderRow = New-Object System.Windows.Forms.TableLayoutPanel
$folderRow.Dock = 'Fill'
$folderRow.ColumnCount = 3
$folderRow.RowCount = 1
$folderRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute,55)))
$folderRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent,100)))
$folderRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute,110)))

$lblFolder = New-Object System.Windows.Forms.Label
$lblFolder.Text = 'Folder:'
$lblFolder.Dock = 'Fill'
$lblFolder.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$lblFolder.Margin = New-Object System.Windows.Forms.Padding(0,6,6,0)

$txtFolder = New-Object System.Windows.Forms.TextBox
$txtFolder.Dock = 'Fill'
$txtFolder.Margin = New-Object System.Windows.Forms.Padding(0,3,6,3)
$txtFolder.AutoCompleteMode = 'SuggestAppend'
$txtFolder.AutoCompleteSource = 'FileSystemDirectories'
$txtFolder.ScrollBars = 'Horizontal'

$btnBrowse = New-Object System.Windows.Forms.Button
$btnBrowse.Text = 'Browse...'
$btnBrowse.Dock = 'Fill'
$btnBrowse.Margin = New-Object System.Windows.Forms.Padding(0,1,0,1)

$folderRow.Controls.Add($lblFolder,0,0)
$folderRow.Controls.Add($txtFolder,1,0)
$folderRow.Controls.Add($btnBrowse,2,0)

$actionsRow = New-Object System.Windows.Forms.FlowLayoutPanel
$actionsRow.Dock = 'Fill'
$actionsRow.FlowDirection = 'LeftToRight'
$actionsRow.WrapContents = $false
$actionsRow.AutoScroll = $true
$actionsRow.Margin = New-Object System.Windows.Forms.Padding(0,6,0,0)

$chkRecursive = New-Object System.Windows.Forms.CheckBox
$chkRecursive.Text = 'Scan recursively'
$chkRecursive.Checked = $true
$chkRecursive.AutoSize = $true
$chkRecursive.Margin = New-Object System.Windows.Forms.Padding(0,10,15,0)

$btnScan = New-Object System.Windows.Forms.Button
$btnScan.Text = 'Scan Folder for AppLocker-eligible Files'
$btnScan.Size = New-Object System.Drawing.Size(300,32)
$btnScan.Margin = New-Object System.Windows.Forms.Padding(0,4,10,0)

$btnGenerate = New-Object System.Windows.Forms.Button
$btnGenerate.Text = 'Generate AppLocker Policy'
$btnGenerate.Size = New-Object System.Drawing.Size(220,32)
$btnGenerate.Margin = New-Object System.Windows.Forms.Padding(0,4,10,0)

$btnMerge = New-Object System.Windows.Forms.Button
$btnMerge.Text = 'Merge with Existing XML'
$btnMerge.Size = New-Object System.Drawing.Size(210,32)
$btnMerge.Margin = New-Object System.Windows.Forms.Padding(0,4,10,0)
$btnMerge.Enabled = $false

$btnClear = New-Object System.Windows.Forms.Button
$btnClear.Text = 'Clear Results'
$btnClear.Size = New-Object System.Drawing.Size(120,32)
$btnClear.Margin = New-Object System.Windows.Forms.Padding(0,4,10,0)

$lblCount = New-Object System.Windows.Forms.Label
$lblCount.Text = 'Files loaded: 0'
$lblCount.AutoSize = $true
$lblCount.Margin = New-Object System.Windows.Forms.Padding(10,10,0,0)

$actionsRow.Controls.AddRange(@(
    $chkRecursive,
    $btnScan,
    $btnGenerate,
    $btnMerge,
    $btnClear,
    $lblCount
))

$topLayout.Controls.Add($folderRow,0,0)
$topLayout.Controls.Add($actionsRow,0,1)
$topPanel.Controls.Add($topLayout)

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Dock = 'Fill'
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.AllowUserToResizeRows = $true
$grid.MultiSelect = $false
$grid.SelectionMode = 'FullRowSelect'
$grid.RowHeadersVisible = $false
$grid.EditMode = 'EditOnEnter'
$grid.AutoSizeRowsMode = 'AllCells'
$grid.BackgroundColor = [System.Drawing.Color]::White
$grid.DefaultCellStyle.WrapMode = [System.Windows.Forms.DataGridViewTriState]::False

$colFile = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colFile.Name = 'FileName'
$colFile.HeaderText = 'File Name'
$colFile.ReadOnly = $true
$colFile.Width = 230

$colPublisher = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colPublisher.Name = 'PublisherRule'
$colPublisher.HeaderText = 'Publisher / Product Rule'
$colPublisher.ReadOnly = $true
$colPublisher.Width = 330

$colPath = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colPath.Name = 'PathRule'
$colPath.HeaderText = 'Path Rule'
$colPath.ReadOnly = $true
$colPath.Width = 360

$colHash = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colHash.Name = 'HashRule'
$colHash.HeaderText = 'Hash Rule'
$colHash.ReadOnly = $true
$colHash.Width = 185

$colSelected = New-Object System.Windows.Forms.DataGridViewComboBoxColumn
$colSelected.Name = 'SelectedRule'
$colSelected.HeaderText = 'Selected Rule'
$colSelected.Width = 120
[void]$colSelected.Items.AddRange(@('Ignore','Publisher','Path','Hash'))

$colDetails = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colDetails.Name = 'RuleDetails'
$colDetails.HeaderText = 'Rule Details'
$colDetails.ReadOnly = $true
$colDetails.Width = 360
$colDetails.DefaultCellStyle.WrapMode = [System.Windows.Forms.DataGridViewTriState]::True

[System.Windows.Forms.DataGridViewColumn[]]$gridColumns = @(
    $colFile,
    $colPublisher,
    $colPath,
    $colHash,
    $colSelected,
    $colDetails
)

$grid.Columns.AddRange($gridColumns)

$rightPanel = New-Object System.Windows.Forms.Panel
$rightPanel.Dock = 'Right'
$rightPanel.Width = 205
$rightPanel.Padding = New-Object System.Windows.Forms.Padding(10)

$lblCopy = New-Object System.Windows.Forms.Label
$lblCopy.Text = 'Copy Collections'
$lblCopy.Dock = 'Top'
$lblCopy.Height = 24
$lblCopy.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$lblCopy.Font = New-Object System.Drawing.Font($form.Font, [System.Drawing.FontStyle]::Bold)

$copyLayout = New-Object System.Windows.Forms.TableLayoutPanel
$copyLayout.Dock = 'Top'
$copyLayout.ColumnCount = 1
$copyLayout.RowCount = 4
$copyLayout.Height = 168
$copyLayout.Padding = New-Object System.Windows.Forms.Padding(0,8,0,0)

for ($i = 0; $i -lt 4; $i++) {
    $copyLayout.RowStyles.Add(
        (New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,40))
    )
}

$btnCopyExe = New-Object System.Windows.Forms.Button
$btnCopyExe.Text = 'Copy EXE Collection'
$btnCopyExe.Dock = 'Fill'
$btnCopyExe.Margin = New-Object System.Windows.Forms.Padding(0,4,0,4)
$btnCopyExe.Enabled = $false

$btnCopyMsi = New-Object System.Windows.Forms.Button
$btnCopyMsi.Text = 'Copy MSI Collection'
$btnCopyMsi.Dock = 'Fill'
$btnCopyMsi.Margin = New-Object System.Windows.Forms.Padding(0,4,0,4)
$btnCopyMsi.Enabled = $false

$btnCopyScript = New-Object System.Windows.Forms.Button
$btnCopyScript.Text = 'Copy Script Collection'
$btnCopyScript.Dock = 'Fill'
$btnCopyScript.Margin = New-Object System.Windows.Forms.Padding(0,4,0,4)
$btnCopyScript.Enabled = $false

$btnCopyDll = New-Object System.Windows.Forms.Button
$btnCopyDll.Text = 'Copy DLL Collection'
$btnCopyDll.Dock = 'Fill'
$btnCopyDll.Margin = New-Object System.Windows.Forms.Padding(0,4,0,4)
$btnCopyDll.Enabled = $false

$copyLayout.Controls.Add($btnCopyExe,0,0)
$copyLayout.Controls.Add($btnCopyMsi,0,1)
$copyLayout.Controls.Add($btnCopyScript,0,2)
$copyLayout.Controls.Add($btnCopyDll,0,3)

$rightPanel.Controls.Add($copyLayout)
$rightPanel.Controls.Add($lblCopy)

$bottomPanel = New-Object System.Windows.Forms.Panel
$bottomPanel.Dock = 'Bottom'
$bottomPanel.Height = 185
$bottomPanel.Padding = New-Object System.Windows.Forms.Padding(10)

$lblDetails = New-Object System.Windows.Forms.Label
$lblDetails.Text = 'Selected row details:'
$lblDetails.Dock = 'Top'
$lblDetails.Height = 20

$txtDetails = New-Object System.Windows.Forms.TextBox
$txtDetails.Multiline = $true
$txtDetails.ReadOnly = $true
$txtDetails.ScrollBars = 'Vertical'
$txtDetails.Dock = 'Fill'
$txtDetails.Font = New-Object System.Drawing.Font('Consolas',9)

$bottomPanel.Controls.Add($txtDetails)
$bottomPanel.Controls.Add($lblDetails)

$statusStrip = New-Object System.Windows.Forms.StatusStrip
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Text = 'Ready'
[void]$statusStrip.Items.Add($statusLabel)

$form.Controls.Add($grid)
$form.Controls.Add($rightPanel)
$form.Controls.Add($bottomPanel)
$form.Controls.Add($topPanel)
$form.Controls.Add($statusStrip)
#endregion

#region Copy button enablement helpers
function Test-AppLockerRuleCollectionHasRules {
    param(
        [Parameter(Mandatory)]
        [xml]$XmlDocument,

        [Parameter(Mandatory)]
        [ValidateSet('Exe','Msi','Script','Dll')]
        [string]$CollectionType
    )

    if (-not $XmlDocument.AppLockerPolicy) {
        return $false
    }

    foreach ($collection in $XmlDocument.AppLockerPolicy.RuleCollection) {
        if ($collection.Type -ne $CollectionType) {
            continue
        }

        foreach ($child in $collection.ChildNodes) {
            if ($child.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                return $true
            }
        }
    }

    return $false
}

function Get-SelectedRuleCollectionCountsFromGrid {
    param(
        [Parameter(Mandatory)]
        [System.Windows.Forms.DataGridView]$Grid
    )

    $counts = @{
        Exe    = 0
        Msi    = 0
        Script = 0
        Dll    = 0
    }

    foreach ($row in $Grid.Rows) {
        if ($row.IsNewRow) {
            continue
        }

        if (-not $row.Tag) {
            continue
        }

        $selectedRule = [string]$row.Cells['SelectedRule'].Value

        if ([string]::IsNullOrWhiteSpace($selectedRule) -or $selectedRule -eq 'Ignore') {
            continue
        }

        $collectionType = [string]$row.Tag.CollectionType

        if ($counts.ContainsKey($collectionType)) {
            $counts[$collectionType]++
        }
    }

    return $counts
}

function Update-CopyButtons {
    param(
        [Parameter(Mandatory)]
        [System.Windows.Forms.DataGridView]$Grid
    )

    $sourceXml = $null

    if ($script:LastMergedXmlDoc) {
        $sourceXml = $script:LastMergedXmlDoc
    }
    elseif ($script:LastGeneratedXmlDoc) {
        $sourceXml = $script:LastGeneratedXmlDoc
    }

    if ($sourceXml) {
        $btnCopyExe.Enabled    = Test-AppLockerRuleCollectionHasRules -XmlDocument $sourceXml -CollectionType 'Exe'
        $btnCopyMsi.Enabled    = Test-AppLockerRuleCollectionHasRules -XmlDocument $sourceXml -CollectionType 'Msi'
        $btnCopyScript.Enabled = Test-AppLockerRuleCollectionHasRules -XmlDocument $sourceXml -CollectionType 'Script'
        $btnCopyDll.Enabled    = Test-AppLockerRuleCollectionHasRules -XmlDocument $sourceXml -CollectionType 'Dll'
        return
    }

    $counts = Get-SelectedRuleCollectionCountsFromGrid -Grid $Grid

    $btnCopyExe.Enabled    = ($counts.Exe -gt 0)
    $btnCopyMsi.Enabled    = ($counts.Msi -gt 0)
    $btnCopyScript.Enabled = ($counts.Script -gt 0)
    $btnCopyDll.Enabled    = ($counts.Dll -gt 0)
}
#endregion

#region UI events
$btnBrowse.Add_Click({
    try {
        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = 'Select the folder to scan'
        $dialog.ShowNewFolderButton = $false

        if (-not [string]::IsNullOrWhiteSpace($txtFolder.Text) -and (Test-Path -LiteralPath $txtFolder.Text -PathType Container)) {
            $dialog.SelectedPath = $txtFolder.Text
        }
        else {
            $dialog.SelectedPath = [Environment]::GetFolderPath('Desktop')
        }

        if ($dialog.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
            $txtFolder.Text = $dialog.SelectedPath
            $txtFolder.SelectionStart = $txtFolder.Text.Length
            $txtFolder.ScrollToCaret()
        }
    }
    catch {
        Show-ErrorMessage -Message "Unable to browse for a folder.`r`n`r`n$($_.Exception.Message)"
    }
})

$btnClear.Add_Click({
    $grid.Rows.Clear()
    $script:ScanResults.Clear()
    $txtDetails.Clear()
    $lblCount.Text = 'Files loaded: 0'

    $script:LastGeneratedXmlPath = $null
    $script:LastGeneratedXmlDoc = $null
    $script:LastMergedXmlPath = $null
    $script:LastMergedXmlDoc = $null

    $btnMerge.Enabled = $false
    Update-CopyButtons -Grid $grid

    $statusLabel.Text = 'Results cleared'
})

$btnCopyExe.Add_Click({
    try {
        $form.UseWaitCursor = $true
        $statusLabel.Text = 'Copying EXE RuleCollection to clipboard...'
        $form.Refresh()

        $result = Copy-AppLockerRuleCollectionToClipboard -CollectionType 'Exe' -Grid $grid

        if ($result) {
            $statusLabel.Text = "Copied EXE RuleCollection to clipboard. Rules: $($result.RuleCount)"
        }
    }
    catch {
        $statusLabel.Text = 'Copy EXE RuleCollection failed'
        Show-ErrorMessage -Message "Failed to copy EXE RuleCollection.`r`n`r`n$($_.Exception.Message)"
    }
    finally {
        $form.UseWaitCursor = $false
        Update-CopyButtons -Grid $grid
        $form.Refresh()
    }
})

$btnCopyMsi.Add_Click({
    try {
        $form.UseWaitCursor = $true
        $statusLabel.Text = 'Copying MSI RuleCollection to clipboard...'
        $form.Refresh()

        $result = Copy-AppLockerRuleCollectionToClipboard -CollectionType 'Msi' -Grid $grid

        if ($result) {
            $statusLabel.Text = "Copied MSI RuleCollection to clipboard. Rules: $($result.RuleCount)"
        }
    }
    catch {
        $statusLabel.Text = 'Copy MSI RuleCollection failed'
        Show-ErrorMessage -Message "Failed to copy MSI RuleCollection.`r`n`r`n$($_.Exception.Message)"
    }
    finally {
        $form.UseWaitCursor = $false
        Update-CopyButtons -Grid $grid
        $form.Refresh()
    }
})

$btnCopyScript.Add_Click({
    try {
        $form.UseWaitCursor = $true
        $statusLabel.Text = 'Copying Script RuleCollection to clipboard...'
        $form.Refresh()

        $result = Copy-AppLockerRuleCollectionToClipboard -CollectionType 'Script' -Grid $grid

        if ($result) {
            $statusLabel.Text = "Copied Script RuleCollection to clipboard. Rules: $($result.RuleCount)"
        }
    }
    catch {
        $statusLabel.Text = 'Copy Script RuleCollection failed'
        Show-ErrorMessage -Message "Failed to copy Script RuleCollection.`r`n`r`n$($_.Exception.Message)"
    }
    finally {
        $form.UseWaitCursor = $false
        Update-CopyButtons -Grid $grid
        $form.Refresh()
    }
})

$btnCopyDll.Add_Click({
    try {
        $form.UseWaitCursor = $true
        $statusLabel.Text = 'Copying DLL RuleCollection to clipboard...'
        $form.Refresh()

        $result = Copy-AppLockerRuleCollectionToClipboard -CollectionType 'Dll' -Grid $grid

        if ($result) {
            $statusLabel.Text = "Copied DLL RuleCollection to clipboard. Rules: $($result.RuleCount)"
        }
    }
    catch {
        $statusLabel.Text = 'Copy DLL RuleCollection failed'
        Show-ErrorMessage -Message "Failed to copy DLL RuleCollection.`r`n`r`n$($_.Exception.Message)"
    }
    finally {
        $form.UseWaitCursor = $false
        Update-CopyButtons -Grid $grid
        $form.Refresh()
    }
})

$grid.add_SelectionChanged({
    Update-DetailsPane -Grid $grid -TextBox $txtDetails
})

$grid.add_CurrentCellDirtyStateChanged({
    if ($grid.IsCurrentCellDirty) {
        $grid.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit)
    }
})

$grid.add_CellValueChanged({
    param($sender,$e)

    if ($e.RowIndex -ge 0 -and $e.RowIndex -lt $grid.Rows.Count) {
        $row = $grid.Rows[$e.RowIndex]

        if ($row -and $row.Tag) {
            Set-RowColours -Row $row
            Update-DetailsPane -Grid $grid -TextBox $txtDetails

            $script:LastGeneratedXmlPath = $null
            $script:LastGeneratedXmlDoc = $null
            $script:LastMergedXmlPath = $null
            $script:LastMergedXmlDoc = $null
            $btnMerge.Enabled = $false

            Update-CopyButtons -Grid $grid
        }
    }
})

$grid.add_DataError({
    param($sender,$e)
    $e.ThrowException = $false
})

$btnScan.Add_Click({
    try {
        $folderPath = $txtFolder.Text.Trim()

        if ([string]::IsNullOrWhiteSpace($folderPath)) {
            Show-WarningMessage -Message 'Please select or enter a folder path first.'
            return
        }

        if (-not (Test-Path -LiteralPath $folderPath -PathType Container)) {
            Show-WarningMessage -Message "The specified folder does not exist:`r`n$folderPath"
            return
        }

        Set-SelectedFolderNameFromPath -FolderPath $folderPath

        $script:LastGeneratedXmlPath = $null
        $script:LastGeneratedXmlDoc = $null
        $script:LastMergedXmlPath = $null
        $script:LastMergedXmlDoc = $null

        $form.UseWaitCursor = $true
        $statusLabel.Text = "Scanning folder. Rule prefix: $script:SelectedFolderName"

        $btnScan.Enabled = $false
        $btnGenerate.Enabled = $false
        $btnMerge.Enabled = $false
        $btnClear.Enabled = $false

        Update-CopyButtons -Grid $grid

        $grid.Rows.Clear()
        $script:ScanResults.Clear()
        $txtDetails.Clear()
        $form.Refresh()

        $files = Get-ChildItem `
            -LiteralPath $folderPath `
            -File `
            -Force `
            -Recurse:$chkRecursive.Checked `
            -ErrorAction SilentlyContinue |
                Where-Object {
                    $script:EligibleExtensions -contains $_.Extension.ToLowerInvariant()
                } |
                Sort-Object FullName

        if (-not $files -or $files.Count -eq 0) {
            $statusLabel.Text = 'No matching files found'
            Show-InfoMessage -Message 'No matching AppLocker-relevant files were found in the selected folder.'
            return
        }

        $processed = 0
        $skipped = New-Object System.Collections.Generic.List[string]

        foreach ($file in $files) {
            try {
                $item = Get-ScanItem -File $file

                if ($null -ne $item) {
                    $script:ScanResults.Add($item) | Out-Null
                    Add-ResultRow -Grid $grid -Item $item
                    $processed++
                }
            }
            catch {
                $skipped.Add("$($file.FullName) - $($_.Exception.Message)") | Out-Null
            }
        }

        $lblCount.Text = "Files loaded: $processed"
        $statusLabel.Text = "Scan complete. Rule prefix: $script:SelectedFolderName"

        Update-CopyButtons -Grid $grid

        if ($processed -eq 0) {
            Show-WarningMessage -Message 'No AppLocker-eligible files could be processed from the selected folder.'
            return
        }

        if ($skipped.Count -gt 0) {
            $sample = $skipped | Select-Object -First 10

            $message = @(
                'Scan complete.',
                '',
                "Rule name prefix: $script:SelectedFolderName",
                "Loaded files: $processed",
                "Skipped files: $($skipped.Count)",
                '',
                'First skipped items:',
                " - $($sample -join "`r`n - ")"
            ) -join "`r`n"

            if ($skipped.Count -gt 10) {
                $message += "`r`n`r`nAdditional skipped items were omitted for brevity."
            }

            Show-WarningMessage -Message $message
        }
        else {
            Show-InfoMessage -Message "Scan complete.`r`n`r`nRule name prefix: $script:SelectedFolderName`r`nLoaded files: $processed"
        }
    }
    catch {
        Show-ErrorMessage -Message "The scan failed.`r`n`r`n$($_.Exception.Message)"
    }
    finally {
        $form.UseWaitCursor = $false
        $btnScan.Enabled = $true
        $btnGenerate.Enabled = $true
        $btnClear.Enabled = $true

        if ($script:LastGeneratedXmlDoc) {
            $btnMerge.Enabled = $true
        }

        Update-CopyButtons -Grid $grid
        $form.Refresh()
    }
})

$btnGenerate.Add_Click({
    try {
        $selectedItems = Get-SelectedItemsFromGrid -Grid $grid

        if ($selectedItems.Count -eq 0) {
            Show-WarningMessage -Message "No rules are selected. Change one or more rows from 'Ignore' to Publisher, Path or Hash."
            return
        }

        $form.UseWaitCursor = $true
        $statusLabel.Text = 'Generating AppLocker XML...'

        $btnGenerate.Enabled = $false
        $btnScan.Enabled = $false
        $btnMerge.Enabled = $false
        $btnClear.Enabled = $false

        Update-CopyButtons -Grid $grid
        $form.Refresh()

        $xmlDoc = Build-AppLockerPolicyXml -SelectedItems $selectedItems

        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Title = 'Save AppLocker XML policy'
        $saveDialog.Filter = 'XML files (*.xml)|*.xml|All files (*.*)|*.*'
        $saveDialog.FileName = "$script:SelectedFolderName-AppLocker-Policy.xml"
        $saveDialog.OverwritePrompt = $true

        if ($saveDialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
            $statusLabel.Text = 'Generation cancelled'
            return
        }

        Save-XmlUtf8 -XmlDocument $xmlDoc -Path $saveDialog.FileName

        $script:LastGeneratedXmlPath = $saveDialog.FileName
        $script:LastGeneratedXmlDoc = $xmlDoc
        $script:LastMergedXmlPath = $null
        $script:LastMergedXmlDoc = $null

        $btnMerge.Enabled = $true

        $ruleCount = Get-AppLockerXmlRuleCount -XmlDocument $xmlDoc

        Update-CopyButtons -Grid $grid

        $statusLabel.Text = 'Policy saved'

        Show-InfoMessage -Message "AppLocker policy generated successfully.`r`n`r`nSaved to:`r`n$($saveDialog.FileName)`r`n`r`nRule name prefix: $script:SelectedFolderName`r`nSelected rows: $($selectedItems.Count)`r`nRules written: $ruleCount`r`n`r`nYou can now use 'Merge with Existing XML'.`r`n`r`nPublisher rules use PublisherName, ProductName and BinaryName. Version is wildcarded."
    }
    catch {
        Show-ErrorMessage -Message "Failed to generate the AppLocker policy.`r`n`r`n$($_.Exception.Message)"
    }
    finally {
        $form.UseWaitCursor = $false
        $btnGenerate.Enabled = $true
        $btnScan.Enabled = $true
        $btnClear.Enabled = $true

        if ($script:LastGeneratedXmlDoc) {
            $btnMerge.Enabled = $true
        }

        Update-CopyButtons -Grid $grid
        $form.Refresh()
    }
})

$btnMerge.Add_Click({
    try {
        if (-not $script:LastGeneratedXmlDoc) {
            Show-WarningMessage -Message 'Please generate and save an AppLocker XML policy before merging.'
            return
        }

        $openDialog = New-Object System.Windows.Forms.OpenFileDialog
        $openDialog.Title = 'Select existing AppLocker XML policy to merge into'
        $openDialog.Filter = 'XML files (*.xml)|*.xml|All files (*.*)|*.*'
        $openDialog.CheckFileExists = $true
        $openDialog.Multiselect = $false

        if ($openDialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
            $statusLabel.Text = 'Merge cancelled'
            return
        }

        [xml]$existingXml = Get-Content -LiteralPath $openDialog.FileName -Raw -ErrorAction Stop

        $generatedClone = New-Object System.Xml.XmlDocument
        $generatedClone.LoadXml($script:LastGeneratedXmlDoc.OuterXml)

        $form.UseWaitCursor = $true
        $statusLabel.Text = 'Merging AppLocker XML...'

        $btnScan.Enabled = $false
        $btnGenerate.Enabled = $false
        $btnMerge.Enabled = $false
        $btnClear.Enabled = $false

        Update-CopyButtons -Grid $grid
        $form.Refresh()

        $mergeResult = Merge-AppLockerPolicyWithExistingXml -ExistingXml $existingXml -GeneratedXml $generatedClone

        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Title = 'Save merged AppLocker XML policy'
        $saveDialog.Filter = 'XML files (*.xml)|*.xml|All files (*.*)|*.*'
        $saveDialog.FileName = "$script:SelectedFolderName-AppLocker-Policy-Merged.xml"
        $saveDialog.OverwritePrompt = $true

        if ($saveDialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
            $statusLabel.Text = 'Merge save cancelled'
            return
        }

        Save-XmlUtf8 -XmlDocument $mergeResult.MergedXml -Path $saveDialog.FileName

        $script:LastMergedXmlPath = $saveDialog.FileName
        $script:LastMergedXmlDoc = New-Object System.Xml.XmlDocument
        $script:LastMergedXmlDoc.LoadXml($mergeResult.MergedXml.OuterXml)

        $reportPath = $null

        if ($mergeResult.ClashReport.Count -gt 0) {
            $reportPath = [System.IO.Path]::ChangeExtension($saveDialog.FileName,'.merge-clashes.txt')

            $reportHeader = @(
                'AppLocker merge clash report',
                "Existing XML: $($openDialog.FileName)",
                "Generated XML: $($script:LastGeneratedXmlPath)",
                "Merged XML: $($saveDialog.FileName)",
                "Added rules: $($mergeResult.AddedRules)",
                "Skipped rules: $($mergeResult.SkippedRules)",
                '',
                'Clashes:'
            )

            ($reportHeader + $mergeResult.ClashReport) | Set-Content -LiteralPath $reportPath -Encoding UTF8
        }

        Update-CopyButtons -Grid $grid

        $statusLabel.Text = 'Merge complete'

        $message = "Merge complete.`r`n`r`nExisting XML:`r`n$($openDialog.FileName)`r`n`r`nGenerated XML:`r`n$($script:LastGeneratedXmlPath)`r`n`r`nMerged XML saved to:`r`n$($saveDialog.FileName)`r`n`r`nAdded rules: $($mergeResult.AddedRules)`r`nSkipped due to clashes: $($mergeResult.SkippedRules)"

        if ($mergeResult.ClashReport.Count -gt 0) {
            $message += "`r`n`r`nClash report saved to:`r`n$reportPath"
            Show-WarningMessage -Message $message -Title 'Merge complete with clashes'
        }
        else {
            $message += "`r`n`r`nNo clashes detected."
            Show-InfoMessage -Message $message -Title 'Merge complete'
        }
    }
    catch {
        Show-ErrorMessage -Message "Failed to merge AppLocker XML.`r`n`r`n$($_.Exception.Message)"
    }
    finally {
        $form.UseWaitCursor = $false
        $btnScan.Enabled = $true
        $btnGenerate.Enabled = $true
        $btnClear.Enabled = $true

        if ($script:LastGeneratedXmlDoc) {
            $btnMerge.Enabled = $true
        }

        Update-CopyButtons -Grid $grid
        $form.Refresh()
    }
})

Update-CopyButtons -Grid $grid
#endregion


#region Start UI
[void]$form.ShowDialog()
#endregion
