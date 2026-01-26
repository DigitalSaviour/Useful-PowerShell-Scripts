
<#
.SYNOPSIS
  Retrieve end-of-life (EOL) and support lifecycle info for a product from endoflife.date.

.DESCRIPTION
  Calls https://endoflife.date API for the specified -Product and prints lifecycle data.
  Optionally exports to CSV using -Csv (with optional -CsvPath).

.PARAMETER Product
  (Mandatory in Run mode) The product slug to query on endoflife.date (e.g., 'windows', 'iphone', 'nodejs').

.PARAMETER Csv
  If provided, exports the results to CSV. When -Csv is used and -CsvPath is not supplied,
  a file named "<Product>_eol.csv" is written to the current directory.

.PARAMETER CsvPath
  Optional explicit path for the CSV output. Ignored unless -Csv is used.

.PARAMETER Help
  Show usage and examples.

.NOTES
  Requires access to https://endoflife.date API.
#>

[CmdletBinding(DefaultParameterSetName = 'Help')]
param(
    # Run mode: Product is mandatory
    [Parameter(ParameterSetName = 'Run', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Product,

    # Optional switches for CSV export (apply to Run mode)
    [Parameter(ParameterSetName = 'Run')]
    [switch]$Csv,

    [Parameter(ParameterSetName = 'Run')]
    [string]$CsvPath = "",

    # Help mode: triggers usage
    [Parameter(ParameterSetName = 'Help')]
    [Alias('?', 'h')]
    [switch]$Help
)

function Show-Usage {
    Write-Host @"
Get-EOL
Auther : Lee Burridge (leeburridge76@gmail.com)
Version : 1.0
Release Date : 26th January 2026

USAGE:
  $(Split-Path -Leaf $PSCommandPath) -Product <slug> [-Csv] [-CsvPath <path>]
  $(Split-Path -Leaf $PSCommandPath) -Help

MANDATORY (Run mode):
  -Product          The product slug (e.g., 'windows', 'iphone', 'nodejs').

OPTIONAL:
  -Csv              If supplied, export results to CSV.
  -CsvPath          Explicit CSV path. If omitted with -Csv, defaults to "<Product>_eol.csv".
  -Help             Show this help and examples.

EXAMPLES:
  .\Get-Eol.ps1 -Product windows
  .\Get-Eol.ps1 -Product nodejs -Csv
  .\Get-Eol.ps1 -Product iphone -Csv -CsvPath "C:\Temp\iphone_eol.csv"
  .\Get-Eol.ps1 -Help
"@
}

# If Help parameter set is active or the user passed -Help/-?
if ($PSCmdlet.ParameterSetName -eq 'Help' -or $Help) {
    Show-Usage
    return
}

# --- Main logic (Run mode only) ---
try {
    $uri = "https://endoflife.date/api/$Product.json"

    # Consider basic validation on slug characters to avoid malformed URIs
    if ($Product -notmatch '^[a-z0-9\-\._]+$') {
        throw "Invalid product slug '$Product'. Use lowercase letters, numbers, dashes, dots or underscores (e.g., 'windows', 'iphone', 'nodejs')."
    }

    $response = Invoke-RestMethod -Uri $uri -Method Get -ContentType 'application/json' -ErrorAction Stop

    if (-not $response -or $response.Count -eq 0) {
        Write-Warning "No lifecycle information found for product '$Product'."
        return
    }

    $results = foreach ($cycle in $response) {
        [PSCustomObject]@{
            Product                 = $Product
            Cycle                   = $cycle.cycle
            ReleaseDate             = $cycle.releaseDate
            EndOfLifeDate           = $cycle.eol
            LatestVersion           = $cycle.latest
            LTS                     = $cycle.lts
            SupportEndDate          = $cycle.support
            ExtendedSupportEndDate  = $cycle.extendedSupport
            MoreInfo                = $cycle.link
        }
    }

    if ($Csv) {
        if ([string]::IsNullOrWhiteSpace($CsvPath)) {
            $CsvPath = Join-Path -Path (Get-Location) -ChildPath ("{0}_eol.csv" -f $Product)
        }

        # Ensure directory exists if user provided a path with folders
        $dir = Split-Path -Path $CsvPath -Parent
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Output "Data exported to $CsvPath"
    }
    else {
        foreach ($res in $results) {
            Write-Output "Product                 : $($res.Product)"
            Write-Output "Cycle                   : $($res.Cycle)"
            Write-Output "Release Date            : $($res.ReleaseDate)"
            Write-Output "End of Life Date        : $($res.EndOfLifeDate)"
            Write-Output "Latest Version          : $($res.LatestVersion)"
            Write-Output "LTS                     : $($res.LTS)"
            Write-Output "Support End Date        : $($res.SupportEndDate)"
            Write-Output "Extended Support End Date: $($res.ExtendedSupportEndDate)"
            if ($res.MoreInfo) {
                Write-Output "More Info               : $($res.MoreInfo)"
            }
            Write-Output "-------------------------"
        }
    }
}
catch {
    Write-Output "Failed to retrieve data for '$Product'. Ensure the product name is correct (e.g., 'windows', 'iphone', 'nodejs'). Error: $($_.Exception.Message)"
}
