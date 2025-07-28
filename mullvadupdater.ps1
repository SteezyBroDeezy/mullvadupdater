# Mullvad VPN Auto-Updater Script for PowerShell 5.1
# Run this script as Administrator for proper installation

param(
    [switch]$Force,
    [switch]$Silent,
    [switch]$NoPause,
    [switch]$NoAutoStart,
    [switch]$IncludeBeta,
    [switch]$AllowDowngrade
)

# Configuration
$PossibleMullvadPaths = @(
    "${env:ProgramFiles}\Mullvad VPN\Mullvad VPN.exe",
    "${env:ProgramFiles(x86)}\Mullvad VPN\Mullvad VPN.exe",
    "$env:LOCALAPPDATA\Mullvad VPN\Mullvad VPN.exe",
    "${env:ProgramFiles}\Mullvad VPN\mullvad-vpn.exe",
    "${env:ProgramFiles(x86)}\Mullvad VPN\mullvad-vpn.exe",
    "${env:ProgramFiles}\Mullvad VPN\app\Mullvad VPN.exe",
    "${env:ProgramFiles(x86)}\Mullvad VPN\app\Mullvad VPN.exe",
    "${env:ProgramFiles}\Mullvad VPN\resources\mullvad.exe"
)
$MullvadPath = $null
$DownloadPath = "$env:TEMP\MullvadVPN-Installer.exe"
$ApiUrl = "https://api.github.com/repos/mullvad/mullvadvpn-app/releases/latest"

function Write-Log {
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$Timestamp] $Message"
}

function Get-InstalledVersion {
    try {
        # Find Mullvad installation
        foreach ($Path in $PossibleMullvadPaths) {
            if (Test-Path $Path) {
                $script:MullvadPath = $Path
                Write-Log "Found Mullvad at: $Path"
                break
            }
        }
        
        if (-not $script:MullvadPath) {
            Write-Log "Mullvad VPN executable not found in standard locations"
            Write-Log "Searched paths:"
            foreach ($Path in $PossibleMullvadPaths) {
                Write-Log "  - $Path"
            }
            return $null
        }
        
        # Try multiple methods to get version
        $Version = $null
        
        # Method 1: File version info
        try {
            $VersionInfo = (Get-ItemProperty $script:MullvadPath).VersionInfo
            if ($VersionInfo.ProductVersion) {
                $Version = $VersionInfo.ProductVersion
                Write-Log "Version from ProductVersion: $Version"
            } elseif ($VersionInfo.FileVersion) {
                $Version = $VersionInfo.FileVersion
                Write-Log "Version from FileVersion: $Version"
            }
        } catch {
            Write-Log "Could not get version from file properties: $($_.Exception.Message)"
        }
        
        # Method 2: Try running executable with version flag
        if (-not $Version) {
            try {
                $VersionCommands = @("--version", "-v", "/version", "version")
                foreach ($VersionCmd in $VersionCommands) {
                    try {
                        $VersionOutput = & $script:MullvadPath $VersionCmd 2>$null
                        if ($VersionOutput -match "(\d+\.\d+\.\d+)") {
                            $Version = $matches[1]
                            Write-Log "Version from '$VersionCmd' command: $Version"
                            break
                        }
                    } catch {
                        # Try next command
                    }
                }
            } catch {
                Write-Log "Could not get version from command line: $($_.Exception.Message)"
            }
        }
        
        # Method 3: Check registry for installed programs
        if (-not $Version) {
            try {
                $RegPaths = @(
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
                )
                
                foreach ($RegPath in $RegPaths) {
                    $MullvadReg = Get-ItemProperty $RegPath -ErrorAction SilentlyContinue | 
                                  Where-Object { $_.DisplayName -like "*Mullvad*" }
                    if ($MullvadReg -and $MullvadReg.DisplayVersion) {
                        $Version = $MullvadReg.DisplayVersion
                        Write-Log "Version from registry: $Version"
                        break
                    }
                }
            } catch {
                Write-Log "Could not get version from registry: $($_.Exception.Message)"
            }
        }
        
        return $Version
    } catch {
        Write-Log "Error in Get-InstalledVersion: $($_.Exception.Message)"
        return $null
    }
}

function Test-StableVersion {
    param([string]$Version)
    
    if (-not $Version) { return $false }
    
    # Convert to lowercase for easier checking
    $VersionLower = $Version.ToLower()
    
    # List of pre-release indicators
    $PreReleaseIndicators = @(
        "alpha", "beta", "rc", "pre", "preview", "dev", "nightly", 
        "snapshot", "test", "experimental", "canary", "unstable"
    )
    
    # Check if version contains any pre-release indicators
    foreach ($Indicator in $PreReleaseIndicators) {
        if ($VersionLower -like "*$Indicator*") {
            return $false
        }
    }
    
    return $true
}

function Get-LatestVersion {
    try {
        Write-Log "Checking for latest Mullvad version..."
        
        # PowerShell 5.1 compatible web request
        $WebRequest = [System.Net.WebRequest]::Create($ApiUrl)
        $WebRequest.UserAgent = "PowerShell-MullvadUpdater"
        $WebRequest.Method = "GET"
        
        $Response = $WebRequest.GetResponse()
        $StreamReader = New-Object System.IO.StreamReader($Response.GetResponseStream())
        $JsonContent = $StreamReader.ReadToEnd()
        $StreamReader.Close()
        $Response.Close()
        
        # Parse JSON manually for better PS 5.1 compatibility
        $ReleaseData = $JsonContent | ConvertFrom-Json
        $LatestVersion = $ReleaseData.tag_name
        
        # Check if this is a pre-release or beta version
        $IsStableRelease = Test-StableVersion -Version $LatestVersion
        $SkipBeta = -not $IncludeBeta
        
        if ($SkipBeta -and -not $IsStableRelease) {
            Write-Log "Latest release ($LatestVersion) is a pre-release/beta version (skipping)"
            Write-Log "Searching for latest stable release..."
            
            # Search all releases for the latest stable version
            try {
                $AllReleasesUrl = "https://api.github.com/repos/mullvad/mullvadvpn-app/releases"
                $AllReleasesRequest = [System.Net.WebRequest]::Create($AllReleasesUrl)
                $AllReleasesRequest.UserAgent = "PowerShell-MullvadUpdater"
                $AllReleasesRequest.Method = "GET"
                
                $AllReleasesResponse = $AllReleasesRequest.GetResponse()
                $AllReleasesReader = New-Object System.IO.StreamReader($AllReleasesResponse.GetResponseStream())
                $AllReleasesJson = $AllReleasesReader.ReadToEnd()
                $AllReleasesReader.Close()
                $AllReleasesResponse.Close()
                
                $AllReleases = $AllReleasesJson | ConvertFrom-Json
                
                # Find the latest stable release with Windows assets
                foreach ($Release in $AllReleases) {
                    # Skip pre-release versions
                    if ($SkipBeta -and -not (Test-StableVersion -Version $Release.tag_name)) {
                        Write-Log "Skipping pre-release: $($Release.tag_name)"
                        continue
                    }
                    
                    $WinAsset = $Release.assets | Where-Object { $_.name -match "\.exe$" -and $_.name -notlike "*arm64*" }
                    
                    if ($WinAsset) {
                        # If multiple assets found, prefer x64 version, then take the first one
                        if ($WinAsset -is [array]) {
                            $PreferredAsset = $WinAsset | Where-Object { $_.name -like "*x64*" -or $_.name -like "*64*" } | Select-Object -First 1
                            if (-not $PreferredAsset) {
                                $PreferredAsset = $WinAsset | Select-Object -First 1
                            }
                            $WinAsset = $PreferredAsset
                        }
                        
                        Write-Log "Found latest stable Windows release: $($Release.tag_name) with asset: $($WinAsset.name)"
                        return @{
                            Version = $Release.tag_name
                            DownloadUrl = $WinAsset.browser_download_url
                            FileName = $WinAsset.name
                        }
                    }
                }
                
                throw "No stable Windows releases found"
                
            } catch {
                Write-Log "Error searching for stable releases: $($_.Exception.Message)"
                throw "Unable to find stable Windows release"
            }
        }
        
        # Debug: Show all available assets
        Write-Log "Available assets in latest release:"
        $ReleaseData.assets | ForEach-Object { Write-Log "  - $($_.name)" }
        
        # Try multiple patterns to find Windows installer
        $WindowsAsset = $null
        $SearchPatterns = @(
            { $ReleaseData.assets | Where-Object { $_.name -like "*windows*.exe" -and $_.name -notlike "*arm64*" } },
            { $ReleaseData.assets | Where-Object { $_.name -like "*.exe" -and $_.name -notlike "*arm64*" -and $_.name -notlike "*linux*" -and $_.name -notlike "*macos*" } },
            { $ReleaseData.assets | Where-Object { $_.name -like "*win*.exe" } },
            { $ReleaseData.assets | Where-Object { $_.name -like "MullvadVPN*.exe" } },
            { $ReleaseData.assets | Where-Object { $_.name -match "\.exe$" } }
        )
        
        foreach ($Pattern in $SearchPatterns) {
            $WindowsAsset = & $Pattern
            if ($WindowsAsset) {
                # If multiple assets found, prefer x64 version, then take the first one
                if ($WindowsAsset -is [array]) {
                    $PreferredAsset = $WindowsAsset | Where-Object { $_.name -like "*x64*" -or $_.name -like "*64*" } | Select-Object -First 1
                    if (-not $PreferredAsset) {
                        $PreferredAsset = $WindowsAsset | Select-Object -First 1
                    }
                    $WindowsAsset = $PreferredAsset
                }
                Write-Log "Found Windows installer using pattern: $($WindowsAsset.name)"
                break
            }
        }
        
        if ($WindowsAsset) {
            return @{
                Version = $LatestVersion
                DownloadUrl = $WindowsAsset.browser_download_url
                FileName = $WindowsAsset.name
            }
        } else {
            # Check if we're looking at a non-Windows release
            if ($ReleaseData.assets.Count -gt 0) {
                Write-Log "Latest release ($LatestVersion) contains only non-Windows assets"
                Write-Log "This might be an Android/mobile-only release"
                
                # Try to get all releases to find the latest Windows release
                Write-Log "Searching for latest Windows release..."
                try {
                    $AllReleasesUrl = "https://api.github.com/repos/mullvad/mullvadvpn-app/releases"
                    $AllReleasesRequest = [System.Net.WebRequest]::Create($AllReleasesUrl)
                    $AllReleasesRequest.UserAgent = "PowerShell-MullvadUpdater"
                    $AllReleasesRequest.Method = "GET"
                    
                    $AllReleasesResponse = $AllReleasesRequest.GetResponse()
                    $AllReleasesReader = New-Object System.IO.StreamReader($AllReleasesResponse.GetResponseStream())
                    $AllReleasesJson = $AllReleasesReader.ReadToEnd()
                    $AllReleasesReader.Close()
                    $AllReleasesResponse.Close()
                    
                    $AllReleases = $AllReleasesJson | ConvertFrom-Json
                    
                    # Find the latest release with Windows assets (stable versions only)
                    foreach ($Release in $AllReleases) {
                        # Skip pre-release versions unless IncludeBeta is specified
                        if (-not $IncludeBeta -and -not (Test-StableVersion -Version $Release.tag_name)) {
                            continue
                        }
                        
                        $WinAsset = $Release.assets | Where-Object { $_.name -match "\.exe$" -and $_.name -notlike "*arm64*" }
                        
                        if ($WinAsset) {
                            # If multiple assets found, prefer x64 version, then take the first one
                            if ($WinAsset -is [array]) {
                                $PreferredAsset = $WinAsset | Where-Object { $_.name -like "*x64*" -or $_.name -like "*64*" } | Select-Object -First 1
                                if (-not $PreferredAsset) {
                                    $PreferredAsset = $WinAsset | Select-Object -First 1
                                }
                                $WinAsset = $PreferredAsset
                            }
                            
                            $ReleaseType = if (Test-StableVersion -Version $Release.tag_name) { "stable" } else { "pre-release" }
                            Write-Log "Found latest Windows release: $($Release.tag_name) ($ReleaseType) with asset: $($WinAsset.name)"
                            return @{
                                Version = $Release.tag_name
                                DownloadUrl = $WinAsset.browser_download_url
                                FileName = $WinAsset.name
                            }
                        }
                    }
                } catch {
                    Write-Log "Error searching all releases: $($_.Exception.Message)"
                }
            }
            throw "No stable Windows installer found in any recent releases"
        }
    } catch {
        Write-Log "Error checking for updates: $($_.Exception.Message)"
        return $null
    }
}

function Compare-Versions {
    param(
        [string]$Current,
        [string]$Latest
    )
    
    if (-not $Current) { return $true }
    
    try {
        # Remove 'v' prefix if present and normalize versions
        $CurrentClean = $Current.TrimStart('v')
        $LatestClean = $Latest.TrimStart('v')
        
        # Remove any beta/alpha suffixes for comparison
        $CurrentClean = $CurrentClean -replace '-.*$', ''
        $LatestClean = $LatestClean -replace '-.*$', ''
        
        $CurrentVersion = [System.Version]::Parse($CurrentClean)
        $LatestVersion = [System.Version]::Parse($LatestClean)
        
        # Only update if the latest version is actually NEWER
        # This prevents downgrades from stable versions
        $IsNewer = $LatestVersion -gt $CurrentVersion
        
        Write-Log "Version comparison: Current=$CurrentClean, Latest=$LatestClean, IsNewer=$IsNewer"
        
        return $IsNewer
    } catch {
        # Fallback to string comparison if version parsing fails
        Write-Log "Version parsing failed, using string comparison"
        return $Latest -ne $Current
    }
}

function Download-MullvadInstaller {
    param([string]$Url)
    
    try {
        Write-Log "Downloading Mullvad installer..."
        Write-Log "Download URL: $Url"
        
        # Validate URL
        if (-not $Url -or $Url -notmatch "^https?://") {
            throw "Invalid download URL: $Url"
        }
        
        # Remove existing installer if present
        if (Test-Path $DownloadPath) {
            Remove-Item $DownloadPath -Force
        }
        
        # Try download with multiple attempts
        $MaxRetries = 3
        $RetryDelay = 5
        
        for ($Attempt = 1; $Attempt -le $MaxRetries; $Attempt++) {
            try {
                Write-Log "Download attempt $Attempt of $MaxRetries"
                
                # PowerShell 5.1 compatible download with progress
                $WebClient = New-Object System.Net.WebClient
                $WebClient.Headers.Add("User-Agent", "PowerShell-MullvadUpdater")
                
                # Add progress if not silent
                if (-not $Silent) {
                    Register-ObjectEvent -InputObject $WebClient -EventName DownloadProgressChanged -Action {
                        $Percent = $Event.SourceEventArgs.ProgressPercentage
                        $BytesReceived = $Event.SourceEventArgs.BytesReceived
                        $TotalBytes = $Event.SourceEventArgs.TotalBytesToReceive
                        
                        if ($TotalBytes -gt 0) {
                            $SizeMB = [math]::Round($TotalBytes / 1MB, 1)
                            Write-Progress -Activity "Downloading Mullvad VPN ($SizeMB MB)" -Status "$Percent% Complete" -PercentComplete $Percent
                        }
                    } | Out-Null
                }
                
                $WebClient.DownloadFile($Url, $DownloadPath)
                $WebClient.Dispose()
                
                if (-not $Silent) {
                    Write-Progress -Activity "Downloading Mullvad VPN" -Completed
                }
                
                # Verify download
                if (Test-Path $DownloadPath) {
                    $FileSize = (Get-Item $DownloadPath).Length
                    if ($FileSize -gt 1MB) {
                        $FileSizeMB = [math]::Round($FileSize / 1MB, 2)
                        Write-Log "Download completed successfully ($FileSizeMB MB)"
                        return $true
                    } else {
                        throw "Downloaded file is too small ($([math]::Round($FileSize/1KB, 2)) KB) - likely corrupted"
                    }
                } else {
                    throw "Downloaded file not found"
                }
                
            } catch {
                $ErrorMsg = $_.Exception.Message
                Write-Log "Download attempt $Attempt failed: $ErrorMsg"
                
                if ($Attempt -lt $MaxRetries) {
                    Write-Log "Retrying in $RetryDelay seconds..."
                    Start-Sleep -Seconds $RetryDelay
                } else {
                    throw "All download attempts failed. Last error: $ErrorMsg"
                }
            } finally {
                if ($WebClient) {
                    $WebClient.Dispose()
                }
            }
        }
        
        return $false
        
    } catch {
        Write-Log "Download error: $($_.Exception.Message)"
        if (-not $Silent) {
            Write-Host "Download failed after $MaxRetries attempts." -ForegroundColor Red
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "This could be due to:" -ForegroundColor Yellow
            Write-Host "  - Network connectivity issues" -ForegroundColor Yellow
            Write-Host "  - GitHub rate limiting" -ForegroundColor Yellow
            Write-Host "  - Firewall/antivirus blocking the download" -ForegroundColor Yellow
        }
        return $false
    }
}

function Install-Mullvad {
    try {
        Write-Log "Installing Mullvad VPN..."
        
        # Verify installer exists and is valid
        if (-not (Test-Path $DownloadPath)) {
            throw "Installer file not found: $DownloadPath"
        }
        
        $FileSize = (Get-Item $DownloadPath).Length
        if ($FileSize -lt 1MB) {
            throw "Installer file appears to be corrupted (too small: $([math]::Round($FileSize/1KB, 2)) KB)"
        }
        
        # Close Mullvad if running
        $MullvadProcesses = @()
        $MullvadProcesses += Get-Process -Name "Mullvad VPN" -ErrorAction SilentlyContinue
        $MullvadProcesses += Get-Process -Name "Mullvad" -ErrorAction SilentlyContinue
        $MullvadProcesses += Get-Process -Name "mullvad-vpn" -ErrorAction SilentlyContinue
        $MullvadProcesses += Get-Process -Name "mullvad*" -ErrorAction SilentlyContinue
        
        # Remove duplicates
        $MullvadProcesses = $MullvadProcesses | Sort-Object Id -Unique
        
        if ($MullvadProcesses) {
            Write-Log "Closing Mullvad VPN processes..."
            $MullvadProcesses | ForEach-Object {
                try {
                    Write-Log "Closing process: $($_.Name) (PID: $($_.Id))"
                    $_.CloseMainWindow()
                    Start-Sleep -Seconds 2
                    if (-not $_.HasExited) {
                        $_ | Stop-Process -Force
                    }
                } catch {
                    Write-Log "Could not close process $($_.Name): $($_.Exception.Message)"
                }
            }
            Start-Sleep -Seconds 3
        }
        
        # Install with appropriate arguments
        Write-Log "Running installer: $DownloadPath"
        $InstallArgs = "/S"  # Mullvad uses /S for silent install
        
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessInfo.FileName = $DownloadPath
        $ProcessInfo.Arguments = $InstallArgs
        $ProcessInfo.UseShellExecute = $false
        $ProcessInfo.RedirectStandardOutput = $true
        $ProcessInfo.RedirectStandardError = $true
        $ProcessInfo.CreateNoWindow = $true
        
        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $ProcessInfo
        $Process.Start() | Out-Null
        
        # Wait for installation with timeout (5 minutes max)
        $TimeoutMinutes = 5
        if (-not $Process.WaitForExit($TimeoutMinutes * 60 * 1000)) {
            $Process.Kill()
            throw "Installation timed out after $TimeoutMinutes minutes"
        }
        
        $ExitCode = $Process.ExitCode
        $StdOut = $Process.StandardOutput.ReadToEnd()
        $StdErr = $Process.StandardError.ReadToEnd()
        
        if ($StdOut) { Write-Log "Installer output: $StdOut" }
        if ($StdErr) { Write-Log "Installer errors: $StdErr" }
        
        if ($ExitCode -eq 0) {
            Write-Log "Installation completed successfully (Exit Code: $ExitCode)"
            return $true
        } else {
            Write-Log "Installation failed with exit code: $ExitCode"
            return $false
        }
    } catch {
        Write-Log "Installation error: $($_.Exception.Message)"
        return $false
    }
}

function Wait-ForKeyPress {
    param(
        [string]$Message = "Press any key to close...",
        [string]$Color = "Cyan"
    )
    
    if (-not $NoPause) {
        Write-Host $Message -ForegroundColor $Color
        if (-not $Silent) {
            try {
                # Try multiple methods for different PowerShell hosts
                if ($Host.UI.RawUI.KeyAvailable -ne $null) {
                    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                } else {
                    throw "ReadKey not available"
                }
            } catch {
                try {
                    # Fallback to Read-Host
                    Read-Host "Press Enter to continue" | Out-Null
                } catch {
                    # Last resort - just pause briefly
                    Write-Host "Pausing for 3 seconds..." -ForegroundColor Yellow
                    Start-Sleep -Seconds 3
                }
            }
        } else {
            Start-Sleep -Seconds 3
        }
    }
}

function Start-MullvadVPN {
    try {
        if ($NoAutoStart) {
            Write-Log "Auto-start disabled by parameter"
            return $true
        }
        
        # Wait a moment for installation to fully complete
        Start-Sleep -Seconds 2
        
        # Find the updated Mullvad executable
        $MullvadExe = $null
        foreach ($Path in $PossibleMullvadPaths) {
            if (Test-Path $Path) {
                $MullvadExe = $Path
                break
            }
        }
        
        if (-not $MullvadExe) {
            Write-Log "Could not find Mullvad executable to start"
            return $false
        }
        
        Write-Log "Starting Mullvad VPN application..."
        Write-Host "Starting Mullvad VPN..." -ForegroundColor Cyan
        
        # Start Mullvad in the background
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessInfo.FileName = $MullvadExe
        $ProcessInfo.UseShellExecute = $true
        $ProcessInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Normal
        
        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $ProcessInfo
        $Started = $Process.Start()
        
        if ($Started) {
            Write-Log "Mullvad VPN started successfully (PID: $($Process.Id))"
            Write-Host "Mullvad VPN started successfully!" -ForegroundColor Green
            return $true
        } else {
            Write-Log "Failed to start Mullvad VPN"
            Write-Host "Failed to start Mullvad VPN automatically." -ForegroundColor Yellow
            return $false
        }
        
    } catch {
        Write-Log "Error starting Mullvad VPN: $($_.Exception.Message)"
        Write-Host "Could not auto-start Mullvad VPN: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "You can start it manually from the Start menu." -ForegroundColor Yellow
        return $false
    }
}

function Cleanup {
    try {
        if (Test-Path $DownloadPath) {
            Remove-Item $DownloadPath -Force
            Write-Log "Cleanup completed"
        }
    } catch {
        Write-Log "Cleanup error: $($_.Exception.Message)"
    }
}

function Exit-WithPersistence {
    param(
        [int]$ExitCode = 0,
        [string]$Message = ""
    )
    
    if ($Message) {
        if ($ExitCode -eq 0) {
            Write-Host $Message -ForegroundColor Green
        } else {
            Write-Host $Message -ForegroundColor Red
        }
    }
    
    Cleanup
    Write-Log "=== Mullvad VPN Auto-Updater Finished with Exit Code: $ExitCode ==="
    
    if ($ExitCode -eq 0) {
        Write-Host "`nScript completed successfully!" -ForegroundColor Green
        Wait-ForKeyPress
    } else {
        Write-Host "`nScript completed with errors!" -ForegroundColor Red
        Wait-ForKeyPress "Press any key to close..." "Yellow"
    }
    
    # Force exit to prevent any loops
    Write-Log "Exiting script with code $ExitCode"
    [Environment]::Exit($ExitCode)
}

# Main execution
$ExitCode = 0
try {
    Write-Log "=== Mullvad VPN Auto-Updater Started ==="
    Write-Log "PowerShell Version: $($PSVersionTable.PSVersion)"
    if (-not $IncludeBeta) {
        Write-Log "Beta filtering: Only stable releases will be considered for updates"
        Write-Log "Use -IncludeBeta parameter to include pre-release versions"
    } else {
        Write-Log "Beta filtering: Pre-release versions will be included"
    }
    
    if ($AllowDowngrade) {
        Write-Log "Downgrade protection: DISABLED - downgrades are allowed"
    } else {
        Write-Log "Downgrade protection: ENABLED - will not downgrade to older versions"
    }
    
    # Check if running as administrator
    $CurrentUser = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $IsAdmin = $CurrentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $IsAdmin) {
        Write-Log "WARNING: Not running as Administrator. Installation may fail."
        Write-Host "To run as admin: Right-click PowerShell -> 'Run as administrator'" -ForegroundColor Yellow
        if (-not $Silent) {
            $Continue = Read-Host "Continue anyway? (y/n)"
            if ($Continue -ne 'y') {
                Write-Log "Cancelled by user - Administrator rights required"
                Write-Host "Script cancelled - Administrator rights recommended for installation." -ForegroundColor Yellow
                Exit-WithPersistence -ExitCode 1
            }
        }
    }
    
    # Get current version
    $CurrentVersion = Get-InstalledVersion
    if ($CurrentVersion) {
        Write-Log "Current Mullvad version: $CurrentVersion"
    } else {
        Write-Log "Mullvad VPN not found or version could not be determined"
        if (-not $Force) {
            Write-Log "Use -Force parameter to install anyway"
            Write-Host "`nMullvad VPN installation not detected!" -ForegroundColor Yellow
            Write-Host "Use -Force parameter to install anyway, or install Mullvad manually first." -ForegroundColor Yellow
            Exit-WithPersistence -ExitCode 1
        }
    }
    
    # Get latest version
    $LatestInfo = Get-LatestVersion
    if (-not $LatestInfo) {
        Write-Log "Failed to check for updates"
        Write-Host "`nFailed to check for updates!" -ForegroundColor Red
        Write-Host "This could be due to:" -ForegroundColor Yellow
        Write-Host "  - Internet connection issues" -ForegroundColor Yellow
        Write-Host "  - GitHub API rate limiting" -ForegroundColor Yellow
        Write-Host "  - No stable Windows releases available currently" -ForegroundColor Yellow
        if (-not $IncludeBeta) {
            Write-Host "  - Only pre-release/beta versions available (use -IncludeBeta to include them)" -ForegroundColor Yellow
        }
        Write-Host "`nYour current version ($CurrentVersion) may already be the latest stable release." -ForegroundColor Green
        Exit-WithPersistence -ExitCode 1
    }
    
    Write-Log "Latest Mullvad version: $($LatestInfo.Version)"
    
    # Check if update is needed
    $UpdateNeeded = $Force -or (Compare-Versions -Current $CurrentVersion -Latest $LatestInfo.Version)
    
    # Additional check to prevent downgrading from newer stable versions
    if ($CurrentVersion -and $LatestInfo.Version) {
        try {
            $CurrentClean = $CurrentVersion.TrimStart('v') -replace '-.*$', ''
            $LatestClean = $LatestInfo.Version.TrimStart('v') -replace '-.*$', ''
            
            $CurrentVer = [System.Version]::Parse($CurrentClean)
            $LatestVer = [System.Version]::Parse($LatestClean)
            
            if ($CurrentVer -gt $LatestVer -and -not $AllowDowngrade) {
                Write-Log "Preventing downgrade: Current ($CurrentClean) is newer than available stable ($LatestClean)"
                Write-Host "`nPreventing downgrade!" -ForegroundColor Yellow
                Write-Host "Current version: $CurrentVersion" -ForegroundColor Green  
                Write-Host "Available stable: $($LatestInfo.Version)" -ForegroundColor Yellow
                Write-Host "Your current version is newer than the latest stable release." -ForegroundColor Cyan
                
                if ($Force -and -not $AllowDowngrade) {
                    Write-Host "`nNote: -Force was used, but downgrades are still prevented." -ForegroundColor Yellow
                    Write-Host "Use both -Force and -AllowDowngrade to force a downgrade." -ForegroundColor Yellow
                }
                
                Write-Host "No downgrade will be performed." -ForegroundColor Cyan
                
                # Start Mullvad and exit
                Start-MullvadVPN
                Exit-WithPersistence -ExitCode 0
            } elseif ($CurrentVer -gt $LatestVer -and $AllowDowngrade) {
                Write-Log "Downgrade allowed: Current ($CurrentClean) is newer than available stable ($LatestClean), but -AllowDowngrade specified"
                Write-Host "`nDowngrade will be performed (AllowDowngrade enabled)!" -ForegroundColor Yellow
                Write-Host "Current version: $CurrentVersion" -ForegroundColor Green  
                Write-Host "Target version: $($LatestInfo.Version)" -ForegroundColor Red
                
                if (-not $Silent) {
                    $Confirm = Read-Host "`nAre you sure you want to downgrade? (y/n)"
                    if ($Confirm -ne 'y') {
                        Write-Log "Downgrade cancelled by user"
                        Write-Host "Downgrade cancelled by user." -ForegroundColor Yellow
                        Start-MullvadVPN
                        Exit-WithPersistence -ExitCode 0
                    }
                }
                
                # Allow the update to proceed (it's actually a downgrade)
                $UpdateNeeded = $true
            }
        } catch {
            Write-Log "Version comparison failed, proceeding with normal update logic"
        }
    }
    
    if (-not $UpdateNeeded) {
        # Check if user has newer version than available
        $CurrentClean = $CurrentVersion.TrimStart('v')
        $LatestClean = $LatestInfo.Version.TrimStart('v')
        
        try {
            $CurrentVer = [System.Version]::Parse($CurrentClean)
            $LatestVer = [System.Version]::Parse($LatestClean)
            
            if ($CurrentVer -gt $LatestVer) {
                Write-Log "Current version ($CurrentVersion) is newer than latest available stable release ($($LatestInfo.Version))"
                Write-Host "You have a newer version than the latest stable release!" -ForegroundColor Green
                Write-Host "Current: $CurrentVersion" -ForegroundColor Green
                Write-Host "Latest Stable: $($LatestInfo.Version)" -ForegroundColor Yellow
                
                if (-not (Test-StableVersion -Version $CurrentVersion) -and -not $IncludeBeta) {
                    Write-Host "You appear to have a beta/pre-release version." -ForegroundColor Cyan
                    Write-Host "Use -IncludeBeta parameter to check for newer pre-release versions." -ForegroundColor Cyan
                } else {
                    Write-Host "You might have a beta or development version." -ForegroundColor Cyan
                }
            } else {
                Write-Log "Mullvad VPN is already up to date with the latest stable release"
                Write-Host "No update needed - you have the latest stable version!" -ForegroundColor Green
            }
        } catch {
            Write-Log "Mullvad VPN is already up to date with the latest stable release"
            Write-Host "No update needed - you have the latest stable version!" -ForegroundColor Green
        }
        
        # Start Mullvad VPN even if no update was needed
        Start-MullvadVPN
        
        Exit-WithPersistence -ExitCode 0
    } else {
        Write-Log "Update available: $CurrentVersion -> $($LatestInfo.Version)"
        
        # Confirm update (unless silent)
        if (-not $Silent -and -not $Force) {
            Write-Host "`nUpdate available!" -ForegroundColor Cyan
            Write-Host "Current: $CurrentVersion" -ForegroundColor Yellow
            Write-Host "Latest:  $($LatestInfo.Version)" -ForegroundColor Green
            $Confirm = Read-Host "`nProceed with update? (y/n)"
            if ($Confirm -ne 'y') {
                Write-Log "Update cancelled by user"
                Write-Host "Update cancelled by user." -ForegroundColor Yellow
                Exit-WithPersistence -ExitCode 0
            }
        }
        
        # Download and install
        if (Download-MullvadInstaller -Url $LatestInfo.DownloadUrl) {
            if (Install-Mullvad) {
                Write-Log "Mullvad VPN update completed successfully!"
                Write-Host "`nUpdate completed successfully!" -ForegroundColor Green
                
                # Verify new version
                Start-Sleep -Seconds 3
                $NewVersion = Get-InstalledVersion
                if ($NewVersion) {
                    Write-Log "New version confirmed: $NewVersion"
                    Write-Host "New version: $NewVersion" -ForegroundColor Green
                }
                
                # Auto-start Mullvad VPN
                Start-MullvadVPN
                
                Exit-WithPersistence -ExitCode 0
            } else {
                Write-Log "Installation failed"
                Write-Host "Installation failed! Check the logs above." -ForegroundColor Red
                Exit-WithPersistence -ExitCode 1
            }
        } else {
            Write-Log "Download failed"
            Write-Host "Download failed! Check your internet connection." -ForegroundColor Red
            Exit-WithPersistence -ExitCode 1
        }
    }
    
} catch {
    Write-Log "Unexpected error occurred: $($_.Exception.Message)"
    Write-Host "`nAn unexpected error occurred: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Script will exit to prevent loops." -ForegroundColor Yellow
    Exit-WithPersistence -ExitCode 1
}

# Usage examples for PowerShell 5.1:
# .\MullvadUpdater.ps1                          # Interactive check/update (STABLE ONLY, NO DOWNGRADES, always starts Mullvad)
# .\MullvadUpdater.ps1 -Silent                  # Silent check/update (STABLE ONLY, NO DOWNGRADES, always starts Mullvad)
# .\MullvadUpdater.ps1 -Force                   # Force update even if versions match (STABLE ONLY, NO DOWNGRADES)
# .\MullvadUpdater.ps1 -Force -AllowDowngrade   # Force update and allow downgrades (use with caution!)
# .\MullvadUpdater.ps1 -IncludeBeta             # Include beta/pre-release versions
# .\MullvadUpdater.ps1 -IncludeBeta -Force      # Force update including betas
# .\MullvadUpdater.ps1 -Silent -Force           # Silent forced update (STABLE ONLY, NO DOWNGRADES)
# .\MullvadUpdater.ps1 -NoPause                 # Don't pause at end (for automation)
# .\MullvadUpdater.ps1 -NoAutoStart             # Don't start Mullvad at end
# .\MullvadUpdater.ps1 -Silent -Force -NoPause  # Full automation mode (STABLE ONLY, NO DOWNGRADES)
# .\MullvadUpdater.ps1 -Silent -NoAutoStart     # Silent check without starting Mullvad

# For automation (Task Scheduler, etc.), use:
# powershell.exe -ExecutionPolicy Bypass -File "C:\Path\To\MullvadUpdater.ps1" -Silent -NoPause -NoAutoStart

# IMPORTANT NOTES:
# - By default, only STABLE releases are considered for updates
# - The script will NEVER downgrade unless BOTH -Force AND -AllowDowngrade are used
# - Beta, alpha, RC, and other pre-release versions are SKIPPED unless -IncludeBeta is used
# - If you have version 2025.8 and latest stable is 2025.7, no downgrade will occur
# - Use -AllowDowngrade only if you specifically want to go back to an older stable version
