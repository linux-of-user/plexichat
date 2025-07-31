# PlexiChat Installer for Windows PowerShell
# Downloads and installs PlexiChat from GitHub

param(
    [string]$InstallPath = "",
    [switch]$Force = $false,
    [switch]$Help = $false
)

# Colors for output
$Colors = @{
    Red = "Red"
    Green = "Green" 
    Yellow = "Yellow"
    Blue = "Blue"
    Cyan = "Cyan"
    White = "White"
}

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Colors[$Color]
}

function Show-Header {
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-ColorOutput "🚀 PlexiChat Installer" "Cyan"
    Write-ColorOutput "Modern Distributed Communication Platform" "Cyan"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host
}

function Show-Help {
    Show-Header
    Write-Host "PlexiChat Installer for Windows"
    Write-Host
    Write-Host "Usage:"
    Write-Host "  .\install.ps1                    # Interactive installation"
    Write-Host "  .\install.ps1 -InstallPath C:\PlexiChat  # Install to specific path"
    Write-Host "  .\install.ps1 -Force             # Force installation"
    Write-Host "  .\install.ps1 -Help              # Show this help"
    Write-Host
    Write-Host "Examples:"
    Write-Host "  .\install.ps1"
    Write-Host "  .\install.ps1 -InstallPath C:\Tools\PlexiChat"
    Write-Host
}

function Test-Requirements {
    Write-ColorOutput "📋 Checking system requirements..." "Blue"
    
    # Check Python
    try {
        $pythonVersion = python --version 2>$null
        if ($pythonVersion) {
            Write-ColorOutput "✅ $pythonVersion found" "Green"
        } else {
            throw "Python not found"
        }
    } catch {
        Write-ColorOutput "❌ Python not found. Please install Python 3.8+ from python.org" "Red"
        return $false
    }
    
    # Check pip
    try {
        python -m pip --version | Out-Null
        Write-ColorOutput "✅ pip found" "Green"
    } catch {
        Write-ColorOutput "❌ pip not found. Please install pip" "Red"
        return $false
    }
    
    # Check internet connection
    try {
        Invoke-WebRequest -Uri "https://github.com" -Method Head -TimeoutSec 5 -UseBasicParsing | Out-Null
        Write-ColorOutput "✅ Internet connection available" "Green"
    } catch {
        Write-ColorOutput "❌ No internet connection" "Red"
        return $false
    }
    
    return $true
}

function Get-PlexiChatInstaller {
    Write-ColorOutput "⬇️  Downloading PlexiChat installer..." "Blue"
    
    # Create temporary directory
    $tempDir = [System.IO.Path]::GetTempPath()
    $installerPath = Join-Path $tempDir "plexichat_install.py"
    
    try {
        # Download installer
        $url = "https://raw.githubusercontent.com/linux-of-user/plexichat/main/installer/install.py"
        Invoke-WebRequest -Uri $url -OutFile $installerPath -UseBasicParsing
        
        Write-ColorOutput "✅ Installer downloaded" "Green"
        return $installerPath
    } catch {
        Write-ColorOutput "❌ Failed to download installer: $($_.Exception.Message)" "Red"
        return $null
    }
}

function Start-Installation {
    param([string]$InstallerPath)
    
    Write-ColorOutput "🚀 Starting PlexiChat installation..." "Blue"
    Write-Host
    
    try {
        # Prepare arguments
        $installerArgs = @()
        if ($InstallPath) {
            $installerArgs += "--install-path", $InstallPath
        }
        if ($Force) {
            $installerArgs += "--force"
        }
        
        # Run Python installer
        $process = Start-Process -FilePath "python" -ArgumentList @($InstallerPath) + $installerArgs -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
            Write-ColorOutput "🎉 Installation completed successfully!" "Green"
        } else {
            Write-ColorOutput "❌ Installation failed with exit code $($process.ExitCode)" "Red"
        }
        
        return $process.ExitCode
    } catch {
        Write-ColorOutput "❌ Installation error: $($_.Exception.Message)" "Red"
        return 1
    } finally {
        # Cleanup
        if (Test-Path $InstallerPath) {
            Remove-Item $InstallerPath -Force
        }
    }
}

function Main {
    # Handle help
    if ($Help) {
        Show-Help
        return 0
    }
    
    Show-Header
    
    # Check requirements
    if (-not (Test-Requirements)) {
        return 1
    }
    
    # Download installer
    $installerPath = Get-PlexiChatInstaller
    if (-not $installerPath) {
        return 1
    }
    
    # Run installation
    $exitCode = Start-Installation -InstallerPath $installerPath
    
    return $exitCode
}

# Handle Ctrl+C
$null = Register-EngineEvent PowerShell.Exiting -Action {
    Write-Host
    Write-ColorOutput "🛑 Installation cancelled" "Yellow"
}

# Run main function
try {
    $exitCode = Main
    exit $exitCode
} catch {
    Write-ColorOutput "❌ Unexpected error: $($_.Exception.Message)" "Red"
    exit 1
}
