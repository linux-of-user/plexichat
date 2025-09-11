@echo off
REM QEMU Setup Script for Windows
REM Installs QEMU, Make, and Git via Chocolatey

echo Installing QEMU, Make, and Git via Chocolatey...

REM Check if Chocolatey is installed, install if not
if not exist "%ChocolateyInstall%" (
    echo Installing Chocolatey...
    powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
)

REM Install packages
choco install qemu make git -y

REM Optional: Install and setup WSL2 with Ubuntu for ARM emulation if needed
echo.
echo Optional: Install WSL2 with Ubuntu (uncomment next lines if needed)
REM wsl --install -d Ubuntu
REM wsl -d Ubuntu -u root bash -c "apt update && apt install -y qemu-system qemu-utils docker.io"

echo QEMU installation complete.
echo Run 'qemu-system-x86_64 --version' to verify.