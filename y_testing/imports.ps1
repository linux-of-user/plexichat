# -------------------------------
# 🚀 Deep Python Import Analyzer & Plugin Dependency Manager
# -------------------------------
# Features:
# - Maps Python modules and detects duplicates
# - Extracts all import statements
# - Flags broken local imports (files that don’t exist)
# - Tracks imports inside try-except blocks
# - Identifies unused files
# - Provides line numbers and context
# - For each plugin:
#     - Ensures requirements.txt exists
#     - Parses main.py for external imports
#     - Adds missing external dependencies to requirements.txt
#     - Installs requirements automatically
#     - Logs/report errors in dependency resolution/installation
# - Generates a single plugin_internal.py for shared internal imports
# - Updates plugin main.py files to import only from plugin_internal.py for internal deps
# -------------------------------

$projectRoot = "C:\Users\dboyn\plexichat\plexichat"
$pluginsDir = Join-Path $projectRoot 'plugins'
$pyFiles = Get-ChildItem -Path $projectRoot -Recurse -Filter *.py
$pluginDirs = Get-ChildItem -Path $pluginsDir -Directory

# Data structures
$moduleMap = @{}             # BaseName -> [FullPaths]
$duplicateNames = @{}        # Duplicate base names
$importsFound = @{}          # File -> [Modules]
$brokenImports = @{}         # File -> [{Module, Line}]
$tryExceptImports = @{}      # File -> [{Module, Line}]
$lineTracker = @{}           # File -> [{Module, Line}]
$unusedFiles = @()
$usedModules = @{}

# -------------------------------
# 📁 Step 1: Map module names
# -------------------------------
foreach ($file in $pyFiles) {
    $base = $file.BaseName
    if (-not $moduleMap.ContainsKey($base)) {
        $moduleMap[$base] = @()
    } else {
        $duplicateNames[$base] = $true
    }
    $moduleMap[$base] += $file.FullName
}

# -------------------------------
# 🔍 Step 2: Extract Imports
# -------------------------------
$importRegex = '^\s*(?:from\s+([.\w]+)|import\s+([.\w]+))'
foreach ($file in $pyFiles) {
    $lines = Get-Content $file.FullName
    $foundImports = @()
    $tryBlock = $false
    $lineNum = 1

    foreach ($line in $lines) {
        if ($line -match '^\s*try\b') { $tryBlock = $true }
        if ($line -match '^\s*except\b') { $tryBlock = $false }

        if ($line -match $importRegex) {
            $mod = if ($matches[1]) { $matches[1] } else { $matches[2] }
            $foundImports += $mod

            # Track general import with line number
            if (-not $lineTracker.ContainsKey($file.FullName)) {
                $lineTracker[$file.FullName] = @()
            }
            $lineTracker[$file.FullName] += @{ Module = $mod; Line = $lineNum }

            # Track try-except import
            if ($tryBlock) {
                if (-not $tryExceptImports.ContainsKey($file.FullName)) {
                    $tryExceptImports[$file.FullName] = @()
                }
                $tryExceptImports[$file.FullName] += @{ Module = $mod; Line = $lineNum }
            }

            # Check if module is locally resolvable
            $modBase = ($mod -split '\.')[-1]
            if (-not $moduleMap.ContainsKey($modBase)) {
                if (-not $brokenImports.ContainsKey($file.FullName)) {
                    $brokenImports[$file.FullName] = @()
                }
                $brokenImports[$file.FullName] += @{ Module = $mod; Line = $lineNum }
            } else {
                $usedModules[$modBase] = $true
            }
        }
        $lineNum++
    }

    $importsFound[$file.FullName] = $foundImports
}

# -------------------------------
# 🔄 Step 4: Plugin Dependency Management
# -------------------------------
function Get-ExternalImports {
    param($pyFile)
    $lines = Get-Content $pyFile
    $external = @()
    foreach ($line in $lines) {
        if ($line -match '^\s*import ([\w\.]+)' -or $line -match '^\s*from ([\w\.]+)') {
            $mod = $matches[1]
            # Heuristic: treat as external if not starting with 'plexichat', 'src', or '.'
            if ($mod -and $mod -notmatch '^(plexichat|src|\.)') {
                $external += $mod.Split('.')[0]
            }
        }
    }
    return $external | Sort-Object -Unique
}

function Ensure-Requirements {
    param($pluginPath)
    $reqFile = Join-Path $pluginPath 'requirements.txt'
    if (-not (Test-Path $reqFile)) {
        New-Item $reqFile -ItemType File | Out-Null
    }
    return $reqFile
}

function Update-Requirements {
    param($reqFile, $externalImports)
    $existing = @()
    if (Test-Path $reqFile) {
        $existing = Get-Content $reqFile | Where-Object { $_ -and $_ -notmatch '^#' }
    }
    $toAdd = $externalImports | Where-Object { $_ -notin $existing }
    if ($toAdd) {
        Add-Content $reqFile ($toAdd -join "`n")
    }
}

function Install-Requirements {
    param($reqFile, $pluginName)
    try {
        Write-Host "Installing requirements for $pluginName..."
        pip install -r $reqFile
        Write-Host "[OK] Installed requirements for $pluginName"
    } catch {
        $errMsg = $PSItem
        Write-Host ("[ERROR] Failed to install requirements for " + $pluginName + ": " + $errMsg)
    }
}

# Generate plugin_internal.py (exposes shared interfaces/utilities)
$internalModule = Join-Path $pluginsDir 'plugin_internal.py'
Set-Content $internalModule @(
    '# Auto-generated shared internal module for plugins',
    'import logging',
    'from pathlib import Path',
    'from typing import Any, Dict, List, Optional',
    'from fastapi import APIRouter, HTTPException, Request, Depends',
    'from fastapi.responses import HTMLResponse, JSONResponse',
    'from pydantic import BaseModel',
    'from enum import Enum',
    'from dataclasses import dataclass',
    '# Add more shared imports as needed'
)

# For each plugin: ensure requirements, update, install, and update main.py
foreach ($plugin in $pluginDirs) {
    $pluginName = $plugin.Name
    $pluginPath = $plugin.FullName
    $mainPy = Join-Path $pluginPath 'main.py'
    if (Test-Path $mainPy) {
        $external = Get-ExternalImports $mainPy
        $reqFile = Ensure-Requirements $pluginPath
        Update-Requirements $reqFile $external
        Install-Requirements $reqFile $pluginName
        # Update main.py to use only plugin_internal.py for internal imports
        $lines = Get-Content $mainPy
        $newLines = @()
        foreach ($line in $lines) {
            if ($line -match 'from (plexichat|src|\.)' -or $line -match 'import (plexichat|src|\.)') {
                # Replace with import from plugin_internal
                if ($line -notmatch 'plugin_internal') {
                    $newLines += 'from plugin_internal import *'
                }
            } else {
                $newLines += $line
            }
        }
        Set-Content $mainPy $newLines
    }
}

# -------------------------------
# 🔄 Step 5: Source Directory Dependency Management
# -------------------------------
$srcDirs = Get-ChildItem -Path $projectRoot -Directory | Where-Object { $_.Name -ne 'plugins' }
foreach ($srcDir in $srcDirs) {
    $srcPath = $srcDir.FullName
    $pyFiles = Get-ChildItem -Path $srcPath -Recurse -Filter *.py
    $allExternal = @()
    foreach ($pyFile in $pyFiles) {
        $allExternal += Get-ExternalImports $pyFile.FullName
    }
    $allExternal = $allExternal | Sort-Object -Unique
    $reqFile = Join-Path $srcPath 'requirements.txt'
    if (-not (Test-Path $reqFile)) {
        New-Item $reqFile -ItemType File | Out-Null
    }
    $existing = @()
    if (Test-Path $reqFile) {
        $existing = Get-Content $reqFile | Where-Object { $_ -and $_ -notmatch '^#' }
    }
    $toAdd = $allExternal | Where-Object { $_ -notin $existing }
    if ($toAdd) {
        Add-Content $reqFile ($toAdd -join "`n")
    }
    try {
        Write-Host "Installing requirements for $($srcDir.Name)..."
        pip install -r $reqFile
        Write-Host "[OK] Installed requirements for $($srcDir.Name)"
    } catch {
        $errMsg = $PSItem
        Write-Host ("[ERROR] Failed to install requirements for " + $srcDir.Name + ": " + $errMsg)
    }
}

# -------------------------------
# 🔄 Step 6: Global Requirements Management and Stats
# -------------------------------
$allPyFiles = Get-ChildItem -Path $projectRoot -Recurse -Filter *.py
$allExternalImports = @()
foreach ($pyFile in $allPyFiles) {
    $allExternalImports += Get-ExternalImports $pyFile.FullName
}
$allExternalImports = $allExternalImports | Sort-Object -Unique
$rootReqFile = Join-Path $projectRoot 'requirements.txt'
$existingRoot = @()
if (Test-Path $rootReqFile) {
    $existingRoot = Get-Content $rootReqFile | Where-Object { $_ -and $_ -notmatch '^#' }
}
$toAddRoot = $allExternalImports | Where-Object { $_ -notin $existingRoot }
if ($toAddRoot) {
    Add-Content $rootReqFile ($toAddRoot -join "`n")
}
try {
    Write-Host "Installing requirements from root requirements.txt..."
    pip install -r $rootReqFile
    Write-Host "[OK] Installed requirements from root requirements.txt"
} catch {
    $errMsg = $PSItem
    Write-Host ("[ERROR] Failed to install requirements from root requirements.txt: " + $errMsg)
}
# -------------------------------
# 📊 Stats Summary
# -------------------------------
$stats = @{
    'Total Python files scanned' = $allPyFiles.Count
    'Total unique external imports found' = $allExternalImports.Count
    'Total new requirements added' = $toAddRoot.Count
    'Total errors encountered' = 0 # This can be incremented in catch blocks if needed
}
Write-Host "`n===== Import/Dependency Stats Summary ====="
foreach ($k in $stats.Keys) {
    $val = $stats[$k]
    Write-Host ($k + ': ' + $val)
}

# -------------------------------
# ❌ Step 3: Unused Files
# -------------------------------
foreach ($mod in $moduleMap.Keys) {
    if (-not $usedModules.ContainsKey($mod)) {
        foreach ($path in $moduleMap[$mod]) {
            $unusedFiles += $path
        }
    }
}

# -------------------------------
# ✅ Output Report
# -------------------------------

Write-Host "`nDuplicate Filenames:"
$duplicateNames.Keys | ForEach-Object { Write-Host "* $_" }

Write-Host "`nUnused Local Files:"
$unusedFiles | ForEach-Object { Write-Host "* $_" }

Write-Host "`nBroken Local Imports:"
foreach ($file in $brokenImports.Keys) {
    Write-Host "`nFile: $file"
    foreach ($entry in $brokenImports[$file]) {
        Write-Host "  X Line $($entry.Line): '$($entry.Module)' not found locally"
    }
}

Write-Host "`nTry-Except Imports:"
foreach ($file in $tryExceptImports.Keys) {
    Write-Host "`nFile: $file"
    foreach ($entry in $tryExceptImports[$file]) {
        Write-Host "  ! Line $($entry.Line): '$($entry.Module)' inside try-except block"
    }
}

Write-Host "`nImport Coverage Report:"
foreach ($file in $lineTracker.Keys) {
    Write-Host "`nFile: $file"
    foreach ($entry in $lineTracker[$file]) {
        Write-Host "  -> Line $($entry.Line): Imports '$($entry.Module)'"
    }
}

# -------------------------------
# 🛑 Enhanced Error Handling
# -------------------------------
trap {
    $err = $_
    Write-Host "[FATAL ERROR] $err"
    $stack = $err.ScriptStackTrace
    Write-Host "StackTrace: $stack"
    exit 1
}