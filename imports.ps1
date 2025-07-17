# -------------------------------
# 🚀 Deep Python Import Analyzer
# -------------------------------
# Features:
# - Maps Python modules and detects duplicates
# - Extracts all import statements
# - Flags broken local imports (files that don’t exist)
# - Tracks imports inside try-except blocks
# - Identifies unused files
# - Provides line numbers and context
# -------------------------------

$projectRoot = "C:\Users\dboyn\plexichat\plexichat"
$pyFiles = Get-ChildItem -Path $projectRoot -Recurse -Filter *.py

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