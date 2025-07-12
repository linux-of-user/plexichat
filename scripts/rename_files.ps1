# PlexiChat File Renaming Script
# Phase VI: Systematic File Renaming & Refactoring

Write-Host "🔄 Starting PlexiChat File Renaming Process..." -ForegroundColor Green

# Define file mappings
$fileMappings = @{
    # Core Authentication Files
    "src/plexichat/core_system/auth/auth.py" = "src/plexichat/core/auth/auth_core.py"
    "src/plexichat/core_system/auth/decorators.py" = "src/plexichat/core/auth/decorators_auth.py"
    "src/plexichat/core_system/auth/exceptions.py" = "src/plexichat/core/auth/exceptions_auth.py"
    "src/plexichat/core_system/auth/middleware.py" = "src/plexichat/core/auth/middleware_auth.py"
    "src/plexichat/core_system/auth/validators.py" = "src/plexichat/core/auth/validators_auth.py"
    "src/plexichat/core_system/auth/__init__.py" = "src/plexichat/core/auth/__init__.py"
    
    # Core Config Files
    "src/plexichat/core_system/config/manager.py" = "src/plexichat/core/config/manager_config.py"
    "src/plexichat/core_system/config/__init__.py" = "src/plexichat/core/config/__init__.py"
    
    # Core Database Files
    "src/plexichat/core_system/database/analytics_clients.py" = "src/plexichat/core/database/client_analytics.py"
    "src/plexichat/core_system/database/global_data_distribution.py" = "src/plexichat/core/database/strategy_distribution.py"
    "src/plexichat/core_system/database/manager.py" = "src/plexichat/core/database/manager_database.py"
    "src/plexichat/core_system/database/database_factory.py" = "src/plexichat/core/database/factory_database.py"
    "src/plexichat/core_system/database/engines.py" = "src/plexichat/core/database/engines_database.py"
    "src/plexichat/core_system/database/indexing_strategy.py" = "src/plexichat/core/database/strategy_indexing.py"
    "src/plexichat/core_system/database/lakehouse.py" = "src/plexichat/core/database/lakehouse_database.py"
    "src/plexichat/core_system/database/migrations.py" = "src/plexichat/core/database/migrations_database.py"
    "src/plexichat/core_system/database/nosql_clients.py" = "src/plexichat/core/database/client_nosql.py"
    "src/plexichat/core_system/database/partitioning_strategy.py" = "src/plexichat/core/database/strategy_partitioning.py"
    "src/plexichat/core_system/database/performance_integration.py" = "src/plexichat/core/database/integration_performance.py"
    "src/plexichat/core_system/database/query_optimizer.py" = "src/plexichat/core/database/optimizer_query.py"
    "src/plexichat/core_system/database/schema_optimizer.py" = "src/plexichat/core/database/optimizer_schema.py"
    "src/plexichat/core_system/database/setup_wizard.py" = "src/plexichat/core/database/wizard_setup.py"
    "src/plexichat/core_system/database/sql_clients.py" = "src/plexichat/core/database/client_sql.py"
    "src/plexichat/core_system/database/stored_procedures.py" = "src/plexichat/core/database/procedures_stored.py"
    "src/plexichat/core_system/database/zero_downtime_migration.py" = "src/plexichat/core/database/migration_zero_downtime.py"
    "src/plexichat/core_system/database/__init__.py" = "src/plexichat/core/database/__init__.py"
    
    # Core Error Handling Files
    "src/plexichat/core_system/error_handling/beautiful_error_handler.py" = "src/plexichat/core/error/handler_beautiful.py"
    "src/plexichat/core_system/error_handling/context.py" = "src/plexichat/core/error/context_error.py"
    "src/plexichat/core_system/error_handling/error_manager.py" = "src/plexichat/core/error/manager_error.py"
    "src/plexichat/core_system/error_handling/__init__.py" = "src/plexichat/core/error/__init__.py"
    
    # Core Integration Files
    "src/plexichat/core_system/integration/orchestrator.py" = "src/plexichat/core/integration/orchestrator_core.py"
    
    # Core Logging Files
    "src/plexichat/core_system/logging/advanced_logger.py" = "src/plexichat/core/logging/logger_advanced.py"
    "src/plexichat/core_system/logging/config.py" = "src/plexichat/core/logging/config_logging.py"
    "src/plexichat/core_system/logging/log_api.py" = "src/plexichat/core/logging/api_log.py"
    "src/plexichat/core_system/logging/performance_logger.py" = "src/plexichat/core/logging/logger_performance.py"
    "src/plexichat/core_system/logging/__init__.py" = "src/plexichat/core/logging/__init__.py"
    
    # Core Maintenance Files
    "src/plexichat/core_system/maintenance/bug_fixes.py" = "src/plexichat/core/maintenance/fixes_bug.py"
    
    # Core Resilience Files
    "src/plexichat/core_system/resilience/manager.py" = "src/plexichat/core/resilience/manager_resilience.py"
    
    # Core Runtime Files
    "src/plexichat/core_system/runtime/instance_manager.py" = "src/plexichat/core/runtime/manager_instance.py"
    "src/plexichat/core_system/runtime/launcher.py" = "src/plexichat/core/runtime/launcher_runtime.py"
    "src/plexichat/core_system/runtime/server_manager.py" = "src/plexichat/core/runtime/manager_server.py"
    
    # Core Security Files
    "src/plexichat/core_system/security/automated_security_testing.py" = "src/plexichat/core/security/testing_automated.py"
    "src/plexichat/core_system/security/certificate_manager.py" = "src/plexichat/core/security/manager_certificate.py"
    "src/plexichat/core_system/security/input_validation.py" = "src/plexichat/core/security/validation_input.py"
    "src/plexichat/core_system/security/unified_audit_system.py" = "src/plexichat/core/security/system_audit.py"
    "src/plexichat/core_system/security/unified_hsm_manager.py" = "src/plexichat/core/security/manager_hsm.py"
    "src/plexichat/core_system/security/unified_security_manager.py" = "src/plexichat/core/security/manager_security.py"
    "src/plexichat/core_system/security/unified_threat_intelligence.py" = "src/plexichat/core/security/intelligence_threat.py"
    
    # Core Updates Files
    "src/plexichat/core_system/updates/git_update_manager.py" = "src/plexichat/core/updates/manager_git.py"
    "src/plexichat/core_system/updates/updater.py" = "src/plexichat/core/updates/updater_core.py"
    
    # Core Versioning Files
    "src/plexichat/core_system/versioning/api_version_manager.py" = "src/plexichat/core/versioning/manager_api_version.py"
    "src/plexichat/core_system/versioning/canary_deployment_manager.py" = "src/plexichat/core/versioning/manager_canary_deployment.py"
    "src/plexichat/core_system/versioning/canary_health_monitor.py" = "src/plexichat/core/versioning/monitor_canary_health.py"
    "src/plexichat/core_system/versioning/canary_node_selector.py" = "src/plexichat/core/versioning/selector_canary_node.py"
    "src/plexichat/core_system/versioning/changelog_manager.py" = "src/plexichat/core/versioning/manager_changelog.py"
    "src/plexichat/core_system/versioning/update_system.py" = "src/plexichat/core/versioning/system_update.py"
    "src/plexichat/core_system/versioning/version_manager.py" = "src/plexichat/core/versioning/manager_version.py"
    "src/plexichat/core_system/versioning/__init__.py" = "src/plexichat/core/versioning/__init__.py"
}

# Function to copy files with error handling
function Copy-FileWithLogging {
    param(
        [string]$Source,
        [string]$Destination
    )
    
    try {
        if (Test-Path $Source) {
            # Ensure destination directory exists
            $destDir = Split-Path $Destination -Parent
            if (!(Test-Path $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }
            
            Copy-Item $Source $Destination -Force
            Write-Host "✅ Copied: $Source -> $Destination" -ForegroundColor Green
            return $true
        } else {
            Write-Host "⚠️  Source not found: $Source" -ForegroundColor Yellow
            return $false
        }
    } catch {
        Write-Host "❌ Error copying $Source : $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Copy all files
$successCount = 0
$totalCount = $fileMappings.Count

Write-Host "📁 Processing $totalCount file mappings..." -ForegroundColor Cyan

foreach ($mapping in $fileMappings.GetEnumerator()) {
    $source = $mapping.Key
    $destination = $mapping.Value
    
    if (Copy-FileWithLogging -Source $source -Destination $destination) {
        $successCount++
    }
}

Write-Host "`n📊 File Renaming Summary:" -ForegroundColor Cyan
Write-Host "   Total files: $totalCount" -ForegroundColor White
Write-Host "   Successfully copied: $successCount" -ForegroundColor Green
Write-Host "   Failed: $($totalCount - $successCount)" -ForegroundColor Red

if ($successCount -eq $totalCount) {
    Write-Host "`n🎉 All files successfully renamed and copied!" -ForegroundColor Green
} else {
    Write-Host "`n⚠️  Some files could not be processed. Check the output above." -ForegroundColor Yellow
}

Write-Host "`n✅ Phase VI file renaming process completed." -ForegroundColor Green
