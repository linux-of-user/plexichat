# PlexiChat File Renaming & Refactoring Plan

**Phase VI: Systematic File Renaming & Refactoring (Steps 51-65)**

## New Naming Convention

`src/plexichat/{domain}/{subdomain}/{module_type}_{name}.py`

Where:
- **domain**: Core functional area (core, features, infrastructure, interfaces)
- **subdomain**: Specific functional group within domain
- **module_type**: Type of module (manager, service, client, handler, etc.)
- **name**: Descriptive name of the specific functionality

## Current Structure Analysis

### Core System Files (src/plexichat/core_system/)
```
core_system/
├── auth/                    -> core/auth/
├── config/                  -> core/config/
├── database/                -> core/database/
├── error_handling/          -> core/error/
├── integration/             -> core/integration/
├── logging/                 -> core/logging/
├── maintenance/             -> core/maintenance/
├── resilience/              -> core/resilience/
├── runtime/                 -> core/runtime/
├── security/                -> core/security/
├── updates/                 -> core/updates/
└── versioning/              -> core/versioning/
```

### Features Files (src/plexichat/features/)
```
features/
├── ai/                      -> features/ai/
├── antivirus/               -> features/security/
├── backup/                  -> features/backup/
├── blockchain/              -> features/blockchain/
├── clustering/              -> features/clustering/
├── identity/                -> features/identity/
├── knowledge/               -> features/knowledge/
├── messaging/               -> features/messaging/
├── plugins/                 -> features/plugins/
├── security/                -> features/security/
└── users/                   -> features/users/
```

### Infrastructure Files (src/plexichat/infrastructure/)
```
infrastructure/
├── analytics/               -> infrastructure/analytics/
├── containerization/        -> infrastructure/containerization/
├── events/                  -> infrastructure/events/
├── installer/               -> infrastructure/installer/
├── integration/             -> infrastructure/integration/
├── messaging/               -> infrastructure/messaging/
├── microservices/           -> infrastructure/microservices/
├── modules/                 -> infrastructure/modules/
├── performance/             -> infrastructure/performance/
├── scalability/             -> infrastructure/scalability/
├── scripts/                 -> infrastructure/scripts/
├── services/                -> infrastructure/services/
└── utils/                   -> infrastructure/utils/
```

### Interface Files (src/plexichat/interfaces/)
```
interfaces/
├── api/                     -> interfaces/api/
├── cli/                     -> interfaces/cli/
├── gui/                     -> interfaces/gui/
└── web/                     -> interfaces/web/
```

## Detailed Renaming Plan

### Phase VI-A: Core System Renaming (Steps 51-55)

#### Authentication Files
```
OLD: src/plexichat/core_system/auth/admin_credentials.py
NEW: src/plexichat/core/auth/credentials_admin.py

OLD: src/plexichat/core_system/auth/admin_manager.py
NEW: src/plexichat/core/auth/manager_admin.py

OLD: src/plexichat/core_system/auth/audit_manager.py
NEW: src/plexichat/core/auth/manager_audit.py

OLD: src/plexichat/core_system/auth/auth_manager.py
NEW: src/plexichat/core/auth/manager_auth.py

OLD: src/plexichat/core_system/auth/biometric_manager.py
NEW: src/plexichat/core/auth/manager_biometric.py

OLD: src/plexichat/core_system/auth/device_manager.py
NEW: src/plexichat/core/auth/manager_device.py

OLD: src/plexichat/core_system/auth/mfa_manager.py
NEW: src/plexichat/core/auth/manager_mfa.py

OLD: src/plexichat/core_system/auth/oauth_manager.py
NEW: src/plexichat/core/auth/manager_oauth.py

OLD: src/plexichat/core_system/auth/password_manager.py
NEW: src/plexichat/core/auth/manager_password.py

OLD: src/plexichat/core_system/auth/session_manager.py
NEW: src/plexichat/core/auth/manager_session.py

OLD: src/plexichat/core_system/auth/token_manager.py
NEW: src/plexichat/core/auth/manager_token.py
```

#### Database Files
```
OLD: src/plexichat/core_system/database/analytics_clients.py
NEW: src/plexichat/core/database/client_analytics.py

OLD: src/plexichat/core_system/database/global_data_distribution.py
NEW: src/plexichat/core/database/strategy_distribution.py

OLD: src/plexichat/core_system/database/enhanced_abstraction.py
NEW: src/plexichat/core/database/abstraction_enhanced.py

OLD: src/plexichat/core_system/database/manager.py
NEW: src/plexichat/core/database/manager_database.py

OLD: src/plexichat/core_system/database/models.py
NEW: src/plexichat/core/database/models_core.py

OLD: src/plexichat/core_system/database/schemas.py
NEW: src/plexichat/core/database/schemas_core.py

OLD: src/plexichat/core_system/database/utils.py
NEW: src/plexichat/core/database/utils_database.py
```

#### Configuration Files
```
OLD: src/plexichat/core_system/config/config_manager.py
NEW: src/plexichat/core/config/manager_config.py

OLD: src/plexichat/core_system/config/settings.py
NEW: src/plexichat/core/config/settings_core.py

OLD: src/plexichat/core_system/config/validation.py
NEW: src/plexichat/core/config/validator_config.py
```

### Phase VI-B: Features Renaming (Steps 56-60)

#### AI Features
```
OLD: src/plexichat/features/ai/ai_coordinator.py
NEW: src/plexichat/features/ai/coordinator_ai.py

OLD: src/plexichat/features/ai/advanced_ai_system.py
NEW: src/plexichat/features/ai/system_advanced.py

OLD: src/plexichat/features/ai/core/ai_abstraction_layer.py
NEW: src/plexichat/features/ai/core/layer_abstraction.py

OLD: src/plexichat/features/ai/features/ai_powered_features_service.py
NEW: src/plexichat/features/ai/features/service_powered.py

OLD: src/plexichat/features/ai/moderation/moderation_engine.py
NEW: src/plexichat/features/ai/moderation/engine_moderation.py
```

#### Security Features
```
OLD: src/plexichat/features/security/security_manager.py
NEW: src/plexichat/features/security/manager_security.py

OLD: src/plexichat/features/antivirus/antivirus_manager.py
NEW: src/plexichat/features/security/manager_antivirus.py

OLD: src/plexichat/features/security/threat_detection.py
NEW: src/plexichat/features/security/detector_threat.py
```

#### Backup Features
```
OLD: src/plexichat/features/backup/backup_manager.py
NEW: src/plexichat/features/backup/manager_backup.py

OLD: src/plexichat/features/backup/nodes/backup_node_main.py
NEW: src/plexichat/features/backup/nodes/node_main.py

OLD: src/plexichat/features/backup/nodes/backup_node_client.py
NEW: src/plexichat/features/backup/nodes/client_node.py
```

### Phase VI-C: Infrastructure Renaming (Steps 61-63)

#### Microservices
```
OLD: src/plexichat/infrastructure/microservices/service_registry.py
NEW: src/plexichat/infrastructure/microservices/registry_service.py

OLD: src/plexichat/infrastructure/microservices/decomposition.py
NEW: src/plexichat/infrastructure/microservices/strategy_decomposition.py

OLD: src/plexichat/infrastructure/scalability/distributed_caching.py
NEW: src/plexichat/infrastructure/scalability/cache_distributed.py

OLD: src/plexichat/infrastructure/scalability/async_task_queue.py
NEW: src/plexichat/infrastructure/scalability/queue_async.py
```

#### Analytics
```
OLD: src/plexichat/infrastructure/analytics/analytics_manager.py
NEW: src/plexichat/infrastructure/analytics/manager_analytics.py

OLD: src/plexichat/infrastructure/performance/performance_monitor.py
NEW: src/plexichat/infrastructure/performance/monitor_performance.py
```

### Phase VI-D: Interface Renaming (Steps 64-65)

#### API Interfaces
```
OLD: src/plexichat/interfaces/api/expansion/user_profiles_api.py
NEW: src/plexichat/interfaces/api/expansion/api_user_profiles.py

OLD: src/plexichat/interfaces/api/expansion/search_api.py
NEW: src/plexichat/interfaces/api/expansion/api_search.py

OLD: src/plexichat/interfaces/api/expansion/safety_api.py
NEW: src/plexichat/interfaces/api/expansion/api_safety.py

OLD: src/plexichat/interfaces/api/expansion/channels_api.py
NEW: src/plexichat/interfaces/api/expansion/api_channels.py
```

#### CLI Interfaces
```
OLD: src/plexichat/interfaces/cli/core/cli_manager.py
NEW: src/plexichat/interfaces/cli/core/manager_cli.py

OLD: src/plexichat/interfaces/cli/commands/cluster.py
NEW: src/plexichat/interfaces/cli/commands/command_cluster.py

OLD: src/plexichat/interfaces/cli/commands/plugins.py
NEW: src/plexichat/interfaces/cli/commands/command_plugins.py

OLD: src/plexichat/interfaces/cli/commands/updates.py
NEW: src/plexichat/interfaces/cli/commands/command_updates.py
```

## Implementation Strategy

### Step 1: Create New Directory Structure
- Create new directories following the naming convention
- Ensure proper __init__.py files are in place

### Step 2: Move and Rename Files
- Move files to new locations with new names
- Maintain file content initially (imports will be updated in Phase VII)

### Step 3: Update __init__.py Files
- Update all __init__.py files to reflect new file names
- Maintain backward compatibility where possible

### Step 4: Update Internal References
- Update relative imports within moved modules
- Update configuration files and scripts

### Step 5: Validation
- Ensure all files are properly moved
- Verify directory structure is correct
- Test basic imports work

## Benefits of New Structure

1. **Clarity**: Clear separation of concerns by domain
2. **Consistency**: Uniform naming convention across all modules
3. **Maintainability**: Easier to locate and maintain specific functionality
4. **Scalability**: Structure supports future growth and additions
5. **Documentation**: Self-documenting file names and structure

## Backward Compatibility

- Maintain import aliases in __init__.py files
- Provide deprecation warnings for old import paths
- Document migration path for external integrations

## Next Phase

Phase VII will update all import statements across the codebase to reflect the new file paths established in Phase VI.
