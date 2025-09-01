# ADR 014: Replace Print Statements with Structured Logging

## Status
Proposed

## Context
The PlexiChat codebase contains numerous print statements scattered across various modules, including core components, interfaces, plugins, and test files. These print statements are used for debugging, status reporting, error messages, and user feedback. While functional for development, print statements lack the structure, configurability, and monitoring capabilities of a proper logging system.

Key issues with current print usage:
- No log levels (debug, info, warning, error, critical)
- No structured logging with context
- Difficult to filter and aggregate logs
- Not suitable for production environments
- Inconsistent formatting across modules
- Missing correlation IDs and timestamps
- Cannot be easily redirected to monitoring systems

The unified logging system already exists and provides structured logging capabilities, but many modules still use print statements instead.

## Decision
Replace all print statements throughout the codebase with appropriate calls to the unified logging system. Use proper log levels, structured logging with context, and ensure backward compatibility where necessary.

## Consequences
- **Positive:** 
  - Improved log aggregation and monitoring
  - Better debugging capabilities in production
  - Consistent log formatting across all modules
  - Configurable log levels and filtering
  - Integration with existing monitoring infrastructure
  - Structured logs with context and correlation IDs

- **Negative:** 
  - Changes to output format may affect scripts that parse stdout/stderr
  - Potential increase in log volume if debug prints are converted to info level
  - Requires logger imports in modules that don't currently have them

- **Risks:** 
  - Performance impact from increased logging in hot paths
  - Breaking changes for external tools that depend on print output
  - Log noise if inappropriate log levels are chosen

- **Mitigation:** 
  - Use appropriate log levels (debug for development, info/warning/error for production)
  - Maintain backward compatibility by configuring logging to output to stdout/stderr when needed
  - Gradual rollout with testing to ensure no breaking changes
  - Performance monitoring during rollout

## Implementation Plan

### Phase 1: Core Modules (High Priority)
1. Replace print statements in core modules (`src/plexichat/core/`)
2. Update authentication, database, and security modules
3. Implement structured logging with context
4. Add correlation IDs for request tracing

### Phase 2: Interface Modules (Medium Priority)
1. Replace print statements in web interfaces (`interfaces/web/`)
2. Update CLI commands and interactive components
3. Implement user-friendly logging with proper formatting
4. Maintain backward compatibility for CLI output

### Phase 3: Infrastructure and Features (Medium Priority)
1. Replace print statements in infrastructure services
2. Update feature modules (AI, backup, etc.)
3. Implement performance logging for monitoring
4. Add security event logging

### Phase 4: Plugins and Tests (Low Priority)
1. Replace print statements in plugin code
2. Update test files to use logging instead of print
3. Implement test result logging
4. Clean up development/debug prints

### Migration Strategy
1. **Identify all print statements** using code analysis tools
2. **Categorize by module and priority** based on impact
3. **Replace with appropriate logger calls:**
   - `print("info message")` → `logger.info("info message")`
   - `print("error:", e)` → `logger.error("error: %s", e)`
   - `print(f"debug: {var}")` → `logger.debug("debug: %s", var)`
4. **Add logger imports** where missing
5. **Configure logging levels** appropriately per module
6. **Test backward compatibility** for CLI and interactive components

### Backward Compatibility
- Configure logging handlers to output to stdout/stderr when running in development mode
- Maintain print-like behavior for CLI tools and interactive sessions
- Use logging formatters that preserve readability for human consumption
- Provide configuration options to restore print-like output if needed

## Alternatives Considered
- **Keep print statements:** Rejected due to poor monitoring and production debugging capabilities
- **Custom logging wrapper:** Rejected to avoid fragmentation with existing unified logging system
- **Selective replacement:** Rejected as it would maintain inconsistency across the codebase

## Related
- ADR 003: WAF Logging Integration with Unified System
- ADR 005: Audit Logging System
- ADR 006: System Monitoring Implementation