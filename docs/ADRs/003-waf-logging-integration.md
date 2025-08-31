# ADR 003: WAF Logging Integration with Unified System

## Status
Proposed

## Context
The WAF middleware contains multiple TODO items for logging integration. Currently, WAF threat detection events are logged using print statements instead of the unified logging system. This prevents proper log aggregation, monitoring, and security event correlation.

## Decision
Integrate WAF logging with the unified logging system, replacing print statements with structured logging calls. Implement proper log levels, event categorization, and correlation IDs for security events.

## Consequences
- **Positive:** Centralized security event logging, improved monitoring and alerting
- **Negative:** Changes to logging format may affect existing log parsing
- **Risks:** Log volume increase, potential performance impact
- **Mitigation:** Gradual rollout with log level controls, performance monitoring

## Implementation Plan
1. Replace print statements with unified logger calls
2. Implement structured event logging for WAF threats
3. Add log aggregation and correlation
4. Create security event dashboards
5. Add configurable log levels for different threat types

## Alternatives Considered
- Keep print statements (rejected due to poor monitoring)
- Custom WAF logging (rejected due to system fragmentation)

## Related
- ADR 005: Audit Logging System
- ADR 006: System Monitoring Implementation