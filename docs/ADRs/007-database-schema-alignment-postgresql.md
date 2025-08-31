# ADR 007: Database Schema Alignment to PostgreSQL

## Status
Proposed

## Context
The current database implementation uses SQLite-based schemas but requirements specify PostgreSQL support. No SQLModel classes are found, and the migration system handles basic schema but not complex PostgreSQL features. This mismatch affects data integrity, performance, and production readiness within the existing `core/database/` module structure.

## Decision
Align database schema with PostgreSQL requirements by implementing proper SQLModel models, enhancing the migration system for PostgreSQL features, and ensuring compatibility while preserving the existing ORM abstraction layer. All changes will be contained within `core/database/` without altering the overall architecture.

## Consequences
- **Positive:** Production-ready PostgreSQL support, improved data integrity and performance
- **Negative:** Potential downtime during schema migration, increased complexity
- **Risks:** Data loss during migration, compatibility issues with existing SQLite data
- **Mitigation:** Comprehensive migration testing, backup verification, phased rollout

## Implementation Plan
1. Implement SQLModel classes for all database entities in `core/database/models.py`
2. Update schema definitions for PostgreSQL compatibility
3. Enhance migration system with PostgreSQL-specific features
4. Add database constraints and indexes for performance
5. Implement connection pooling optimized for PostgreSQL
6. Update ORM abstraction to support PostgreSQL features
7. Add database-level security measures

## Migration and Rollback Procedures
- **Migration:** Create migration scripts to transform SQLite schema to PostgreSQL
- **Rollback:** Backup SQLite database, rollback migration scripts
- **Testing:** Test migration on production-like data sets

## Testing and Validation Criteria
- Schema validation tests for PostgreSQL compatibility
- Migration tests with data integrity verification
- Performance tests comparing SQLite vs PostgreSQL
- Integration tests with PostgreSQL-specific features
- Security tests for database-level protections

## Risk Assessment
- **High Risk:** Data corruption during migration, production downtime
- **Medium Risk:** Performance regression, compatibility breaks
- **Low Risk:** Backward compatibility with SQLite for development

## Alternatives Considered
- Maintain SQLite for production (rejected due to scalability requirements)
- Use external ORM (rejected due to architectural consistency)

## Related
- ADR 004: Database Hardening
- ADR 001: Security Management APIs