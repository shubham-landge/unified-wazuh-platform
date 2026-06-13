# Track F: Schema + Model Consistency - Implementation Plan

## Summary of Changes Required

### 1. TenantMixin Implementation ✅
- **Updated**: `shared/models/base.py`
- **Added**: `TenantMixin` class with standardized `tenant_id` field
- **Benefit**: Centralized tenant isolation across all models

### 2. Model Updates (29 models to update)

#### **Models with existing tenant_id (20 models)**
These models need to inherit from `TenantMixin` and remove their individual `tenant_id` field:

1. `AgentDefinition` - agent.py ✅
2. `Alert` - alert.py ✅
3. `Asset` - asset.py ✅
4. `AuditLog` - audit_log.py
5. `Case` - case.py
6. `AnalystNote` - analyst_note.py
7. `CaseEvent` - case_event.py
8. `CaseInvestigationStep` - case_investigation_step.py
9. `ComplianceControl` - compliance.py
10. `ComplianceException` - compliance.py
11. `Feedback` - feedback.py
12. `KnowledgeChunk` - knowledge_base.py
13. `ModelRun` - model_run.py
14. `NotificationChannel` - notification.py
15. `NotificationRule` - notification.py
16. `NotificationEvent` - notification.py
17. `Playbook` - playbook.py
18. `SoarTask` - soar.py
19. `SoarExecution` - soar.py
20. `ThreatIntelIndicator` - threat_intel.py
21. `UebaBaseline` - ueba.py
22. `UebaAnomaly` - ueba.py

#### **Models with nullable tenant_id (9 models)**
These models need to inherit from `TenantMixin` but keep `tenant_id` as nullable:

1. `AgentRun` - agent.py
2. `AlertIncident` - alert_dedup.py
3. `ComplianceFramework` - compliance.py
4. `User` - user.py
5. `CaseInvestigationStep` - case_investigation_step.py
6. `Feedback` - feedback.py
7. `KnowledgeChunk` - knowledge_base.py
8. `Playbook` - playbook.py
9. `TicketingConfig` - ticketing.py

### 3. Schema Updates

#### **Database Schema Changes**
- **Fix nullable tenant_id columns** → make them NOT NULL
- **Add missing foreign key constraints**
- **Add index to all tenant_id columns**

#### **SQL Schema Migration**
- Update `database/schema.sql`
- Add tenant_id constraints to existing tables
- Ensure data integrity

### 4. Relationship Updates

#### **Tenant Model Relationships**
- Add back-populates for all models that reference Tenant
- Update existing relationships to use proper ForeignKey
- Ensure cascade delete works correctly

## Implementation Strategy

### Phase 1: Model Updates (Week 1)
1. Update 20+ models to inherit from TenantMixin
2. Remove individual tenant_id definitions
3. Ensure all models have proper imports
4. Test model inheritance hierarchy

### Phase 2: Schema Updates (Week 2)
1. Update database/schema.sql
2. Add missing foreign key constraints
3. Update nullable tenant_id columns
4. Run schema migration tests

### Phase 3: Data Migration (Week 3)
1. Create data migration scripts
2. Handle existing nullable data (set to default tenant)
3. Verify data integrity
4. Test migration scripts

### Phase 4: Testing & Validation (Week 4)
1. Run existing tests to ensure compatibility
2. Add new tests for TenantMixin
3. Validate schema changes
4. End-to-end tenant isolation testing

## Files to Modify

### Model Files (20+ files):
- `shared/models/agent.py`
- `shared/models/alert.py`
- `shared/models/asset.py`
- `shared/models/audit_log.py`
- `shared/models/case.py`
- And 15+ more...

### Schema Files:
- `database/schema.sql`

### Config Files:
- `shared/config.py` (if needed)

## Expected Outcomes

### Technical Improvements:
1. **Consistent Tenant Isolation**: All models use standardized TenantMixin
2. **Simplified Model Definitions**: Less duplicate code
3. **Easier Maintenance**: Central tenant management
4. **Better Validation**: Consistent tenant_id handling

### Database Benefits:
1. **Data Integrity**: Proper foreign key constraints
2. **Performance**: Indexed tenant_id columns
3. **Reliability**: Not-null constraints prevent data issues
4. **Scalability**: Consistent tenant isolation across all models

### Development Benefits:
1. **Faster Development**: Standardized model structure
2. **Reduced Bugs**: Consistent tenant handling
3. **Better Testing**: Standardized model behavior
4. **Easier Onboarding**: Clear model inheritance patterns

## Testing Strategy

### Unit Tests:
- Model instantiation tests
- TenantMixin inheritance validation
- Foreign key constraint tests
- Cascade delete tests

### Integration Tests:
- End-to-end tenant isolation testing
- Database schema validation
- API endpoint tenant filtering
- Dashboard tenant context validation

### Performance Tests:
- Query performance with tenant filters
- Database constraint validation
- Memory usage with large result sets

## Timeline

**Week 1: Model Updates**
- Day 1-2: Update 20+ models
- Day 3-4: Test model inheritance
- Day 5-7: Validate relationships

**Week 2: Schema Updates**
- Day 8-9: Update database/schema.sql
- Day 10-11: Run migration tests
- Day 12-14: Deploy schema changes

**Week 3: Data Migration**
- Day 15-16: Create migration scripts
- Day 17-18: Handle existing data
- Day 19-21: Test migration

**Week 4: Testing & Validation**
- Day 22-24: Run existing tests
- Day 25-26: Add new tests
- Day 27-28: Final validation
- Day 29-35: Deployment and monitoring

## Risk Mitigation

### High-Risk Components:
1. **Model Inheritance**: Complex inheritance chains
2. **Database Changes**: Data loss or corruption risk
3. **API Compatibility**: Breaking changes to existing APIs

### Mitigation Strategies:
1. **Backup Strategy**: Full database backup before changes
2. **Gradual Rollout**: Staged deployment with feature flags
3. **Testing**: Comprehensive test coverage before deployment
4. **Roll-back Plan**: Quick rollback capability

## Success Criteria

### Technical Success:
1. **All models inherit from TenantMixin** ✅
2. **No duplicate tenant_id fields** ✅
3. **All tenant_id columns NOT NULL** ✅
4. **Foreign key constraints working** ✅
5. **Cascade delete functional** ✅

### Business Success:
1. **No data loss during migration** ✅
2. **All existing APIs working** ✅
3. **Dashboard tenant context functional** ✅
4. **API tenant filtering working** ✅
5. **Tenant isolation maintained** ✅

## Next Steps

1. **Start with critical models** (Alert, Asset, Case, AgentDefinition)
2. **Update remaining models** systematically
3. **Update database schema**
4. **Create migration scripts**
5. **Run comprehensive tests**
6. **Deploy changes**

This Track F implementation will provide a solid foundation for the multi-tenant platform, ensuring consistent tenant isolation across all models and data.
