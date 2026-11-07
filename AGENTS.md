# AGENTS.md

## Lint and Typecheck

```bash
npm run lint           # tsc --noEmit — run before every commit
```

Tests:

```bash
npm test                # node --import tsx --test (all tests)
npm run test:unit       # supported node:test suite (alias of npm test)
npm run test:ci         # requires TEST_DATABASE_URL; use a disposable database
```

ML subsystem only:

```bash
node --import tsx --test --test-concurrency=1 tests/ml-*.test.ts
```

ML training cron (standalone):

```bash
node --import tsx server/ml/train/cron.ts
```

## New Agent: Email Delivery Action Center

**File:** `src/components/ActionCenter.tsx`

The Action Center provides comprehensive email delivery monitoring and management:

**Key Features:**

- Real-time SLA monitoring with delivery rate, average delivery times, and compliance tracking
- Bulk operations (retry, cancel, send now) for multiple email logs
- Advanced filtering by status, provider, date range, and recipient type
- Interactive table with status badges, SLA indicators, and action buttons
- Auto-refresh every 30 seconds for live metrics
- Search functionality for finding specific deliveries by recipient, subject, or advisory

**Navigation:**

- Added to "Autonomous pipeline" section in sidebar
- Accessible via `/autonomous-pipeline/action-center`
- Also available as "Email delivery action center" in main navigation

**Permissions:** Requires ADMIN or OPERATOR role for management actions

**Components:**

- Email delivery SLA metrics dashboard
- Delivery status monitoring with real-time updates
- Bulk action toolbar for selected logs
- Advanced filtering and search interface
- Email queue management with retry capabilities
- Delivery timeline and history tracking
