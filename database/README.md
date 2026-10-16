# Verdyx Database Layer

Column purpose, ownership, and sensitive fields: `docs/database/data-model.md`.
Retention and backup: `docs/database/retention-and-backup.md`.

> ## ⚠️ SOURCE OF TRUTH (read this first)
>
> The **authoritative schema is the per-service `migrations/` folder inside each
> backend service** (e.g. `backend/user-service/migrations/`,
> `backend/consensus-service/migrations/`, etc.). At runtime:
>
> 1. `database/init/01-init-databases.sql` runs once on first Postgres start and
>    creates **one database per service** (`verdyx_gateway`, `verdyx_users`,
>    `verdyx_analysis`, `verdyx_bounty`, `verdyx_submissions`,
>    `verdyx_consensus`, `verdyx_payments`, `verdyx_reputation`,
>    `verdyx_notifications`).
> 2. Each service then applies its own migrations via `sqlx::migrate!` on boot.
>
> Therefore the files under `database/postgres/migrations/` and the master
> `database/schema.sql` in this folder are **LEGACY / REFERENCE ONLY**. They are
> not executed by any service and may drift from reality. Do **not** treat them
> as the live schema. If you change a table, change it in the owning service's
> `migrations/` folder. The sections below that describe a single monolithic
> `verdyx` database are historical and kept for high-level domain reference only.
>
> **Operations:**
> - Backup all databases + Redis + MinIO: `scripts/maintenance/backup.sh`
> - Restore from a snapshot: `scripts/maintenance/restore.sh --backup <dir>`
> - Migration authoring rules and rollback procedure: [`docs/database/migrations.md`](../docs/database/migrations.md)


This directory contains all database configurations, schemas, migrations, and initialization scripts for the Verdyx threat intelligence platform.

## 📁 Directory Structure

```
database/
├── docker-compose.yml          # Docker orchestration for all databases
├── .env.example               # Environment configuration template
├── schema.sql                 # Master schema orchestration script
├── README.md                  # This file
│
├── postgres/                  # PostgreSQL relational database
│   ├── migrations/           # Schema migrations (versioned)
│   │   ├── 001_user_engine.sql           # Users, engines, submissions
│   │   ├── 002_bounty_system.sql         # Bounties, rewards, consensus
│   │   ├── 003_blockchain.sql            # Blockchain integration
│   │   ├── 004_reputation_system.sql     # Reputation & scoring
│   │   └── 005_fix_user_schema.sql       # Schema fixes
│   ├── seeds/                # Test/seed data
│   │   └── test_data.sql                 # Development test data
│   ├── functions/            # Custom PostgreSQL functions
│   └── triggers/             # Database triggers
│
├── mongodb/                   # MongoDB document database
│   ├── init.js               # MongoDB initialization entry point
│   ├── init/                 # Initialization scripts
│   │   └── init-db.js                    # Collections & indexes
│   └── schemas/              # JSON schemas
│       └── analysis-results.json         # Analysis results schema
│
└── redis/                     # Redis cache & session store
    ├── redis.conf            # Redis configuration
    └── init/                 # Initialization scripts
        └── cache-warmup.sh               # Cache warmup script
```

## 🗄️ Database Architecture

Verdyx uses a **polyglot persistence** architecture with three databases:

### 1. PostgreSQL (Primary Relational Database)
**Purpose:** Structured data, transactions, relationships

**Schema Modules:**
- **User & Engine Management** (001): User accounts, engines, authentication, API keys
- **Bounty System** (002): Bounties, participations, rewards, consensus
- **Blockchain Integration** (003): Networks, contracts, transactions, staking, governance
- **Reputation System** (004): Reputation scores, performance metrics, leaderboards

**Key Features:**
- 40+ tables with full referential integrity
- 100+ optimized indexes
- Custom functions for reputation calculation
- Automated triggers for timestamps and calculations
- Database views for complex queries
- JSONB columns for flexible metadata

### 2. MongoDB (Document Store)
**Purpose:** Unstructured analysis data, file metadata, large documents

**Collections:**
- `analysis_results` - Detailed analysis outputs from engines
- `file_metadata` - File hashes, PE info, strings, imports/exports
- `engine_stats` - Real-time engine statistics
- `consensus_results` - Aggregated consensus verdicts
- `threat_indicators` - IOCs (IPs, domains, hashes)
- `sandbox_reports` - Dynamic analysis results

**Key Features:**
- Schema validation with JSON Schema
- 18+ indexes for fast queries
- TTL indexes for automatic data expiration
- Flexible document structure for diverse analysis formats

### 3. Redis (Cache & Session Store)
**Purpose:** Caching, sessions, rate limiting, real-time data

**Database Organization:**
- **DB 0:** Session storage (allkeys-lru policy)
- **DB 1:** API rate limiting
- **DB 2:** Analysis results cache (24h TTL)
- **DB 3:** Engine reputation cache
- **DB 4:** Temporary file processing (1h TTL)
- **DB 5:** WebSocket connection tracking

**Pub/Sub Channels:**
- `analysis:started` - Analysis start notifications
- `analysis:completed` - Analysis completion notifications
- `consensus:reached` - Consensus achieved notifications
- `payment:processed` - Payment transaction notifications
- `reputation:updated` - Reputation score updates

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- OR: PostgreSQL 16+, MongoDB 7+, Redis 7+

### Option 1: Docker Setup (Recommended)

1. **Copy environment file:**
```bash
cp .env.example .env
# Edit .env with your configuration
```

2. **Start databases:**
```bash
# Start core databases
docker-compose up -d postgres mongodb redis

# Or start with admin tools (development)
docker-compose --profile dev up -d

# Or start everything including init
docker-compose --profile init up -d
```

3. **Verify services:**
```bash
docker-compose ps
docker-compose logs -f
```

4. **Access admin tools (if using --profile dev):**
- pgAdmin: http://localhost:5050
- Mongo Express: http://localhost:8081
- Redis Commander: http://localhost:8082

### Option 2: Manual Setup

#### PostgreSQL Setup
```bash
# Create database
createdb verdyx

# Run migrations
psql -d verdyx -f schema.sql

# Load test data (optional)
psql -d verdyx -f postgres/seeds/test_data.sql

# Verify
psql -d verdyx -c "\dt"
```

#### MongoDB Setup
```bash
# Start MongoDB
mongod --dbpath /data/db

# Initialize database
mongosh verdyx < mongodb/init/init-db.js

# Verify
mongosh verdyx --eval "db.getCollectionNames()"
```

#### Redis Setup
```bash
# Start Redis with config
redis-server redis/redis.conf

# Warm up cache (optional)
bash redis/init/cache-warmup.sh

# Verify
redis-cli ping
```

## 🔗 Backend Integration

### PostgreSQL Connection (Rust/sqlx)

```rust
use sqlx::postgres::PgPoolOptions;

let database_url = std::env::var("DATABASE_URL")
    .unwrap_or_else(|_| "postgresql://postgres:password@localhost:5432/verdyx".to_string());

let pool = PgPoolOptions::new()
    .max_connections(100)
    .min_connections(10)
    .connect_timeout(Duration::from_secs(30))
    .idle_timeout(Some(Duration::from_secs(600)))
    .max_lifetime(Some(Duration::from_secs(1800)))
    .connect(&database_url)
    .await?;
```

### MongoDB Connection (Rust/mongodb)

```rust
use mongodb::{Client, options::ClientOptions};

let mongodb_url = std::env::var("MONGODB_URL")
    .unwrap_or_else(|_| "mongodb://verdyx_admin:password@localhost:27017/verdyx".to_string());

let mut client_options = ClientOptions::parse(&mongodb_url).await?;
client_options.app_name = Some("Verdyx".to_string());
client_options.max_pool_size = Some(50);

let client = Client::with_options(client_options)?;
let database = client.database("verdyx");
```

### Redis Connection (Rust/redis)

```rust
use redis::Client;

let redis_url = std::env::var("REDIS_URL")
    .unwrap_or_else(|_| "redis://localhost:6379".to_string());

let client = Client::open(redis_url)?;
let mut con = client.get_connection()?;

// Or use async
let client = redis::Client::open(redis_url)?;
let mut con = client.get_async_connection().await?;
```

### Complete Backend Configuration

The backend services use the configuration structure defined in [backend/api-gateway/src/config.rs](file:///Users/arjun/Developer/Verdyx/backend/api-gateway/src/config.rs):

**Environment Variables:**
```bash
# PostgreSQL
DATABASE_URL=postgresql://postgres:password@localhost:5432/verdyx
DATABASE_MAX_CONNECTIONS=100

# MongoDB
MONGODB_URL=mongodb://verdyx_admin:password@localhost:27017/verdyx

# Redis
REDIS_URL=redis://localhost:6379
```

**Configuration File (config.toml):**
```toml
[database]
url = "postgresql://postgres:password@localhost:5432/verdyx"
max_connections = 100
min_connections = 10
connection_timeout_seconds = 30
idle_timeout_seconds = 600
max_lifetime_seconds = 1800
enable_logging = false
run_migrations = true

[redis]
url = "redis://localhost:6379"
max_connections = 50
connection_timeout_seconds = 5
pool_timeout_seconds = 10
enable_cluster = false
key_prefix = "verdyx:"
default_ttl_seconds = 3600
```

## 📊 Database Schema Details

### Key Tables

#### Users & Authentication
- `users` - User accounts with wallet addresses
- `engines` - Analysis engines (automated & human)
- `user_sessions` - Active sessions
- `api_keys` - API authentication keys
- `wallet_connections` - Web3 wallet connections

#### Bounty System
- `bounties` - Threat analysis bounties
- `submissions` - Files/URLs for analysis
- `bounty_participations` - Engine participation & stakes
- `analysis_results` - Detailed analysis outputs
- `consensus_results` - Aggregated verdicts
- `reward_distributions` - Payouts tracking

#### Blockchain Integration
- `blockchain_networks` - Supported networks (Ethereum, Polygon, BSC)
- `smart_contracts` - Deployed contract addresses
- `blockchain_transactions` - On-chain transaction tracking
- `token_balances` - User token balances
- `staking_pools` - Various staking mechanisms
- `governance_proposals` - DAO proposals
- `governance_votes` - Voting records

#### Reputation System
- `reputation_events` - All reputation-affecting actions
- `reputation_scores` - Detailed scoring breakdown
- `performance_metrics` - Time-based performance tracking
- `user_expertise` - Specialized knowledge domains
- `trust_relationships` - Inter-user/engine trust
- `leaderboards` - Ranking system

### Database Functions

**PostgreSQL Custom Functions:**
1. `update_updated_at_column()` - Automatic timestamp updates
2. `get_user_total_stake(user_id)` - Calculate total staked amount
3. `calculate_voting_power(user_id)` - Compute voting power
4. `calculate_reputation_score(entity_id, is_user)` - Reputation calculation
5. `update_performance_metrics(entity_id, is_user, period)` - Metrics update

### Views

**PostgreSQL Views:**
1. `bounty_stats` - Bounty statistics overview
2. `blockchain_activity` - Comprehensive blockchain activity
3. `reputation_overview` - Reputation rankings

## 🔧 Maintenance

### Backup

**PostgreSQL:**
```bash
# Backup
pg_dump verdyx > backup_$(date +%Y%m%d).sql

# Restore
psql verdyx < backup_20240101.sql
```

**MongoDB:**
```bash
# Backup
mongodump --db verdyx --out ./backups/

# Restore
mongorestore --db verdyx ./backups/verdyx/
```

**Redis:**
```bash
# Backup
redis-cli SAVE
cp /data/dump.rdb ./backups/redis_backup_$(date +%Y%m%d).rdb

# Restore
cp ./backups/redis_backup_20240101.rdb /data/dump.rdb
redis-cli SHUTDOWN NOSAVE
redis-server
```

### Migrations

To add a new migration:

1. Create new file: `postgres/migrations/00X_description.sql`
2. Update `schema.sql` to include new migration
3. Test locally:
```bash
psql verdyx -f postgres/migrations/00X_description.sql
```

### Performance Tuning

**PostgreSQL:**
```sql
-- Check table sizes
SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename))
FROM pg_tables WHERE schemaname = 'public' ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Analyze query performance
EXPLAIN ANALYZE SELECT ...;

-- Rebuild indexes
REINDEX DATABASE verdyx;
```

**MongoDB:**
```javascript
// Check collection sizes
db.stats()

// Analyze query performance
db.analysis_results.find({...}).explain("executionStats")

// Rebuild indexes
db.analysis_results.reIndex()
```

**Redis:**
```bash
# Monitor performance
redis-cli --stat

# Check memory usage
redis-cli INFO memory

# Flush specific database
redis-cli -n 2 FLUSHDB
```

## 🔒 Security Considerations

1. **Change default passwords** in production
2. **Enable SSL/TLS** for all database connections
3. **Use strong JWT secrets** (minimum 32 characters)
4. **Restrict network access** to databases
5. **Regular backups** with encryption
6. **Monitor for SQL injection** attempts
7. **Use prepared statements** in application code
8. **Implement rate limiting** via Redis
9. **Enable audit logging** for sensitive operations
10. **Rotate API keys** regularly

## 📝 Test Data

The `postgres/seeds/test_data.sql` file includes:
- 5 test users (password: `TestPassword123!`)
- 5 analysis engines
- 4 test submissions
- 4 bounties with participations
- Complete reputation and performance data
- Blockchain network configurations
- Smart contract deployments (local testnet addresses)

## 🐛 Troubleshooting

### Connection Issues

**PostgreSQL:**
```bash
# Check if running
pg_isready -h localhost -p 5432

# Check connections
psql -c "SELECT * FROM pg_stat_activity;"
```

**MongoDB:**
```bash
# Check if running
mongosh --eval "db.adminCommand('ping')"

# Check connections
mongosh --eval "db.serverStatus().connections"
```

**Redis:**
```bash
# Check if running
redis-cli ping

# Check info
redis-cli INFO
```

### Docker Issues

```bash
# Check logs
docker-compose logs -f postgres
docker-compose logs -f mongodb
docker-compose logs -f redis

# Restart services
docker-compose restart postgres mongodb redis

# Clean restart (WARNING: destroys data)
docker-compose down -v
docker-compose up -d
```

## 📚 Additional Resources

- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [MongoDB Documentation](https://docs.mongodb.com/)
- [Redis Documentation](https://redis.io/documentation)
- [sqlx Documentation](https://docs.rs/sqlx/)
- [mongodb Rust Driver](https://docs.rs/mongodb/)
- [redis-rs Documentation](https://docs.rs/redis/)

## 🤝 Contributing

When contributing to the database layer:

1. Follow the existing naming conventions
2. Add appropriate indexes for new queries
3. Include migration scripts for schema changes
4. Update this README with any architectural changes
5. Test migrations on a clean database
6. Provide rollback scripts for migrations

## 📄 License

This database schema is part of the Verdyx project.
