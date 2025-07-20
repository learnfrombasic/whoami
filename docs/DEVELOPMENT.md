# WHOAMI - Development Guide

## Getting Started

### Prerequisites

Before you begin development, ensure you have the following installed:

- **Rust** (1.70 or later)
- **SQLite** (3.35 or later)
- **Git**
- **Visual Studio Code** or **JetBrains RustRover** (recommended IDEs)

#### Installing Rust

```bash
# Install Rust via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Source the environment
source ~/.cargo/env

# Verify installation
rustc --version
cargo --version
```

#### Installing SQLite

```bash
# macOS
brew install sqlite

# Ubuntu/Debian
sudo apt update
sudo apt install sqlite3 libsqlite3-dev

# Windows (via Chocolatey)
choco install sqlite

# Or download from https://sqlite.org/download.html
```

### Project Setup

#### 1. Clone the Repository

```bash
git clone <repository-url>
cd whoami
```

#### 2. Environment Configuration

Create a `.env` file in the project root:

```bash
cat > .env << EOF
DATABASE_URL=sqlite:./dev.db
JWT_SECRET=development-secret-key-change-in-production
SERVER_HOST=127.0.0.1
SERVER_PORT=8080
RUST_LOG=debug
SQLX_OFFLINE=true
EOF
```

#### 3. Install Dependencies

```bash
# Install project dependencies
cargo build

# Install development tools
cargo install sqlx-cli --no-default-features --features sqlite
cargo install cargo-watch
cargo install cargo-audit
```

#### 4. Database Setup

```bash
# Create database and run migrations
sqlx database create
sqlx migrate run

# Or use the application's built-in table creation
cargo run
```

#### 5. Run the Application

```bash
# Development with auto-reload
cargo watch -x run

# Regular run
cargo run

# Run with specific log level
RUST_LOG=debug cargo run
```

---

## Development Workflow

### Project Structure

```
whoami/
├── src/
│   ├── main.rs              # Application entry point
│   ├── mod.rs               # Module declarations
│   ├── core/                # Core infrastructure
│   │   ├── mod.rs
│   │   ├── config.rs        # Configuration management
│   │   ├── database.rs      # Database connection & setup
│   │   └── errors.rs        # Error types and handling
│   ├── models/              # Domain models
│   │   ├── mod.rs
│   │   ├── user.rs          # User entity
│   │   ├── role.rs          # Role entity
│   │   └── policy.rs        # Policy entity
│   ├── repository/          # Data access layer
│   │   ├── mod.rs
│   │   ├── user_repository.rs
│   │   ├── role_repository.rs
│   │   └── policy_repository.rs
│   ├── services/            # Business logic layer
│   │   ├── mod.rs
│   │   ├── auth_service.rs
│   │   ├── user_service.rs
│   │   ├── role_service.rs
│   │   └── policy_service.rs
│   ├── schemas/             # API schemas
│   │   ├── mod.rs
│   │   ├── auth.rs
│   │   ├── user.rs
│   │   ├── role.rs
│   │   └── policy.rs
│   └── routes/              # HTTP handlers
│       ├── mod.rs
│       ├── auth_routes.rs
│       ├── user_routes.rs
│       ├── role_routes.rs
│       └── policy_routes.rs
├── docs/                    # Documentation
├── tests/                   # Integration tests
├── migrations/              # Database migrations
├── .env                     # Environment variables
├── Cargo.toml              # Dependencies
└── README.md
```

### Development Commands

```bash
# Format code
cargo fmt

# Lint code
cargo clippy

# Run tests
cargo test

# Check compilation without building
cargo check

# Build for release
cargo build --release

# Generate documentation
cargo doc --open

# Security audit
cargo audit

# Watch for changes and run tests
cargo watch -x test

# Watch for changes and run clippy
cargo watch -x clippy
```

---

## Adding New Features

### Adding a New Model

1. **Create the model file** in `src/models/`:

```rust
// src/models/session.rs
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
}

impl Session {
    pub fn new(user_id: String, token_hash: String, expires_at: DateTime<Utc>) -> Self {
        let now = Utc::now();
        Session {
            id: Uuid::new_v4().to_string(),
            user_id,
            token_hash,
            expires_at,
            created_at: now,
            last_used_at: now,
        }
    }
}
```

2. **Update the models module** in `src/models/mod.rs`:

```rust
pub mod user;
pub mod role;
pub mod policy;
pub mod session; // Add this line

pub use user::User;
pub use role::Role;
pub use policy::Policy;
pub use session::Session; // Add this line
```

3. **Create the repository** in `src/repository/session_repository.rs`:

```rust
use sqlx::SqlitePool;
use crate::core::errors::AppError;
use crate::models::Session;

pub struct SessionRepository {
    pool: SqlitePool,
}

impl SessionRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, session: &Session) -> Result<Session, AppError> {
        let created_session = sqlx::query_as!(
            Session,
            r#"
            INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at, last_used_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            RETURNING *
            "#,
            session.id,
            session.user_id,
            session.token_hash,
            session.expires_at,
            session.created_at,
            session.last_used_at
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(created_session)
    }

    pub async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<Session>, AppError> {
        let session = sqlx::query_as!(
            Session,
            "SELECT * FROM sessions WHERE token_hash = ?1 AND expires_at > datetime('now')",
            token_hash
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(session)
    }

    pub async fn delete_by_token_hash(&self, token_hash: &str) -> Result<(), AppError> {
        sqlx::query!("DELETE FROM sessions WHERE token_hash = ?1", token_hash)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
```

4. **Add database migration** in `migrations/`:

```sql
-- migrations/004_create_sessions_table.sql
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
```

### Adding a New API Endpoint

1. **Define the schema** in `src/schemas/`:

```rust
// src/schemas/session.rs
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSessionRequest {
    pub user_id: String,
    pub expires_in_hours: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SessionResponse {
    pub id: String,
    pub user_id: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
```

2. **Create the service logic** in `src/services/`:

```rust
// src/services/session_service.rs
use crate::core::errors::AppError;
use crate::models::Session;
use crate::repository::SessionRepository;
use crate::schemas::CreateSessionRequest;
use chrono::{Duration, Utc};

pub struct SessionService {
    session_repo: SessionRepository,
}

impl SessionService {
    pub fn new(session_repo: SessionRepository) -> Self {
        Self { session_repo }
    }

    pub async fn create_session(&self, request: CreateSessionRequest, token_hash: String) -> Result<Session, AppError> {
        let expires_in_hours = request.expires_in_hours.unwrap_or(24);
        let expires_at = Utc::now() + Duration::hours(expires_in_hours as i64);
        
        let session = Session::new(request.user_id, token_hash, expires_at);
        self.session_repo.create(&session).await
    }
}
```

3. **Add the route handler** in `src/routes/`:

```rust
// src/routes/session_routes.rs
use actix_web::{web, HttpResponse, Result};
use crate::services::SessionService;
use crate::schemas::CreateSessionRequest;

pub fn configure_session_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/sessions")
            .route("", web::post().to(create_session))
            .route("/{token_hash}", web::delete().to(delete_session))
    );
}

#[utoipa::path(
    post,
    path = "/sessions",
    request_body = CreateSessionRequest,
    responses(
        (status = 201, description = "Session created successfully", body = SessionResponse),
        (status = 400, description = "Bad request")
    ),
    tag = "Sessions"
)]
async fn create_session(
    session_service: web::Data<SessionService>,
    request: web::Json<CreateSessionRequest>,
) -> Result<HttpResponse> {
    // Implementation here
    Ok(HttpResponse::NotImplemented().json("Not implemented yet"))
}

async fn delete_session(
    path: web::Path<String>,
    session_service: web::Data<SessionService>,
) -> Result<HttpResponse> {
    // Implementation here
    Ok(HttpResponse::NotImplemented().json("Not implemented yet"))
}
```

---

## Testing

### Unit Testing

Create unit tests for your services and repositories:

```rust
// src/services/user_service.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::UserRepository;
    use mockall::mock;

    mock! {
        UserRepo {
            async fn create(&self, user: &User) -> Result<User, AppError>;
            async fn find_by_id(&self, id: &str) -> Result<Option<User>, AppError>;
        }
    }

    #[tokio::test]
    async fn test_create_user_success() {
        let mut mock_repo = MockUserRepo::new();
        let user = User::new("test_user".to_string(), "test@example.com".to_string(), "hashed_password".to_string());
        
        mock_repo
            .expect_create()
            .returning(|_| Ok(user.clone()));

        let service = UserService::new(mock_repo);
        let request = CreateUserRequest {
            username: "test_user".to_string(),
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
        };

        let result = service.create_user(request).await;
        assert!(result.is_ok());
    }
}
```

### Integration Testing

Create integration tests in the `tests/` directory:

```rust
// tests/integration_test.rs
use actix_web::{test, App};
use serde_json::json;
use whoami::create_app; // Assuming you export a create_app function

#[actix_rt::test]
async fn test_user_registration() {
    let app = test::init_service(create_app().await).await;
    
    let req = test::TestRequest::post()
        .uri("/api/v1/auth/register")
        .set_json(&json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "password123"
        }))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201);
}
```

### Running Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_user_registration

# Run tests with coverage (requires cargo-tarpaulin)
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

---

## Database Management

### Creating Migrations

```bash
# Create a new migration
sqlx migrate add create_sessions_table

# This creates: migrations/{timestamp}_create_sessions_table.sql
```

### Running Migrations

```bash
# Run pending migrations
sqlx migrate run

# Revert last migration
sqlx migrate revert

# Show migration status
sqlx migrate info
```

### SQLx Offline Mode

For CI/CD without database access:

```bash
# Prepare query metadata
cargo sqlx prepare

# This generates .sqlx/ directory with query metadata
```

Add to `.gitignore`:
```
.sqlx/
```

But commit the metadata for CI:
```bash
git add .sqlx/
git commit -m "Add SQLx query metadata"
```

---

## Code Standards

### Formatting

Use `rustfmt` with the following configuration in `rustfmt.toml`:

```toml
max_width = 100
hard_tabs = false
tab_spaces = 4
newline_style = "Unix"
use_small_heuristics = "Default"
indent_style = "Block"
wrap_comments = false
normalize_comments = false
format_code_in_doc_comments = false
format_macro_matchers = false
format_strings = false
imports_layout = "Mixed"
merge_imports = false
use_try_shorthand = false
force_explicit_abi = true
normalize_doc_attributes = false
license_template_path = ""
```

### Linting

Configure Clippy with these settings in `Cargo.toml`:

```toml
[lints.clippy]
all = "warn"
pedantic = "warn"
nursery = "warn"
cargo = "warn"

# Allow some pedantic lints that are too strict
module_name_repetitions = "allow"
missing_errors_doc = "allow"
missing_panics_doc = "allow"
```

### Documentation

Document all public APIs:

```rust
/// Creates a new user in the system.
/// 
/// # Arguments
/// 
/// * `request` - The user creation request containing username, email, and password
/// 
/// # Returns
/// 
/// * `Ok(User)` - The created user
/// * `Err(AppError)` - Error if user creation fails
/// 
/// # Errors
/// 
/// * `AppError::BadRequest` - If username or email already exists
/// * `AppError::InternalError` - If password hashing fails
pub async fn create_user(&self, request: CreateUserRequest) -> Result<User, AppError> {
    // Implementation
}
```

---

## Performance Optimization

### Database Performance

1. **Use indexes** for frequently queried columns:
```sql
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
```

2. **Use connection pooling** with appropriate settings:
```rust
let pool = SqlitePool::connect_with(
    SqliteConnectOptions::from_str(&database_url)?
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(30))
        .pragma("cache_size", "-64000") // 64MB cache
).await?;
```

3. **Use prepared statements** (SQLx does this automatically)

### Memory Optimization

1. **Use `Box<str>` instead of `String`** for immutable strings
2. **Implement `Clone` efficiently** for large structs
3. **Use `Arc<T>` for shared data**

### Async Performance

1. **Use `tokio::spawn` for CPU-intensive tasks**
2. **Batch database operations** where possible
3. **Use connection pooling**

---

## Security Best Practices

### Input Validation

```rust
use validator::{Validate, ValidationError};

#[derive(Deserialize, Validate)]
pub struct CreateUserRequest {
    #[validate(length(min = 3, max = 50))]
    #[validate(regex = "USERNAME_REGEX")]
    pub username: String,
    
    #[validate(email)]
    pub email: String,
    
    #[validate(length(min = 8))]
    pub password: String,
}

lazy_static! {
    static ref USERNAME_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9_]+$").unwrap();
}
```

### Error Handling

Never expose internal errors to clients:

```rust
impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        log::error!("Database error: {}", err);
        AppError::InternalError("Internal server error".to_string())
    }
}
```

### JWT Security

```rust
use jsonwebtoken::{Algorithm, Validation};

let mut validation = Validation::new(Algorithm::HS256);
validation.validate_exp = true;
validation.validate_nbf = true;
validation.leeway = 60; // 60 seconds leeway
```

---

## Deployment

### Docker

Create a `Dockerfile`:

```dockerfile
FROM rust:1.70 as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/whoami /usr/local/bin/whoami
EXPOSE 8080
CMD ["whoami"]
```

And `docker-compose.yml`:

```yaml
version: '3.8'
services:
  whoami:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=sqlite:/data/whoami.db
      - JWT_SECRET=your-production-secret
      - RUST_LOG=info
    volumes:
      - ./data:/data
```

### Environment Variables

Production environment variables:

```bash
# Production .env
DATABASE_URL=sqlite:/data/whoami.db
JWT_SECRET=your-very-secure-production-secret-key
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
RUST_LOG=info
```

---

## Monitoring and Debugging

### Logging

Configure structured logging:

```rust
use tracing::{info, error, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn init_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into())
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();
}
```

### Health Checks

```rust
// src/routes/health.rs
use actix_web::{web, HttpResponse, Result};

pub fn configure_health_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/health", web::get().to(health_check));
}

async fn health_check() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now(),
        "version": env!("CARGO_PKG_VERSION")
    })))
}
```

### Metrics

```rust
use prometheus::{Counter, Histogram, register_counter, register_histogram};

lazy_static! {
    static ref HTTP_REQUESTS_TOTAL: Counter = register_counter!(
        "http_requests_total", "Total number of HTTP requests"
    ).unwrap();
    
    static ref HTTP_REQUEST_DURATION: Histogram = register_histogram!(
        "http_request_duration_seconds", "HTTP request duration"
    ).unwrap();
}
```

---

## Troubleshooting

### Common Issues

#### SQLite Database Locked
```rust
// Solution: Use WAL mode and increase busy timeout
let options = SqliteConnectOptions::from_str(&database_url)?
    .journal_mode(SqliteJournalMode::Wal)
    .busy_timeout(Duration::from_secs(30));
```

#### JWT Token Validation Fails
```rust
// Check token format and secret
let validation = Validation::new(Algorithm::HS256);
match decode::<Claims>(token, &DecodingKey::from_secret(secret.as_ref()), &validation) {
    Ok(data) => println!("Token valid: {:?}", data.claims),
    Err(e) => println!("Token invalid: {}", e),
}
```

#### Port Already in Use
```bash
# Find process using port 8080
lsof -i :8080

# Kill the process
kill -9 <PID>
```

### Debug Mode

Run with debug logging:

```bash
RUST_LOG=debug cargo run
```

### Database Inspection

```bash
# Open SQLite database
sqlite3 whoami.db

# List tables
.tables

# Show schema
.schema users

# Query data
SELECT * FROM users;
``` 