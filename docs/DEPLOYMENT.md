# WHOAMI - Deployment Guide

## Overview

This guide covers various deployment strategies for the WHOAMI IAM service, from development to production environments. The service is designed to be lightweight and can be deployed in multiple ways.

---

## Local Development Deployment

### Quick Start

```bash
# Clone and setup
git clone <repository-url>
cd whoami

# Create environment file
cat > .env << EOF
DATABASE_URL=sqlite:./dev.db
JWT_SECRET=development-secret-key
SERVER_HOST=127.0.0.1
SERVER_PORT=8080
RUST_LOG=debug
EOF

# Build and run
cargo run
```

### Development with Auto-reload

```bash
# Install cargo-watch
cargo install cargo-watch

# Run with auto-reload
cargo watch -x run

# Or with specific command
cargo watch -x 'run --bin whoami'
```

---

## Docker Deployment

### Single Container

#### Dockerfile

```dockerfile
# Build stage
FROM rust:1.75-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency files first for better caching
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release && rm src/main.rs

# Copy source code and build
COPY src ./src
RUN touch src/main.rs && cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -r -s /bin/false -m -d /app whoami

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/target/release/whoami /usr/local/bin/whoami

# Create data directory
RUN mkdir -p /app/data && chown whoami:whoami /app/data

# Switch to app user
USER whoami

# Set environment variables
ENV DATABASE_URL=sqlite:/app/data/whoami.db
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=8080
ENV RUST_LOG=info

EXPOSE 8080
VOLUME ["/app/data"]

CMD ["whoami"]
```

#### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  whoami:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=sqlite:/app/data/whoami.db
      - JWT_SECRET=${JWT_SECRET:-change-me-in-production}
      - SERVER_HOST=0.0.0.0
      - SERVER_PORT=8080
      - RUST_LOG=info
    volumes:
      - whoami_data:/app/data
      - ./config:/app/config:ro  # Optional config directory
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # Optional: Reverse proxy
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/ssl:ro
    depends_on:
      - whoami
    restart: unless-stopped

volumes:
  whoami_data:
```

#### Build and Run

```bash
# Build image
docker build -t whoami:latest .

# Run with docker-compose
docker-compose up -d

# View logs
docker-compose logs -f whoami

# Stop services
docker-compose down
```

---

## Production Deployment

### Environment Configuration

#### Production Environment Variables

```bash
# .env.production
DATABASE_URL=sqlite:/data/whoami.db
JWT_SECRET=your-super-secure-random-jwt-secret-minimum-32-characters
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
RUST_LOG=info

# SSL/TLS Configuration
ENABLE_HTTPS=true
CERT_FILE=/certs/fullchain.pem
KEY_FILE=/certs/privkey.pem

# Security Configuration
ALLOWED_ORIGINS=https://yourdomain.com,https://api.yourdomain.com
MAX_REQUEST_SIZE=1048576  # 1MB
REQUEST_TIMEOUT=30

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60

# Database Configuration
DB_POOL_SIZE=10
DB_TIMEOUT=30

# Monitoring
ENABLE_METRICS=true
METRICS_PORT=9090
```

#### Systemd Service

```ini
# /etc/systemd/system/whoami.service
[Unit]
Description=WHOAMI IAM Service
After=network.target

[Service]
Type=simple
User=whoami
Group=whoami
WorkingDirectory=/opt/whoami
ExecStart=/opt/whoami/bin/whoami
Restart=always
RestartSec=5
Environment=RUST_LOG=info
EnvironmentFile=/opt/whoami/.env

# Security settings
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/whoami/data
PrivateTmp=yes

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

#### Installation Script

```bash
#!/bin/bash
# install.sh

set -euo pipefail

INSTALL_DIR="/opt/whoami"
SERVICE_USER="whoami"
SERVICE_GROUP="whoami"

# Create service user
sudo useradd -r -s /bin/false -d $INSTALL_DIR $SERVICE_USER

# Create directories
sudo mkdir -p $INSTALL_DIR/{bin,data,logs,config}

# Copy binary and set permissions
sudo cp target/release/whoami $INSTALL_DIR/bin/
sudo chown -R $SERVICE_USER:$SERVICE_GROUP $INSTALL_DIR
sudo chmod +x $INSTALL_DIR/bin/whoami

# Create environment file
sudo tee $INSTALL_DIR/.env > /dev/null << EOF
DATABASE_URL=sqlite:$INSTALL_DIR/data/whoami.db
JWT_SECRET=$(openssl rand -hex 32)
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
RUST_LOG=info
EOF

sudo chown $SERVICE_USER:$SERVICE_GROUP $INSTALL_DIR/.env
sudo chmod 600 $INSTALL_DIR/.env

# Install systemd service
sudo cp whoami.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable whoami
sudo systemctl start whoami

echo "WHOAMI IAM service installed and started"
echo "Check status with: sudo systemctl status whoami"
```

---

## Kubernetes Deployment

### Kubernetes Manifests

#### ConfigMap

```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: whoami-config
  namespace: default
data:
  RUST_LOG: "info"
  SERVER_HOST: "0.0.0.0"
  SERVER_PORT: "8080"
  RATE_LIMIT_REQUESTS: "100"
  RATE_LIMIT_WINDOW: "60"
```

#### Secret

```yaml
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: whoami-secret
  namespace: default
type: Opaque
data:
  # Base64 encoded values
  jwt-secret: <base64-encoded-jwt-secret>
  database-url: <base64-encoded-database-url>
```

#### Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: whoami-deployment
  namespace: default
  labels:
    app: whoami
spec:
  replicas: 3
  selector:
    matchLabels:
      app: whoami
  template:
    metadata:
      labels:
        app: whoami
    spec:
      containers:
      - name: whoami
        image: whoami:latest
        imagePullPolicy: Always
        ports:
        - containerPort: 8080
          name: http
        envFrom:
        - configMapRef:
            name: whoami-config
        env:
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: whoami-secret
              key: jwt-secret
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: whoami-secret
              key: database-url
        livenessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        volumeMounts:
        - name: data-volume
          mountPath: /app/data
      volumes:
      - name: data-volume
        persistentVolumeClaim:
          claimName: whoami-pvc
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: whoami-pvc
  namespace: default
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

#### Service

```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: whoami-service
  namespace: default
  labels:
    app: whoami
spec:
  selector:
    app: whoami
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
    name: http
  type: ClusterIP
```

#### Ingress

```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: whoami-ingress
  namespace: default
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - api.yourdomain.com
    secretName: whoami-tls
  rules:
  - host: api.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: whoami-service
            port:
              number: 80
```

#### Deploy to Kubernetes

```bash
# Apply all manifests
kubectl apply -f k8s/

# Check deployment status
kubectl get deployments
kubectl get pods
kubectl get services

# View logs
kubectl logs -f deployment/whoami-deployment

# Port forward for testing
kubectl port-forward service/whoami-service 8080:80
```

---

## Cloud Deployment

### AWS ECS

#### Task Definition

```json
{
  "family": "whoami-task",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "whoami",
      "image": "YOUR_ECR_URI/whoami:latest",
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "RUST_LOG",
          "value": "info"
        },
        {
          "name": "SERVER_HOST",
          "value": "0.0.0.0"
        }
      ],
      "secrets": [
        {
          "name": "JWT_SECRET",
          "valueFrom": "arn:aws:ssm:REGION:ACCOUNT:parameter/whoami/jwt-secret"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/whoami",
          "awslogs-region": "us-west-2",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": [
          "CMD-SHELL",
          "curl -f http://localhost:8080/health || exit 1"
        ],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ]
}
```

### Google Cloud Run

#### Dockerfile for Cloud Run

```dockerfile
FROM rust:1.75-slim as builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libsqlite3-dev

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/whoami /usr/local/bin/whoami

# Cloud Run requires PORT environment variable
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=${PORT:-8080}
ENV RUST_LOG=info

EXPOSE ${PORT:-8080}

CMD ["whoami"]
```

#### Deploy to Cloud Run

```bash
# Build and push image
gcloud builds submit --tag gcr.io/PROJECT_ID/whoami

# Deploy to Cloud Run
gcloud run deploy whoami \
  --image gcr.io/PROJECT_ID/whoami \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars RUST_LOG=info \
  --set-secrets JWT_SECRET=jwt-secret:latest \
  --memory 512Mi \
  --cpu 1 \
  --max-instances 10
```

---

## Reverse Proxy Configuration

### Nginx Configuration

```nginx
# /etc/nginx/sites-available/whoami
upstream whoami_backend {
    server 127.0.0.1:8080;
    # Add more servers for load balancing
    # server 127.0.0.1:8081;
    # server 127.0.0.1:8082;
}

# Rate limiting
limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;

server {
    listen 80;
    server_name api.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    # SSL configuration
    ssl_certificate /etc/ssl/certs/fullchain.pem;
    ssl_certificate_key /etc/ssl/private/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Rate limiting
    location /api/v1/auth/ {
        limit_req zone=auth burst=10 nodelay;
        proxy_pass http://whoami_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api/v1/ {
        limit_req zone=api burst=50 nodelay;
        proxy_pass http://whoami_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Health check
    location /health {
        proxy_pass http://whoami_backend;
        access_log off;
    }

    # API documentation
    location /docs {
        proxy_pass http://whoami_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Traefik Configuration (Docker)

```yaml
# docker-compose.traefik.yml
version: '3.8'

services:
  traefik:
    image: traefik:v3.0
    command:
      - --api.dashboard=true
      - --providers.docker=true
      - --providers.docker.exposedbydefault=false
      - --entrypoints.web.address=:80
      - --entrypoints.websecure.address=:443
      - --certificatesresolvers.letsencrypt.acme.tlschallenge=true
      - --certificatesresolvers.letsencrypt.acme.email=admin@yourdomain.com
      - --certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"  # Dashboard
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./letsencrypt:/letsencrypt
    restart: unless-stopped

  whoami:
    build: .
    labels:
      - traefik.enable=true
      - traefik.http.routers.whoami.rule=Host(`api.yourdomain.com`)
      - traefik.http.routers.whoami.entrypoints=websecure
      - traefik.http.routers.whoami.tls.certresolver=letsencrypt
      - traefik.http.services.whoami.loadbalancer.server.port=8080
      # Rate limiting
      - traefik.http.middlewares.auth-ratelimit.ratelimit.average=5
      - traefik.http.middlewares.auth-ratelimit.ratelimit.period=1m
      - traefik.http.middlewares.api-ratelimit.ratelimit.average=100
      - traefik.http.middlewares.api-ratelimit.ratelimit.period=1m
    environment:
      - DATABASE_URL=sqlite:/app/data/whoami.db
      - JWT_SECRET=${JWT_SECRET}
    volumes:
      - whoami_data:/app/data

volumes:
  whoami_data:
```

---

## Database Setup

### SQLite Production Configuration

```bash
#!/bin/bash
# setup-database.sh

DB_PATH="/opt/whoami/data/whoami.db"
DB_DIR="/opt/whoami/data"

# Create database directory
mkdir -p $DB_DIR
chown whoami:whoami $DB_DIR
chmod 750 $DB_DIR

# Initialize database
sqlite3 $DB_PATH << EOF
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=10000;
PRAGMA temp_store=memory;
PRAGMA mmap_size=268435456;

-- Verify settings
PRAGMA journal_mode;
PRAGMA synchronous;
EOF

# Set permissions
chown whoami:whoami $DB_PATH
chmod 640 $DB_PATH

echo "Database setup complete"
```

### Database Backup Script

```bash
#!/bin/bash
# backup-database.sh

DB_PATH="/opt/whoami/data/whoami.db"
BACKUP_DIR="/opt/whoami/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/whoami_backup_$DATE.db"

# Create backup directory
mkdir -p $BACKUP_DIR

# Create backup
sqlite3 $DB_PATH ".backup $BACKUP_FILE"

# Compress backup
gzip $BACKUP_FILE

# Keep only last 30 backups
find $BACKUP_DIR -name "whoami_backup_*.db.gz" -type f -mtime +30 -delete

echo "Backup created: $BACKUP_FILE.gz"
```

---

## Monitoring and Observability

### Prometheus Metrics

Add to `Cargo.toml`:
```toml
[dependencies]
prometheus = "0.13"
actix-web-prometheus = "0.1"
```

```rust
// src/monitoring.rs
use prometheus::{Counter, Histogram, Registry, Encoder, TextEncoder};
use actix_web::{web, HttpResponse, Result};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref HTTP_REQUESTS_TOTAL: Counter = Counter::new(
        "http_requests_total", "Total number of HTTP requests"
    ).expect("metric can be created");
    
    pub static ref HTTP_REQUEST_DURATION: Histogram = Histogram::new(
        "http_request_duration_seconds", "HTTP request duration in seconds"
    ).expect("metric can be created");
}

pub fn init_metrics() {
    REGISTRY.register(Box::new(HTTP_REQUESTS_TOTAL.clone()))
        .expect("collector can be registered");
    REGISTRY.register(Box::new(HTTP_REQUEST_DURATION.clone()))
        .expect("collector can be registered");
}

pub async fn metrics() -> Result<HttpResponse> {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    Ok(HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4; charset=utf-8")
        .body(buffer))
}
```

### Health Check Endpoint

```rust
// src/routes/health.rs
use actix_web::{web, HttpResponse, Result};
use sqlx::SqlitePool;
use serde_json::json;

pub async fn health_check(pool: web::Data<SqlitePool>) -> Result<HttpResponse> {
    // Check database connectivity
    let db_status = match sqlx::query("SELECT 1").fetch_one(pool.as_ref()).await {
        Ok(_) => "healthy",
        Err(_) => "unhealthy",
    };
    
    let response = json!({
        "status": if db_status == "healthy" { "healthy" } else { "unhealthy" },
        "timestamp": chrono::Utc::now(),
        "version": env!("CARGO_PKG_VERSION"),
        "database": db_status,
    });
    
    if db_status == "healthy" {
        Ok(HttpResponse::Ok().json(response))
    } else {
        Ok(HttpResponse::ServiceUnavailable().json(response))
    }
}
```

### Logging Configuration

```rust
// src/logging.rs
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub fn init_logging() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info".into());
    
    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().json())
        .init();
}
```

---

## Performance Tuning

### Database Optimization

```sql
-- SQLite performance settings
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = 10000;
PRAGMA temp_store = memory;
PRAGMA mmap_size = 268435456;

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_role_policies_role_id ON role_policies(role_id);
CREATE INDEX IF NOT EXISTS idx_role_policies_policy_id ON role_policies(policy_id);
```

### Connection Pool Tuning

```rust
use sqlx::sqlite::{SqlitePool, SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous};
use std::time::Duration;

pub async fn create_optimized_pool(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::from_str(database_url)?
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(30))
        .pragma("cache_size", "-64000")  // 64MB cache
        .pragma("temp_store", "memory")
        .pragma("mmap_size", "268435456"); // 256MB mmap
    
    SqlitePool::connect_with(options).await
}
```

---

## Scaling Considerations

### Horizontal Scaling

1. **Stateless Design**: The application is already stateless with JWT tokens
2. **Load Balancing**: Use nginx, HAProxy, or cloud load balancers
3. **Database**: Consider moving to PostgreSQL for better concurrent access
4. **Caching**: Add Redis for session/token caching

### Vertical Scaling

- **Memory**: Start with 512MB, scale based on usage
- **CPU**: Single core sufficient for low traffic, scale based on load
- **Storage**: SQLite file grows slowly, monitor disk space

---

## Troubleshooting

### Common Deployment Issues

#### Port Binding Issues
```bash
# Check if port is already in use
netstat -tlnp | grep :8080
lsof -i :8080

# Use different port
SERVER_PORT=8081 cargo run
```

#### Database Permissions
```bash
# Fix database file permissions
chown whoami:whoami /path/to/whoami.db
chmod 640 /path/to/whoami.db

# Fix directory permissions
chown whoami:whoami /path/to/data/
chmod 750 /path/to/data/
```

#### SSL Certificate Issues
```bash
# Test certificate
openssl x509 -in /path/to/cert.pem -text -noout

# Test private key
openssl rsa -in /path/to/key.pem -check

# Test certificate and key match
openssl x509 -noout -modulus -in cert.pem | openssl md5
openssl rsa -noout -modulus -in key.pem | openssl md5
```

---

This deployment guide covers various scenarios from development to production. Choose the deployment method that best fits your infrastructure and requirements. Remember to properly secure your deployment by following the security guidelines and using HTTPS in production environments. 