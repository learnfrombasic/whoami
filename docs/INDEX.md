# WHOAMI - Documentation Index

Welcome to the comprehensive documentation for WHOAMI, an educational IAM (Identity and Access Management) service built in Rust. This documentation covers everything from basic usage to advanced deployment scenarios.

## 📚 Documentation Overview

### Quick Start
- **[README.md](../README.md)** - Project overview and quick start guide
- **[Getting Started](#getting-started)** - Basic setup and first steps

### Core Documentation
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture and design principles
- **[API_REFERENCE.md](API_REFERENCE.md)** - Complete API documentation with examples
- **[DEVELOPMENT.md](DEVELOPMENT.md)** - Development guide and best practices
- **[SECURITY.md](SECURITY.md)** - Security considerations and implementation details

### Deployment & Operations
- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Deployment guides for various environments
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Common issues and solutions

### Learning Resources
- **[EXAMPLES.md](EXAMPLES.md)** - Practical examples and tutorials
- **[API Examples](#api-examples)** - SDK examples in multiple languages

---

## 🚀 Getting Started

### Prerequisites
- Rust 1.70 or later
- SQLite 3.35 or later
- Git

### Quick Setup

```bash
# Clone the repository
git clone <repository-url>
cd whoami

# Create environment file
cat > .env << EOF
DATABASE_URL=sqlite:./whoami.db
JWT_SECRET=your-super-secure-secret-key
SERVER_HOST=127.0.0.1
SERVER_PORT=8080
RUST_LOG=info
EOF

# Build and run
cargo run
```

### First Steps

1. **Start the service** - Follow the setup above
2. **Register an admin user** - Use the registration API
3. **Create policies and roles** - Set up your permission system
4. **Assign roles to users** - Implement access control
5. **Test the system** - Verify everything works

---

## 🏗️ Architecture Overview

WHOAMI follows a clean, layered architecture:

```
┌─────────────────┐
│     Routes      │  ← HTTP API endpoints
├─────────────────┤
│    Services     │  ← Business logic
├─────────────────┤
│  Repository     │  ← Data access
├─────────────────┤
│    Models       │  ← Domain entities
├─────────────────┤
│     Core        │  ← Infrastructure
└─────────────────┘
```

**Key Components:**
- **Authentication**: JWT-based stateless authentication
- **Authorization**: Policy-based access control (AWS IAM-style)
- **Database**: SQLite with connection pooling
- **API**: RESTful API with OpenAPI documentation

For detailed architecture information, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## 🔐 Security Model

WHOAMI implements a comprehensive security model:

### Authentication
- **Password Security**: bcrypt hashing with configurable cost
- **JWT Tokens**: Stateless authentication with configurable expiration
- **Token Validation**: Comprehensive validation with proper error handling

### Authorization
- **Policy-Based Access Control (PBAC)**: Similar to AWS IAM
- **Users, Roles, and Policies**: Flexible permission system
- **Policy Evaluation**: Explicit deny takes precedence over allow

### Security Features
- Input validation and sanitization
- SQL injection prevention
- XSS protection
- CORS configuration
- Security headers
- Audit logging

For comprehensive security details, see [SECURITY.md](SECURITY.md).

---

## 🛠️ API Reference

### Base URL
```
http://localhost:8080/api/v1
```

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Register new user |
| POST | `/auth/login` | Login and get JWT token |
| GET | `/auth/me` | Get current user info |
| POST | `/auth/refresh` | Refresh JWT token |

### Management Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/users` | List all users |
| POST | `/users` | Create new user |
| GET | `/users/{id}` | Get user details |
| PUT | `/users/{id}` | Update user |
| DELETE | `/users/{id}` | Delete user |
| GET | `/roles` | List all roles |
| POST | `/roles` | Create new role |
| GET | `/policies` | List all policies |
| POST | `/policies` | Create new policy |

For complete API documentation with examples, see [API_REFERENCE.md](API_REFERENCE.md).

---

## 💡 Examples and Tutorials

### Basic Authentication Flow

```bash
# 1. Register a user
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@company.com","password":"SecurePass123!"}'

# 2. Login to get token
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SecurePass123!"}'

# 3. Use token for authenticated requests
curl -X GET http://localhost:8080/api/v1/auth/me \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Policy Management

```bash
# Create an admin policy
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "AdminFullAccess",
    "description": "Full administrative access",
    "document": {
      "version": "2012-10-17",
      "statement": [{
        "effect": "Allow",
        "action": ["*"],
        "resource": ["*"]
      }]
    }
  }'
```

For complete examples and tutorials, see [EXAMPLES.md](EXAMPLES.md).

---

## 🚀 Deployment Options

### Local Development
```bash
cargo run
```

### Docker
```bash
docker-compose up -d
```

### Production (Systemd)
```bash
# Install as system service
sudo cp whoami.service /etc/systemd/system/
sudo systemctl enable whoami
sudo systemctl start whoami
```

### Kubernetes
```bash
kubectl apply -f k8s/
```

### Cloud Platforms
- AWS ECS
- Google Cloud Run
- Azure Container Instances

For detailed deployment guides, see [DEPLOYMENT.md](DEPLOYMENT.md).

---

## 🔧 Development Guide

### Project Structure
```
src/
├── main.rs              # Application entry point
├── core/                # Core infrastructure
│   ├── config.rs        # Configuration
│   ├── database.rs      # Database setup
│   └── errors.rs        # Error types
├── models/              # Domain models
├── repository/          # Data access layer
├── services/            # Business logic
├── schemas/             # API schemas
└── routes/              # HTTP handlers
```

### Adding New Features
1. **Models**: Define data structures in `src/models/`
2. **Repository**: Implement data access in `src/repository/`
3. **Services**: Add business logic in `src/services/`
4. **Schemas**: Define API contracts in `src/schemas/`
5. **Routes**: Implement HTTP handlers in `src/routes/`

### Testing
```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Integration tests
./scripts/integration-test.sh
```

For comprehensive development information, see [DEVELOPMENT.md](DEVELOPMENT.md).

---

## 📊 Monitoring and Observability

### Health Checks
```bash
curl http://localhost:8080/health
```

### Metrics (if enabled)
```bash
curl http://localhost:9090/metrics
```

### Logging
```bash
# Set log level
RUST_LOG=debug cargo run

# View logs (systemd)
journalctl -u whoami -f
```

---

## 🐛 Troubleshooting

### Common Issues

#### Port Already in Use
```bash
lsof -i :8080
kill -9 <PID>
```

#### Database Locked
```bash
lsof whoami.db
kill -9 <PID>
```

#### JWT Token Issues
```bash
# Decode JWT to check expiration
echo "$TOKEN" | cut -d '.' -f 2 | base64 -d | jq
```

For comprehensive troubleshooting, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

---

## 🌟 Key Features

### ✅ Implemented
- [x] User registration and authentication
- [x] JWT token-based authentication
- [x] Password hashing with bcrypt
- [x] Policy-based access control
- [x] Role-based access control (RBAC)
- [x] RESTful API with OpenAPI documentation
- [x] SQLite database with automatic setup
- [x] Docker support
- [x] Comprehensive error handling
- [x] Security headers and CORS
- [x] Health check endpoints

### 🚧 Planned Enhancements
- [ ] Multi-factor authentication (MFA)
- [ ] OAuth2/OIDC integration
- [ ] PostgreSQL support
- [ ] Redis caching
- [ ] Rate limiting
- [ ] Audit logging
- [ ] Policy simulation
- [ ] Webhook notifications
- [ ] API versioning

---

## 🎓 Learning Resources

### Understanding IAM Concepts
1. **Users**: Identity entities that can authenticate
2. **Roles**: Collections of permissions
3. **Policies**: JSON documents defining permissions
4. **Policy Evaluation**: AWS IAM-style evaluation logic

### Best Practices
- **Principle of Least Privilege**: Grant minimum necessary permissions
- **Explicit Deny**: Deny statements take precedence
- **Regular Audits**: Review and update permissions regularly
- **Secure Defaults**: Default to deny unless explicitly allowed

### Related Technologies
- **JWT (JSON Web Tokens)**: Token-based authentication
- **bcrypt**: Password hashing algorithm
- **SQLite**: Lightweight SQL database
- **Actix-Web**: High-performance Rust web framework
- **OpenAPI**: API documentation standard

---

## 📝 Contributing

### Code Standards
- Follow Rust conventions and idioms
- Write comprehensive tests
- Document all public APIs
- Follow the established architecture

### Development Workflow
1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Update documentation
5. Submit a pull request

### Reporting Issues
When reporting issues, please include:
- System information
- Service configuration
- Relevant log messages
- Steps to reproduce

---

## ⚠️ Important Notes

### Educational Purpose
**WHOAMI is designed for educational purposes.** While it implements security best practices, it should undergo thorough security review and testing before production use.

### Security Considerations
- Change default JWT secrets in production
- Use HTTPS in production environments
- Implement rate limiting for production
- Regular security updates and audits
- Proper backup and disaster recovery

### Performance Considerations
- SQLite is suitable for small to medium loads
- For high concurrency, consider PostgreSQL
- Implement caching for better performance
- Monitor resource usage and scale accordingly

---

## 📞 Support and Community

### Getting Help
1. Check the [Troubleshooting Guide](TROUBLESHOOTING.md)
2. Review the [FAQ section](TROUBLESHOOTING.md#frequently-asked-questions-faq)
3. Search existing issues
4. Create a new issue with detailed information

### Documentation Feedback
If you find issues with the documentation or have suggestions for improvement, please create an issue or submit a pull request.

---

**Happy coding! 🚀**

*This documentation is continuously updated. For the latest information, check the repository.* 