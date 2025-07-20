# WHOAMI - Educational IAM Service

A simple Identity and Access Management (IAM) service built in Rust, inspired by AWS IAM. This project demonstrates how to build a basic authentication and authorization system from scratch.

## Quick Start

1. **Create environment file:**
   ```bash
   echo "DATABASE_URL=sqlite:./whoami.db
   JWT_SECRET=your-super-secret-jwt-key-change-in-production
   SERVER_HOST=127.0.0.1
   SERVER_PORT=8080
   RUST_LOG=info" > .env
   ```

2. **Run the application:**
   ```bash
   cargo run
   ```

3. **Access the API:**
   - Base URL: http://localhost:8080/api/v1
   - Swagger Docs: http://localhost:8080/docs

## Testing the Authentication

```bash
# Register a new user
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "email": "admin@example.com", "password": "password123"}'

# Login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password123"}'

# Get current user (use token from login response)
curl -X GET http://localhost:8080/api/v1/auth/me \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Project Structure

The application follows a clean architecture with the following layers:
- **Core**: Configuration, database, and error handling
- **Models**: Data structures and database entities
- **Repository**: Database access layer
- **Services**: Business logic layer
- **Schemas**: API request/response structures
- **Routes**: HTTP endpoint handlers

## Features Implemented

✅ **Authentication System**
- User registration and login
- JWT token-based authentication
- Password hashing with bcrypt
- Token refresh capability

✅ **Core IAM Models**
- Users with roles and policies
- Roles as collections of permissions
- Policies as JSON documents (AWS IAM-style)
- Many-to-many relationships

✅ **Database Layer**
- SQLite with automatic table creation
- Repository pattern for data access
- Proper error handling

✅ **API Documentation**
- OpenAPI/Swagger integration
- Interactive API documentation

## Coming Soon

🚧 User, Role, and Policy management endpoints are stubbed but not yet fully implemented.

See `docs/README.md` for detailed documentation.