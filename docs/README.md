# WHOAMI - Simple IAM Service

A simple IAM (Identity and Access Management) service built in Rust, inspired by AWS IAM. This project is designed for educational purposes to understand how IAM systems work.

## Tech Stack

- **Rust** - Programming language
- **Actix-web** - Web framework
- **SQLite** - Database
- **SQLx** - Database toolkit
- **JWT** - JSON Web Tokens for authentication
- **OpenAPI/Swagger** - API documentation
- **Bcrypt** - Password hashing

## Project Structure

```
whoami/
├── app/
│   ├── core/           # Core functionality (config, database, errors)
│   ├── models/         # Database models (User, Role, Policy)
│   ├── repository/     # Database access layer
│   ├── services/       # Business logic layer
│   ├── schemas/        # API request/response schemas
│   ├── routes/         # HTTP route handlers
│   └── main.rs         # Application entry point
├── docs/              # Documentation
├── Cargo.toml         # Dependencies
└── README.md
```

## Core Concepts

### Users
- Unique identities in the system
- Can have multiple roles and policies
- Authentication through username/password

### Roles
- Collections of permissions
- Can be assigned to users
- Can have multiple policies attached

### Policies
- JSON documents defining permissions
- Support Allow/Deny effects
- Similar to AWS IAM policy structure
- Can be attached to users directly or through roles

### Policy Document Structure

```json
{
  "version": "2012-10-17",
  "statement": [
    {
      "effect": "Allow",
      "action": ["user:GetUser", "user:ListUsers"],
      "resource": ["*"],
      "condition": {}
    }
  ]
}
```

## Getting Started

### Prerequisites
- Rust (1.70+)
- SQLite3

### Environment Setup

Create a `.env` file in the root directory:

```env
DATABASE_URL=sqlite:./whoami.db
JWT_SECRET=your-super-secret-jwt-key-change-in-production
SERVER_HOST=127.0.0.1
SERVER_PORT=8080
RUST_LOG=info
```

### Running the Application

1. **Install dependencies:**
   ```bash
   cargo build
   ```

2. **Run the application:**
   ```bash
   cargo run --bin app
   ```

3. **Access the API:**
   - API Base URL: `http://localhost:8080/api/v1`
   - Swagger Documentation: `http://localhost:8080/docs`

## API Endpoints

### Authentication
- `POST /api/v1/auth/register` - Register a new user
- `POST /api/v1/auth/login` - Login with credentials
- `POST /api/v1/auth/refresh` - Refresh JWT token
- `GET /api/v1/auth/me` - Get current user info

### Users (Coming Soon)
- `GET /api/v1/users` - List all users
- `POST /api/v1/users` - Create a new user
- `GET /api/v1/users/{id}` - Get user details
- `PUT /api/v1/users/{id}` - Update user
- `DELETE /api/v1/users/{id}` - Delete user

### Roles (Coming Soon)
- `GET /api/v1/roles` - List all roles
- `POST /api/v1/roles` - Create a new role
- `GET /api/v1/roles/{id}` - Get role details
- `PUT /api/v1/roles/{id}` - Update role
- `DELETE /api/v1/roles/{id}` - Delete role

### Policies (Coming Soon)
- `GET /api/v1/policies` - List all policies
- `POST /api/v1/policies` - Create a new policy
- `GET /api/v1/policies/{id}` - Get policy details
- `PUT /api/v1/policies/{id}` - Update policy
- `DELETE /api/v1/policies/{id}` - Delete policy

## Example Usage

### 1. Register a User
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@example.com",
    "password": "password123"
  }'
```

### 2. Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "password123"
  }'
```

### 3. Access Protected Endpoint
```bash
curl -X GET http://localhost:8080/api/v1/auth/me \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Database Schema

### Users Table
- `id` - Primary key (UUID)
- `username` - Unique username
- `email` - Unique email address
- `password_hash` - Bcrypt hashed password
- `is_active` - Boolean flag
- `created_at`, `updated_at` - Timestamps

### Roles Table
- `id` - Primary key (UUID)
- `name` - Unique role name
- `description` - Optional description
- `created_at`, `updated_at` - Timestamps

### Policies Table
- `id` - Primary key (UUID)
- `name` - Unique policy name
- `description` - Optional description
- `document` - JSON policy document
- `created_at`, `updated_at` - Timestamps

### Junction Tables
- `user_roles` - Many-to-many relationship between users and roles
- `role_policies` - Many-to-many relationship between roles and policies
- `user_policies` - Many-to-many relationship between users and policies (direct assignment)

## Policy Evaluation

The system implements a simplified version of AWS IAM policy evaluation:

1. **Explicit Deny**: If any policy has a "Deny" effect for the requested action/resource, access is denied
2. **Explicit Allow**: If any policy has an "Allow" effect and no explicit deny exists, access is granted
3. **Default Deny**: If no explicit allow or deny, access is denied by default

## Development

### Adding New Routes

1. Create handler functions in the appropriate route file
2. Add OpenAPI documentation with `#[utoipa::path]`
3. Register routes in the configure function
4. Update the OpenAPI spec in main.rs

### Adding New Models

1. Create the model in `app/models/`
2. Implement repository methods in `app/repository/`
3. Add business logic in `app/services/`
4. Create request/response schemas in `app/schemas/`

## Security Considerations

⚠️ **This is for educational purposes only. Do not use in production without proper security review.**

Current security features:
- Password hashing with bcrypt
- JWT token authentication
- CORS support
- SQL injection protection via SQLx

Missing security features for production:
- Rate limiting
- Input validation and sanitization
- Audit logging
- Token blacklisting
- Password complexity requirements
- Multi-factor authentication

## Contributing

This is an educational project. Feel free to:
- Add missing route implementations
- Improve error handling
- Add more comprehensive tests
- Enhance security features
- Optimize database queries

## License

MIT License - see LICENSE file for details. 