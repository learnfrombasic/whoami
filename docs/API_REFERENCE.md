# WHOAMI - API Reference

## Base Information

- **Base URL**: `http://localhost:8080/api/v1`
- **Authentication**: Bearer Token (JWT)
- **Content-Type**: `application/json`
- **API Version**: v1

## Authentication

All protected endpoints require a Bearer token in the Authorization header:

```
Authorization: Bearer <jwt_token>
```

## Error Response Format

All error responses follow a consistent format:

```json
{
  "error": "Error description"
}
```

### HTTP Status Codes

| Status | Description |
|--------|-------------|
| 200 | OK - Request successful |
| 201 | Created - Resource created successfully |
| 400 | Bad Request - Invalid request format or parameters |
| 401 | Unauthorized - Authentication required or failed |
| 403 | Forbidden - Access denied |
| 404 | Not Found - Resource not found |
| 409 | Conflict - Resource already exists |
| 422 | Unprocessable Entity - Validation failed |
| 500 | Internal Server Error - Server error |

---

## Authentication Endpoints

### Register User

Register a new user account.

**Endpoint**: `POST /auth/register`

**Request Body**:
```json
{
  "username": "string",
  "email": "string",
  "password": "string"
}
```

**Request Example**:
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "securePassword123"
  }'
```

**Response (201 Created)**:
```json
{
  "id": "uuid-string",
  "username": "john_doe",
  "email": "john@example.com",
  "is_active": true,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

**Validation Rules**:
- `username`: 3-50 characters, alphanumeric and underscore only, unique
- `email`: Valid email format, unique
- `password`: Minimum 8 characters

**Error Examples**:
```json
// Username already exists
{
  "error": "Username already exists"
}

// Invalid email format
{
  "error": "Bad request: Invalid email format"
}
```

---

### Login

Authenticate user and receive JWT token.

**Endpoint**: `POST /auth/login`

**Request Body**:
```json
{
  "username": "string",
  "password": "string"
}
```

**Request Example**:
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "securePassword123"
  }'
```

**Response (200 OK)**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "user": {
    "id": "uuid-string",
    "username": "john_doe",
    "email": "john@example.com",
    "is_active": true
  }
}
```

**Response Fields**:
- `access_token`: JWT token for authentication
- `token_type`: Always "Bearer"
- `expires_in`: Token lifetime in seconds
- `user`: User information object

**Error Examples**:
```json
// Invalid credentials
{
  "error": "Invalid credentials"
}

// Inactive account
{
  "error": "Authentication error: User account is inactive"
}
```

---

### Get Current User

Get information about the currently authenticated user.

**Endpoint**: `GET /auth/me`

**Headers**:
```
Authorization: Bearer <jwt_token>
```

**Request Example**:
```bash
curl -X GET http://localhost:8080/api/v1/auth/me \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Response (200 OK)**:
```json
{
  "id": "uuid-string",
  "username": "john_doe",
  "email": "john@example.com",
  "is_active": true,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

---

### Refresh Token

Generate a new JWT token using the current valid token.

**Endpoint**: `POST /auth/refresh`

**Headers**:
```
Authorization: Bearer <jwt_token>
```

**Request Example**:
```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Response (200 OK)**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

---

## User Management Endpoints

### List Users

Get a list of all users (Admin only).

**Endpoint**: `GET /users`

**Headers**:
```
Authorization: Bearer <jwt_token>
```

**Request Example**:
```bash
curl -X GET http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Response (200 OK)**:
```json
[
  {
    "id": "uuid-string-1",
    "username": "john_doe",
    "email": "john@example.com",
    "is_active": true,
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:30:00Z"
  },
  {
    "id": "uuid-string-2",
    "username": "jane_smith",
    "email": "jane@example.com",
    "is_active": true,
    "created_at": "2024-01-14T15:20:00Z",
    "updated_at": "2024-01-14T15:20:00Z"
  }
]
```

---

### Create User

Create a new user (Admin only).

**Endpoint**: `POST /users`

**Headers**:
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

**Request Body**:
```json
{
  "username": "string",
  "email": "string",
  "password": "string"
}
```

**Request Example**:
```bash
curl -X POST http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice_brown",
    "email": "alice@example.com",
    "password": "password123"
  }'
```

**Response (201 Created)**:
```json
{
  "id": "uuid-string",
  "username": "alice_brown",
  "email": "alice@example.com",
  "is_active": true,
  "created_at": "2024-01-15T11:00:00Z",
  "updated_at": "2024-01-15T11:00:00Z"
}
```

---

### Get User

Get details of a specific user.

**Endpoint**: `GET /users/{user_id}`

**Path Parameters**:
- `user_id`: UUID of the user

**Headers**:
```
Authorization: Bearer <jwt_token>
```

**Request Example**:
```bash
curl -X GET http://localhost:8080/api/v1/users/uuid-string \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Response (200 OK)**:
```json
{
  "id": "uuid-string",
  "username": "john_doe",
  "email": "john@example.com",
  "is_active": true,
  "roles": [
    {
      "id": "role-uuid",
      "name": "developer",
      "description": "Developer role with limited permissions"
    }
  ],
  "policies": [
    {
      "id": "policy-uuid",
      "name": "read-only-access",
      "description": "Read-only access to user resources"
    }
  ]
}
```

---

### Update User

Update user information.

**Endpoint**: `PUT /users/{user_id}`

**Path Parameters**:
- `user_id`: UUID of the user

**Headers**:
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

**Request Body** (all fields optional):
```json
{
  "username": "string",
  "email": "string",
  "is_active": boolean
}
```

**Request Example**:
```bash
curl -X PUT http://localhost:8080/api/v1/users/uuid-string \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe_updated",
    "is_active": false
  }'
```

**Response (200 OK)**:
```json
{
  "id": "uuid-string",
  "username": "john_doe_updated",
  "email": "john@example.com",
  "is_active": false,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T12:00:00Z"
}
```

---

### Delete User

Delete a user account.

**Endpoint**: `DELETE /users/{user_id}`

**Path Parameters**:
- `user_id`: UUID of the user

**Headers**:
```
Authorization: Bearer <jwt_token>
```

**Request Example**:
```bash
curl -X DELETE http://localhost:8080/api/v1/users/uuid-string \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Response (200 OK)**:
```json
{
  "message": "User deleted successfully"
}
```

---

### Assign Role to User

Assign a role to a user.

**Endpoint**: `POST /users/{user_id}/roles`

**Path Parameters**:
- `user_id`: UUID of the user

**Headers**:
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

**Request Body**:
```json
{
  "role_id": "string"
}
```

**Request Example**:
```bash
curl -X POST http://localhost:8080/api/v1/users/uuid-string/roles \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "role_id": "role-uuid-string"
  }'
```

**Response (200 OK)**:
```json
{
  "message": "Role assigned successfully"
}
```

---

### Remove Role from User

Remove a role from a user.

**Endpoint**: `DELETE /users/{user_id}/roles/{role_id}`

**Path Parameters**:
- `user_id`: UUID of the user
- `role_id`: UUID of the role

**Headers**:
```
Authorization: Bearer <jwt_token>
```

**Request Example**:
```bash
curl -X DELETE http://localhost:8080/api/v1/users/uuid-string/roles/role-uuid \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Response (200 OK)**:
```json
{
  "message": "Role removed successfully"
}
```

---

## Role Management Endpoints

### List Roles

Get all roles in the system.

**Endpoint**: `GET /roles`

**Headers**:
```
Authorization: Bearer <jwt_token>
```

**Request Example**:
```bash
curl -X GET http://localhost:8080/api/v1/roles \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Response (200 OK)**:
```json
[
  {
    "id": "role-uuid-1",
    "name": "admin",
    "description": "Administrator role with full permissions",
    "created_at": "2024-01-15T09:00:00Z",
    "updated_at": "2024-01-15T09:00:00Z"
  },
  {
    "id": "role-uuid-2",
    "name": "developer",
    "description": "Developer role with limited permissions",
    "created_at": "2024-01-15T09:15:00Z",
    "updated_at": "2024-01-15T09:15:00Z"
  }
]
```

---

### Create Role

Create a new role.

**Endpoint**: `POST /roles`

**Headers**:
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

**Request Body**:
```json
{
  "name": "string",
  "description": "string" // optional
}
```

**Request Example**:
```bash
curl -X POST http://localhost:8080/api/v1/roles \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "name": "qa_engineer",
    "description": "Quality Assurance Engineer role"
  }'
```

**Response (201 Created)**:
```json
{
  "id": "role-uuid",
  "name": "qa_engineer",
  "description": "Quality Assurance Engineer role",
  "created_at": "2024-01-15T13:00:00Z",
  "updated_at": "2024-01-15T13:00:00Z"
}
```

---

### Get Role

Get details of a specific role including attached policies and users.

**Endpoint**: `GET /roles/{role_id}`

**Path Parameters**:
- `role_id`: UUID of the role

**Headers**:
```
Authorization: Bearer <jwt_token>
```

**Request Example**:
```bash
curl -X GET http://localhost:8080/api/v1/roles/role-uuid \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Response (200 OK)**:
```json
{
  "id": "role-uuid",
  "name": "developer",
  "description": "Developer role with limited permissions",
  "policies": [
    {
      "id": "policy-uuid",
      "name": "dev-access",
      "description": "Development environment access"
    }
  ],
  "users": [
    {
      "id": "user-uuid",
      "username": "john_doe",
      "email": "john@example.com"
    }
  ]
}
```

---

## Policy Management Endpoints

### List Policies

Get all policies in the system.

**Endpoint**: `GET /policies`

**Headers**:
```
Authorization: Bearer <jwt_token>
```

**Request Example**:
```bash
curl -X GET http://localhost:8080/api/v1/policies \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Response (200 OK)**:
```json
[
  {
    "id": "policy-uuid-1",
    "name": "admin-policy",
    "description": "Full administrative access",
    "created_at": "2024-01-15T08:00:00Z",
    "updated_at": "2024-01-15T08:00:00Z"
  },
  {
    "id": "policy-uuid-2",
    "name": "read-only-policy",
    "description": "Read-only access to resources",
    "created_at": "2024-01-15T08:30:00Z",
    "updated_at": "2024-01-15T08:30:00Z"
  }
]
```

---

### Create Policy

Create a new policy with a policy document.

**Endpoint**: `POST /policies`

**Headers**:
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

**Request Body**:
```json
{
  "name": "string",
  "description": "string", // optional
  "document": {
    "version": "2012-10-17",
    "statement": [
      {
        "effect": "Allow" | "Deny",
        "action": ["action1", "action2", "*"],
        "resource": ["resource1", "resource2", "*"],
        "condition": {} // optional
      }
    ]
  }
}
```

**Request Example**:
```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "name": "s3-read-only",
    "description": "Read-only access to S3 buckets",
    "document": {
      "version": "2012-10-17",
      "statement": [
        {
          "effect": "Allow",
          "action": [
            "s3:GetObject",
            "s3:ListBucket"
          ],
          "resource": [
            "s3:::my-bucket/*",
            "s3:::my-bucket"
          ]
        }
      ]
    }
  }'
```

**Response (201 Created)**:
```json
{
  "id": "policy-uuid",
  "name": "s3-read-only",
  "description": "Read-only access to S3 buckets",
  "created_at": "2024-01-15T14:00:00Z",
  "updated_at": "2024-01-15T14:00:00Z"
}
```

---

### Get Policy

Get details of a specific policy including the policy document.

**Endpoint**: `GET /policies/{policy_id}`

**Path Parameters**:
- `policy_id`: UUID of the policy

**Headers**:
```
Authorization: Bearer <jwt_token>
```

**Request Example**:
```bash
curl -X GET http://localhost:8080/api/v1/policies/policy-uuid \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Response (200 OK)**:
```json
{
  "id": "policy-uuid",
  "name": "s3-read-only",
  "description": "Read-only access to S3 buckets",
  "document": {
    "version": "2012-10-17",
    "statement": [
      {
        "effect": "Allow",
        "action": [
          "s3:GetObject",
          "s3:ListBucket"
        ],
        "resource": [
          "s3:::my-bucket/*",
          "s3:::my-bucket"
        ]
      }
    ]
  },
  "attached_roles": [
    {
      "id": "role-uuid",
      "name": "s3-user",
      "description": "S3 user role"
    }
  ],
  "attached_users": [
    {
      "id": "user-uuid",
      "username": "s3_user",
      "email": "s3user@example.com"
    }
  ]
}
```

---

## Policy Document Format

### Structure

Policy documents follow the AWS IAM policy format:

```json
{
  "version": "2012-10-17",
  "statement": [
    {
      "effect": "Allow" | "Deny",
      "action": ["action1", "action2"] | "*",
      "resource": ["resource1", "resource2"] | "*",
      "condition": {
        // Optional condition block
      }
    }
  ]
}
```

### Fields Description

- **version**: Policy language version (always "2012-10-17")
- **statement**: Array of permission statements
  - **effect**: "Allow" or "Deny"
  - **action**: Array of actions or "*" for all actions
  - **resource**: Array of resources or "*" for all resources
  - **condition**: Optional conditions (future enhancement)

### Example Policies

#### Admin Policy (Full Access)
```json
{
  "version": "2012-10-17",
  "statement": [
    {
      "effect": "Allow",
      "action": ["*"],
      "resource": ["*"]
    }
  ]
}
```

#### Read-Only Policy
```json
{
  "version": "2012-10-17",
  "statement": [
    {
      "effect": "Allow",
      "action": [
        "user:GetUser",
        "user:ListUsers",
        "role:GetRole",
        "role:ListRoles",
        "policy:GetPolicy",
        "policy:ListPolicies"
      ],
      "resource": ["*"]
    }
  ]
}
```

#### Deny Policy Example
```json
{
  "version": "2012-10-17",
  "statement": [
    {
      "effect": "Deny",
      "action": [
        "user:DeleteUser",
        "role:DeleteRole"
      ],
      "resource": ["*"]
    }
  ]
}
```

---

## Authentication and Authorization

### JWT Token Structure

JWT tokens contain the following claims:

```json
{
  "sub": "user-uuid",        // Subject (user ID)
  "username": "john_doe",    // Username
  "email": "john@example.com", // Email
  "iat": 1642248000,         // Issued at timestamp
  "exp": 1642334400          // Expiration timestamp
}
```

### Permission Evaluation

The system evaluates permissions using the following algorithm:

1. **Explicit Deny**: If any policy has a "Deny" effect for the action/resource, access is denied
2. **Explicit Allow**: If any policy has an "Allow" effect and no explicit deny exists, access is granted
3. **Default Deny**: If no explicit allow or deny, access is denied by default

### Action Format

Actions follow the format: `service:action`

Examples:
- `user:GetUser`
- `user:CreateUser`
- `user:UpdateUser`
- `user:DeleteUser`
- `role:AttachPolicy`
- `policy:CreatePolicy`

### Resource Format

Resources can be:
- `*` for all resources
- Specific resource identifiers
- Resource patterns with wildcards (future enhancement)

---

## Rate Limiting

Currently not implemented, but planned for future versions:

- Authentication endpoints: 5 requests per minute per IP
- API endpoints: 100 requests per minute per user
- Admin endpoints: 50 requests per minute per admin user

---

## Webhook Support

Not currently implemented, but planned for future versions:

- User creation/deletion events
- Role assignment/removal events
- Policy changes
- Authentication events

---

## SDK Examples

### JavaScript/Node.js

```javascript
const axios = require('axios');

class WhoamiClient {
  constructor(baseUrl, token = null) {
    this.baseUrl = baseUrl;
    this.token = token;
  }

  async login(username, password) {
    const response = await axios.post(`${this.baseUrl}/auth/login`, {
      username,
      password
    });
    this.token = response.data.access_token;
    return response.data;
  }

  async getCurrentUser() {
    const response = await axios.get(`${this.baseUrl}/auth/me`, {
      headers: { Authorization: `Bearer ${this.token}` }
    });
    return response.data;
  }

  async listUsers() {
    const response = await axios.get(`${this.baseUrl}/users`, {
      headers: { Authorization: `Bearer ${this.token}` }
    });
    return response.data;
  }
}

// Usage
const client = new WhoamiClient('http://localhost:8080/api/v1');
await client.login('admin', 'password');
const currentUser = await client.getCurrentUser();
```

### Python

```python
import requests

class WhoamiClient:
    def __init__(self, base_url, token=None):
        self.base_url = base_url
        self.token = token
    
    def login(self, username, password):
        response = requests.post(f"{self.base_url}/auth/login", json={
            "username": username,
            "password": password
        })
        data = response.json()
        self.token = data["access_token"]
        return data
    
    def get_current_user(self):
        response = requests.get(f"{self.base_url}/auth/me", 
                              headers={"Authorization": f"Bearer {self.token}"})
        return response.json()
    
    def list_users(self):
        response = requests.get(f"{self.base_url}/users",
                              headers={"Authorization": f"Bearer {self.token}"})
        return response.json()

# Usage
client = WhoamiClient("http://localhost:8080/api/v1")
client.login("admin", "password")
current_user = client.get_current_user()
```

---

## OpenAPI/Swagger Documentation

Interactive API documentation is available at:
- **Swagger UI**: `http://localhost:8080/docs`
- **OpenAPI JSON**: `http://localhost:8080/api-docs/openapi.json`

The Swagger UI provides:
- Interactive API testing
- Request/response examples
- Schema documentation
- Authentication testing 