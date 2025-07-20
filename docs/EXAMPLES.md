# WHOAMI - Examples and Tutorials

## Overview

This document provides comprehensive examples and tutorials for using the WHOAMI IAM service. It covers everything from basic authentication to advanced policy management scenarios.

---

## Basic Authentication Tutorial

### Step 1: Starting the Service

```bash
# Start the service
cargo run

# Or with Docker
docker-compose up -d
```

### Step 2: Register Your First User

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@company.com",
    "password": "SecurePassword123!"
  }'
```

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "admin",
  "email": "admin@company.com",
  "is_active": true,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

### Step 3: Login and Get Token

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "SecurePassword123!"
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "admin",
    "email": "admin@company.com",
    "is_active": true
  }
}
```

### Step 4: Use the Token for Authenticated Requests

```bash
# Store the token
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Get current user info
curl -X GET http://localhost:8080/api/v1/auth/me \
  -H "Authorization: Bearer $TOKEN"
```

---

## Policy Management Tutorial

### Creating Basic Policies

#### 1. Admin Policy (Full Access)

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "AdminFullAccess",
    "description": "Full administrative access to all resources",
    "document": {
      "version": "2012-10-17",
      "statement": [
        {
          "effect": "Allow",
          "action": ["*"],
          "resource": ["*"]
        }
      ]
    }
  }'
```

#### 2. Read-Only Policy

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ReadOnlyAccess",
    "description": "Read-only access to all resources",
    "document": {
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
  }'
```

#### 3. User Self-Management Policy

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "UserSelfManagement",
    "description": "Allow users to manage their own profile",
    "document": {
      "version": "2012-10-17",
      "statement": [
        {
          "effect": "Allow",
          "action": [
            "user:GetUser",
            "user:UpdateUser"
          ],
          "resource": ["user:self"]
        }
      ]
    }
  }'
```

### Creating Roles

#### 1. Admin Role

```bash
curl -X POST http://localhost:8080/api/v1/roles \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Administrator",
    "description": "System administrator with full access"
  }'
```

#### 2. Developer Role

```bash
curl -X POST http://localhost:8080/api/v1/roles \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Developer",
    "description": "Development team member with limited access"
  }'
```

#### 3. Viewer Role

```bash
curl -X POST http://localhost:8080/api/v1/roles \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Viewer",
    "description": "Read-only access for viewing resources"
  }'
```

---

## Real-World Scenarios

### Scenario 1: Company IAM Setup

Let's set up an IAM system for a software company with different teams and access levels.

#### 1. Create Policies for Different Access Levels

```bash
# Development Environment Access
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "DevelopmentAccess",
    "description": "Access to development environment resources",
    "document": {
      "version": "2012-10-17",
      "statement": [
        {
          "effect": "Allow",
          "action": [
            "dev:*",
            "user:GetUser",
            "user:UpdateUser"
          ],
          "resource": [
            "dev:*",
            "user:self"
          ]
        },
        {
          "effect": "Deny",
          "action": [
            "prod:*",
            "user:DeleteUser"
          ],
          "resource": ["*"]
        }
      ]
    }
  }'

# Production Read Access
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ProductionReadAccess",
    "description": "Read-only access to production resources",
    "document": {
      "version": "2012-10-17",
      "statement": [
        {
          "effect": "Allow",
          "action": [
            "prod:GetLogs",
            "prod:GetMetrics",
            "prod:ListServices"
          ],
          "resource": ["prod:*"]
        }
      ]
    }
  }'

# HR Access Policy
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "HRAccess",
    "description": "HR department access to user management",
    "document": {
      "version": "2012-10-17",
      "statement": [
        {
          "effect": "Allow",
          "action": [
            "user:*",
            "role:GetRole",
            "role:ListRoles"
          ],
          "resource": ["*"]
        },
        {
          "effect": "Deny",
          "action": [
            "user:DeleteUser"
          ],
          "resource": ["*"]
        }
      ]
    }
  }'
```

#### 2. Create Roles for Each Team

```bash
# Software Engineer Role
curl -X POST http://localhost:8080/api/v1/roles \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SoftwareEngineer",
    "description": "Software engineer with development access"
  }'

# Senior Engineer Role
curl -X POST http://localhost:8080/api/v1/roles \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SeniorEngineer",
    "description": "Senior engineer with additional production read access"
  }'

# HR Manager Role
curl -X POST http://localhost:8080/api/v1/roles \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "HRManager",
    "description": "HR manager with user management capabilities"
  }'
```

#### 3. Attach Policies to Roles

```bash
# Attach DevelopmentAccess to SoftwareEngineer role
curl -X POST http://localhost:8080/api/v1/roles/SOFTWARE_ENGINEER_ROLE_ID/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "DEVELOPMENT_POLICY_ID"
  }'

# Attach both Development and Production read access to SeniorEngineer
curl -X POST http://localhost:8080/api/v1/roles/SENIOR_ENGINEER_ROLE_ID/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "DEVELOPMENT_POLICY_ID"
  }'

curl -X POST http://localhost:8080/api/v1/roles/SENIOR_ENGINEER_ROLE_ID/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "PRODUCTION_READ_POLICY_ID"
  }'

# Attach HR access to HR Manager role
curl -X POST http://localhost:8080/api/v1/roles/HR_MANAGER_ROLE_ID/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "HR_ACCESS_POLICY_ID"
  }'
```

#### 4. Create Users and Assign Roles

```bash
# Create a software engineer
curl -X POST http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_engineer",
    "email": "john@company.com",
    "password": "TempPassword123!"
  }'

# Assign SoftwareEngineer role to the user
curl -X POST http://localhost:8080/api/v1/users/JOHN_USER_ID/roles \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "role_id": "SOFTWARE_ENGINEER_ROLE_ID"
  }'
```

### Scenario 2: Multi-Tenant Application

Setting up IAM for a SaaS application with multiple tenants.

#### 1. Tenant-Specific Policies

```bash
# Tenant Admin Policy
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "TenantAdminAccess",
    "description": "Full access within tenant boundary",
    "document": {
      "version": "2012-10-17",
      "statement": [
        {
          "effect": "Allow",
          "action": ["*"],
          "resource": ["tenant:{{tenant_id}}:*"]
        },
        {
          "effect": "Deny",
          "action": ["*"],
          "resource": ["tenant:*"]
        }
      ]
    }
  }'

# Tenant User Policy
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "TenantUserAccess",
    "description": "Limited access within tenant boundary",
    "document": {
      "version": "2012-10-17",
      "statement": [
        {
          "effect": "Allow",
          "action": [
            "app:ReadData",
            "app:WriteOwnData",
            "user:GetUser",
            "user:UpdateUser"
          ],
          "resource": [
            "tenant:{{tenant_id}}:data:*",
            "user:self"
          ]
        }
      ]
    }
  }'
```

### Scenario 3: Time-Based Access

Creating policies that grant temporary access.

```bash
# Temporary Admin Access (with condition)
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "TemporaryAdminAccess",
    "description": "Temporary administrative access",
    "document": {
      "version": "2012-10-17",
      "statement": [
        {
          "effect": "Allow",
          "action": ["*"],
          "resource": ["*"],
          "condition": {
            "DateGreaterThan": {
              "aws:CurrentTime": "2024-01-15T00:00:00Z"
            },
            "DateLessThan": {
              "aws:CurrentTime": "2024-01-16T00:00:00Z"
            }
          }
        }
      ]
    }
  }'
```

---

## JavaScript SDK Example

### Basic Usage

```javascript
// whoami-sdk.js
class WhoamiClient {
  constructor(baseUrl, token = null) {
    this.baseUrl = baseUrl;
    this.token = token;
    this.axios = require('axios');
  }

  async login(username, password) {
    try {
      const response = await this.axios.post(`${this.baseUrl}/auth/login`, {
        username,
        password
      });
      this.token = response.data.access_token;
      return response.data;
    } catch (error) {
      throw new Error(`Login failed: ${error.response?.data?.error || error.message}`);
    }
  }

  async register(username, email, password) {
    try {
      const response = await this.axios.post(`${this.baseUrl}/auth/register`, {
        username,
        email,
        password
      });
      return response.data;
    } catch (error) {
      throw new Error(`Registration failed: ${error.response?.data?.error || error.message}`);
    }
  }

  async getCurrentUser() {
    this.ensureToken();
    try {
      const response = await this.axios.get(`${this.baseUrl}/auth/me`, {
        headers: { Authorization: `Bearer ${this.token}` }
      });
      return response.data;
    } catch (error) {
      throw new Error(`Failed to get user: ${error.response?.data?.error || error.message}`);
    }
  }

  async createUser(username, email, password) {
    this.ensureToken();
    try {
      const response = await this.axios.post(`${this.baseUrl}/users`, {
        username,
        email,
        password
      }, {
        headers: { Authorization: `Bearer ${this.token}` }
      });
      return response.data;
    } catch (error) {
      throw new Error(`Failed to create user: ${error.response?.data?.error || error.message}`);
    }
  }

  async listUsers() {
    this.ensureToken();
    try {
      const response = await this.axios.get(`${this.baseUrl}/users`, {
        headers: { Authorization: `Bearer ${this.token}` }
      });
      return response.data;
    } catch (error) {
      throw new Error(`Failed to list users: ${error.response?.data?.error || error.message}`);
    }
  }

  async createRole(name, description) {
    this.ensureToken();
    try {
      const response = await this.axios.post(`${this.baseUrl}/roles`, {
        name,
        description
      }, {
        headers: { Authorization: `Bearer ${this.token}` }
      });
      return response.data;
    } catch (error) {
      throw new Error(`Failed to create role: ${error.response?.data?.error || error.message}`);
    }
  }

  async createPolicy(name, description, document) {
    this.ensureToken();
    try {
      const response = await this.axios.post(`${this.baseUrl}/policies`, {
        name,
        description,
        document
      }, {
        headers: { Authorization: `Bearer ${this.token}` }
      });
      return response.data;
    } catch (error) {
      throw new Error(`Failed to create policy: ${error.response?.data?.error || error.message}`);
    }
  }

  async assignRoleToUser(userId, roleId) {
    this.ensureToken();
    try {
      const response = await this.axios.post(`${this.baseUrl}/users/${userId}/roles`, {
        role_id: roleId
      }, {
        headers: { Authorization: `Bearer ${this.token}` }
      });
      return response.data;
    } catch (error) {
      throw new Error(`Failed to assign role: ${error.response?.data?.error || error.message}`);
    }
  }

  ensureToken() {
    if (!this.token) {
      throw new Error('Not authenticated. Please login first.');
    }
  }
}

module.exports = WhoamiClient;
```

### Usage Example

```javascript
const WhoamiClient = require('./whoami-sdk');

async function example() {
  const client = new WhoamiClient('http://localhost:8080/api/v1');
  
  try {
    // Register admin user
    console.log('Registering admin user...');
    await client.register('admin', 'admin@company.com', 'SecurePassword123!');
    
    // Login
    console.log('Logging in...');
    const loginResult = await client.login('admin', 'SecurePassword123!');
    console.log('Logged in successfully:', loginResult.user);
    
    // Create a read-only policy
    console.log('Creating read-only policy...');
    const policy = await client.createPolicy(
      'ReadOnlyPolicy',
      'Read-only access to all resources',
      {
        version: '2012-10-17',
        statement: [{
          effect: 'Allow',
          action: ['user:GetUser', 'user:ListUsers'],
          resource: ['*']
        }]
      }
    );
    console.log('Policy created:', policy);
    
    // Create a viewer role
    console.log('Creating viewer role...');
    const role = await client.createRole('Viewer', 'Read-only access role');
    console.log('Role created:', role);
    
    // Create a regular user
    console.log('Creating regular user...');
    const user = await client.createUser('john_doe', 'john@company.com', 'Password123!');
    console.log('User created:', user);
    
    // Assign viewer role to the user
    console.log('Assigning role to user...');
    await client.assignRoleToUser(user.id, role.id);
    console.log('Role assigned successfully');
    
  } catch (error) {
    console.error('Error:', error.message);
  }
}

example();
```

---

## Python SDK Example

```python
# whoami_client.py
import requests
from typing import Dict, List, Optional

class WhoamiClient:
    def __init__(self, base_url: str, token: Optional[str] = None):
        self.base_url = base_url
        self.token = token
        self.session = requests.Session()
    
    def login(self, username: str, password: str) -> Dict:
        """Login and store the token"""
        response = self.session.post(f"{self.base_url}/auth/login", json={
            "username": username,
            "password": password
        })
        response.raise_for_status()
        data = response.json()
        self.token = data["access_token"]
        self.session.headers.update({"Authorization": f"Bearer {self.token}"})
        return data
    
    def register(self, username: str, email: str, password: str) -> Dict:
        """Register a new user"""
        response = self.session.post(f"{self.base_url}/auth/register", json={
            "username": username,
            "email": email,
            "password": password
        })
        response.raise_for_status()
        return response.json()
    
    def get_current_user(self) -> Dict:
        """Get current user information"""
        self._ensure_token()
        response = self.session.get(f"{self.base_url}/auth/me")
        response.raise_for_status()
        return response.json()
    
    def create_user(self, username: str, email: str, password: str) -> Dict:
        """Create a new user (admin only)"""
        self._ensure_token()
        response = self.session.post(f"{self.base_url}/users", json={
            "username": username,
            "email": email,
            "password": password
        })
        response.raise_for_status()
        return response.json()
    
    def list_users(self) -> List[Dict]:
        """List all users"""
        self._ensure_token()
        response = self.session.get(f"{self.base_url}/users")
        response.raise_for_status()
        return response.json()
    
    def create_role(self, name: str, description: Optional[str] = None) -> Dict:
        """Create a new role"""
        self._ensure_token()
        response = self.session.post(f"{self.base_url}/roles", json={
            "name": name,
            "description": description
        })
        response.raise_for_status()
        return response.json()
    
    def create_policy(self, name: str, description: str, document: Dict) -> Dict:
        """Create a new policy"""
        self._ensure_token()
        response = self.session.post(f"{self.base_url}/policies", json={
            "name": name,
            "description": description,
            "document": document
        })
        response.raise_for_status()
        return response.json()
    
    def assign_role_to_user(self, user_id: str, role_id: str) -> Dict:
        """Assign a role to a user"""
        self._ensure_token()
        response = self.session.post(f"{self.base_url}/users/{user_id}/roles", json={
            "role_id": role_id
        })
        response.raise_for_status()
        return response.json()
    
    def _ensure_token(self):
        """Ensure we have a valid token"""
        if not self.token:
            raise ValueError("Not authenticated. Please login first.")

# Usage example
def main():
    client = WhoamiClient("http://localhost:8080/api/v1")
    
    try:
        # Setup admin user
        print("Setting up admin user...")
        client.register("admin", "admin@company.com", "SecurePassword123!")
        client.login("admin", "SecurePassword123!")
        
        # Create policies
        print("Creating policies...")
        admin_policy = client.create_policy(
            "AdminFullAccess",
            "Full administrative access",
            {
                "version": "2012-10-17",
                "statement": [{
                    "effect": "Allow",
                    "action": ["*"],
                    "resource": ["*"]
                }]
            }
        )
        
        read_only_policy = client.create_policy(
            "ReadOnlyAccess",
            "Read-only access to resources",
            {
                "version": "2012-10-17",
                "statement": [{
                    "effect": "Allow",
                    "action": [
                        "user:GetUser",
                        "user:ListUsers",
                        "role:GetRole",
                        "role:ListRoles"
                    ],
                    "resource": ["*"]
                }]
            }
        )
        
        # Create roles
        print("Creating roles...")
        admin_role = client.create_role("Administrator", "System administrator")
        viewer_role = client.create_role("Viewer", "Read-only user")
        
        # Create users
        print("Creating users...")
        manager = client.create_user("manager", "manager@company.com", "ManagerPass123!")
        employee = client.create_user("employee", "employee@company.com", "EmployeePass123!")
        
        # Assign roles
        print("Assigning roles...")
        client.assign_role_to_user(manager["id"], admin_role["id"])
        client.assign_role_to_user(employee["id"], viewer_role["id"])
        
        print("Setup completed successfully!")
        
        # List all users to verify
        users = client.list_users()
        print(f"\nCreated {len(users)} users:")
        for user in users:
            print(f"  - {user['username']} ({user['email']})")
            
    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error: {e.response.status_code} - {e.response.text}")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
```

---

## Testing Examples

### Unit Test Examples

```bash
# Create test environment
cat > .env.test << EOF
DATABASE_URL=sqlite::memory:
JWT_SECRET=test-secret-key
SERVER_HOST=127.0.0.1
SERVER_PORT=8081
RUST_LOG=debug
EOF

# Run tests
RUST_ENV=test cargo test
```

### Integration Test Script

```bash
#!/bin/bash
# integration-test.sh

set -e

BASE_URL="http://localhost:8080/api/v1"
ADMIN_TOKEN=""

echo "Starting integration tests..."

# Function to make API requests
api_request() {
    local method=$1
    local endpoint=$2
    local data=$3
    local headers=$4
    
    if [ -n "$headers" ]; then
        curl -s -X "$method" "$BASE_URL$endpoint" \
            -H "Content-Type: application/json" \
            -H "$headers" \
            -d "$data"
    else
        curl -s -X "$method" "$BASE_URL$endpoint" \
            -H "Content-Type: application/json" \
            -d "$data"
    fi
}

# Test 1: Register admin user
echo "Test 1: Registering admin user..."
response=$(api_request POST "/auth/register" '{
  "username": "test_admin",
  "email": "admin@test.com",
  "password": "TestPassword123!"
}')

if echo "$response" | grep -q "test_admin"; then
    echo "✓ Admin user registered successfully"
else
    echo "✗ Failed to register admin user"
    echo "Response: $response"
    exit 1
fi

# Test 2: Login
echo "Test 2: Logging in..."
login_response=$(api_request POST "/auth/login" '{
  "username": "test_admin",
  "password": "TestPassword123!"
}')

ADMIN_TOKEN=$(echo "$login_response" | jq -r '.access_token')

if [ "$ADMIN_TOKEN" != "null" ] && [ -n "$ADMIN_TOKEN" ]; then
    echo "✓ Login successful"
else
    echo "✗ Login failed"
    echo "Response: $login_response"
    exit 1
fi

# Test 3: Get current user
echo "Test 3: Getting current user..."
user_response=$(api_request GET "/auth/me" "" "Authorization: Bearer $ADMIN_TOKEN")

if echo "$user_response" | grep -q "test_admin"; then
    echo "✓ Current user retrieved successfully"
else
    echo "✗ Failed to get current user"
    echo "Response: $user_response"
    exit 1
fi

# Test 4: Create a policy
echo "Test 4: Creating a policy..."
policy_response=$(api_request POST "/policies" '{
  "name": "TestPolicy",
  "description": "Test policy for integration tests",
  "document": {
    "version": "2012-10-17",
    "statement": [{
      "effect": "Allow",
      "action": ["user:GetUser"],
      "resource": ["*"]
    }]
  }
}' "Authorization: Bearer $ADMIN_TOKEN")

if echo "$policy_response" | grep -q "TestPolicy"; then
    echo "✓ Policy created successfully"
else
    echo "✗ Failed to create policy"
    echo "Response: $policy_response"
    exit 1
fi

echo "All integration tests passed! ✓"
```

---

## Performance Testing

### Load Test Script (using Apache Bench)

```bash
#!/bin/bash
# load-test.sh

BASE_URL="http://localhost:8080/api/v1"

# First, get a token
TOKEN=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SecurePassword123!"}' | \
  jq -r '.access_token')

# Test authentication endpoint
echo "Testing authentication endpoint..."
ab -n 1000 -c 10 -T "application/json" \
   -H "Authorization: Bearer $TOKEN" \
   "$BASE_URL/auth/me"

# Test user listing endpoint
echo "Testing user listing endpoint..."
ab -n 500 -c 5 -T "application/json" \
   -H "Authorization: Bearer $TOKEN" \
   "$BASE_URL/users"

echo "Load testing complete!"
```

### Stress Test with Artillery

```yaml
# artillery-config.yml
config:
  target: 'http://localhost:8080/api/v1'
  phases:
    - duration: 60
      arrivalRate: 10
  payload:
    path: "./users.csv"
    fields:
      - "username"
      - "password"

scenarios:
  - name: "Authentication Flow"
    weight: 70
    flow:
      - post:
          url: "/auth/login"
          json:
            username: "{{ username }}"
            password: "{{ password }}"
          capture:
            - json: "$.access_token"
              as: "token"
      - get:
          url: "/auth/me"
          headers:
            Authorization: "Bearer {{ token }}"
  
  - name: "User Management"
    weight: 30
    flow:
      - post:
          url: "/auth/login"
          json:
            username: "admin"
            password: "SecurePassword123!"
          capture:
            - json: "$.access_token"
              as: "admin_token"
      - get:
          url: "/users"
          headers:
            Authorization: "Bearer {{ admin_token }}"
```

```bash
# Run artillery test
npm install -g artillery
artillery run artillery-config.yml
```

---

## Monitoring Examples

### Health Check Script

```bash
#!/bin/bash
# health-check.sh

check_health() {
    local url=$1
    local response=$(curl -s -w "%{http_code}" "$url/health")
    local http_code="${response: -3}"
    local body="${response%???}"
    
    if [ "$http_code" -eq 200 ]; then
        echo "✓ Service is healthy"
        echo "Response: $body"
        return 0
    else
        echo "✗ Service is unhealthy (HTTP $http_code)"
        echo "Response: $body"
        return 1
    fi
}

# Check main service
check_health "http://localhost:8080"

# Check if running in Docker
if docker ps | grep -q whoami; then
    echo "Service is running in Docker"
fi

# Check database file
if [ -f "./whoami.db" ]; then
    echo "Database file exists ($(du -h whoami.db | cut -f1))"
else
    echo "Database file not found"
fi
```

### Metrics Collection Script

```bash
#!/bin/bash
# collect-metrics.sh

METRICS_URL="http://localhost:9090/metrics"
OUTPUT_FILE="metrics_$(date +%Y%m%d_%H%M%S).txt"

echo "Collecting metrics at $(date)"
echo "================================"

# Collect Prometheus metrics if available
if curl -s "$METRICS_URL" > /dev/null 2>&1; then
    echo "Collecting Prometheus metrics..."
    curl -s "$METRICS_URL" > "$OUTPUT_FILE"
    echo "Metrics saved to $OUTPUT_FILE"
else
    echo "Prometheus metrics not available"
fi

# Basic system metrics
echo "System metrics:"
echo "CPU usage: $(top -l 1 | grep "CPU usage" | head -1)"
echo "Memory usage: $(free -h | grep Mem)"
echo "Disk usage: $(df -h | grep -E '^/dev/')"

# Service-specific metrics
if pgrep -f whoami > /dev/null; then
    PID=$(pgrep -f whoami)
    echo "Service PID: $PID"
    echo "Memory usage: $(ps -p $PID -o rss= | tail -1) KB"
    echo "CPU usage: $(ps -p $PID -o %cpu= | tail -1)%"
else
    echo "WHOAMI service not running"
fi
```

---

This comprehensive examples documentation provides practical guidance for using the WHOAMI IAM service in various scenarios, from basic authentication to complex enterprise setups. The examples cover multiple programming languages and deployment scenarios to help users get started quickly and understand the system's capabilities. 