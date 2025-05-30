# Banking Auth Service

A secure JWT-based authentication and authorization microservice built with Go. This service provides centralized authentication for the Banking Microservices System, implementing role-based access control (RBAC) and cross-service token validation.

![Go](https://img.shields.io/badge/Go-1.24-blue.svg)
![JWT](https://img.shields.io/badge/Auth-JWT-green.svg)
![MySQL](https://img.shields.io/badge/Database-MySQL-orange.svg)
![Testing](https://img.shields.io/badge/Coverage-90%25-brightgreen.svg)

## 🎓 Part of Banking Microservices System

This service is part of a comprehensive banking microservices project inspired by the **[Building Microservices API in Go](https://www.coursera.org/learn/packt-building-microservices-api-in-go-bq6wv)** course on Coursera. 

**Related Services:**
- 🏦 **[Banking Service](https://github.com/kal997/banking-service)** - Core banking operations
- 📚 **[Banking Lib](https://github.com/kal997/banking-lib)** - Shared utilities and error handling
- 📖 **[Complete System Documentation](https://github.com/kal997/banking-microservices-docs)** - Full architecture guide

## 🔐 Features

### **Authentication**
- **JWT token generation** with custom claims
- **User credential validation** against database
- **Token expiration handling** (configurable TTL)
- **Secure password storage** (ready for bcrypt integration)

### **Authorization**
- **Role-based access control** (Admin/User roles)
- **Route-level permissions** validation
- **Account-level access control** for users
- **Cross-service token verification** API

### **Security**
- **HMAC-signed JWT tokens** with configurable secrets
- **Input validation** and sanitization
- **SQL injection prevention** with parameterized queries
- **Structured error responses** without information leakage

### **Enterprise Features**
- **Clean architecture** with dependency injection
- **Comprehensive logging** using Uber Zap
- **Environment-based configuration**
- **Health check endpoints** (ready to implement)

## 🏗️ Architecture

### **Service Architecture**
```
┌─────────────────────┐
│   HTTP Handlers     │ ← Login, Verify endpoints
├─────────────────────┤
│   Auth Service      │ ← Business logic, JWT handling
├─────────────────────┤
│   Domain Models     │ ← User, Login, Claims, Roles
├─────────────────────┤
│   Repository        │ ← Database operations
└─────────────────────┘
```

### **Dependencies**
- **[Banking Lib](https://github.com/kal997/banking-lib)**: Shared logging and error handling
- **MySQL**: User credentials and role storage
- **JWT**: Stateless token-based authentication

## 🚀 Quick Start

### Prerequisites
- **Go 1.24+**
- **MySQL 8.0+**
- **Banking Lib** dependency

### 1. Clone and Setup
```bash
git clone https://github.com/kal997/banking-auth.git
cd banking-auth
go mod tidy
```

### 2. Database Setup
```sql
-- Create database
CREATE DATABASE banking_auth_db;
USE banking_auth_db;

-- Create users table
CREATE TABLE users (
    username VARCHAR(20) PRIMARY KEY,
    password VARCHAR(20) NOT NULL,
    role VARCHAR(10) NOT NULL,
    customer_id INT,
    created_on DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample users
INSERT INTO users (username, password, role, customer_id) VALUES
('admin', 'admin123', 'admin', NULL),
('khaled_user', 'user123', 'user', 2000);
```

### 3. Configuration
Create environment variables:
```bash
export SERVER_ADDRESS=localhost
export SERVER_PORT=8080
export DB_USER=your_db_user
export DB_PASSWD=your_db_password
export DB_ADDR=localhost
export DB_PORT=3306
export DB_NAME=banking_auth_db
```

### 4. Run Service
```bash
go run main.go
```

Service will start on `http://localhost:8080`

## 📖 API Documentation

### **Login**
Authenticate user and receive JWT token.

```http
POST /auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin123"
}
```

**Response:**
```json
{
  "accesstoken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### **Token Verification**
Verify JWT token and check route permissions.

```http
GET /auth/verify?token=<JWT>&routeName=<ROUTE>&customer_id=<ID>
```

**Parameters:**
- `token`: JWT token to verify
- `routeName`: Route to check permission for (`GetCustomer`, `NewAccount`, etc.)
- `customer_id`: Customer ID (required for user role)
- `account_id`: Account ID (required for transaction routes)

**Response:**
```json
{
  "isAuthorized": true
}
```

## 🔑 JWT Token Structure

### **Admin Token Claims**
```json
{
  "username": "admin",
  "role": "admin",
  "exp": 1642678800
}
```

### **User Token Claims**
```json
{
  "customer_id": "2000",
  "accounts": ["95470", "95471"],
  "username": "khaled_user",
  "role": "user",
  "exp": 1642678800
}
```

## 🛡️ Role-Based Permissions

| Role | Allowed Routes |
|------|----------------|
| **admin** | GetAllCustomers, GetCustomer, NewAccount, NewTransaction |
| **user** | GetCustomer (own only), NewTransaction (own accounts only) |

### **Permission Logic**
- **Admin users**: Can access all routes and all customer data
- **Regular users**: Can only access their own customer data and accounts
- **Account validation**: Users can only perform transactions on their owned accounts
## 🔧 Configuration

### **Environment Variables**

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_ADDRESS` | Server bind address | `localhost` |
| `SERVER_PORT` | Server port | `8080` |
| `DB_USER` | Database username | - |
| `DB_PASSWD` | Database password | - |
| `DB_ADDR` | Database address | `localhost` |
| `DB_PORT` | Database port | `3306` |
| `DB_NAME` | Database name | - |

### **Database Configuration**
- **Connection pooling**: 10 max connections, 3-minute lifetime
- **Prepared statements**: Used for all queries to prevent SQL injection
- **ACID compliance**: Proper transaction handling

## 🚀 Deployment

### **Docker**
```dockerfile
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o banking-auth main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/banking-auth .
CMD ["./banking-auth"]
```
## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/new-feature`
3. Add tests for new functionality
4. Ensure all tests pass: `go test ./... -cover`
5. Commit changes: `git commit -am 'Add new feature'`
6. Push branch: `git push origin feature/new-feature`
7. Create Pull Request

## 👤 Author

**Khaled Hussein** - *Backend Engineer*
- 📧 Email: khaled.soliman97@gmail.com
- 💼 LinkedIn: [linkedin.com/in/khaled-soliman-ali](https://linkedin.com/in/khaled-soliman-ali)
- 🐙 GitHub: [@kal997](https://github.com/kal997)

---

**Built with 🔐 and Go | Part of Banking Microservices System**
