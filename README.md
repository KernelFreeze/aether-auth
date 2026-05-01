# Aether Auth

Aether Auth implements an auth microservice built with **Go**, **Gin**, **GORM**, **PostgreSQL**, and **Redis**.

This project implements authentication and identity flows including **OAuth2**, **OIDC**, **Passkeys**, and related auth service capabilities.

## 🚀 Features

- **RESTful API** using Gin
- **PostgreSQL + Redis** integration
- **Modular service-based architecture**
- **Middleware support** (CORS, Logging)
- **Graceful shutdown handling**
- **Environment variable configuration**

---

## 📌 Getting Started

### Prerequisites

Ensure you have the following installed:

- [Go](https://go.dev/doc/install) (1.22+ recommended)
- [PostgreSQL](https://www.postgresql.org/download/)
- [Redis](https://redis.io/download/)
- [Podman](https://podman.io/) (optional, for containers)

### Installation

1. Clone the repository:

   ```bash
   git clone git@github.com:KernelFreeze/aether-auth.git
   cd aether-auth
   ```

2. Create a `.env` file and configure database credentials:

   ```bash
   cp .env.example .env
   ```

3. Install dependencies:

   ```bash
   go mod tidy
   ```

4. Run the database migrations (if applicable):

   ```bash
   go run scripts/migrate.go
   ```

5. Start the server:

   ```bash
   go run cmd/api/main.go
   ```

   The server should be running at **http://localhost:8080**

### Podman

Build and run the containerized stack:

```bash
just podman-build
just podman-run
```

---

## 📂 Project Structure

```
├── config/          # Configuration files
├── controllers/     # API Controllers
├── models/         # Database Models
├── routes/         # Route Handlers
├── services/       # Business Logic Layer
├── database/       # DB Connection & Migrations
├── middleware/     # Middleware (CORS, Auth, Logging)
├── templates/      # HTML Templates
├── main.go         # Entry Point
└── .env.example    # Environment Config Sample
```

---

## 📡 Auth Capabilities

- OAuth2 authorization flows
- OIDC identity provider support
- Passkey-based authentication
- Session and token management
- Auth service APIs for applications

---

## 🛠 Technologies Used

- **Go** - Core language
- **Gin** - HTTP framework
- **GORM** - ORM for PostgreSQL
- **Redis** - In-memory caching
- **Podman** - Containerization (optional)

---

## 📝 License

This project is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0-only). See [LICENSE](./LICENSE) and [LICENSING.md](./LICENSING.md).

---

## 🤝 Contributing

Contributions are welcome! If you find issues or have improvements, feel free to open an issue or PR.

---

### 🎯 Author

Aether Auth is maintained by **KernelFreeze**.
