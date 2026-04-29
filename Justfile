app_image := "localhost/aether-auth:latest"

build:
    mkdir -p bin
    go build -o bin/api ./cmd/api
    go build -o bin/worker ./cmd/worker
    go build -o bin/migrate ./cmd/migrate

run:
    if command -v air >/dev/null 2>&1; then air; else go run ./cmd/api; fi

worker:
    go run ./cmd/worker

test:
    go test -v ./...

test-integration:
    go test -tags=integration -v ./...

test-e2e:
    go test -tags=e2e -v ./test/e2e/...

podman-build:
    podman build -t {{app_image}} -f Containerfile .

podman-run:
    podman compose -f podman-compose.yml up -d

dev:
    air

clean:
    rm -rf bin/ tmp/

fmt:
    go fmt ./...

lint:
    golangci-lint run ./...

vet:
    go vet ./...

staticcheck:
    go install honnef.co/go/tools/cmd/staticcheck@latest
    staticcheck ./...

install-lint:
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# --- migrations ---------------------------------------------------------------

# Apply all pending migrations.
migrate-up:
    go run ./cmd/migrate up

# Roll back the last N migrations (default 1).
migrate-down n="1":
    go run ./cmd/migrate down {{n}}

# Create a new migration pair: just migrate-new slug=add_audit_indexes
migrate-new slug:
    @command -v migrate >/dev/null 2>&1 || { echo "install golang-migrate CLI: https://github.com/golang-migrate/migrate"; exit 1; }
    migrate create -ext sql -dir migrations -seq {{slug}}

# Force the schema_migrations row to a specific version (use after fixing a
# dirty state).
migrate-force version:
    go run ./cmd/migrate force {{version}}

migrate-version:
    go run ./cmd/migrate version

# --- code generation ----------------------------------------------------------

# Regenerate the sqlc Go code from db/queries/*.sql.
sqlc:
    @command -v sqlc >/dev/null 2>&1 || { echo "install sqlc: https://docs.sqlc.dev/en/latest/overview/install.html"; exit 1; }
    sqlc -f configs/sqlc.yaml generate

# Regenerate the moq mocks declared via go:generate directives.
gen-mocks:
    @command -v moq >/dev/null 2>&1 || go install github.com/matryer/moq@latest
    go generate ./...
