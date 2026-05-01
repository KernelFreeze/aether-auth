//go:build integration

package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestRedisCheckerLimitsRequests(t *testing.T) {
	client := newRedisClient(t)
	checker := NewRedisChecker(client, Config{
		Namespace: "integration",
		PerIP:     Limit{Rate: 2, Burst: 2, Period: time.Minute},
	})

	req := Request{Subject: Subject{IP: "203.0.113.10", Endpoint: "/auth/login"}}
	for i := 0; i < 2; i++ {
		decision, err := checker.Check(context.Background(), req)
		if err != nil {
			t.Fatalf("check %d: %v", i, err)
		}
		if !decision.Allowed {
			t.Fatalf("check %d should be allowed", i)
		}
	}

	decision, err := checker.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("check denied request: %v", err)
	}
	if decision.Allowed {
		t.Fatal("third request should be denied")
	}
	if decision.RetryAfter <= 0 {
		t.Fatalf("retry after = %s, want positive duration", decision.RetryAfter)
	}
}

func newRedisClient(t testing.TB) *redis.Client {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "docker.io/library/redis:7-alpine",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForListeningPort("6379/tcp"),
		},
		Started: true,
	})
	if ctr != nil {
		testcontainers.CleanupContainer(t, ctr)
	}
	if err != nil {
		t.Fatalf("start redis container: %v", err)
	}

	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatalf("redis host: %v", err)
	}
	port, err := ctr.MappedPort(ctx, "6379/tcp")
	if err != nil {
		t.Fatalf("redis port: %v", err)
	}
	client := redis.NewClient(&redis.Options{Addr: host + ":" + port.Port()})
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("ping redis: %v", err)
	}
	return client
}
