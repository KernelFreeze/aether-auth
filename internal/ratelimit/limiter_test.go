package ratelimit

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRuleCheckerChecksIPUsernameAndEndpointBuckets(t *testing.T) {
	fake := &fakeBucketLimiter{
		results: []BucketResult{
			{Allowed: true, Limit: 100, Remaining: 99},
			{Allowed: true, Limit: 10, Remaining: 9},
			{Allowed: true, Limit: 5, Remaining: 4},
		},
	}
	checker := NewChecker(fake, Config{
		Namespace:             "test",
		PerIP:                 Limit{Rate: 100, Period: time.Minute},
		PerAccount:            Limit{Rate: 10, Period: time.Minute},
		EndpointLimits:        map[string]Limit{"/auth/reset-password/request": {Rate: 5, Period: time.Minute}},
		HashIdentifyingValues: true,
	})

	decision, err := checker.Check(context.Background(), Request{
		Subject: Subject{
			IP:       "203.0.113.10",
			Username: "User@Example.com",
			Endpoint: "/auth/reset-password/request",
		},
		Cost: 1,
	})
	if err != nil {
		t.Fatalf("check rate limit: %v", err)
	}
	if !decision.Allowed {
		t.Fatal("decision should allow the request")
	}
	if decision.Remaining != 4 {
		t.Fatalf("remaining = %d, want 4", decision.Remaining)
	}
	if len(fake.calls) != 3 {
		t.Fatalf("bucket calls = %d, want 3", len(fake.calls))
	}
	wantScopes := []Scope{ScopeIP, ScopeUsername, ScopeEndpoint}
	for i, call := range fake.calls {
		if !strings.Contains(call.key, ":") {
			t.Fatalf("call %d key = %q, want namespaced key", i, call.key)
		}
		if !strings.Contains(call.key, string(wantScopes[i])) {
			t.Fatalf("call %d key = %q, want scope %q", i, call.key, wantScopes[i])
		}
		if strings.Contains(call.key, "User@Example.com") {
			t.Fatalf("call %d key leaks username: %q", i, call.key)
		}
	}
}

func TestRuleCheckerStopsAtDeniedBucket(t *testing.T) {
	fake := &fakeBucketLimiter{
		results: []BucketResult{
			{Allowed: true, Limit: 100, Remaining: 99},
			{Allowed: false, Limit: 10, Remaining: 0, RetryAfter: 30 * time.Second},
			{Allowed: true, Limit: 5, Remaining: 4},
		},
	}
	checker := NewChecker(fake, Config{
		PerIP:      Limit{Rate: 100, Period: time.Minute},
		PerAccount: Limit{Rate: 10, Period: time.Minute},
		EndpointLimits: map[string]Limit{
			"/auth/login": {Rate: 5, Period: time.Minute},
		},
	})

	decision, err := checker.Check(context.Background(), Request{
		Subject: Subject{
			IP:        "203.0.113.10",
			AccountID: "acct_123",
			Endpoint:  "/auth/login",
		},
	})
	if err != nil {
		t.Fatalf("check rate limit: %v", err)
	}
	if decision.Allowed {
		t.Fatal("decision should deny the request")
	}
	if decision.Scope != ScopeAccount {
		t.Fatalf("scope = %q, want %q", decision.Scope, ScopeAccount)
	}
	if decision.RetryAfter != 30*time.Second {
		t.Fatalf("retry after = %s, want 30s", decision.RetryAfter)
	}
	if len(fake.calls) != 2 {
		t.Fatalf("bucket calls = %d, want 2", len(fake.calls))
	}
}

type fakeBucketLimiter struct {
	results []BucketResult
	calls   []bucketCall
}

type bucketCall struct {
	key   string
	limit Limit
	cost  int
}

func (l *fakeBucketLimiter) Allow(_ context.Context, key string, limit Limit, cost int) (BucketResult, error) {
	l.calls = append(l.calls, bucketCall{key: key, limit: limit, cost: cost})
	if len(l.results) == 0 {
		return BucketResult{Allowed: true, Limit: limit.Rate, Remaining: limit.Rate - cost}, nil
	}
	result := l.results[0]
	l.results = l.results[1:]
	return result, nil
}
