# Hurl e2e flows

These files exercise public HTTP contracts against a running Aether Auth API.
They are not part of `just test`; run them only after the local stack is ready.

Startup order:

1. Start Postgres, Redis, and Mailpit with `just podman-run`.
2. Apply migrations with `just migrate-up`.
3. Start the API with `just run`.
4. Start the worker when a flow checks async mail, cleanup, or queue behavior.
5. Run `just test-hurl vars=test/e2e/hurl/local.env`.

Create `local.env` from `local.env.example` and use throwaway values. Do not
commit generated account names, emails, passwords, reset tokens, OAuth codes,
or session tokens.
