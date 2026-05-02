POST {{BASE_URL}}/auth/reset-password/request
Content-Type: application/json
X-Request-Id: hurl-stage10-reset-known
User-Agent: aether-auth-hurl/1.0
{
  "username": "{{REGISTRATION_USERNAME}}"
}

HTTP 202
[Asserts]
jsonpath "$.code" == "reset_request_accepted"
jsonpath "$.detail" == "If the account can be reset, instructions will be sent."
body not contains "token"
body not contains "password_hash"
body not contains "credential_data"

POST {{BASE_URL}}/auth/reset-password/request
Content-Type: application/json
X-Request-Id: hurl-stage10-reset-unknown
User-Agent: aether-auth-hurl/1.0
{
  "identifier": "{{RESET_UNKNOWN_IDENTIFIER}}"
}

HTTP 202
[Asserts]
jsonpath "$.code" == "reset_request_accepted"
jsonpath "$.detail" == "If the account can be reset, instructions will be sent."
body not contains "missing"
body not contains "unknown"
body not contains "exists"
