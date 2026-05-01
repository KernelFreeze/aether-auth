POST {{BASE_URL}}/auth/register
Content-Type: application/json
X-Request-Id: hurl-stage04-registration-create
User-Agent: aether-auth-hurl/1.0
{
  "username": "{{REGISTRATION_USERNAME}}",
  "email": "{{REGISTRATION_EMAIL}}",
  "display_name": "{{REGISTRATION_DISPLAY_NAME}}"
}

HTTP 202
[Asserts]
jsonpath "$.message" == "If the account can be created, check your email."
body not contains "password"
body not contains "hash"
body not contains "credential_data"
body not contains "reset_token"

POST {{BASE_URL}}/auth/register
Content-Type: application/json
X-Request-Id: hurl-stage04-registration-duplicate
User-Agent: aether-auth-hurl/1.0
{
  "username": "{{REGISTRATION_USERNAME}}",
  "email": "{{REGISTRATION_EMAIL}}",
  "display_name": "{{REGISTRATION_DISPLAY_NAME}}"
}

HTTP 202
[Asserts]
jsonpath "$.message" == "If the account can be created, check your email."
body not contains "duplicate"
body not contains "taken"
body not contains "exists"
