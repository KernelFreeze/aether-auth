POST {{BASE_URL}}/auth/login
Content-Type: application/json
X-Request-Id: hurl-stage04-credentials-login
User-Agent: aether-auth-hurl/1.0
{
  "kind": "password",
  "username": "{{AUTHENTICATED_USERNAME}}",
  "password": "{{AUTHENTICATED_PASSWORD}}"
}

HTTP 200
[Captures]
access_token: jsonpath "$.session.access_token"
[Asserts]
jsonpath "$.status" == "authenticated"
jsonpath "$.session.id" exists
jsonpath "$.session.refresh_token" exists
jsonpath "$.session.expires_at" exists
body not contains "password_hash"
body not contains "credential_data"

GET {{BASE_URL}}/account/credentials
Authorization: Bearer {{access_token}}
X-Request-Id: hurl-stage04-credentials-list
User-Agent: aether-auth-hurl/1.0

HTTP 200
[Asserts]
jsonpath "$.credentials" exists
jsonpath "$.credentials[0].id" exists
jsonpath "$.credentials[0].kind" exists
body not contains "ciphertext"
body not contains "credential_data"
body not contains "external_subject"

DELETE {{BASE_URL}}/account/credentials/018f1f74-10a1-7000-9000-00000000ffff
Authorization: Bearer {{access_token}}
X-Request-Id: hurl-stage04-credentials-remove-missing
User-Agent: aether-auth-hurl/1.0

HTTP 404
[Asserts]
jsonpath "$.code" == "credential_not_found"
body not contains "ciphertext"
body not contains "credential_data"
