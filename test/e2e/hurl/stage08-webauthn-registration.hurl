POST {{BASE_URL}}/auth/login
Content-Type: application/json
X-Request-Id: hurl-stage08-passkey-login
User-Agent: aether-auth-hurl/1.0
{
  "kind": "password",
  "username": "{{AUTHENTICATED_USERNAME}}",
  "password": "{{AUTHENTICATED_PASSWORD}}"
}

HTTP 200
[Captures]
access_token: jsonpath "$.session.access_token"

POST {{BASE_URL}}/account/passkeys/registration/options
Authorization: Bearer {{access_token}}
Content-Type: application/json
X-Request-Id: hurl-stage08-passkey-registration-options
User-Agent: aether-auth-hurl/1.0
{
  "user_verification": "preferred"
}

HTTP 201
[Captures]
passkey_challenge_id: jsonpath "$.challenge_id"
[Asserts]
jsonpath "$.challenge_id" exists
jsonpath "$.expires_at" exists
jsonpath "$.options.publicKey.challenge" exists
jsonpath "$.options.publicKey.rp.id" exists
jsonpath "$.options.publicKey.user.id" exists
body not contains "private"
body not contains "public_key"
body not contains "credential_data"

POST {{BASE_URL}}/account/passkeys/registration/confirm
Authorization: Bearer {{access_token}}
Content-Type: application/json
X-Request-Id: hurl-stage08-passkey-registration-malformed
User-Agent: aether-auth-hurl/1.0
{
  "challenge_id": "{{passkey_challenge_id}}",
  "credential_name": "Malformed Hurl passkey",
  "attestation_response": {}
}

HTTP 400
[Asserts]
jsonpath "$.code" == "invalid_passkey_request"
body not contains "public_key"
body not contains "credential_data"
