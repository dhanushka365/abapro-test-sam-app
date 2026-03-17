# Postman cURL Commands for Users API

## Base URL
Replace `{API_ENDPOINT}` with your actual API Gateway endpoint URL (format: `https://{api-id}.execute-api.{region}.amazonaws.com/prod`)
Replace `{AUTHORIZATION_TOKEN}` with your Cognito JWT token (IdToken from Cognito authentication)

---

## 1. GET All Users

```bash
curl --location --request GET '{API_ENDPOINT}/users' \
--header 'Authorization: Bearer {AUTHORIZATION_TOKEN}' \
--header 'Content-Type: application/json'
```

---

## 2. GET User by ID

```bash
curl --location --request GET '{API_ENDPOINT}/users/{userid}' \
--header 'Authorization: Bearer {AUTHORIZATION_TOKEN}' \
--header 'Content-Type: application/json'
```

**Example:**
```bash
curl --location --request GET '{API_ENDPOINT}/users/f8216640-91a2-11eb-8ab9-57aa454facef' \
--header 'Authorization: Bearer {AUTHORIZATION_TOKEN}' \
--header 'Content-Type: application/json'
```

---

## 3. POST Create User

> **No Authorization token required** — this endpoint is public so new users can register.

```bash
curl --location --request POST '{API_ENDPOINT}/users' \
--header 'Content-Type: application/json' \
--data-raw '{
    "name": "John Doe",
    "email": "john.doe@example.com",
    "password": "Password123"
}'
```

**Example with more fields:**
```bash
curl --location --request POST '{API_ENDPOINT}/users' \
--header 'Content-Type: application/json' \
--data-raw '{
    "name": "Jane Smith",
    "email": "jane.smith@example.com",
    "password": "Password123",
    "age": 30,
    "city": "New York"
}'
```

> After registration, the user will receive a **confirmation email**. The account must be confirmed before logging in.  
> The `password` field is **never stored** in DynamoDB — only the Cognito `sub` (userid) is saved.

---

## 4. POST Verify Email

> **No Authorization token required** — this endpoint is public.

After registering, Cognito sends a 6-digit confirmation code to the user's email. Submit it here to activate the account.

```bash
curl --location --request POST '{API_ENDPOINT}/users/verify' \
--header 'Content-Type: application/json' \
--data-raw '{
    "email": "john.doe@example.com",
    "code": "123456"
}'
```

**Success response (200):**
```json
{ "Message": "Email verified successfully. You can now log in." }
```

**Error responses:**
| HTTP | ErrorCode | Meaning |
|------|-----------|---------|
| 400 | `CodeMismatchException` | Wrong code entered |
| 400 | `ExpiredCodeException` | Code expired — re-register or request new code |
| 400 | `NotAuthorizedException` | Account already confirmed |
| 400 | `UserNotFoundException` | No account with that email |

---

## 5. POST Login

> **No Authorization token required** — this endpoint is public.

Authenticates with Cognito and returns JWT tokens. Use the `IdToken` as the `{AUTHORIZATION_TOKEN}` for all protected endpoints.

```bash
curl --location --request POST '{API_ENDPOINT}/users/login' \
--header 'Content-Type: application/json' \
--data-raw '{
    "email": "john.doe@example.com",
    "password": "Password123"
}'
```

**Success response (200):**
```json
{
    "IdToken":      "eyJraWQiOi...",
    "AccessToken":  "eyJraWQiOi...",
    "RefreshToken": "eyJjdHki...",
    "ExpiresIn":    3600,
    "TokenType":    "Bearer"
}
```

**Error responses:**
| HTTP | ErrorCode | Meaning |
|------|-----------|---------|
| 401 | `NotAuthorizedException` | Wrong email or password |
| 401 | `UserNotConfirmedException` | Email not verified yet — call `/users/verify` first |
| 401 | `UserNotFoundException` | No account with that email |
| 401 | `PasswordResetRequiredException` | Password reset required |

> Use the `IdToken` value as `{AUTHORIZATION_TOKEN}` in all subsequent requests.

---

## 6. PUT Update User by ID

```bash
curl --location --request PUT '{API_ENDPOINT}/users/{userid}' \
--header 'Authorization: Bearer {AUTHORIZATION_TOKEN}' \
--header 'Content-Type: application/json' \
--data-raw '{
    "name": "John Doe Updated",
    "email": "john.doe.updated@example.com"
}'
```

**Example:**
```bash
curl --location --request PUT '{API_ENDPOINT}/users/f8216640-91a2-11eb-8ab9-57aa454facef' \
--header 'Authorization: Bearer {AUTHORIZATION_TOKEN}' \
--header 'Content-Type: application/json' \
--data-raw '{
    "name": "John Doe Updated",
    "email": "john.doe.updated@example.com",
    "age": 35,
    "city": "Los Angeles"
}'
```

**Note:** Only the owner (userid matching Cognito sub) can update their own record.

---

## 5. DELETE User by ID

```bash
curl --location --request DELETE '{API_ENDPOINT}/users/{userid}' \
--header 'Authorization: Bearer {AUTHORIZATION_TOKEN}' \
--header 'Content-Type: application/json'
```

**Example:**
```bash
curl --location --request DELETE '{API_ENDPOINT}/users/f8216640-91a2-11eb-8ab9-57aa454facef' \
--header 'Authorization: Bearer {AUTHORIZATION_TOKEN}' \
--header 'Content-Type: application/json'
```

**Note:** Only the owner (userid matching Cognito sub) can delete their own record.

---

## How to Get Authorization Token

Use `POST /users/login` (see section 5 above) to get the JWT tokens. Copy the `IdToken` from the response and use it as `{AUTHORIZATION_TOKEN}` in all protected endpoint requests.

### Alternative: Using AWS CLI directly
```bash
aws cognito-idp initiate-auth \
  --auth-flow USER_PASSWORD_AUTH \
  --client-id {USER_POOL_CLIENT_ID} \
  --auth-parameters USERNAME={email},PASSWORD={password} \
  --region {AWS_REGION}
```

Extract the `IdToken` from the response and use it as `{AUTHORIZATION_TOKEN}`.

### Alternative: Using cURL directly against Cognito
```bash
curl --location --request POST 'https://cognito-idp.{AWS_REGION}.amazonaws.com/' \
--header 'X-Amz-Target: AWSCognitoIdentityProviderService.InitiateAuth' \
--header 'Content-Type: application/x-amz-json-1.1' \
--data-raw '{
    "ClientId": "{USER_POOL_CLIENT_ID}",
    "AuthFlow": "USER_PASSWORD_AUTH",
    "AuthParameters": {
        "USERNAME": "{email}",
        "PASSWORD": "{password}"
    }
}'
```

---

## Quick Reference

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/users` | Get all users | Yes |
| GET | `/users/{userid}` | Get user by ID | Yes |
| POST | `/users` | Register new user in Cognito + DynamoDB | **No** |
| POST | `/users/verify` | Confirm email with verification code | **No** |
| POST | `/users/login` | Authenticate and get JWT tokens | **No** |
| PUT | `/users/{userid}` | Update user by ID | Yes (Owner only) |
| DELETE | `/users/{userid}` | Delete user by ID | Yes (Owner only) |

---

## Notes

- All endpoints **except POST /users, POST /users/verify, and POST /users/login** require Cognito authentication via the `Authorization: Bearer {token}` header
- **POST /users** is a public endpoint — it registers the user in Cognito **and** saves the profile to DynamoDB
- **POST /users/verify** is a public endpoint — submit the 6-digit code from the confirmation email to activate the account
- **POST /users/login** is a public endpoint — returns `IdToken`, `AccessToken`, `RefreshToken`; use `IdToken` as the bearer token for protected endpoints
- `email` and `password` are required in the POST body; `password` is sent to Cognito only and is **never stored** in DynamoDB
- After registration the user receives a **confirmation email** — call `/users/verify` with the code before logging in
- The `userid` in DynamoDB is automatically set to the Cognito `sub` (unique identity) upon registration
- PUT and DELETE operations can only be performed by the owner (userid must match Cognito sub)
- The API returns JSON responses with appropriate HTTP status codes
- CORS is enabled for all origins (`*`)
