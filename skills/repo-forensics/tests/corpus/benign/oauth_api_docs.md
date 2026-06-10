# API Authentication Guide

## Overview

This API uses OAuth 2.0 for authentication. All requests must include a
valid access token in the Authorization header.

## Obtaining a Token

1. Register your application in the developer portal.
2. Complete the OAuth 2.0 authorization code flow.
3. Exchange the authorization code for an access token.

## Making Authenticated Requests

Include your access token in the Authorization header using the Bearer
scheme:

```
Authorization: Bearer <ACCESS_TOKEN>
```

Replace `<ACCESS_TOKEN>` with the token returned by the /auth/token endpoint.

## Token Expiry and Refresh

Access tokens expire after 3600 seconds. When a request returns HTTP 401,
use your refresh_token to obtain a new access_token:

```
POST /auth/refresh
Content-Type: application/json

{
  "grant_type": "refresh_token",
  "refresh_token": "<REFRESH_TOKEN>",
  "client_id": "<CLIENT_ID>"
}
```

## Security Requirements

- Always transmit tokens over HTTPS.
- Store tokens in environment variables or a secure secrets manager.
- Never hardcode credentials in application source code.
- Rotate client secrets every 90 days.
- Use the minimum required OAuth scopes.
