# Verdyx API Contract Lock

Locked on: 2026-04-15  
Version: v1.0 (contract freeze)

This file is the source of truth for payload shapes used by:
- frontend (`frontend/client`)
- API gateway (`backend/api-gateway`)
- websocket consumers (`/ws`)

If code and this file differ, code must be updated to match this file.

## 1) Transport and Versioning

- Browser-facing REST base path: `/api/*`
- Internal gateway route namespace: `/api/v1/*`
- Browser-facing websocket endpoint: `/ws`
- Content type: `application/json`
- Time format: ISO-8601 UTC (`2026-04-15T12:34:56Z`)
- IDs: UUID strings

Important lock:
- Browser code MUST call `/api/...` (not `/api/v1/...`) when going through frontend proxy/BFF.

## 2) Response Envelope Rules

### 2.1 Auth endpoints use envelope

```json
{
  "success": true,
  "data": {},
  "message": null,
  "timestamp": "2026-04-15T12:34:56Z"
}
```

### 2.2 Non-auth endpoints return bare JSON

No `success/data/message/timestamp` wrapper unless explicitly documented.

## 3) Auth Contract

## 3.1 Shared types

`AuthUser`
```json
{
  "id": "uuid",
  "username": "string",
  "email": "string",
  "walletAddress": "string|null",
  "reputationScore": 0,
  "totalEarnings": "string",
  "createdAt": "2026-04-15T12:34:56Z",
  "isVerified": true
}
```

`AuthTokens`
```json
{
  "user": "AuthUser",
  "accessToken": "jwt",
  "refreshToken": "jwt",
  "expiresIn": 3600
}
```

## 3.2 Endpoints

### `POST /api/auth/register`
Request:
```json
{
  "username": "string",
  "email": "string",
  "password": "string",
  "wallet_address": "string (optional)"
}
```
Response: `ApiResponse<AuthTokens>`

### `POST /api/auth/login`
Request:
```json
{
  "identifier": "string",
  "password": "string"
}
```
Response: `ApiResponse<AuthTokens>`

### `POST /api/auth/refresh`
Request:
```json
{
  "refresh_token": "jwt"
}
```
Response: `ApiResponse<AuthTokens>`

### `GET /api/auth/verify`
Headers: `Authorization: Bearer <accessToken>`  
Response: `ApiResponse<AuthUser>`

### `GET /api/auth/profile`
Headers: `Authorization: Bearer <accessToken>`  
Response: `ApiResponse<AuthUser>`

### `POST /api/auth/wallet/connect`
Headers: `Authorization: Bearer <accessToken>`  
Request:
```json
{
  "wallet_address": "0x...",
  "signature": "0x...",
  "message": "string"
}
```
Response: `ApiResponse<AuthUser>`

### `POST /api/auth/wallet/disconnect`
Headers: `Authorization: Bearer <accessToken>`  
Response: `ApiResponse<AuthUser>`

### `PUT /api/users/me`

Headers: `Authorization: Bearer <accessToken>`

Request (all fields optional, at least one required to change anything):

```json
{
  "username": "string",
  "email": "string",
  "bio": "string"
}
```

`username`: 3–50 characters, ASCII letters, numbers, or `_`.
`email`: valid mailbox, stored lowercased. Changing it clears email verification.

Success: the current user profile JSON (`username`, `email`, and the other profile fields the gateway already returns).

Errors: `{ "error": "string", "status": 400|401|409|502 }`. `409` means the username or email is taken.

### `DELETE /api/users/me`

Headers: `Authorization: Bearer <accessToken>`

Success: `204` empty body. The account is soft-deleted by user-service and an `account.deleted` audit row is written. The client must drop its tokens.

Errors: `{ "error": "string", "status": 401|502 }`.

### `POST /api/auth/logout`
Headers: `Authorization: Bearer <accessToken>`  
Response:
```json
{
  "success": true,
  "data": null,
  "message": "Successfully logged out",
  "timestamp": "2026-04-15T12:34:56Z"
}
```

## 4) Submissions Contract

Note: `submissions` endpoints currently use snake_case response keys. This is locked for v1.

## 4.1 `POST /api/submissions/file` (frontend form path)

Request:
```json
{
  "filename": "string (optional)",
  "originalFilename": "string (optional)",
  "submissionType": "file|url",
  "description": "string|null",
  "fileHash": "string|null",
  "fileSize": 12345,
  "analysisType": "full|quick|deep|behavioral|null",
  "bountyAmount": "string|null",
  "priority": true
}
```

Response:
```json
{
  "id": "uuid",
  "submitter_id": "uuid",
  "original_filename": "string|null",
  "file_hash": "string|null",
  "file_size": 12345,
  "submission_type": "file|url",
  "analysis_status": "pending|analyzing|completed|failed",
  "description": "string|null",
  "created_at": "2026-04-15T12:34:56Z"
}
```

## 4.2 `GET /api/submissions`

Query params (all optional):
- `bounty_id` (uuid)
- `engine_id` (string)
- `verdict` (string)
- `min_confidence` (number)
- `max_confidence` (number)
- `status` (string)
- `date_from` (datetime)
- `date_to` (datetime)
- `page` (number, default 1)
- `limit` (number, default 20)

Response:
```json
{
  "submissions": [
    {
      "id": "uuid",
      "bounty_id": "uuid",
      "engine_id": "string",
      "engine_name": "string",
      "engine_version": "string",
      "verdict": "malicious|benign|suspicious",
      "confidence": 0.95,
      "threat_types": ["string"],
      "risk_score": 80,
      "analysis_summary": "string",
      "stake_amount": 100,
      "submitted_at": "2026-04-15T12:34:56Z",
      "updated_at": "2026-04-15T12:34:56Z|null",
      "status": "Pending|Processing|Completed|Failed|Disputed|Verified",
      "is_winner": true,
      "reward_earned": 0,
      "reputation_change": 0
    }
  ],
  "total_count": 0,
  "page": 1,
  "limit": 20,
  "filters_applied": {}
}
```

## 4.3 `GET /api/submissions/:submission_id`

Response:
```json
{
  "submission": "SubmissionResponse",
  "technical_details": {},
  "signatures": ["string"],
  "analysis_metrics": {
    "processing_time_ms": 0,
    "signatures_matched": 0,
    "false_positive_rate": 0.0,
    "detection_accuracy": 0.0,
    "resource_usage": {
      "cpu_time_ms": 0,
      "memory_usage_mb": 0,
      "disk_io_mb": 0
    }
  },
  "file_info": {
    "hash": "string",
    "size": 0,
    "file_type": "string",
    "mime_type": "string",
    "upload_timestamp": "2026-04-15T12:34:56Z",
    "scan_count": 0,
    "last_analysis": "2026-04-15T12:34:56Z|null"
  }
}
```

## 4.4 `POST /api/submissions/:submission_id/start-analysis`

Response:
```json
{
  "success": true,
  "submission_id": "uuid",
  "status": "Processing",
  "message": "Analysis started"
}
```

## 4.5 `GET /api/submissions/:submission_id/analyses`

Response:
```json
[
  {
    "id": "uuid",
    "file_hash": "string|null",
    "status": "string|null",
    "verdict": "string|null",
    "confidence": 0.0,
    "created_at": "2026-04-15T12:34:56Z",
    "completed_at": "2026-04-15T12:34:56Z|null"
  }
]
```

## 4.6 `GET /api/submissions/:submission_id/consensus`

Response:
```json
{
  "finalVerdict": "malicious|suspicious|clean",
  "confidenceScore": 91.3,
  "maliciousVotes": 0,
  "suspiciousVotes": 0,
  "cleanVotes": 0,
  "totalVotes": 0
}
```

## 4.7 `POST /api/submissions/:submission_id/vote`

Request:
```json
{
  "verdict": "malicious|benign|suspicious|agree|disagree",
  "confidence": 0.95
}
```
Response:
```json
{
  "success": true,
  "vote_id": "uuid",
  "submission_id": "uuid",
  "verdict": "string",
  "confidence": 0.95
}
```

## 4.8 `POST /api/submissions/:submission_id/verify`

Response:
```json
{
  "success": true,
  "submission_id": "uuid",
  "status": "Verified",
  "message": "Submission has been verified"
}
```

## 5) Stats Contract

### `GET /api/analysis/stats`

Response:
```json
{
  "totalAnalyses": 0,
  "pending": 0,
  "completed": 0,
  "maliciousCount": 0,
  "benignCount": 0,
  "suspiciousCount": 0,
  "totalSubmissions": 0,
  "activeAnalyses": 0,
  "completedToday": 0,
  "threatsDetected": 0,
  "totalEngines": 0
}
```

## 6) Engines Contract

### `GET /api/engines`

Query params (optional):
- `page` (number)
- `limit` (number)
- `engine_type` (string)

Response:
```json
[
  {
    "id": "uuid",
    "name": "string",
    "engineType": "string",
    "description": "string|null",
    "accuracyRate": 0.0,
    "totalAnalyses": 0,
    "isActive": true,
    "createdAt": "2026-04-15T12:34:56Z"
  }
]
```

### `GET /api/engines/:engine_id`

Response: same shape as one engine item above.

## 7) WebSocket Contract (`/ws`)

All server messages MUST use this envelope:
```json
{
  "type": "event_name",
  "data": {},
  "ts": "2026-04-15T12:34:56Z"
}
```

Event naming lock:
- Use `snake_case` event names.
- Do NOT use dotted names (`analysis.completed`) on frontend websocket stream.

## 7.1 Server -> client events

### `new_submission`
```json
{
  "type": "new_submission",
  "data": {
    "submissionId": "uuid",
    "fileName": "string",
    "submissionType": "file|url"
  }
}
```

### `analysis_started`
```json
{
  "type": "analysis_started",
  "data": {
    "submissionId": "uuid",
    "status": "analyzing"
  }
}
```

### `analysis_updated`
```json
{
  "type": "analysis_updated",
  "data": {
    "submissionId": "uuid",
    "status": "pending|analyzing|completed|failed",
    "engineName": "string|null",
    "verdict": "malicious|suspicious|clean|null",
    "confidenceScore": 0.0
  }
}
```

### `analysis_completed`
```json
{
  "type": "analysis_completed",
  "data": {
    "submissionId": "uuid",
    "consensus": {
      "finalVerdict": "malicious|suspicious|clean",
      "confidenceScore": 91.3,
      "maliciousVotes": 0,
      "suspiciousVotes": 0,
      "cleanVotes": 0,
      "totalVotes": 0
    }
  }
}
```

### `bounty_claimed`
```json
{
  "type": "bounty_claimed",
  "data": {
    "bountyId": "uuid",
    "amount": "string"
  }
}
```

### `reputation_updated`
```json
{
  "type": "reputation_updated",
  "data": {
    "userId": "uuid",
    "change": 0,
    "newScore": 0
  }
}
```

### `engine_status`
```json
{
  "type": "engine_status",
  "data": {
    "engineId": "uuid|string",
    "engineName": "string",
    "status": "online|offline|degraded"
  }
}
```

## 7.2 Client -> server control events

```json
{
  "type": "ping",
  "data": { "ts": "2026-04-15T12:34:56Z" }
}
```

```json
{
  "type": "subscribe",
  "data": { "events": ["analysis_updated", "analysis_completed"] }
}
```

```json
{
  "type": "unsubscribe",
  "data": { "events": ["analysis_updated"] }
}
```

## 8) Contract Guardrails

- Do not change field casing silently.
- Do not wrap non-auth endpoints in `ApiResponse` without version bump.
- Keep websocket payload keys camelCase.
- Any breaking change requires:
  - contract version bump,
  - migration notes,
  - frontend + backend updates in same PR.
