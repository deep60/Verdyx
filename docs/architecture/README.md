# Architecture Docs

Verdyx uses a service-oriented backend with a Rust API gateway, Rust domain services, PostgreSQL, Redis, optional MinIO/ClamAV, and blockchain integration.

## Files

- `service-ownership.md`: Who owns each write, how services talk, and the submission trace.
- `system-design.md`: Components, responsibilities, and boundaries.
- `data-flow.md`: End-to-end request and event flows.
- `diagrams/system-context.mmd`: Mermaid source for high-level context.
- `diagrams/analysis-flow.mmd`: Mermaid source for analysis request flow.

## Service Map (Current Compose Ports)

- API Gateway: `8080`
- User Service: `8081`
- Analysis Engine: `8082`
- Bounty Manager: `8083`
- Submission Service: `8084`
- Consensus Service: `8085`
- Payment Service: `8086`
- Reputation Service: `8087`
- Notification Service: `8088`
- Frontend: `5000`

## Data Plane

- PostgreSQL: system of record.
- Redis: cache/session/rate-limit/event-style pub-sub.
- MinIO: object storage for submission artifacts.
- ClamAV and YARA: malware scanning controls.

## Control Plane

- Docker Compose: local and single-host orchestration.
- Kubernetes manifests: cluster deployment path under `infrastructure/kubernetes`.
