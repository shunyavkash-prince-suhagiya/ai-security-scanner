# SaaS Blueprint

## Product model

- Multi-user accounts with role-based access
- Project-based scans scoped to a workspace or uploaded archive
- API key access for CI/CD integrations
- Usage limits by tier

## Database schema

### users
- id
- email
- password_hash
- role
- api_key
- created_at

### projects
- id
- user_id
- name
- repository_url
- created_at

### scan_jobs
- id
- project_id
- user_id
- status
- target_name
- report_path
- summary_json
- created_at
- updated_at

### scan_findings
- id
- scan_id
- finding_type
- risk_level
- risk_score
- file_path
- line_number
- detector
- value_preview

### subscriptions
- id
- user_id
- tier
- monthly_scan_limit
- monthly_storage_mb
- billing_customer_id

## API design

- `POST /auth/login`
- `POST /scan`
- `GET /scan/{id}`
- `GET /reports`
- `GET /projects`
- `POST /projects`
- `POST /api-keys`

## Billing-ready structure

- Free tier:
  - low monthly scan quota
  - short report retention
  - single project limit
- Paid tier:
  - higher concurrency
  - long report retention
  - API access
  - team seats

## Security controls

- Per-user upload directories
- JWT auth for UI and API
- API key rotation support
- Audit log table for login, scan, and download actions
