# Ansible — Verdyx server bootstrap

Bootstraps a fresh VM into a Verdyx production host: Docker, Compose,
nginx (TLS-terminating reverse proxy), system hardening (UFW, fail2ban,
unattended upgrades), backup cron, and node_exporter for monitoring.

## Layout

```
ansible/
├── ansible.cfg
├── inventories/
│   ├── production.ini
│   └── staging.ini
├── playbooks/
│   ├── site.yml          # Full bootstrap
│   ├── deploy.yml        # Re-deploy app only
│   └── backup.yml        # On-demand backup
└── roles/
    ├── common/           # Base packages, users, ssh
    ├── docker/           # Install Docker + Compose
    ├── nginx/            # Reverse proxy + TLS
    ├── verdyx/           # Pull repo, render env, compose up
    └── monitoring/       # node_exporter
```

## Usage

```bash
# Bootstrap a brand new host
ansible-playbook -i inventories/production.ini playbooks/site.yml

# Redeploy app code only
ansible-playbook -i inventories/production.ini playbooks/deploy.yml

# Trigger a backup right now
ansible-playbook -i inventories/production.ini playbooks/backup.yml
```

## Required vault variables

Store these in `group_vars/all/vault.yml` encrypted with `ansible-vault`:

- `vault_postgres_password`
- `vault_redis_password`
- `vault_jwt_secret`
- `vault_minio_root_password`
- `vault_smtp_password`

The roles render `.env` from these into `/opt/verdyx/.env` with mode 0600.
