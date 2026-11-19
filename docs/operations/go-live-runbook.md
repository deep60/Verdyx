# Verdyx — Go-live runbook

A compressed checklist for getting Verdyx into production. Each step
references the file or script that does the work.

## 0. Pre-flight (offline)

- [ ] Decide on a domain and verify you control it.
- [ ] Decide on cloud provider (AWS, GCP, DigitalOcean, etc.) and create
      the target account if it doesn't exist.
- [ ] Pick a chain: mainnet, Sepolia testnet, or Polygon. Audit cost and
      finality requirements.

## 1. Generate production secrets

```bash
./scripts/maintenance/generate-prod-secrets.sh > /tmp/prod-secrets.env
chmod 600 /tmp/prod-secrets.env
```

Push every value into your secrets manager (AWS Secrets Manager, GCP
Secret Manager, Vault, or a sealed-secrets store). Do **not** commit the
file. Delete it from disk once the manager confirms storage.

No service needs a blockchain signing key: people sign marketplace
transactions in their own wallets. The contract deployer key lives only in
the GitHub environment used by the Deploy contracts workflow.

## 2. Deploy smart contracts

```bash
cd blockchain
# Sepolia (recommended first):
SEPOLIA_RPC=https://eth-sepolia.g.alchemy.com/v2/<api_key> \
PRIVATE_KEY=<deployer_key> \
  npm run deploy:sepolia

# Verify on Etherscan
ETHERSCAN_API=<etherscan_api_key> \
  npx hardhat verify --network sepolia <contract_address> [constructor_args]
```

Take the printed addresses and store them as the `*_ADDRESS` values in
your secrets manager. Update `blockchain/deployed-addresses.json` with
the same values and commit.

## 3. Provision infrastructure

Choose one of:

### a. Terraform (cloud-managed)

```bash
cd infrastructure/terraform
cp terraform.tfvars.example terraform.tfvars
# Fill in cloud account ids, region, instance sizes
terraform init
terraform plan -out=plan.tfplan
terraform apply plan.tfplan
```

### b. Ansible (single VM)

```bash
cd infrastructure/ansible
cp group_vars/all/vault.yml.example group_vars/all/vault.yml
# Edit, then encrypt:
ansible-vault encrypt group_vars/all/vault.yml
# Update inventories/production.ini with the real host
ansible-playbook -i inventories/production.ini playbooks/site.yml --ask-vault-pass
```

## 4. Configure DNS + TLS

- [ ] Create A records for `verdyx.com`, `app.verdyx.com`, `api.verdyx.com`
      pointing to the production load balancer / VM.
- [ ] If on Kubernetes: install cert-manager and apply
      `infrastructure/kubernetes/base/cert-manager.yaml`.
- [ ] If on a bare VM: the Ansible nginx role runs certbot automatically.
- [ ] Verify TLS works: `curl -I https://api.verdyx.com/api/v1/health/live`

## 5. Apply Kubernetes manifests (if K8s)

```bash
kubectl apply -f infrastructure/kubernetes/namespace.yaml
kubectl apply -f infrastructure/kubernetes/base/
# Apply each service:
for d in infrastructure/kubernetes/{api-gateway,user-service,submission-service,consensus-service,bounty-manager,payment-service,reputation-service,notification-service,analysis-engine,frontend}; do
  kubectl apply -f "$d/"
done
kubectl apply -f infrastructure/kubernetes/ingress.yaml
kubectl apply -f infrastructure/kubernetes/monitoring/
```

Confirm rollout:

```bash
kubectl -n verdyx get pods
kubectl -n verdyx rollout status deploy/verdyx-api-gateway
```

## 6. Smoke test

```bash
BASE_URL=https://api.verdyx.com FRONTEND_URL=https://app.verdyx.com \
  scripts/test/smoke.sh --remote
```

## 7. Configure monitoring

- [ ] Apply `monitoring/grafana.yaml`, `prometheus.yaml`, `alertmanager.yaml`,
      `alerts.yaml`.
- [ ] Replace `CHANGE_ME` placeholders in `alertmanager-slack` Secret and
      `verdyx-grafana-secret`.
- [ ] Confirm a test alert fires by `kubectl scale deploy/verdyx-api-gateway --replicas=0`
      and waiting for the `ServiceDown` alert in Slack. Scale back after.

## 8. Backups

- [ ] Confirm `scripts/maintenance/backup.sh` runs nightly via cron
      (Ansible role `verdyx` installs the cron entry).
- [ ] Test restore on a staging cluster:
      `./scripts/maintenance/restore.sh --backup backups/<TIMESTAMP> --yes`.

## 9. Final checks

- [ ] `scripts/maintenance/check-migrations.sh` — no drift
- [ ] `curl https://api.verdyx.com/api/v1/health/ready` returns 200
- [ ] Frontend at `https://app.verdyx.com` loads and registers a test
      account end-to-end
- [ ] Bounty creation submits a transaction successfully on-chain
- [ ] Grafana dashboard "Verdyx — Platform Overview" shows live metrics

## Rollback

If something goes wrong, see
[`docs/database/rollback-strategy.md`](../database/rollback-strategy.md)
for DB-level rollback and
[`docs/operations/incident-response.md`](./incident-response.md) for
incident handling.
