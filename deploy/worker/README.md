# Worker VM: ClamAV and the ML model

The main VM has 1 GB of memory. ClamAV needs about 1.2 GB for its signature
database and the Windows-program model needs about 200 MB, so both run on a
second machine: an Oracle **Always Free Ampere A1** VM in the same network. The
main VM reaches them over private addresses; nothing here is open to the
internet.

```
 main VM (1 GB)                          worker (A1, arm64)
 analysis-engine ──── 10.0.0.x:3310 ───▶ clamav (clamd)
                 └─── 10.0.0.x:8090 ───▶ ml-service (EMBER2024 model, token required)
```

## 1. Create the VM (Oracle Cloud console)

1. **Compute → Instances → Create instance.** Name it `verdyx-worker`.
2. **Image and shape → Edit:**
   - Image: **Canonical Ubuntu 24.04**. The aarch64 build is picked automatically for Ampere.
   - Shape: **Ampere → VM.Standard.A1.Flex**, **2 OCPUs and 12 GB** memory.
     Always Free covers up to 4 OCPUs and 24 GB in total, so this leaves room
     for later.
3. **Networking:** choose **the same VCN and subnet as the main VM**. Keep
   **Assign a public IPv4 address** on: it's for SSH and for pulling images.
4. **SSH keys:** upload the public key you already use, `~/.ssh/verdyx-oracle.pub`.
5. **Boot volume:** 50 GB is plenty. The free tier allows 200 GB in total.
6. **Create.**

**"Out of capacity"** is common for A1:
- Try the other availability domains under **Placement**.
- Try again later; capacity frees up through the day.
- Upgrading the account to **Pay As You Go** usually ends the problem. Always
  Free resources stay free on it. Add a budget alert (Billing → Budgets, e.g.
  $1) so you'd hear about any charge.

Once it's running, note two addresses from **Instance details → Primary VNIC**:
- the worker's **private IPv4 address**, `WORKER_PRIVATE_IP` below;
- its **public IPv4 address**, for SSH.

Also note the **main VM's private IPv4 address**, `MAIN_PRIVATE_IP` below.

## 2. Let the main VM reach it (security list)

**Networking → Virtual cloud networks → your VCN → Security Lists → Default
Security List → Add Ingress Rules**, one rule:

| Field | Value |
|---|---|
| Source CIDR | `MAIN_PRIVATE_IP/32` (e.g. `10.0.0.12/32`) |
| IP Protocol | TCP |
| Destination Port Range | `3310,8090` |
| Description | Verdyx main VM to worker |

Don't add these ports for `0.0.0.0/0`. clamd has no login at all.

## 3. Set it up (from your Mac)

Copy this folder to the worker and run the setup script. It installs Docker,
writes `/opt/verdyx-worker` with a new ML token, allows only the main VM through
the host firewall, and adds swap.

```bash
scp -i ~/.ssh/verdyx-oracle -r deploy/worker ubuntu@<WORKER_PUBLIC_IP>:~/
```

```bash
ssh -i ~/.ssh/verdyx-oracle ubuntu@<WORKER_PUBLIC_IP> 'sudo bash ~/worker/setup.sh <WORKER_PRIVATE_IP> <MAIN_PRIVATE_IP>'
```

## 4. Install the trained model

The bundle trained on your Mac is in `/Volumes/PD/Developer/verdyx-ml-bundle`:

```bash
scp -i ~/.ssh/verdyx-oracle /Volumes/PD/Developer/verdyx-ml-bundle/{model.txt,calibration.json,bundle.json,report.md} ubuntu@<WORKER_PUBLIC_IP>:/tmp/
```

```bash
ssh -i ~/.ssh/verdyx-oracle ubuntu@<WORKER_PUBLIC_IP> 'sudo mv /tmp/model.txt /tmp/calibration.json /tmp/bundle.json /tmp/report.md /opt/verdyx-worker/ml-models/pe/'
```

## 5. Start it

```bash
ssh -i ~/.ssh/verdyx-oracle ubuntu@<WORKER_PUBLIC_IP> 'cd /opt/verdyx-worker && sudo docker compose up -d'
```

The first start downloads ClamAV's signatures and takes a few minutes. Check
both services from the **main VM**, which also proves the network path:

```bash
curl -s http://<WORKER_PRIVATE_IP>:8090/health
```

```bash
printf 'zPING\0' | nc -w 5 <WORKER_PRIVATE_IP> 3310; echo
```

The first should show `"loaded": true` and `"quality_gate_passed": true`. The
second should print `PONG`.

## 6. Point the engine at it (main VM)

Read the token the setup wrote on the worker:

```bash
ssh -i ~/.ssh/verdyx-oracle ubuntu@<WORKER_PUBLIC_IP> 'sudo grep ML_SERVICE_TOKEN /opt/verdyx-worker/.env'
```

Add these lines to `/opt/verdyx/.env` on the main VM, replacing any existing
ones:

```
ENABLE_CLAMAV=true
CLAMAV_HOST=<WORKER_PRIVATE_IP>:3310
PE_MODEL_URL=http://<WORKER_PRIVATE_IP>:8090
PE_MODEL_VOTE=auto
ML_SERVICE_TOKEN=<the token>
```

Then recreate the engine:

```bash
cd /opt/verdyx && sudo docker compose -f docker-compose.gcp.yml up -d --force-recreate --no-deps analysis-engine
```

`https://api.verdyx.dev/api/v1/engines` should now list ClamAV as online and
**Windows Program Model (EMBER2024)**.

## Updates

Watchtower on the worker pulls new `ml-service` and ClamAV images. clamd also
updates its own signatures several times a day. To install a newly trained
model, replace the files in `/opt/verdyx-worker/ml-models/pe` and run
`sudo docker restart verdyx-ml-service`.
