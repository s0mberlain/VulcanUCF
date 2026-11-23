# Vulcan UCF on Kubernetes

```
Ingress (TLS) ─→ Service vulcan ─→ Deployment vulcan (1..N pods, image from private GHCR)
                                        │  DATABASE_URL = Secret vulcan-db-app / uri
                                        ▼
                                   CloudNativePG Cluster vulcan-db (primary + standby)
                                        ▲
                                   CronJob vulcan-backup (daily pg_dump → PVC, 14 days)
```

All app data, including interview and purple team evidence files, lives in PostgreSQL. The app
pods keep nothing that has to survive a restart.

| File | What it is |
|---|---|
| `namespace.yaml` | Namespace `vulcan`, Pod Security Standard *restricted* enforced |
| `postgres.yaml` | CloudNativePG `Cluster`: 2 instances, PostgreSQL 16, 10 Gi each |
| `configmap.yaml` | Non-secret settings: `BASE_URL`, `FORWARDED_ALLOW_IPS`, … |
| `deployment.yaml` | The app: non-root (UID 999), read-only root filesystem, no capabilities, probes |
| `service.yaml`, `ingress.yaml` | Port 80 → 8080, TLS at the ingress (ingress-nginx class) |
| `networkpolicy.yaml` | Default deny; app only from the ingress controller; DB only from app, backup, operator |
| `backup-cronjob.yaml` | Daily `pg_dump` to a 20 Gi PVC |

## 1. Install the CloudNativePG operator (once per cluster)

```bash
helm repo add cnpg https://cloudnative-pg.github.io/charts
helm upgrade --install cnpg --namespace cnpg-system --create-namespace cnpg/cloudnative-pg
```

(Or from Rancher: Apps → Charts → CloudNativePG.) `networkpolicy.yaml` expects the operator in
the namespace `cnpg-system`.

## 2. Adjust to your cluster

- `configmap.yaml`: `BASE_URL` (your https address) and `FORWARDED_ALLOW_IPS` (pod CIDR of the
  ingress controller; `10.42.0.0/16` is the RKE2 / k3s default).
- `ingress.yaml`: host name, `ingressClassName`, TLS secret or the cert-manager annotation.
- `networkpolicy.yaml`: the ingress controller's namespace (`kube-system` on RKE2 / k3s).
- `postgres.yaml` / `backup-cronjob.yaml`: storage sizes, optionally `storageClass`.
- `deployment.yaml`: the image tag.

## 3. Create the namespace and the secrets

Secrets are not stored in this folder.

```bash
kubectl apply -f namespace.yaml

# App secrets. Keep SECRET_KEY somewhere safe (password manager): it encrypts the 2FA secrets.
kubectl -n vulcan create secret generic vulcan-app \
  --from-literal=SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')" \
  --from-literal=ADMIN_PASSWORD='<initial admin password, 12+ chars>'

# Pull access to the private GHCR image: a classic token with only read:packages.
kubectl -n vulcan create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io --docker-username=<github-user> --docker-password="$GHCR_READ_PAT"
```

`ADMIN_PASSWORD` is only used to create the `admin` account on an empty database. After the
first sign-in you can delete it from the secret:
`kubectl -n vulcan patch secret vulcan-app --type=json -p='[{"op":"remove","path":"/data/ADMIN_PASSWORD"}]'`.

## 4. Deploy

```bash
kubectl apply -k .
kubectl -n vulcan get cluster vulcan-db     # wait for "Cluster in healthy state"
kubectl -n vulcan rollout status deploy/vulcan
```

The first start migrates the database and seeds the catalogue. Sign in as `admin` at `BASE_URL`.

## Updating

Push a new image tag, change `image:` in `deployment.yaml`, `kubectl apply -k .`. Migrations run
on start; with several replicas they run under a database lock.

## Backups and restore

- Run a backup now: `kubectl -n vulcan create job --from=cronjob/vulcan-backup backup-now`.
- The dumps stay in the cluster (PVC `vulcan-backup`). Copy them off-site, or configure
  CloudNativePG's Barman Cloud plugin for S3-compatible storage with point-in-time recovery.
- Restore a dump into the cluster:
  ```bash
  kubectl -n vulcan scale deploy/vulcan --replicas=0
  kubectl -n vulcan exec -i vulcan-db-1 -- pg_restore --clean --if-exists -d magma < vulcan-<date>.dump
  kubectl -n vulcan scale deploy/vulcan --replicas=1
  ```
  (`vulcan-db-1` must be the primary: `kubectl -n vulcan get cluster vulcan-db` shows it.)

## Security notes

- Rotate the `ghcr-pull` token on a schedule; a `read:packages` token can read all private
  packages of its account.
- Leave `DEMO_DATA` / `ALLOW_DEMO_DATA` unset in production.
- With more than one replica, the per-IP login limit counts per pod; the per-account lockout is
  in the database and unaffected.
