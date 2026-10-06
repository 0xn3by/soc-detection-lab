# Dockerized Splunk on Fedora/Linux

## Prerequisites

Use an x86-64 Linux host, Python 3.10+, Docker Engine, and Docker Compose v2 or
newer. Allow roughly 4 CPU cores, 8 GB available RAM, and 15 GB free disk as a
practical lab budget, not an official production sizing recommendation. Initial
image download and startup require internet access and may take several minutes.

Check existing tools first:

```bash
python3 --version
docker --version
docker compose version
docker info
```

If Docker is absent, follow the current [official Fedora installation guide](https://docs.docker.com/engine/install/fedora/).
For a clean supported Fedora installation using Docker's repository:

```bash
sudo dnf install dnf-plugins-core
sudo dnf config-manager addrepo --from-repofile=https://download.docker.com/linux/fedora/docker-ce.repo
sudo dnf install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker info
```

Do not mix an existing Fedora/Moby installation with Docker CE unnecessarily.
If your user lacks daemon access, use `sudo docker ...` consistently for Docker
commands. Do not make the Docker socket world-writable. Container administration
provides extensive host privileges.

## Credentials and startup

The version is pinned to `splunk/splunk:10.0.0` for a repeatable starting point;
it is not a claim that this is the latest or security-supported release. Before
extended use, select a current supported image and repeat the validation checklist.
The service is only exposed on loopback. No HEC or management port is published.

```bash
cp -n .env.example .env
chmod 600 .env
python3 scripts/generate_events.py
```

Edit `.env` in a local editor. Set `SPLUNK_PASSWORD` to a unique password with at
least 12 characters, upper/lowercase letters, and digits. Use letters and digits
for the simplest Compose parsing; never paste it into screenshots or Git.
The password is used for the initial `admin` account. Changing `.env` after
initialization does not reset an existing account in the persistent volume.

Read the [Splunk Docker licensing instructions](https://github.com/splunk/docker-splunk#license)
and applicable [Splunk terms](https://www.splunk.com/en_us/legal/splunk-general-terms.html).
If you accept them, set these entries in your local `.env`:

```dotenv
SPLUNK_START_ARGS=--accept-license
SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com
```

Splunk 10.x Docker images require both acceptance settings, as documented by the
[official image repository](https://github.com/splunk/docker-splunk).
They are intentionally empty in the example file. There is no bundled license;
trial/free capabilities and expiration depend on the installed Splunk license.

```bash
docker compose config --quiet
docker compose pull
docker compose up -d
docker compose ps
docker compose logs --tail=80 splunk
```

Wait for initialization, then open **http://127.0.0.1:8000**. Sign in as `admin`
with the password from `.env`. Use **Search & Reporting**. Set the search user's
time zone to UTC in account preferences so displayed timelines match the reports.
Select **All time**: fixtures use **2026-01-15**, not the current date.

The container's image health check, startup logs, and a successful login are
better indicators than merely seeing a container listed as running. Keep logs
private because startup diagnostics can include environment details.

## Storage and network

- `127.0.0.1:8000` exposes Splunk Web only to the host. Do not change it to a
  public binding for this lab.
- Named volumes `splunk-etc` and `splunk-var` persist configuration and indexes.
- `setup/splunk-app` is mounted read-only as the `soc_lab` app.
- `logs` is mounted read-only at `/lab/logs`. The input monitors `*.jsonl`.
- The `Z` mount option gives the two project directories private SELinux labels
  for this container on Fedora. Keep SELinux enabled.
- There is no forwarder, HEC token, cloud service, real endpoint, or external scan.

The app mount follows Splunk's documented [volume-mounted app approach](https://github.com/splunk/docker-splunk/blob/develop/docs/advanced/APP_INSTALL.md).
Make app changes in the repository and restart the container; the mounted app
cannot be edited through Splunk Web. Save your search reports in Search & Reporting.

Stop while retaining state:

```bash
docker compose stop
```

Restart with `docker compose start`. `docker compose down` removes the container
and network while keeping named volumes. **`docker compose down -v` deletes this
lab's Splunk indexes and credentials**; use it only for an intentional full reset.
Do not reset other Docker projects or delete system logs.

## Troubleshooting

- **Permission denied on Docker socket:** check `sudo docker info`; use sudo for
  Docker operations or follow your host's authorized Docker access procedure.
- **Missing variable / weak password:** edit `.env`, keep it out of Git, and
  rerun `docker compose config --quiet`. Avoid `docker compose config` without
  `--quiet`, which expands the password into terminal output.
- **Image unavailable / unsupported architecture:** inspect the image tag in
  Docker Hub and host `uname -m`; this guide targets x86-64. Set `SPLUNK_IMAGE`
  to an available supported release and document the one actually tested.
- **Startup fails / container exits:** inspect `docker compose logs --tail=80
  splunk`, available RAM, disk, and licensing settings. Do not disable license checks.
- **Port occupied:** change only the host side to `127.0.0.1:8001:8000` and open
  port 8001 instead.
- **Bind mount access denied:** ensure project directories are traversable and
  config/log files readable. Preserve `:ro,Z`; do not disable SELinux or use
  blanket `chmod 777`.
- **No events / wrong fields:** use the focused [ingestion checks](log-ingestion.md).
- **After app configuration changes:** run `docker compose restart splunk`.
  Timestamp parsing changes only affect newly indexed events; correct the config
  and intentionally reset this lab if the initial data was indexed incorrectly.
