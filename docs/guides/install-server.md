# Install the server
<!-- group: Start here; order: 2; pages: - -->

Run your own mustra server with Docker, from a fresh Linux machine to a console you can sign in to, then put it behind HTTPS and keep it up to date.

## What you need

- A Linux server (a virtual machine is fine). The image build needs about **6 GB** of free disk, and the message broker reserves **3 GB** more for agent messages; allow room for the database to grow with your fleet. The first build compiles the agent for six platforms and is the slowest step.
- **Docker** with the **compose** plugin (version 2).
- An address your endpoints can reach: the server's LAN IP, or a DNS name.
- Two free ports: **8080** for the console and **4222** for agents. You can choose others.

## 1. Get mustra and start it

```
git clone <repository URL> mustra
cd mustra/deploy
./init.sh --start
```

`init.sh` checks the machine, writes `deploy/.env` with newly generated secrets, creates the certificates agents use to trust the server (with this machine's LAN address in them), builds the images and starts everything. It ends by printing the console address.

If endpoints will reach the server by a different address or name than the one `init.sh` detects, name it:

```
./init.sh --ip 192.0.2.10 --start
./init.sh --public-hostname mustra.example.com --start
```

## 2. Create the first administrator

The server prints a one-time setup link the first time it starts:

```
docker compose logs server | grep "FIRST-RUN SETUP"
```

Open it, choose a username and a password of at least 12 characters, accept the [Terms of Use](https://github.com/mustra-dev/mustra/blob/main/TERMS.md), and **Create account**. The link stops working once used. There is no default password.

## 3. Put the console behind HTTPS

The console should be reached over HTTPS: sign-in cookies are marked secure and enrollment tokens travel through it.

- **Your own reverse proxy** (nginx, Caddy, Traefik): forward `https://mustra.example.com` to `http://<server>:8080`, and run `./init.sh --public-hostname mustra.example.com`.
- **Cloudflare Tunnel**: set your tunnel's credentials in `deploy/cloudflared/` and start the stack with `docker compose --profile tunnel up -d`.

For a test on a trusted network only, `./init.sh --insecure-http --start` serves plain HTTP on the LAN address.

Agents connect to port 4222 directly, with TLS, whatever you choose for the console.

## 4. Add endpoints

Follow [Getting started](getting-started.md) from step 2.

## Keep it safe

- **`deploy/.env` holds every secret**, including `MUSTRA_CREDENTIAL_ENCRYPTION_KEY`, which encrypts stored credentials. Back it up, and the `deploy/nats/certs/` folder, somewhere safe and separate from the server. A server backup does not include them.
- Turn on the nightly backup under **Backup**. See [Audit log and server backups](audit-and-backup.md).
- Require two-step sign-in for local accounts. See [Accounts, roles and sign-in](users-and-access.md).

## Upgrade

```
cd mustra
git pull
cd deploy
./init.sh --start
```

`init.sh` never overwrites existing settings or certificates; it only adds what a newer version needs, then rebuilds and restarts the stack. Database changes apply automatically when the server starts. Read the release notes under **Administration → About** first. Then update agents from **Client Management → Overview**.

## If it does not come up

| What you see | Usually |
| --- | --- |
| `server` keeps restarting; the log mentions placeholder secrets | `.env` was copied by hand instead of generated. Run `./init.sh`. |
| `nats` will not start | The certificates are missing. Run `./init.sh` again. |
| Agents install but never appear | The address in the install command is not reachable from the endpoint, or the certificate does not name it. Re-run `./init.sh --ip <address>` after deleting `deploy/nats/certs/`, then reinstall the agents. |
| Every agent reports `Authorization Violation` | The server is down; the broker asks it about every agent connection. |

`docker compose logs server` explains most other problems.
