# L.O.L | Link-Open-Lab

```text
 _      ____   _
| |    / __ \ | |
| |   | |  | || |
| |   | |  | || |
| |___| |__| || |____
|______\____/ |______|
```

[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![PHP](https://img.shields.io/badge/PHP-CLI-777BB4?logo=php&logoColor=white)](https://www.php.net/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Author](<https://img.shields.io/badge/Author-Abdalla%20Omran%20(dx0rz)-111827>)](https://github.com/dx0rz)

Professional Unified Phishing Simulation & Security Auditing Framework by Abdalla Omran (dx0rz).

## Elevator Pitch

L.O.L is a unified, automation-first framework designed for controlled phishing simulation, form-flow analysis, and defensive security auditing in authorized lab environments. It combines Python orchestration, PHP template execution, and optional cloud tunnel exposure into one streamlined developer experience.

## Core Architecture

L.O.L orchestrates three layers seamlessly:

1. Python Control Plane
   : Service orchestration, proxying, monitoring, NDJSON event normalization, and live dashboard rendering.
2. PHP Execution Layer
   : Template runtime served from published content in `.lol_runtime/www`.
3. Cloudflared Edge Bridge (Optional)
   : Automatic temporary public URL provisioning for controlled remote testing.

This architecture provides a reproducible end-to-end workflow with minimal manual setup.

## F34TUR3 SH0WC4S3

- 🛡️ Real-time proxying and request inspection
- 🎭 30+ pre-built templates from `.sites`
- ☁️ Instant cloudflared tunneling with live URL capture
- 📡 Live dashboard with local/public endpoints and service status
- 🧾 Compact NDJSON capture pipeline (one event per line)
- 🧠 Smart credential-like field extraction for security analysis
- 🧰 Docker-ready runtime for portable execution
- 🔔 Optional Telegram status/alert notifications

## Requirements

- Python 3.12+
- PHP CLI
- cloudflared (optional)

## Installation (From Scratch)

### 1. Clone repository

```bash
git clone https://github.com/dx0rz/L.O.L.git
cd L.O.L
```

### 2. Create virtual environment (recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

### 3. Validate setup

```bash
python3 main.py --list-sites
```

### 4. Start framework

```bash
python3 main.py
```

## First Run Experience

When you launch L.O.L:

1. Pick a template from the interactive list.
2. L.O.L publishes it to `.lol_runtime/www`.
3. PHP backend + Python monitor start automatically.
4. If cloudflared is available, a public tunnel URL is captured.
5. Live captures are rendered in the dashboard panel in real time.

## Professional CLI Reference

| Flag                   | Description                                         |
| ---------------------- | --------------------------------------------------- |
| `--project-root`       | Set workspace root directory.                       |
| `--sites-dir`          | Set template library directory (default: `.sites`). |
| `--site`               | Select a specific template to serve.                |
| `--list-sites`         | List available templates and exit.                  |
| `--php-host`           | PHP bind host.                                      |
| `--php-port`           | PHP bind port.                                      |
| `-p`, `--port`         | Legacy alias for `--php-port`.                      |
| `--monitor-host`       | Proxy/dashboard bind host.                          |
| `--monitor-port`       | Proxy/dashboard bind port.                          |
| `--traffic-log-file`   | NDJSON output path for captured traffic.            |
| `--cloudflared-url`    | Explicit cloudflared target URL override.           |
| `--php-router`         | Optional PHP router script path.                    |
| `--telegram-bot-token` | Optional Telegram bot token.                        |
| `--telegram-chat-id`   | Optional Telegram chat id.                          |
| `-c`, `--show-auth`    | Print credential-like data from log and exit.       |
| `-i`, `--show-ip`      | Print unique client IPs from log and exit.          |

## Command Examples

```bash
python3 main.py --site instagram
python3 main.py --monitor-port 8081 --php-port 8001
python3 main.py --show-auth --traffic-log-file traffic_log.json
python3 main.py --show-ip --traffic-log-file traffic_log.json
```

## Logging Format (NDJSON)

Each capture event is stored as one JSON line:

```json
{
  "timestamp": "2026-03-19T00:00:00Z",
  "site": "yahoo",
  "user": "example@mail.com",
  "pass": "example-password"
}
```

## Visuals

The screenshots below illustrate the default operator flow and dashboard experience.

![Interactive Template Selection](.github/misc/screenshot-template-selection.png)
![Live Dashboard and Tunnel Status](.github/misc/screenshot-live-dashboard.png)

## Docker

```bash
docker build -t lol-link-open-lab:release .
docker run --rm lol-link-open-lab:release python3 main.py --list-sites
```

## Troubleshooting

### `externally-managed-environment` during pip install

Use a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

### `php: command not found`

```bash
sudo apt install php-cli
```

### cloudflared URL not appearing

- Ensure `cloudflared` is installed and executable.
- Restart and wait a few seconds for tunnel initialization.

## Legal Warning

**This project is strictly for educational, authorized testing, and defensive security research. Unauthorized deployment, phishing abuse, credential theft, or testing without explicit permission is prohibited. You are solely responsible for legal compliance in your jurisdiction. The lead developer, Abdalla Omran (dx0rz), disclaims liability for misuse or unlawful operation.**

## Security & Privacy Best Practices

- Never commit `.lol_runtime/` or runtime logs.
- Sanitize screenshots before publishing.
- Mask local usernames, tunnel URLs, and captured credentials.
- Keep Telegram tokens and chat IDs out of source control.

## Maintainer

Lead Developer: Abdalla Omran (dx0rz)

## License

GPL-3.0. See `LICENSE`.
