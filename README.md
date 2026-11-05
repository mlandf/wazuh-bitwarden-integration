# Wazuh Bitwarden Integration

Custom Wazuh decoders, rules and OpenSearch alerting for self-hosted [Bitwarden](https://bitwarden.com/) instances (Docker deployment).

Detects failed logins, brute force attempts, application errors and service disruptions — with optional Microsoft Teams notifications via OpenSearch Alerting.

## Features

- **Custom decoder** for Bitwarden's Serilog format with pcre2 regex
- **Field extraction** — `srcip` and `dstuser` from failed login events
- **17 detection rules** covering authentication failures, errors, shutdowns, brute force
- **Noise suppression** — healthchecks and feature flag warnings silenced (level 0)
- **OpenSearch alert** with Teams webhook (MessageCard format)

## Architecture

```
Bitwarden Server                        Wazuh Manager
┌─────────────────────┐                 ┌──────────────────────────────┐
│ Bitwarden (Docker)  │                 │ Wazuh Manager                │
│  └─ bwdata/logs/    │                 │  ├─ Decoder (pcre2)          │
│      ├─ admin/      │   TCP/1514      │  │  ├─ log_level             │
│      ├─ api/        │ ──────────────► │  │  ├─ message               │
│      ├─ identity/   │   AES           │  │  ├─ srcip (failed login)  │
│      ├─ events/     │                 │  │  └─ dstuser (failed login)│
│      ├─ sso/        │                 │  ├─ Rules (100800–100899)    │
│      ├─ nginx/      │                 │  │  ├─ INF  → Level 3       │
│      └─ mssql/      │                 │  │  ├─ WRN  → Level 7       │
│                     │                 │  │  ├─ ERR  → Level 10      │
│ Wazuh Agent         │                 │  │  └─ FTL  → Level 13      │
│                     │                 │  ├─ OpenSearch Alerting      │
│                     │                 │  │  └─ Teams Webhook         │
│                     │                 │  └─ Wazuh Dashboard          │
└─────────────────────┘                 └──────────────────────────────┘
```

## Log Format

Bitwarden uses [Serilog](https://serilog.net/) with this format:

```
YYYY-MM-DDThh:mm:ss.nnnnnnn+00:00 [RequestID] [LEVEL] message (event_id)
```

Examples:
```
2024-01-15T10:05:00.0002591+00:00  [INF] Starting job "DeleteSendsJob" (41861683)
2024-01-15T10:05:00.0002591+00:00 0HNPQT458G3D8:00000001 [WRN] Failed login attempt. IpAddress: "10.1.2.3" (811b9f1e)
2024-01-15T10:05:02.0002591+00:00 0HNPQT458G3D8:00000001 [INF] "User authentication failed: ": "invalid_username_or_password", details: TokenRequestValidationLog { ...UserName: "user@example.com"... } (d2b492ef)
```

The pre-decoder parses the request ID (e.g. `0HNPQT458G3D8`) as `program_name`, which is why two parent decoders are needed.

## Rules Overview

| Rule ID | Level | Description | Group |
|---|---|---|---|
| **100800** | 0 | Base rule: any Bitwarden Serilog event | bitwarden |
| **100801** | 0 | `/alive` healthchecks (suppressed) | bitwarden |
| **100802** | 0 | Unknown feature flag (suppressed) | bitwarden |
| **100810** | 3 | INF-level events | bitwarden |
| **100820** | 7 | WRN-level events | bitwarden |
| **100830** | 10 | ERR-level events | bitwarden |
| **100835** | 13 | FTL-level events (fatal) | bitwarden |
| **100840** | 7 | Application shutdown | bitwarden |
| **100841** | 3 | Application started | bitwarden |
| **100842** | 7 | LaunchDarkly SDK key invalid | bitwarden |
| **100850** | 9 | Failed login (WRN: Invalid password / Failed login attempt) | authentication_failed |
| **100852** | 9 | Failed login (INF: invalid_username_or_password) | authentication_failed |
| **100851** | 12 | Brute force (5 failures in 2 minutes) | authentication_failures |
| **100860** | 5 | User created/invited | account_changed |
| **100870** | 10 | Database error (MSSQL) | bitwarden |
| **100880** | 5 | Data protection keys not persisted | bitwarden |

## Installation

### Prerequisites

- Wazuh Manager 4.x
- Wazuh Agent installed on the Bitwarden server
- Self-hosted Bitwarden (Docker deployment with `bwdata/logs/`)

### 1. Agent Configuration (Bitwarden Server)

#### 1.1 Set File Permissions

The `wazuh` user needs read access to Bitwarden logs. Since `/opt/bitwarden/` is typically restricted, use ACLs:

```bash
apt install acl

# Execute permission on parent directories
setfacl -m u:wazuh:x /opt/bitwarden
setfacl -m u:wazuh:x /opt/bitwarden/bwdata
setfacl -m u:wazuh:x /opt/bitwarden/bwdata/logs

# Execute permission on all log subdirectories
for dir in admin admin/Admin api api/Api events events/Events \
           identity identity/Identity notifications notifications/Notifications \
           sso sso/SSO nginx mssql; do
  setfacl -m u:wazuh:x /opt/bitwarden/bwdata/logs/$dir
done

# Read access + default ACL for new files
setfacl -R -m u:wazuh:rX /opt/bitwarden/bwdata/logs
setfacl -R -d -m u:wazuh:rX /opt/bitwarden/bwdata/logs

# Verify
sudo -u wazuh cat /opt/bitwarden/bwdata/logs/admin/Admin/$(date +%Y%m%d).txt | head -3
```

#### 1.2 Add localfile Entries to ossec.conf

Add before the last `</ossec_config>` in `/var/ossec/etc/ossec.conf`:

```xml
<!-- Bitwarden - .NET Services (Serilog) -->
<localfile>
  <log_format>syslog</log_format>
  <location>/opt/bitwarden/bwdata/logs/admin/Admin/*.txt</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/opt/bitwarden/bwdata/logs/api/Api/*.txt</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/opt/bitwarden/bwdata/logs/events/Events/*.txt</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/opt/bitwarden/bwdata/logs/identity/Identity/*.txt</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/opt/bitwarden/bwdata/logs/notifications/Notifications/*.txt</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/opt/bitwarden/bwdata/logs/sso/SSO/*.txt</location>
</localfile>

<!-- Bitwarden - Nginx -->
<localfile>
  <log_format>apache</log_format>
  <location>/opt/bitwarden/bwdata/logs/nginx/access.log</location>
</localfile>

<localfile>
  <log_format>apache</log_format>
  <location>/opt/bitwarden/bwdata/logs/nginx/error.log</location>
</localfile>

<!-- Bitwarden - MSSQL -->
<localfile>
  <log_format>multi-line:3</log_format>
  <location>/opt/bitwarden/bwdata/logs/mssql/errorlog</location>
</localfile>
```

> **Important:** Use `syslog` format, not `multi-line:3`, for the Serilog logs. With multi-line, events are bundled together and individual login failures get buried in combined blocks.

#### 1.3 Restart Agent

```bash
systemctl restart wazuh-agent
```

### 2. Manager Configuration (Wazuh Manager)

#### 2.1 Install Decoder and Rules

```bash
cp 0850-bitwarden_decoders.xml /var/ossec/etc/decoders/
cp 0850-bitwarden_rules.xml /var/ossec/etc/rules/
```

#### 2.2 Validate and Restart

```bash
/var/ossec/bin/wazuh-analysisd -t
systemctl restart wazuh-manager
```

### 3. OpenSearch Alerting (Optional)

The included monitor sends Microsoft Teams notifications on failed login attempts.

#### 3.1 Prerequisites

- Create a Teams Incoming Webhook and configure it as an OpenSearch Alerting destination
- Note the `destination_id` from OpenSearch

#### 3.2 Configure

Edit `opensearch-alert-bitwarden-failed-logins.json`:
- Replace `<YOUR_TEAMS_DESTINATION_ID>` with your destination ID
- Replace `<YOUR_WAZUH_DASHBOARD>` with your dashboard IP/hostname

#### 3.3 Import

```bash
curl -k -u admin:$OS_PASS -X POST "https://127.0.0.1:9200/_plugins/_alerting/monitors/" \
  -H 'Content-Type: application/json' \
  -d @opensearch-alert-bitwarden-failed-logins.json
```

#### 3.4 Test

```bash
# Replace <MONITOR_ID> with the ID from the create response
curl -k -u admin:$OS_PASS -X POST \
  "https://127.0.0.1:9200/_plugins/_alerting/monitors/<MONITOR_ID>/_execute"
```

The Teams notification shows:

| Field | Source | Available for |
|---|---|---|
| **Benutzer** (username) | `data.dstuser` | Rule 100852 (INF line) |
| **Quell-IP** (source IP) | `data.srcip` | Rule 100850 (WRN line) |
| **Zeit** (timestamp) | `timestamp` | All rules |
| **Server** | `agent.name` | All rules |

## Decoder Details

### Why Two Parent Decoders?

Bitwarden logs come in two variants:
- **With request ID:** `...+00:00 0HNPQT458G3D8:00000001 [WRN] Failed login...`
- **Without request ID:** `...+00:00  [INF] Starting job...`

The Wazuh pre-decoder parses `0HNPQT458G3D8` as `program_name`. The first parent decoder matches these via `<program_name>^0HN</program_name>`. The second uses `<prematch>\p\w\w\w\p</prematch>` (OS_Regex matching `[INF]`, `[WRN]`, etc.) for logs without a request ID.

### Why Child Decoders Need prematch

When child decoders exist for a parent, Wazuh tries each child's regex in order. **If a child's regex beginning matches but the full pattern fails, Wazuh commits to that child and skips all subsequent children.** This means a child decoder for `IpAddress:` would block the fallback decoder for lines without an IP address.

The fix: add `<prematch>` to each child decoder. Wazuh only tries a child's regex if its prematch succeeds first, allowing clean fallthrough to the next child.

```
Log line with IpAddress:  → prematch "IpAddress:" matches  → IP child extracts srcip
Log line with UserName:   → prematch "UserName:" matches   → User child extracts dstuser
Any other log line:       → no prematch on fallback        → base child extracts log_level + message
```

## Testing

### Decoder Test with wazuh-logtest

```bash
# INF event
echo '2024-01-15T10:05:00.0002591+00:00  [INF] Starting job "DeleteSendsJob" (41861683)' \
  | /var/ossec/bin/wazuh-logtest

# Failed login (WRN — extracts srcip)
echo '2024-01-15T10:05:00.0002591+00:00 0HNPQT458G3D8:00000001 [WRN] Failed login attempt. Is2FARequest: False IpAddress: "10.1.2.3" (811b9f1e)' \
  | /var/ossec/bin/wazuh-logtest

# Failed login (INF — extracts dstuser)
echo '2024-01-15T10:05:02.0002591+00:00 0HNPQT458G3D8:00000001 [INF] "User authentication failed: ": "invalid_username_or_password", details: TokenRequestValidationLog { ClientId: "web", UserName: "user@example.com", Raw: [] } (d2b492ef)' \
  | /var/ossec/bin/wazuh-logtest
```

### Live Verification (Manager)

```bash
# All Bitwarden events in archive
grep -i "bwdata" /var/ossec/logs/archives/archives.log | tail -20

# Alerts only
grep "bitwarden" /var/ossec/logs/alerts/alerts.log | tail -20
```

### Wazuh Dashboard

Filter: `rule.groups: bitwarden` or `agent.name: Bitwarden`

## Monitored Log Sources

| Directory | Format | Pattern | Content |
|---|---|---|---|
| `admin/Admin/` | Serilog (syslog) | `YYYYMMDD.txt` | Background jobs |
| `api/Api/` | Serilog (syslog) | `YYYYMMDD.txt` | API calls, EmergencyAccess |
| `events/Events/` | Serilog (syslog) | `YYYYMMDD.txt` | Event processing |
| `identity/Identity/` | Serilog (syslog) | `YYYYMMDD.txt` | IdentityServer, logins, tokens |
| `notifications/Notifications/` | Serilog (syslog) | `YYYYMMDD.txt` | SignalR, push notifications |
| `sso/SSO/` | Serilog (syslog) | `YYYYMMDD.txt` | SSO endpoints, SAML/OIDC |
| `nginx/` | Apache Combined | `access.log`, `error.log` | HTTP access (built-in decoder) |
| `mssql/` | Multi-line | `errorlog` | MSSQL errors |

**Not monitored:**
- `icons/` — favicon fetching only (noise)
- `portal/` — typically empty
- `mssql/*.xel` — binary Extended Events (not readable by Wazuh)

## Troubleshooting

| Problem | Solution |
|---|---|
| No events in archive | Check `<logall>yes</logall>` in manager ossec.conf |
| Permission denied on logs | Verify ACLs: `getfacl /opt/bitwarden/bwdata/logs/` |
| Decoder doesn't match | Feed a real log line to `wazuh-logtest` |
| New log files not read | Check default ACL: should show `default:user:wazuh:r-x` |
| Agent not reading files | Check agent log: `grep -i "bwdata\|error" /var/ossec/logs/ossec.log` |
| Child decoder fields missing | Ensure child decoders have `<prematch>` (see Decoder Details above) |

## Files

```
wazuh-bitwarden-integration/
├── README.md                                          # This documentation
├── 0850-bitwarden_decoders.xml                        # → /var/ossec/etc/decoders/ (Manager)
├── 0850-bitwarden_rules.xml                           # → /var/ossec/etc/rules/ (Manager)
└── opensearch-alert-bitwarden-failed-logins.json      # OpenSearch Alerting monitor (import via API)
```

## Compatibility

- Tested with Wazuh 4.14.x and Bitwarden self-hosted (Docker)
- Requires pcre2 regex support in decoders (Wazuh 4.2+)
- OpenSearch Alerting plugin for Teams notifications

## License

MIT
