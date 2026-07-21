# Windows Server 2019 Production Deployment

## Architecture

CTI Dashboard Version 1.0 runs as a modular Flask application behind Waitress:

```text
Internal client
    |
TCP 8000 (Domain and Private network profiles)
    |
Windows Service: CTIDashboard
    |
NSSM service wrapper
    |
Windows PowerShell (non-interactive)
    |
scripts/start-cti-dashboard.ps1
    |
.venv/Scripts/waitress-serve.exe
    |
wsgi:app -> Flask Application Factory
    |
SQL Server 2022 Express on WEBSERVER01:14330
```

NSSM supervises the foreground PowerShell/Waitress process and redirects standard output and error to files under `logs`. The application remains internal HTTP unless an approved TLS reverse proxy is added later.

## Prerequisites

- Windows Server 2019 with current security updates.
- PowerShell 5.1 or later.
- Python 3.13 and the existing virtual environment at `D:\project\CTI-Dashboard\.venv`.
- Microsoft ODBC Driver 18 for SQL Server.
- SQL Server 2022 Express reachable at `WEBSERVER01:14330`.
- `CTIDashboard` database initialized with the approved SQL scripts.
- A dedicated Windows service identity with:
  - Log on as a service;
  - read/execute access to the project and virtual environment;
  - write access only to `D:\project\CTI-Dashboard\logs`;
  - Windows-authenticated SQL permissions limited to the application database.
- An approved NSSM binary supplied by the administrator. The project never downloads NSSM.
- Local administrator rights for service and firewall configuration.

## Production environment variables

The existing database configuration remains unchanged and is loaded through `.env`:

```dotenv
SQLALCHEMY_DATABASE_URI=mssql+pyodbc://@WEBSERVER01:14330/CTIDashboard?driver=ODBC+Driver+18+for+SQL+Server&trusted_connection=yes&TrustServerCertificate=yes
SECRET_KEY=<replace-with-a-long-random-value>
```

Protect `.env` with NTFS permissions granting access only to administrators and the service identity. Never place credentials in PowerShell scripts, service arguments, or logs.

Waitress settings use process environment variables:

| Variable | Default | Purpose |
|---|---:|---|
| `CTI_HOST` | `0.0.0.0` | Listen address |
| `CTI_PORT` | `8000` | Internal HTTP port |
| `CTI_THREADS` | `8` | Waitress worker threads |

Set machine-level values from an elevated shell before starting the service, if defaults are unsuitable:

```powershell
[Environment]::SetEnvironmentVariable("CTI_HOST", "0.0.0.0", "Machine")
[Environment]::SetEnvironmentVariable("CTI_PORT", "8000", "Machine")
[Environment]::SetEnvironmentVariable("CTI_THREADS", "8", "Machine")
```

Restart the service after changing these variables. The startup script validates numeric values and falls back to safe defaults for invalid ports or thread counts.

## Dependency installation

From an administrative deployment shell:

```powershell
Set-Location D:\project\CTI-Dashboard
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip show waitress
```

The supported project pin is `waitress==3.0.2`, which supports Python 3.13. Do not use Flask's development server in production.

## Manual Waitress test

Run this only during an approved maintenance/test window:

```powershell
Set-Location D:\project\CTI-Dashboard
.\scripts\start-cti-dashboard.ps1
```

The script does not activate the virtual environment. It executes the virtual environment's `waitress-serve.exe` directly and serves `wsgi:app` with debug and traceback exposure disabled.

From a second shell:

```powershell
Invoke-RestMethod http://localhost:8000/health
```

Stop the manual test with Ctrl+C before installing or starting the service.

## Health endpoint

`GET /health` performs `SELECT 1` through SQLAlchemy using a short-lived connection.

Healthy response:

```json
{"application":"CTI Dashboard","status":"ok"}
```

Database-unavailable response uses HTTP 503:

```json
{"application":"CTI Dashboard","status":"unavailable"}
```

The endpoint performs no writes and returns no exception, connection string, database credential, or stack trace.

## NSSM preparation

1. Obtain NSSM through the organization's approved software process.
2. Verify its source, version, digital signature, and approved file hash.
3. Place the 64-bit executable at an administrator-controlled path such as:

   ```text
   C:\Tools\nssm\win64\nssm.exe
   ```

4. Do not place NSSM in the project virtual environment and do not download it from the installation script.

Built-in `sc.exe` can register an executable, but it cannot reliably supervise an arbitrary foreground PowerShell script as a service. NSSM supplies the required Windows service wrapper while `sc.exe` configures recovery actions.

## Service installation

Do not install until the manual Waitress and health checks succeed.

From elevated PowerShell:

```powershell
Set-Location D:\project\CTI-Dashboard
.\scripts\install-cti-dashboard-service.ps1 `
    -NssmPath C:\Tools\nssm\win64\nssm.exe
```

The script creates but does not start:

- service name `CTIDashboard`;
- display name `CTI Dashboard`;
- Automatic startup;
- working directory `D:\project\CTI-Dashboard` when deployed at the specified project path;
- restart recovery after first, second, and subsequent failures;
- stdout and stderr log redirection with 10 MB rotation.

Before first start, open `services.msc`, open **CTI Dashboard**, select **Log On**, and assign the approved service identity. Do not use an interactive administrator account. Confirm that the same identity can connect to SQL Server using Windows Integrated Authentication.

## Service operations

Start:

```powershell
Start-Service CTIDashboard
```

Stop:

```powershell
Stop-Service CTIDashboard
```

Restart:

```powershell
Restart-Service CTIDashboard
```

Status:

```powershell
Get-Service CTIDashboard
sc.exe query CTIDashboard
```

Recovery configuration:

```powershell
sc.exe qfailure CTIDashboard
```

The implementation does not start the service automatically.

## Firewall configuration

Create or reconcile the inbound TCP 8000 rule from elevated PowerShell:

```powershell
.\scripts\configure-cti-firewall.ps1
```

The rule applies only to Domain and Private profiles and is idempotent.

Remove it explicitly:

```powershell
.\scripts\configure-cti-firewall.ps1 -Remove
```

The implementation does not execute either command automatically. For stronger internal restriction, narrow the rule's remote addresses through an approved operational change after confirming client subnets.

## Client access test

From an allowed internal workstation:

```powershell
Test-NetConnection WEBSERVER01 -Port 8000
Invoke-RestMethod http://WEBSERVER01:8000/health
```

Then open:

```text
http://WEBSERVER01:8000/
```

A failed health check with TCP connectivity generally indicates application or database connectivity failure. A failed TCP test generally indicates service, binding, routing, or firewall configuration.

## Log locations

NSSM redirects process streams to:

```text
D:\project\CTI-Dashboard\logs\cti-dashboard-stdout.log
D:\project\CTI-Dashboard\logs\cti-dashboard-stderr.log
```

The files rotate at approximately 10 MB through NSSM settings. Also review Windows Event Viewer and NSSM service events. Logs are excluded from Git while `logs/.gitkeep` preserves the directory.

Do not log `.env`, connection strings, service credentials, cookies, or request authorization data. Protect logs with NTFS permissions and include them in the organization's retention and monitoring policy.

## Database connectivity checks

Network reachability:

```powershell
Test-NetConnection WEBSERVER01 -Port 14330
```

Application-level connectivity:

```powershell
Invoke-RestMethod http://localhost:8000/health
```

If Windows Trusted Connection fails under the service but succeeds interactively, verify:

- the CTIDashboard service Log On identity;
- SQL Server login/user mapping for that Windows identity;
- database permissions;
- SQL Server TCP/IP and port 14330 configuration;
- ODBC Driver 18 availability to the service process;
- SPN/Kerberos policy where domain authentication requires it;
- `.env` NTFS access and URI formatting.

## Rollback and uninstall

Stop and remove only the service:

```powershell
Set-Location D:\project\CTI-Dashboard
.\scripts\uninstall-cti-dashboard-service.ps1
```

Remove the firewall rule separately:

```powershell
.\scripts\configure-cti-firewall.ps1 -Remove
```

The uninstall script does not delete application files, virtual environments, logs, Product Catalog data, Assets, Threats, or any database data.

For an application rollback:

1. Stop `CTIDashboard`.
2. Restore the previously approved application release directory and dependency lock/pins.
3. Preserve `.env` and logs with their ACLs.
4. Restore the database only when a database rollback is explicitly approved and restore-tested.
5. Reinstall dependencies if requirements changed.
6. Start the service and verify `/health` before client access.

## Troubleshooting

### Service stops immediately

- Read both files under `logs`.
- Run `Get-Service CTIDashboard` and `sc.exe queryex CTIDashboard`.
- Confirm `.venv\Scripts\waitress-serve.exe` exists.
- Run the startup script manually under the intended service identity.
- Check the service working directory and PowerShell execution policy.

### Port is unavailable

```powershell
Get-NetTCPConnection -LocalPort 8000
```

Stop the conflicting process or approve a coordinated `CTI_PORT` and firewall change. The supplied firewall script is fixed to the Version 1.0 port 8000.

### Health returns 503

- Test SQL port 14330.
- Validate service-account Windows authentication and database permissions.
- Confirm SQL Server and the CTIDashboard database are online.
- Review application logs for the generic exception type.

### Clients cannot connect

- Confirm the service is Running.
- Confirm Waitress is listening on the intended interface and port.
- Confirm the server's active network profile is Domain or Private.
- Confirm routing and the named inbound rule.

## Security limitations

- Version 1.0 has no application authentication or role-based access control.
- Direct Waitress access is HTTP without TLS.
- Binding to `0.0.0.0` exposes the listener on all server interfaces permitted by host firewall policy.
- Flask forms retain the project's current CSRF limitations.
- The health endpoint is unauthenticated but exposes only generic state.
- Internal-only placement and firewall profiles reduce exposure but do not replace authentication, TLS, network segmentation, host hardening, or monitoring.
- The fallback `SECRET_KEY` is not suitable for production; set a strong environment value.
- Run the service with least privilege and restrict `.env`, logs, source files, and the virtual environment with NTFS ACLs.

## Backup recommendation

Before deployment and before each upgrade:

- take a SQL Server full backup of `CTIDashboard`;
- copy the approved application release, `requirements.txt`, scripts, and configuration separately;
- protect `.env` as a secret and never place it in source control or ordinary logs;
- store backups off-host according to organizational policy;
- periodically restore-test both the database and application deployment;
- record the deployed Git revision and dependency versions in the change ticket.
