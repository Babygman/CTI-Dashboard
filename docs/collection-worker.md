# Scheduled collection worker

The collection worker polls the `Sources` table, atomically leases due sources,
and invokes the same collector runner used by manual collection.

## Configuration

Set the same `SQLALCHEMY_DATABASE_URI` used by the web application. Optional
environment variables:

- `CTI_WORKER_POLL_INTERVAL_SECONDS` (default `30`)
- `CTI_WORKER_LEASE_TIMEOUT_SECONDS` (default `300`)
- `CTI_WORKER_HEARTBEAT_INTERVAL_SECONDS` (default `30`; must be less than the lease timeout)
- `CTI_WORKER_RETRY_INTERVAL_SECONDS` (default `300`)
- `CTI_WORKER_BATCH_SIZE` (default `25`)

Apply the database migration, then start the long-running process:

```powershell
.\.venv\Scripts\alembic.exe upgrade head
.\.venv\Scripts\python.exe worker.py
```

Run multiple worker processes for availability if desired. The database lease
ensures that only one worker can collect a given source at a time.

## Windows Task Scheduler

Create a task that runs whether or not a user is logged on:

1. Trigger **At startup**.
2. Set **Program/script** to the project's
   `.venv\Scripts\python.exe`.
3. Set **Add arguments** to `worker.py`.
4. Set **Start in** to the CTI Dashboard project directory.
5. Enable **Restart the task if it fails** and select **Do not start a new
   instance** when the task is already running.

The task account must be able to read the project and `.env`, write application
logs, and connect to SQL Server.

## NSSM Windows service

From an elevated terminal:

```powershell
nssm install CTIDashboardWorker C:\CTI-Dashboard\.venv\Scripts\python.exe
nssm set CTIDashboardWorker AppParameters worker.py
nssm set CTIDashboardWorker AppDirectory C:\CTI-Dashboard
nssm set CTIDashboardWorker Start SERVICE_AUTO_START
nssm set CTIDashboardWorker AppExit Default Restart
nssm start CTIDashboardWorker
```

Configure environment variables for the service account (or provide the
project's `.env`) before starting it. Use `nssm status CTIDashboardWorker` and
the application logs to verify operation.

## Lease behavior

Only enabled sources with `NextRunAt` at or before the current UTC time are
candidates. Acquisition is one owner- and expiry-checked `UPDATE`. A heartbeat
extends `LeaseExpiresAt`; completion clears the owner and schedules the normal
source interval, while failure schedules the retry interval. An expired lease
is immediately eligible for another worker, so no separate cleanup task is
needed.
