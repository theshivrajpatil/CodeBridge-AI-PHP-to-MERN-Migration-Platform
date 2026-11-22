# Deployment checklist — blog

CodeBridge AI generated these files only. **Nothing has been built or deployed.** A human must complete every step.

1. Review `MIGRATION_REPORT.md`; resolve or accept every STUB and every security finding.
2. Install and test: `cd server && npm ci && npm test`; run an `npm audit`.
3. Run differential tests against the original application in an isolated environment with disposable data (V5.23 runtime harness).
4. Create secrets outside the repository: `JWT_SECRET` (>= 32 random chars), `MONGO_ROOT_USER`, `MONGO_ROOT_PASSWORD`. Compose refuses to start without them.
5. Put the stack behind TLS (reverse proxy / load balancer); set `CORS_ORIGINS` to the exact client origin(s).
6. Migrate data with a reviewed script; existing bcrypt password hashes remain valid.
7. Deploy with `docker compose up --build` in a staging environment first; record approval before production.
