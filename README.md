# Mnemosyne Admin

Mnemosyne Admin is an Express + PostgreSQL web app for managing community birthday entries using Discord OAuth authentication.

## Features

- Discord OAuth login (`/login` → `/callback`)
- Role-based admin access using Discord guild roles
- Personal birthday management (`/me/birthdays`)
- Admin user directory and per-user management (`/admin/users`, `/admin/users/:id`)
- JSON export/import tools for backups (`/admin/export.json`, `/admin/import`)
- Server-side sessions stored in Postgres (`connect-pg-simple`)
- Basic hardening:
  - HTTP-only secure session cookie
  - CSRF validation on all POST routes
  - Security headers (`X-Frame-Options`, `X-Content-Type-Options`, etc.)
- Responsive admin directory view for smaller screens

## Tech Stack

- Node.js (ESM)
- Express
- PostgreSQL (`pg`)
- `express-session` + `connect-pg-simple`

## Environment Variables

### Required

- `DATABASE_URL`
- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_REDIRECT_URI`
- `DISCORD_GUILD_ID`
- `BOT_TOKEN`
- `SESSION_SECRET`

### Optional

- `ADMIN_ROLE_IDS` (comma-separated Discord role IDs)
- `BIRTHDAYS_TABLE` (default: `birthdays`)
- `PORT` (default: `3000`)
- `PGSSLMODE` (`disable` to turn off SSL)

## Local Development

1. Install dependencies:
   ```bash
   npm install
   ```
2. Set env vars in your shell (or `.env` if your workflow loads it).
3. Start server:
   ```bash
   npm start
   ```
4. Open `http://localhost:3000`.

## Route Overview

### Public/Auth

- `GET /` – home
- `GET /login` – start Discord OAuth
- `GET /callback` – OAuth callback
- `GET /logout` – clear session

### Authenticated User

- `GET /me/birthdays`
- `POST /me/birthdays`
- `POST /me/birthdays/:id/edit`
- `POST /me/birthdays/:id/delete`

### Admin

- `GET /admin/users`
- `GET /admin/users/:id`
- `POST /admin/users/:id/add`
- `POST /admin/users/:id/delete`
- `GET /admin/export.json`
- `GET /admin/import`
- `POST /admin/import`

## Data Model (high level)

- `discord_users`
  - `user_id` (PK), `username`, `avatar`, `last_seen_at`
- birthdays table (defaults to `birthdays`)
  - `id`, `user_id`, `character_name`, `character_name_key`, `month`, `day`, `image_url`, timestamps

Schema/bootstrap is handled on server startup in `ensureSchema()`.

## Notes

- Run this behind HTTPS in production.
- Keep `SESSION_SECRET`, OAuth credentials, and bot token private.
- Restrict `ADMIN_ROLE_IDS` to trusted roles only.
