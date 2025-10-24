```markdown
# Microsoft Credentials (Certifications) Real-time Dashboard

This project scrapes Microsoft Learn certification/exam/skill pages and provides a dashboard that updates in real time when new items are discovered. It also supports email subscriptions with confirmation and unsubscribe flows.

WARNING: This implementation scrapes HTML pages using heuristics. Scraping may violate terms of service. If Microsoft provides an official API for the dataset you need, use that instead.

## New features in this update
- Email confirmation flow: subscribers receive a confirmation email and must confirm before notifications are sent.
- Unsubscribe flow: every notification email includes an unsubscribe link; unsubscribing marks the subscription inactive.
- Subscriptions are only considered active when confirmed and not unsubscribed.

## Environment variables
- LIST_URL (optional) — page to scrape (default: https://learn.microsoft.com/en-us/certifications/)
- POLL_INTERVAL_MS (optional) — poll interval in ms (default: 60000)
- PORT (optional) — server port (default: 3000)
- BASE_URL (recommended) — public base URL used in email links (default: http://localhost:PORT)
- SMTP_HOST — SMTP server host (required to actually send emails)
- SMTP_PORT — SMTP server port (e.g., 587 or 465)
- SMTP_USER — SMTP username
- SMTP_PASS — SMTP password
- EMAIL_FROM — from address for outbound emails (e.g., "no-reply@yourdomain.com")

## Endpoints
- GET /api/credentials — list all discovered credentials
- GET /api/credentials?type=exam — filter by type (certification|exam|skill)
- POST /api/subscribe { email, types } — create a subscription (requires email confirmation)
- GET /confirm?token=... — confirmation link from email
- GET /unsubscribe?token=... — unsubscribe link from emails

## Notes & migration
- The subscriptions table schema has been extended. If you already have an existing data.db, you may need to recreate it or migrate it to include the new columns: confirmed, confirmation_token, unsubscribe_token, confirmed_at, unsubscribed_at.
- Confirmation and unsubscribe flows rely on BASE_URL being reachable by the subscriber (if running locally, set BASE_URL to your ngrok or public URL to test email links).
- If SMTP is not configured, subscriptions will still be created but confirmation and notification emails will not be sent; check logs for warnings.

## Running
1. Install
   ```
   npm install
   ```
2. Configure environment variables (SMTP, BASE_URL)
3. Start
   ```
   npm start
   ```
4. Visit http://localhost:3000

## Next improvements you may want
- Add email confirmation token expiration.
- Add double opt-in with a confirmation token stored and a "resend confirmation" endpoint.
- Add rate-limiting, captcha, or confirmation email rate controls to prevent abuse.
- Implement a background job queue for emails (e.g., Bull, RabbitMQ) and send batched digests rather than immediate per-subscriber emails for scale.

```
