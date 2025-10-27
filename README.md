```markdown
# Microsoft Credentials Dashboard (robust scraper + email subscriptions)

This project scrapes Microsoft Learn certification/exam/skill pages and provides a real-time dashboard with email subscription (confirm/unsubscribe) flows. This release improves scraping reliability by:

- Using multiple extraction strategies (anchor heuristics + card detection)
- Falling back to parsing the Learn sitemap when the landing page yields no items
- Adding /api/status so you can see last scrape time, errors and total items
- Better logging for debugging

IMPORTANT: Scraping sites can violate Terms of Service. Prefer an official API where available.

Quick start (non-developer friendly)
- Easiest: deploy on Replit or Render using the files in this repo.
- You must set SMTP_* env vars if you want emails to be sent. If SMTP is not configured, the app will still collect subscriptions and show the dashboard but won't send email.

Required environment variables (minimum for email flows)
- BASE_URL — public reachable base URL used in email links (e.g., https://your-app.example)
- SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS — your SMTP provider (SendGrid, Mailgun, etc.)
- EMAIL_FROM — verified sender email
- ADMIN_TOKEN — random token to protect admin endpoint (optional but recommended)

Endpoints
- GET / — dashboard
- GET /api/credentials — list credentials
- GET /api/status — shows last_scrape, last_error, total count
- POST /api/subscribe { email, types } — subscribe, sends confirmation email
- GET /confirm?token=... — confirmation link
- GET /unsubscribe?token=... — unsubscribe link
- POST /api/resend-confirmation { email } — resend confirmation
- POST /api/request-unsubscribe { email } — request unsubscribe email
- GET /api/admin/subscriptions — admin list (requires x-admin-token header or admin_token query, equal to ADMIN_TOKEN)

Troubleshooting notes
- If /api/status shows last_error or zero total items:
  - It may mean Microsoft Learn required JS rendering or blocked requests.
  - If last_error shows 403 or 429, the site may be blocking scraping — use official APIs or run behind a headless browser (Puppeteer).
- For testing email flows locally, use a service like Mailtrap or SendGrid and set BASE_URL to a public tunnel (eg. ngrok) so email links are reachable.

```
