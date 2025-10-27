# Microsoft Credentials Static Dashboard (GitHub Pages + Action)

What this change does
- Converts the dynamic Node backend approach to a static pipeline suitable for GitHub Pages.
- A GitHub Action runs a Node scraper on schedule or on-demand and writes credentials.json into the repo.
- The static frontend (public/index.html) fetches credentials.json and displays the list and basic debug info.

Why this is necessary
- GitHub Pages only serves static files and cannot run Node servers or Socket.IO. Trying to run /api/... from a Page returns the Pages 404 page (what you observed).
- This static approach gives you automatic updates without a separate server.

How to install
1. Add the files above to your repository (commit to the main branch).
   - package.json
   - scripts/scrape.js
   - .github/workflows/scrape.yml
   - public/index.html (replace your existing if needed)
   - README.md (optional)
2. Ensure GitHub Actions are enabled for your repo.
3. If your Pages site serves from root or `/public`:
   - The workflow writes `credentials.json` to repo root by default. If your index.html is located in a different folder, update `OUTPUT_PATH` in the workflow to match (for example `docs/credentials.json`).
   - In that case, also move/ensure `public/index.html` is the file served by Pages, or adjust accordingly.
4. Check Actions → Workflows → "Scrape and publish credentials.json" and trigger a workflow_dispatch run or wait for the schedule.
5. After the Action finishes, you will see `credentials.json` added/updated in the repo. GitHub Pages will serve it next; open your site and the dashboard should load data.

Notes and next steps
- Email subscriptions (confirm/unsubscribe) require a backend or a third-party service. If you want email notifications, choose one:
  - Deploy the Node server (server.js) I built earlier to Replit/Render/Railway and then point the frontend to that backend. I can give step-by-step instructions.
  - Or build a subscription workflow that stores subscriber emails in the repo (not recommended — exposes PII), or uses a third-party form/email provider (Formspree, Mailgun inbound forms) + an action to send emails (requires secrets).
- If the scraper returns zero items or the Action log shows fetch errors (403/429), Microsoft Learn may be blocking automated requests. If that happens, I can:
  - Add a headless browser (Puppeteer) step to the Action to render pages (heavier CPU and potentially slower), or
  - Switch to scraping other pages/sitemap or request an official API, if available.

If you want me to:
- Prepare a version that auto-deploys the Node backend on Replit and provide the exact frontend that points to it, I will create that repo-ready code and step-by-step Replit instructions.
- Or update the Action to target the `docs/` folder or gh-pages branch (tell me which you want).

Which option do you prefer: (A) use this static Action approach (I’ve already provided the files above), or (B) I will prepare the easy Replit/Render deployment for the full dynamic backend (email subscriptions + live updates)? I’ll proceed immediately with the one you choose and give exact next steps.
