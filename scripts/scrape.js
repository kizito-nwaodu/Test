/**
 * scripts/scrape.js
 *
 * Usage in GitHub Action: node scripts/scrape.js
 *
 * Writes credentials.json at OUTPUT_PATH (default "./credentials.json").
 *
 * Environment variables:
 *  - LIST_URL (optional) - page to scrape (default Microsoft Learn certs)
 *  - SITEMAP_URL (optional) - sitemap used as fallback
 *  - OUTPUT_PATH (optional) - path to write JSON (default "./credentials.json")
 *
 * The output JSON format:
 * {
 *   "generated_at": "2025-10-27T...",
 *   "source": "LIST_URL or sitemap",
 *   "items": [
 *     { "id": "...", "title": "...", "url": "...", "type": "certification|exam|skill" },
 *     ...
 *   ]
 * }
 */
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const cheerio = require('cheerio');
const { parseStringPromise } = require('xml2js');
const crypto = require('crypto');

const LIST_URL = process.env.LIST_URL || 'https://learn.microsoft.com/en-us/certifications/';
const SITEMAP_URL = process.env.SITEMAP_URL || 'https://learn.microsoft.com/sitemap.xml';
const OUTPUT_PATH = process.env.OUTPUT_PATH || './credentials.json';
const USER_AGENT = 'ms-credentials-static-scraper/1.0 (+https://example.com)';

function idForUrl(url) {
  return crypto.createHash('md5').update(url).digest('hex');
}

function classifyItem(title = '', url = '') {
  const t = String(title).toLowerCase();
  const u = String(url).toLowerCase();
  if (u.includes('/exams/') || t.includes('exam')) return 'exam';
  if (u.includes('/skills/') || t.includes('skill')) return 'skill';
  return 'certification';
}

async function fetchHtml(url) {
  const res = await axios.get(url, { headers: { 'User-Agent': USER_AGENT }, timeout: 20000 });
  return res.data;
}

function extractFromHtml(html, baseUrl) {
  const $ = cheerio.load(html);
  const found = new Map();

  $('a[href]').each((i, el) => {
    let href = $(el).attr('href');
    let text = $(el).text().trim() || $(el).attr('aria-label') || $(el).attr('title') || '';
    if (!href || !text) return;
    const lowText = text.toLowerCase();
    if (
      href.includes('/certifications/') ||
      href.includes('/certification/') ||
      href.includes('/exams/') ||
      href.includes('/skills/') ||
      lowText.includes('cert') ||
      lowText.includes('exam') ||
      lowText.includes('skill')
    ) {
      let url = href;
      try {
        if (url.startsWith('/')) {
          const parsed = new URL(baseUrl);
          url = `${parsed.protocol}//${parsed.host}${url}`;
        } else if (!url.startsWith('http')) {
          url = new URL(url, baseUrl).toString();
        }
      } catch (e) {
        // skip malformed
      }
      if (!found.has(url)) {
        found.set(url, { title: text, url, type: classifyItem(text, url) });
      }
    }
  });

  // Look for common card titles if anchors not enough
  $('article, .card, .product-card, .ms-card').each((i, el) => {
    const a = cheerio(el).find('a[href]').first();
    let href = a && a.attr && a.attr('href');
    let title = cheerio(el).find('h1,h2,h3,h4').first().text().trim() || (a && a.text && a.text().trim());
    if (!href || !title) return;
    let url = href;
    try {
      if (url.startsWith('/')) {
        const parsed = new URL(baseUrl);
        url = `${parsed.protocol}//${parsed.host}${url}`;
      } else if (!url.startsWith('http')) {
        url = new URL(url, baseUrl).toString();
      }
    } catch (e) {}
    if (!found.has(url)) {
      found.set(url, { title, url, type: classifyItem(title, url) });
    }
  });

  return Array.from(found.values());
}

async function extractFromSitemap(limit = 200) {
  try {
    const res = await axios.get(SITEMAP_URL, { headers: { 'User-Agent': USER_AGENT }, timeout: 20000 });
    const xml = res.data;
    const obj = await parseStringPromise(xml);
    const urls = [];
    if (obj.urlset && obj.urlset.url) {
      for (const u of obj.urlset.url) {
        if (u.loc && u.loc[0]) urls.push(u.loc[0]);
      }
    } else if (obj.sitemapindex && obj.sitemapindex.sitemap) {
      for (const s of obj.sitemapindex.sitemap) {
        if (s.loc && s.loc[0]) urls.push(s.loc[0]);
      }
    }
    const candidates = urls.filter(u => /certif|certifications|exam|exams|skills?/.test(u)).slice(0, limit);
    const found = [];
    for (const u of candidates) {
      try {
        const html = await axios.get(u, { headers: { 'User-Agent': USER_AGENT }, timeout: 15000 }).then(r => r.data);
        const $ = cheerio.load(html);
        const title = $('h1').first().text().trim() || $('title').first().text().trim() || u;
        found.push({ title, url: u, type: classifyItem(title, u) });
      } catch (e) {
        // ignore per-page fetch errors
      }
    }
    return found;
  } catch (e) {
    return [];
  }
}

(async () => {
  try {
    console.log('Scraper: LIST_URL=', LIST_URL);
    let html = null;
    try {
      html = await fetchHtml(LIST_URL);
      console.log('Scraper: fetched LIST_URL OK');
    } catch (err) {
      console.warn('Scraper: failed to fetch LIST_URL:', err && err.message ? err.message : err);
    }

    let items = [];
    if (html) {
      items = extractFromHtml(html, LIST_URL);
      console.log('Scraper: primary extraction found', items.length, 'items');
    }

    if (!items || items.length === 0) {
      console.log('Scraper: falling back to sitemap...');
      items = await extractFromSitemap(200);
      console.log('Scraper: sitemap extraction found', items.length, 'items');
    }

    // Normalize, ensure ids
    const normalized = items.map(it => ({ id: idForUrl(it.url), title: it.title, url: it.url, type: it.type }));
    const out = {
      generated_at: new Date().toISOString(),
      source: html ? LIST_URL : `sitemap:${SITEMAP_URL}`,
      items: normalized
    };

    const outPath = path.resolve(process.cwd(), OUTPUT_PATH);
    fs.writeFileSync(outPath, JSON.stringify(out, null, 2), 'utf8');
    console.log('Scraper: wrote', outPath, 'items:', normalized.length);
    process.exit(0);
  } catch (e) {
    console.error('Scraper error', e && e.message ? e.message : e);
    process.exit(1);
  }
})();
