# Scam Image Filter Bot

A Discord bot that automatically removes scam content — fake giveaways,
crypto-casino screenshots, phishing links, and the like.

It catches scams three ways:

1. **Known scam images** — mods teach it scam images; it blocks any future image
   that looks close enough, even recompressed, re-screenshotted, or differently
   padded. (Auto-crop + DCT-based perceptual hash, matched by Hamming distance.)
2. **Brand-new scam images (OCR)** — for images it hasn't seen, it reads the text
   inside the image and scores it for scam signals. If it looks like a scam, it
   removes it *and* learns its hash so every repost gets the instant check.
3. **Scam links in text** — it scans message text for known scam domains and
   removes posts that contain them.

---

## Commands (mods only — requires Manage Messages)

| Command | What it does |
| --- | --- |
| `!addscam [note]` | Add a scam image to the blocklist. Attach the image, or reply to a message that has it. |
| `!adddomain <domain>` | Add a scam domain, e.g. `!adddomain deezbet.com`. |
| `!removescam <hash>` | Remove an image hash by its exact value. |
| `!removedomain <domain>` | Remove a scam domain. |
| `!listscam` | Show counts (hashes + domains) and current settings. |

When something is caught, the bot deletes it and posts a short notice that
auto-clears after a few seconds. Auto-learned scams show up in the list with the
note `OCR: ...` and the author `auto-ocr`.

---

## Configuration (top of `index.js`)

- `matchThreshold` — image hash tolerance (0 = identical, higher = looser). 8–12.
- `enableOcr` — turn the OCR tier on/off.
- `ocrScoreThreshold` — how many scam words inside an image before it's flagged.
- `autoLearnFromOcr` — auto-add OCR-caught scams to the hash list.
- `scamTerms` — the word/phrase list used for scoring text and OCR results.
- `seedScamDomains` / `allowedDomains` — known-bad and always-safe domains.
- `textScamRequiresKnownDomain` — if true (default), plain text is only acted on
  when it contains a *known* scam domain (safest). Set false to also catch
  "scam words + unknown link" in text (more aggressive).
- `notice`, `noticeDeleteAfterSeconds`, `logChannelId` — action/notice settings.

Environment variables (never hard-code these):

- `DISCORD_TOKEN` — your bot token.
- `BLOCKLIST_PATH` — where to save data, e.g. `/app/data/scam-hashes.json` on a
  Railway volume so it survives redeploys. The domain list is stored next to it
  as `scam-domains.json` automatically.

---

## Run locally

```bash
npm install
export DISCORD_TOKEN=your_token_here
npm start
```

Live once the logs show `Logged in as ...`. The first OCR check downloads the
English language data once, then caches it.

---

## Deploy on Railway

1. Push to GitHub.
2. **New Project → Deploy from GitHub repo**.
3. **Variables**: add `DISCORD_TOKEN`.
4. **Settings → Volumes** (create from the canvas: right-click or Cmd/Ctrl+K →
   "volume"): mount at `/app/data`, then add `BLOCKLIST_PATH=/app/data/scam-hashes.json`.
5. Watch the deploy logs for `Logged in as ...`.

---

## Discord setup

- Developer Portal → **Bot** → enable **Message Content Intent**.
- Invite with the `bot` scope and **Manage Messages** + **Read Message History**.

---

## Notes

- OCR uses some memory while running (a few hundred MB when active). Fine on
  Railway's Hobby plan; on a very small instance, watch memory.
- OCR only runs on images that don't already match a known hash, so known scams
  stay instant and only genuinely new images pay the OCR cost.
