# Scam Image Filter Bot

> **Open-source project by [Midoralis](https://midoralis.com/).**
> Free to use, modify, and share. Contributions welcome.

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

## Installation — step by step

Follow these steps if you've never set up a Discord bot before.

### 1. Prerequisites

- **Node.js 18 or newer** — download from [nodejs.org](https://nodejs.org/).
  Verify with:
  ```bash
  node -v
  npm -v
  ```
- **Git** (optional, only if you want to clone the repo) —
  [git-scm.com](https://git-scm.com/).

### 2. Get the code

Either clone it:
```bash
git clone https://github.com/your-user/MidoralisScamDetector.git
cd MidoralisScamDetector
```
…or download the ZIP from GitHub and extract it, then `cd` into the folder.

### 3. Install dependencies

```bash
npm install
```
This installs `discord.js`, `sharp`, and `tesseract.js`.

### 4. Create a Discord application + bot

1. Go to the [Discord Developer Portal](https://discord.com/developers/applications).
2. Click **New Application**, give it a name, and create it.
3. Open the **Bot** tab → **Reset Token** → copy the token somewhere safe.
   *(Treat this like a password — never commit it.)*
4. Still on the **Bot** tab, scroll down and enable **Message Content Intent**.

### 5. Invite the bot to your server

1. In the Developer Portal go to **OAuth2 → URL Generator**.
2. Under **Scopes**, tick `bot`.
3. Under **Bot Permissions**, tick:
   - Read Messages / View Channels
   - Send Messages
   - Manage Messages
   - Read Message History
4. Copy the generated URL, open it in a browser, and invite the bot to your
   server.

### 6. Add your token

Set the `DISCORD_TOKEN` environment variable:

**macOS / Linux:**
```bash
export DISCORD_TOKEN=your_token_here
```

**Windows (PowerShell):**
```powershell
$env:DISCORD_TOKEN="your_token_here"
```

**Windows (cmd):**
```cmd
set DISCORD_TOKEN=your_token_here
```

Optionally set `BLOCKLIST_PATH` to control where data is stored (defaults to
`./scam-hashes.json` in the project folder).

### 7. Start the bot

```bash
npm start
```

You should see something like:
```
Midoralis Scam Detector (open-source)
Created by Midoralis — https://midoralis.com/
Logged in as YourBot#1234
```

The bot is now live. The first time OCR runs it will download the English
language data (a one-time, ~10 MB download) and cache it.

### 8. Try it out

In your server, as a mod:
- Reply to a scam image with `!addscam` to teach it.
- Run `!listscam` to see how many hashes and domains are loaded.
- Post a known scam image again — the bot should delete it instantly.

---

## Run locally (short version)

```bash
npm install
export DISCORD_TOKEN=your_token_here
npm start
```

Live once the logs show `Logged in as ...`.

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
