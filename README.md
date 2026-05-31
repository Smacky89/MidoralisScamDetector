# Scam Image Filter Bot

A Discord bot that automatically deletes reposted scam images (fake giveaways,
crypto-casino screenshots, etc.). Mods teach it known scam images; it blocks any
future image that looks close enough, even if recompressed or lightly cropped.

It works by computing a **perceptual hash** (dHash) of every uploaded image and
comparing it against a saved blocklist using Hamming distance — so near-identical
variants still match, with a tunable tolerance.

---

## Commands (mods only — requires Manage Messages)

| Command | What it does |
| --- | --- |
| `!addscam [note]` | Adds the scam image to the blocklist. Either **attach the image** to the command, or **reply** to a message that has it. Optional note, e.g. `!addscam fake mrbeast`. |
| `!listscam` | Shows how many hashes are stored and the current match threshold. |
| `!removescam <hash>` | Removes a hash by its exact value. |

When a match is found, the bot deletes the message and posts a short notice that
auto-clears after a few seconds.

---

## Configuration

All settings live in the `CONFIG` block at the top of `index.js`:

- `matchThreshold` — how close a hash must be to count as a match (0 = identical,
  higher = more lenient). 8–12 is a good range. Lower it if you get false positives.
- `notice` — the message posted when something is deleted.
- `noticeDeleteAfterSeconds` — how long the notice stays (0 = keep it forever).
- `logChannelId` — optional channel ID to log every action for review.

Two values come from environment variables (never hard-code these):

- `DISCORD_TOKEN` — your bot token.
- `BLOCKLIST_PATH` — where to save the hash list (point this at a Railway volume,
  e.g. `/data/scam-hashes.json`, so it survives redeploys).

---

## Run locally (for testing)

```bash
npm install
export DISCORD_TOKEN=your_token_here
npm start
```

The bot is live once the logs show `Logged in as YourBot#1234`.

---

## Deploy on Railway

1. Push this folder to a GitHub repo.
2. In Railway: **New Project → Deploy from GitHub repo** and select it.
3. In **Variables**, add `DISCORD_TOKEN`.
4. In **Settings → Volumes**, add a volume mounted at `/data`,
   then add the variable `BLOCKLIST_PATH=/data/scam-hashes.json`.
5. Railway builds and runs it automatically. Watch the deploy logs for the
   `Logged in as ...` line.

---

## Discord setup

- In the **Developer Portal → Bot**, enable the **Message Content Intent**.
- Invite the bot with the `bot` scope and the **Manage Messages** permission.

---

## Note

This catches images that have already been added to the blocklist. It does not
detect a brand-new scam template the first time it appears — for that you'd add an
OCR/keyword tier that auto-learns new scams.
