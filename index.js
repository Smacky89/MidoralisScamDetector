import {
  Client,
  GatewayIntentBits,
  Partials,
  PermissionFlagsBits,
} from 'discord.js';
import sharp from 'sharp';
import { createWorker } from 'tesseract.js';
import { readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';

// ─────────────────────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────────────────────
const CONFIG = {
  token: process.env.DISCORD_TOKEN,
  prefix: '!',

  // ── Image hash matching ──
  // How close a hash must be to count as a match (0 = identical,
  // higher = more lenient). 8–12 is a good range.
  matchThreshold: 10,

  // ── OCR tier (catches brand-new scams by reading text in the image) ──
  enableOcr: true,
  ocrScoreThreshold: 3,          // how many scam terms before it's flagged
  autoLearnFromOcr: true,        // auto-add the hash so reposts get the fast check

  // Words/phrases commonly found in giveaway / crypto-casino scams.
  // Matched case-insensitively as substrings of the OCR'd or message text.
  scamTerms: [
    'promo code', 'promocode', 'bonus code', 'use code',
    'withdraw', 'free $', 'free bonus', '100% bonus', 'deposit bonus',
    'giveaway', 'crypto', 'bitcoin', 'casino', 'register and',
    'claim your', 'claim now', 'exclusive offer', 'limited time',
    'airdrop', 'double your', 'guaranteed profit', 'investment',
  ],

  // ── Domain blocklist (scans message TEXT for links) ──
  // Known scam domains. Add more live with !adddomain. Learned ones persist.
  seedScamDomains: [
    // 'deezbet.com',   // example from a real scam — add your own
  ],
  // Domains that are always fine (never flagged as a suspicious URL):
  allowedDomains: [
    'discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net',
    'tenor.com', 'giphy.com', 'imgur.com',
    'youtube.com', 'youtu.be', 'twitch.tv',
    'twitter.com', 'x.com', 'github.com',
    'itch.io', 'midoralis.com',           // your own stuff
  ],
  // If true, message TEXT is only auto-acted on when it contains a *known*
  // scam domain (safest). If false, generic "scam words + unknown link" in
  // plain text also triggers action (more aggressive, more false positives).
  textScamRequiresKnownDomain: true,

  // ── Actions ──
  deleteMessage: true,
  notice: 'Scam message was detected and auto-deleted.',
  noticeDeleteAfterSeconds: 10,
  logChannelId: '',              // optional channel ID for an audit log

  // ── Storage ──
  blocklistFile: process.env.BLOCKLIST_PATH || './scam-hashes.json',
};

// scam-domains.json lives next to the hash file (same volume)
const DOMAINS_FILE = join(dirname(CONFIG.blocklistFile), 'scam-domains.json');

// ─────────────────────────────────────────────────────────────
// PERCEPTUAL HASHING (pHash, 64-bit, DCT-based, with auto-crop)
// ─────────────────────────────────────────────────────────────
async function autoCrop(buffer) {
  try {
    return await sharp(buffer).trim({ threshold: 10 }).toBuffer();
  } catch {
    return buffer;
  }
}

function dct1d(vector) {
  const N = vector.length;
  const out = new Float64Array(N);
  for (let k = 0; k < N; k++) {
    let sum = 0;
    for (let n = 0; n < N; n++) {
      sum += vector[n] * Math.cos((Math.PI / N) * (n + 0.5) * k);
    }
    out[k] = sum;
  }
  return out;
}

async function perceptualHash(buffer) {
  const SIZE = 32;
  const cropped = await autoCrop(buffer);

  const { data } = await sharp(cropped)
    .grayscale()
    .resize(SIZE, SIZE, { fit: 'fill' })
    .raw()
    .toBuffer({ resolveWithObject: true });

  const matrix = [];
  for (let y = 0; y < SIZE; y++) {
    const row = new Float64Array(SIZE);
    for (let x = 0; x < SIZE; x++) row[x] = data[y * SIZE + x];
    matrix.push(row);
  }

  const rowDct = matrix.map(dct1d);
  const dct = Array.from({ length: SIZE }, () => new Float64Array(SIZE));
  for (let x = 0; x < SIZE; x++) {
    const col = new Float64Array(SIZE);
    for (let y = 0; y < SIZE; y++) col[y] = rowDct[y][x];
    const colDct = dct1d(col);
    for (let y = 0; y < SIZE; y++) dct[y][x] = colDct[y];
  }

  const vals = [];
  for (let y = 0; y < 8; y++)
    for (let x = 0; x < 8; x++) vals.push(dct[y][x]);

  const sorted = vals.slice(1).sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];

  let bits = '';
  for (let i = 0; i < 64; i++) bits += vals[i] > median ? '1' : '0';

  let hex = '';
  for (let i = 0; i < 64; i += 4) {
    hex += parseInt(bits.slice(i, i + 4), 2).toString(16);
  }
  return hex;
}

function hamming(hexA, hexB) {
  let x = BigInt('0x' + hexA) ^ BigInt('0x' + hexB);
  let count = 0;
  while (x > 0n) {
    count += Number(x & 1n);
    x >>= 1n;
  }
  return count;
}

async function fetchImageBuffer(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`fetch failed: ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

// ─────────────────────────────────────────────────────────────
// PERSISTENCE — image hashes + scam domains
// ─────────────────────────────────────────────────────────────
let blocklist = [];                                   // [{ hash, addedBy, addedAt, note }]
let scamDomains = new Set(CONFIG.seedScamDomains.map((d) => d.toLowerCase()));

async function loadAll() {
  if (existsSync(CONFIG.blocklistFile)) {
    try {
      blocklist = JSON.parse(await readFile(CONFIG.blocklistFile, 'utf8'));
    } catch (e) {
      console.error('Bad hash file, starting empty:', e.message);
    }
  }
  if (existsSync(DOMAINS_FILE)) {
    try {
      const arr = JSON.parse(await readFile(DOMAINS_FILE, 'utf8'));
      arr.forEach((d) => scamDomains.add(d.toLowerCase()));
    } catch (e) {
      console.error('Bad domains file:', e.message);
    }
  }
  console.log(`Loaded ${blocklist.length} hashes, ${scamDomains.size} domains.`);
}

const saveHashes = () => writeFile(CONFIG.blocklistFile, JSON.stringify(blocklist, null, 2));
const saveDomains = () => writeFile(DOMAINS_FILE, JSON.stringify([...scamDomains], null, 2));

function findMatch(hash) {
  let best = null;
  for (const entry of blocklist) {
    const dist = hamming(hash, entry.hash);
    if (dist <= CONFIG.matchThreshold && (!best || dist < best.dist)) {
      best = { entry, dist };
    }
  }
  return best;
}

// ─────────────────────────────────────────────────────────────
// TEXT / DOMAIN SCAM SCORING
// ─────────────────────────────────────────────────────────────
function extractDomains(text) {
  const out = [];
  const re = /\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b/gi;
  let m;
  while ((m = re.exec(text)) !== null) out.push(m[1].toLowerCase());
  return out;
}

function isAllowedDomain(domain) {
  return CONFIG.allowedDomains.some((d) => domain === d || domain.endsWith('.' + d));
}

function isScamDomain(domain) {
  return [...scamDomains].some((d) => domain === d || domain.endsWith('.' + d));
}

// returns { termHits:[], knownBad:string|undefined, unknownUrl:bool }
function scoreScamText(text) {
  const lower = (text || '').toLowerCase();
  const termHits = CONFIG.scamTerms.filter((t) => lower.includes(t));
  const domains = extractDomains(lower);
  const knownBad = domains.find((d) => isScamDomain(d));
  const unknownUrl = domains.some((d) => !isAllowedDomain(d) && !isScamDomain(d));
  return { termHits, knownBad, unknownUrl };
}

// ─────────────────────────────────────────────────────────────
// OCR (lazy single worker, reused)
// ─────────────────────────────────────────────────────────────
let ocrWorker = null;
async function getOcrWorker() {
  if (!ocrWorker) {
    ocrWorker = await createWorker('eng');
    console.log('OCR worker ready.');
  }
  return ocrWorker;
}

// ─────────────────────────────────────────────────────────────
// BOT
// ─────────────────────────────────────────────────────────────
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
  ],
  partials: [Partials.Message, Partials.Channel],
});

client.once('clientReady', async () => {
  await loadAll();
  console.log(`Logged in as ${client.user.tag}`);
});

function isImage(att) {
  return att.contentType?.startsWith('image/') ||
    /\.(png|jpe?g|webp|gif|bmp)$/i.test(att.name ?? '');
}

function isMod(member) {
  return member?.permissions.has(PermissionFlagsBits.ManageMessages);
}

async function log(guild, text) {
  if (!CONFIG.logChannelId) return;
  const ch = await guild.channels.fetch(CONFIG.logChannelId).catch(() => null);
  if (ch?.isTextBased()) ch.send(text).catch(() => {});
}

// delete + post notice + log, all in one place
async function takeAction(msg, reason) {
  if (CONFIG.deleteMessage) await msg.delete().catch(() => {});
  if (CONFIG.notice) {
    const sent = await msg.channel.send(`🚫 ${CONFIG.notice}`).catch(() => null);
    if (sent && CONFIG.noticeDeleteAfterSeconds > 0) {
      setTimeout(() => sent.delete().catch(() => {}), CONFIG.noticeDeleteAfterSeconds * 1000);
    }
  }
  await log(
    msg.guild,
    `🚫 Removed scam from **${msg.author.tag}** in <#${msg.channel.id}> — ${reason}`
  );
  console.log(`Blocked scam from ${msg.author.tag} (${reason})`);
}

client.on('messageCreate', async (msg) => {
  if (msg.author.bot || !msg.guild) return;

  // ── Mod commands ──────────────────────────────────────────
  if (msg.content.startsWith(CONFIG.prefix)) {
    const [cmd, ...args] = msg.content.slice(CONFIG.prefix.length).trim().split(/\s+/);

    if (cmd === 'addscam') {
      if (!isMod(msg.member)) return;
      const sources = [];
      if (msg.reference?.messageId) {
        const ref = await msg.channel.messages.fetch(msg.reference.messageId).catch(() => null);
        if (ref) sources.push(...ref.attachments.values());
      }
      sources.push(...msg.attachments.values());
      const images = sources.filter(isImage);
      if (images.length === 0) {
        return void msg.reply(
          'Attach an image, or reply to a message that has the scam image.'
        );
      }
      let added = 0, dupes = 0;
      const note = args.join(' ') || '';
      for (const att of images) {
        try {
          const buf = await fetchImageBuffer(att.url);
          const hash = await perceptualHash(buf);
          if (findMatch(hash)) { dupes++; continue; }
          blocklist.push({ hash, addedBy: msg.author.tag, addedAt: new Date().toISOString(), note });
          added++;
        } catch (e) {
          console.error('addscam error:', e.message);
        }
      }
      await saveHashes();
      return void msg.reply(
        `Added ${added} new hash(es)${dupes ? `, ${dupes} already covered` : ''}. ` +
        `Now ${blocklist.length} hashes.`
      );
    }

    if (cmd === 'adddomain') {
      if (!isMod(msg.member)) return;
      const d = (args[0] || '').toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
      if (!d || !d.includes('.')) return void msg.reply('Usage: `!adddomain example.com`');
      scamDomains.add(d);
      await saveDomains();
      return void msg.reply(`Added scam domain \`${d}\`. Now ${scamDomains.size} domain(s).`);
    }

    if (cmd === 'removedomain') {
      if (!isMod(msg.member)) return;
      const d = (args[0] || '').toLowerCase();
      const had = scamDomains.delete(d);
      if (had) await saveDomains();
      return void msg.reply(had ? `Removed \`${d}\`.` : 'That domain was not in the list.');
    }

    if (cmd === 'removescam') {
      if (!isMod(msg.member)) return;
      const h = args[0];
      const before = blocklist.length;
      blocklist = blocklist.filter((e) => e.hash !== h);
      await saveHashes();
      return void msg.reply(
        before === blocklist.length
          ? 'No hash matched. Use the exact hash string.'
          : `Removed. Now ${blocklist.length} hashes.`
      );
    }

    if (cmd === 'listscam') {
      if (!isMod(msg.member)) return;
      return void msg.reply(
        `**${blocklist.length}** image hashes, **${scamDomains.size}** scam domains. ` +
        `Hash threshold ${CONFIG.matchThreshold}. OCR ${CONFIG.enableOcr ? 'on' : 'off'}.`
      );
    }

    return;
  }

  // ── 1. Scan message TEXT for scam links ──────────────────
  if (msg.content) {
    const { termHits, knownBad, unknownUrl } = scoreScamText(msg.content);
    const textScam = !!knownBad ||
      (!CONFIG.textScamRequiresKnownDomain && termHits.length >= 3 && unknownUrl);
    if (textScam) {
      await takeAction(
        msg,
        knownBad ? `known scam link "${knownBad}"` : `scam text (${termHits.slice(0, 4).join(', ')})`
      );
      return;
    }
  }

  // ── 2. Scan uploaded images ──────────────────────────────
  const images = [...msg.attachments.values()].filter(isImage);
  if (images.length === 0) return;

  // Process each image; collect OCR signals across ALL images so multi-image
  // scams (one message with several pictures) are still caught even if each
  // individual image has only a few scam terms.
  const ocrResults = [];           // { hash, termHits:Set, knownBad, unknownUrl }
  const aggregateTerms = new Set();
  let aggregateKnownBad = null;
  let aggregateUnknownUrl = false;

  for (const att of images) {
    try {
      const buf = await fetchImageBuffer(att.url);
      const hash = await perceptualHash(buf);

      // 2a. known scam image → instant action
      const match = findMatch(hash);
      if (match) {
        await takeAction(
          msg,
          `known scam image (dist ${match.dist}${match.entry.note ? `, "${match.entry.note}"` : ''})`
        );
        return;
      }

      // 2b. new image → read its text and score it
      if (CONFIG.enableOcr) {
        const worker = await getOcrWorker();
        const { data: { text } } = await worker.recognize(buf);
        const { termHits, knownBad, unknownUrl } = scoreScamText(text);

        // Per-image scam check (fast path: a single image is obviously scam)
        const isScam = !!knownBad ||
          termHits.length >= CONFIG.ocrScoreThreshold ||
          (termHits.length >= 2 && unknownUrl);

        if (isScam) {
          if (CONFIG.autoLearnFromOcr && !findMatch(hash)) {
            blocklist.push({
              hash,
              addedBy: 'auto-ocr',
              addedAt: new Date().toISOString(),
              note: `OCR: ${knownBad || termHits.slice(0, 3).join(', ')}`,
            });
            await saveHashes();
          }
          await takeAction(
            msg,
            knownBad
              ? `scam link "${knownBad}" found in image`
              : `OCR scam signals (${termHits.slice(0, 4).join(', ')})`
          );
          return;
        }

        // Not enough on its own — remember it for the aggregate check below.
        ocrResults.push({ hash, termHits, knownBad, unknownUrl });
        termHits.forEach((t) => aggregateTerms.add(t));
        if (knownBad) aggregateKnownBad = knownBad;
        if (unknownUrl) aggregateUnknownUrl = true;
      }
    } catch (e) {
      console.error('scan error:', e.message);
    }
  }

  // 2c. Aggregate check across ALL images in this message.
  // If a scammer spreads scam terms across multiple images, the totals will
  // trip the threshold here even though no single image did.
  if (CONFIG.enableOcr && ocrResults.length > 1) {
    const totalTerms = [...aggregateTerms];
    const isScam = !!aggregateKnownBad ||
      totalTerms.length >= CONFIG.ocrScoreThreshold ||
      (totalTerms.length >= 2 && aggregateUnknownUrl);

    if (isScam) {
      if (CONFIG.autoLearnFromOcr) {
        for (const r of ocrResults) {
          if (!findMatch(r.hash)) {
            blocklist.push({
              hash: r.hash,
              addedBy: 'auto-ocr',
              addedAt: new Date().toISOString(),
              note: `OCR (multi-image): ${aggregateKnownBad || totalTerms.slice(0, 3).join(', ')}`,
            });
          }
        }
        await saveHashes();
      }
      await takeAction(
        msg,
        aggregateKnownBad
          ? `scam link "${aggregateKnownBad}" found across ${ocrResults.length} images`
          : `OCR scam signals across ${ocrResults.length} images (${totalTerms.slice(0, 4).join(', ')})`
      );
      return;
    }
  }
});

client.login(CONFIG.token);
