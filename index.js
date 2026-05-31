import {
  Client,
  GatewayIntentBits,
  Partials,
  PermissionFlagsBits,
} from 'discord.js';
import sharp from 'sharp';
import { readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';

// ─────────────────────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────────────────────
const CONFIG = {
  token: process.env.DISCORD_TOKEN,        // set in your environment
  prefix: '!',                              // command prefix for mod commands

  // How close a hash must be to count as a match.
  // 0 = pixel-identical. Higher = more lenient (catches more variants
  // but risks false positives). 8–12 is a good range for "same image".
  matchThreshold: 10,

  // What to do when a match is found:
  deleteMessage: true,
  notice: 'Scam message was detected and auto-deleted.',
  noticeDeleteAfterSeconds: 10,             // auto-clear the notice (0 = keep it)

  // Channel ID where actions get logged (optional, '' to disable):
  logChannelId: '',

  // Where the learned scam hashes are stored. On Railway, set a volume
  // and point BLOCKLIST_PATH at it (e.g. /data/scam-hashes.json) so the
  // list survives redeploys. Falls back to a local file for testing.
  blocklistFile: process.env.BLOCKLIST_PATH || './scam-hashes.json',
};

// ─────────────────────────────────────────────────────────────
// PERCEPTUAL HASHING (dHash, 64-bit)
// ─────────────────────────────────────────────────────────────
async function dHash(buffer) {
  const W = 9, H = 8;
  const { data } = await sharp(buffer)
    .grayscale()
    .resize(W, H, { fit: 'fill' })
    .raw()
    .toBuffer({ resolveWithObject: true });

  let bits = '';
  for (let row = 0; row < H; row++) {
    for (let col = 0; col < W - 1; col++) {
      const left = data[row * W + col];
      const right = data[row * W + col + 1];
      bits += left < right ? '1' : '0';   // 64 bits total
    }
  }
  // pack 64 bits into a 16-char hex string
  let hex = '';
  for (let i = 0; i < bits.length; i += 4) {
    hex += parseInt(bits.slice(i, i + 4), 2).toString(16);
  }
  return hex;
}

// Hamming distance between two 64-bit hex hashes
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
// BLOCKLIST PERSISTENCE
// ─────────────────────────────────────────────────────────────
// shape: [{ hash, addedBy, addedAt, note }]
let blocklist = [];

async function loadBlocklist() {
  if (existsSync(CONFIG.blocklistFile)) {
    try {
      blocklist = JSON.parse(await readFile(CONFIG.blocklistFile, 'utf8'));
      console.log(`Loaded ${blocklist.length} scam hashes.`);
    } catch (e) {
      console.error('Could not parse blocklist, starting empty:', e.message);
      blocklist = [];
    }
  }
}

async function saveBlocklist() {
  await writeFile(CONFIG.blocklistFile, JSON.stringify(blocklist, null, 2));
}

// Returns the matching entry (and distance) or null
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
// BOT
// ─────────────────────────────────────────────────────────────
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,      // privileged intent — enable in Dev Portal
  ],
  partials: [Partials.Message, Partials.Channel],
});

client.once('clientReady', async () => {
  await loadBlocklist();
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

client.on('messageCreate', async (msg) => {
  if (msg.author.bot || !msg.guild) return;

  // ── Mod commands ──────────────────────────────────────────
  if (msg.content.startsWith(CONFIG.prefix)) {
    const [cmd, ...args] = msg.content.slice(CONFIG.prefix.length).trim().split(/\s+/);

    if (cmd === 'addscam') {
      if (!isMod(msg.member)) return;

      // collect images: from the replied-to message and/or this message's attachments
      const sources = [];
      if (msg.reference?.messageId) {
        const ref = await msg.channel.messages
          .fetch(msg.reference.messageId).catch(() => null);
        if (ref) sources.push(...ref.attachments.values());
      }
      sources.push(...msg.attachments.values());

      const images = sources.filter(isImage);
      if (images.length === 0) {
        return void msg.reply(
          'Attach an image to this command, or reply to a message that has the scam image.'
        );
      }

      let added = 0, dupes = 0;
      const note = args.join(' ') || '';
      for (const att of images) {
        try {
          const buf = await fetchImageBuffer(att.url);
          const hash = await dHash(buf);
          if (findMatch(hash)) { dupes++; continue; }   // already covered
          blocklist.push({
            hash,
            addedBy: msg.author.tag,
            addedAt: new Date().toISOString(),
            note,
          });
          added++;
        } catch (e) {
          console.error('addscam hash error:', e.message);
        }
      }
      await saveBlocklist();
      return void msg.reply(
        `Added ${added} new hash(es)${dupes ? `, ${dupes} already covered` : ''}. ` +
        `Blocklist now has ${blocklist.length}.`
      );
    }

    if (cmd === 'listscam') {
      if (!isMod(msg.member)) return;
      return void msg.reply(
        `Blocklist has **${blocklist.length}** scam hashes. ` +
        `Match threshold: ${CONFIG.matchThreshold} bits.`
      );
    }

    if (cmd === 'removescam') {
      if (!isMod(msg.member)) return;
      const h = args[0];
      const before = blocklist.length;
      blocklist = blocklist.filter((e) => e.hash !== h);
      await saveBlocklist();
      return void msg.reply(
        before === blocklist.length
          ? 'No hash matched that value. Use the exact hash string.'
          : `Removed. Blocklist now has ${blocklist.length}.`
      );
    }

    return; // unknown command, ignore
  }

  // ── Scan uploaded images ─────────────────────────────────
  const images = [...msg.attachments.values()].filter(isImage);
  if (images.length === 0) return;

  for (const att of images) {
    try {
      const buf = await fetchImageBuffer(att.url);
      const hash = await dHash(buf);
      const match = findMatch(hash);
      if (!match) continue;

      const reason = `Matched known scam image (distance ${match.dist}` +
        `${match.entry.note ? `, "${match.entry.note}"` : ''})`;

      if (CONFIG.deleteMessage) await msg.delete().catch(() => {});

      if (CONFIG.notice) {
        const sent = await msg.channel.send(`🚫 ${CONFIG.notice}`).catch(() => null);
        if (sent && CONFIG.noticeDeleteAfterSeconds > 0) {
          setTimeout(
            () => sent.delete().catch(() => {}),
            CONFIG.noticeDeleteAfterSeconds * 1000
          );
        }
      }

      await log(
        msg.guild,
        `🚫 Removed scam image from **${msg.author.tag}** in <#${msg.channel.id}> — ${reason}`
      );
      console.log(`Blocked scam image from ${msg.author.tag} (${reason})`);
      break; // one action per message is enough
    } catch (e) {
      console.error('scan error:', e.message);
    }
  }
});

client.login(CONFIG.token);
