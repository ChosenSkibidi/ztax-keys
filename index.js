const KEY_TTL = 86400; // 24 hours
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function reply(content) {
  return { type: 4, data: { content, flags: 64 } };
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function randomKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  const chars = Array.from(bytes, (b) => ALPHABET[b % ALPHABET.length]);
  return "ZTAX-" + [0, 4, 8].map((i) => chars.slice(i, i + 4).join("")).join("-");
}

async function verifyDiscord(request, body, publicKey) {
  const signature = request.headers.get("X-Signature-Ed25519");
  const timestamp = request.headers.get("X-Signature-Timestamp");
  if (!signature || !timestamp) return false;
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      hexToBytes(publicKey),
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    return await crypto.subtle.verify(
      "Ed25519",
      key,
      hexToBytes(signature),
      new TextEncoder().encode(timestamp + body)
    );
  } catch {
    return false;
  }
}

async function isMember(userId, env) {
  const res = await fetch(
    `https://discord.com/api/v10/guilds/${env.GUILD_ID}/members/${userId}`,
    { headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` } }
  );
  if (res.status === 200) return true;
  if (res.status === 404) return false;
  return null;
}

async function getKey(interaction, env) {
  if (!interaction.member || interaction.guild_id !== env.GUILD_ID) {
    return reply("Use this command inside the server.");
  }
  if (env.REQUIRED_ROLE_ID && !interaction.member.roles.includes(env.REQUIRED_ROLE_ID)) {
    return reply("You need the required role to get a key.");
  }

  const userId = interaction.member.user.id;
  let key = await env.KEYS.get("user:" + userId);
  let record = key ? await env.KEYS.get("key:" + key, "json") : null;

  if (!record) {
    key = randomKey();
    const now = Math.floor(Date.now() / 1000);
    record = { userId, createdAt: now, expiresAt: now + KEY_TTL, device: null };
    await env.KEYS.put("key:" + key, JSON.stringify(record), { expiration: record.expiresAt });
    await env.KEYS.put("user:" + userId, key, { expiration: record.expiresAt });
  }

  return reply(
    `Your key: \`${key}\`\nExpires <t:${record.expiresAt}:R>. It locks to the first device you use it on, so don't share it.`
  );
}

async function interactions(request, env) {
  const body = await request.text();
  if (!(await verifyDiscord(request, body, env.DISCORD_PUBLIC_KEY))) {
    return new Response("bad signature", { status: 401 });
  }
  const interaction = JSON.parse(body);
  if (interaction.type === 1) return json({ type: 1 });
  if (interaction.type === 2 && interaction.data.name === "getkey") {
    return json(await getKey(interaction, env));
  }
  return json(reply("Unknown command."));
}

async function validate(request, env) {
  let data;
  try {
    data = await request.json();
  } catch {
    return json({ ok: false, reason: "bad_request" }, 400);
  }

  const key = String(data.key || "").trim().toUpperCase();
  const device = String(data.device || "").slice(0, 200);
  if (!key || !device) return json({ ok: false, reason: "bad_request" });

  const now = Math.floor(Date.now() / 1000);
  const record = await env.KEYS.get("key:" + key, "json");
  if (!record || record.expiresAt <= now) {
    return json({ ok: false, reason: "invalid_or_expired" });
  }
  if (record.device && record.device !== device) {
    return json({ ok: false, reason: "wrong_device" });
  }

  const member = await isMember(record.userId, env);
  if (member === null) return json({ ok: false, reason: "server_error" });
  if (member === false) return json({ ok: false, reason: "not_in_server" });

  if (!record.device) {
    record.device = device;
    await env.KEYS.put("key:" + key, JSON.stringify(record), { expiration: record.expiresAt });
  }

  const out = { ok: true, expiresAt: record.expiresAt };
  if (env.SCRIPT_URL) {
    const res = await fetch(env.SCRIPT_URL);
    if (res.ok) out.script = await res.text();
  }
  return json(out);
}

async function register(url, env) {
  if (!env.REGISTER_SECRET || url.searchParams.get("secret") !== env.REGISTER_SECRET) {
    return new Response("forbidden", { status: 403 });
  }
  const res = await fetch(
    `https://discord.com/api/v10/applications/${env.DISCORD_APP_ID}/guilds/${env.GUILD_ID}/commands`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify([
        { name: "getkey", description: "Get your 24-hour key", type: 1 },
      ]),
    }
  );
  return new Response(await res.text(), { status: res.status });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/register") return register(url, env);
    if (request.method !== "POST") return new Response("key server online");
    if (url.pathname === "/validate") return validate(request, env);
    return interactions(request, env);
  },
};
