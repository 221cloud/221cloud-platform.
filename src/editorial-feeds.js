const FEEDS = Object.freeze([
  { id: "bbc-football", name: "BBC Sport · Football", url: "https://feeds.bbci.co.uk/sport/football/rss.xml", domain: "bbc.co.uk" },
  { id: "sky-football", name: "Sky Sports · Football", url: "https://www.skysports.com/rss/11095", domain: "skysports.com" },
  { id: "guardian-football", name: "The Guardian · Football", url: "https://www.theguardian.com/football/rss", domain: "theguardian.com" }
]);
const MAX_FEED_BYTES = 1024 * 1024;
const MAX_ITEMS_PER_FEED = 20;

function decodeXml(value) {
  return String(value || "")
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/&amp;/gi, "&").replace(/&lt;/gi, "<").replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"').replace(/&apos;|&#39;/gi, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Math.min(0x10ffff, Number(n))))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(Math.min(0x10ffff, parseInt(n, 16))));
}
function tagValue(xml, tag) {
  const escaped = tag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = xml.match(new RegExp("<(?:[\\w.-]+:)?" + escaped + "(?:\\s[^>]*)?>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?" + escaped + "\\s*>", "i"));
  if (!match) return "";
  return decodeXml(match[1].replace(/<[^>]*>/g, " ")).replace(/\s+/g, " ").trim();
}
function safeHttpUrl(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password) return "";
    if (url.hostname.length > 253) return "";
    return url.href.slice(0, 2000);
  } catch { return ""; }
}
function parseFeed(xml, source) {
  const blocks = [...xml.matchAll(/<(item|entry)(?:\s[^>]*)?>([\s\S]*?)<\/\1>/gi)].slice(0, MAX_ITEMS_PER_FEED);
  return blocks.map((match, index) => {
    const block = match[2];
    const title = tagValue(block, "title").slice(0, 500);
    const description = (tagValue(block, "description") || tagValue(block, "summary") || tagValue(block, "content")).slice(0, 3000);
    let link = tagValue(block, "link");
    if (!link) {
      const linkMatch = block.match(/<link\b[^>]*href=["']([^"']+)["'][^>]*>/i);
      link = linkMatch ? decodeXml(linkMatch[1]) : "";
    }
    const url = safeHttpUrl(link);
    const published = tagValue(block, "pubDate") || tagValue(block, "published") || tagValue(block, "updated") || tagValue(block, "date");
    const parsedDate = published ? new Date(published) : null;
    const publishedAt = parsedDate && !Number.isNaN(parsedDate.getTime()) ? parsedDate.toISOString() : null;
    if (!title || !url) return null;
    return { title, description, url, published_at: publishedAt, source_id: source.id, source_name: source.name, source_domain: source.domain, position: index };
  }).filter(Boolean);
}

async function fetchFeed(source) {
  const response = await fetch(source.url, {
    method: "GET",
    redirect: "error",
    headers: { "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9", "User-Agent": "221Cloud-FutPulse-Editorial/1.0" },
    signal: AbortSignal.timeout(8000)
  });
  if (!response.ok) throw new Error("Flux indisponible (HTTP " + response.status + ").");
  const length = Number(response.headers.get("Content-Length") || 0);
  if (length > MAX_FEED_BYTES) throw new Error("Flux trop volumineux.");
  const reader = response.body?.getReader();
  if (!reader) throw new Error("Réponse RSS vide.");
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      total += part.value.byteLength;
      if (total > MAX_FEED_BYTES) { await reader.cancel(); throw new Error("Flux trop volumineux."); }
      chunks.push(part.value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  const xml = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  if (!/<(?:rss|feed|rdf:RDF)\b/i.test(xml)) throw new Error("Format RSS/Atom non reconnu.");
  return parseFeed(xml, source);
}

export async function handleEditorialFeedsRequest(request, env, path, user) {
  const match = path.match(/^\/api\/projects\/([^/]+)\/editorial-agent\/(items|sources\/sync)$/);
  if (!match || !["GET", "POST"].includes(request.method)) return null;
  const projectId = decodeURIComponent(match[1]);
  const action = match[2];
  const project = await env.DB.prepare(
    "SELECT id, type FROM projects WHERE id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1"
  ).bind(projectId, user.id).first();
  if (!project || project.type !== "application") return Response.json({ error: "Application introuvable ou non autorisée." }, { status: 404 });

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS editorial_items (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      source_id TEXT NOT NULL,
      source_name TEXT NOT NULL,
      source_domain TEXT NOT NULL,
      title TEXT NOT NULL CHECK(length(title) <= 500),
      description TEXT NOT NULL DEFAULT '' CHECK(length(description) <= 3000),
      url TEXT NOT NULL CHECK(length(url) <= 2000),
      published_at TEXT,
      fetched_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, project_id, url)
    )
  `).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_editorial_items_owner ON editorial_items(user_id, project_id, fetched_at DESC)").run();

  if (request.method === "GET" && action === "items") {
    const rows = await env.DB.prepare(`
      SELECT id, source_id, source_name, source_domain, title, description, url, published_at, fetched_at
      FROM editorial_items WHERE user_id = ? AND project_id = ?
      ORDER BY COALESCE(published_at, fetched_at) DESC LIMIT 100
    `).bind(user.id, projectId).all();
    return Response.json({ items: rows.results || [], sources: FEEDS.map(({ id, name, domain }) => ({ id, name, domain })) });
  }
  if (request.method === "POST" && action === "sources/sync") {
    const results = [];
    for (const source of FEEDS) {
      try {
        const items = await fetchFeed(source);
        let saved = 0;
        for (const item of items) {
          const id = crypto.randomUUID();
          const result = await env.DB.prepare(`
            INSERT INTO editorial_items (id,user_id,project_id,source_id,source_name,source_domain,title,description,url,published_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(user_id,project_id,url) DO UPDATE SET
              title=excluded.title, description=excluded.description,
              published_at=COALESCE(excluded.published_at, editorial_items.published_at),
              fetched_at=CURRENT_TIMESTAMP
          `).bind(id, user.id, projectId, item.source_id, item.source_name, item.source_domain, item.title, item.description, item.url, item.published_at).run();
          saved += Number(result.meta?.changes || 0);
        }
        results.push({ source: source.name, received: items.length, saved, status: "ok" });
      } catch (error) {
        results.push({ source: source.name, received: 0, saved: 0, status: "error", message: String(error?.message || "Erreur de collecte").slice(0, 180) });
      }
    }
    const total = results.reduce((sum, result) => sum + result.saved, 0);
    return Response.json({ message: "Collecte terminée. Les contenus restent des sources à examiner, pas des faits vérifiés.", saved: total, results });
  }
  return Response.json({ error: "Route de collecte introuvable." }, { status: 404 });
}
