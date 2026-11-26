const FEEDS = Object.freeze([
  { id: "bbc-football", name: "BBC Sport · Football", url: "https://feeds.bbci.co.uk/sport/football/rss.xml", domain: "bbc.co.uk" },
  { id: "sky-football", name: "Sky Sports · Football", url: "https://www.skysports.com/rss/11095", domain: "skysports.com" },
  { id: "guardian-football", name: "The Guardian · Football", url: "https://www.theguardian.com/football/rss", domain: "theguardian.com" },
  { id: "rfi-afrique-foot", name: "RFI · Afrique Foot", url: "https://www.rfi.fr/fr/afrique-foot/rss", domain: "rfi.fr" },
  { id: "wiwsport", name: "Wiwsport · Sénégal", url: "https://wiwsport.com/feed/", domain: "wiwsport.com" },
  { id: "afrik-foot", name: "Afrik-Foot · Football africain", url: "https://www.afrik-foot.com/feed", domain: "afrik-foot.com" }
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
  // Recherche directement la balise demandée, même imbriquée dans item/entry.
  const name = String(tag || "").replace(/[^a-z0-9_-]/gi, "");
  if (!name) return "";
  const pattern = new RegExp("<(?:[\\w.-]+:)?" + name + "\\b[^>]*>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?" + name + "\\s*>", "i");
  const match = xml.match(pattern);
  if (!match) return "";
  return decodeXml(match[1]).replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
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
  // Accepte RSS/Atom avec ou sans préfixes XML (ex. content:item, atom:entry).
  const blocks = [...xml.matchAll(/<(?:[\w.-]+:)?(item|entry)\b([^>]*)>([\s\S]*?)<\/(?:[\w.-]+:)?\1\s*>/gi)].slice(0, MAX_ITEMS_PER_FEED);
  const diagnostics = { detected_blocks: blocks.length, titles_found: 0, links_found: 0, https_links: 0, rejected_links: 0 };
  const items = blocks.map((match, index) => {
    const attributes = match[2] || "";
    const block = match[3];
    const title = tagValue(block, "title").slice(0, 500);
    if (title) diagnostics.titles_found++;
    const description = (tagValue(block, "description") || tagValue(block, "summary") || tagValue(block, "encoded") || tagValue(block, "content")).slice(0, 3000);
    let link = tagValue(block, "link");
    if (!link) {
      const linkMatch = block.match(/<(?:[\w.-]+:)?link\b[^>]*href=["']([^"']+)["'][^>]*\/?\s*>/i);
      link = linkMatch ? decodeXml(linkMatch[1]) : "";
    }
    // RSS 1.0 peut placer l'URL dans rdf:about ; certains flux utilisent guid ou atom:id.
    if (!link) link = tagValue(block, "guid") || tagValue(block, "id");
    if (!link) {
      const aboutMatch = attributes.match(/(?:[\w.-]+:)?about=["']([^"']+)["']/i);
      link = aboutMatch ? decodeXml(aboutMatch[1]) : "";
    }
    if (link) diagnostics.links_found++;
    const url = safeHttpUrl(link);
    if (url) diagnostics.https_links++;
    else if (link) diagnostics.rejected_links++;
    const published = tagValue(block, "pubDate") || tagValue(block, "published") || tagValue(block, "updated") || tagValue(block, "date") || tagValue(block, "issued");
    const parsedDate = published ? new Date(published) : null;
    const publishedAt = parsedDate && !Number.isNaN(parsedDate.getTime()) ? parsedDate.toISOString() : null;
    if (!title || !url) return null;
    return { title, description, url, published_at: publishedAt, source_id: source.id, source_name: source.name, source_domain: source.domain, position: index };
  }).filter(Boolean);
  diagnostics.accepted_items = items.length;
  return { items, diagnostics };
}

async function fetchFeed(source) {
  const response = await fetch(source.url, {
    method: "GET",
    redirect: "manual",
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
  const parsed = parseFeed(xml, source);
  const items = parsed.items;
  const itemTagMatches = [...xml.matchAll(/<(?:[\w.-]+:)?(?:item|entry)\b/gi)];
  const firstBlockMatch = xml.match(/<(?:[\w.-]+:)?(?:item|entry)\b[^>]*>([\s\S]*?)<\/(?:[\w.-]+:)?(?:item|entry)\s*>/i);
  const firstBlock = firstBlockMatch ? firstBlockMatch[1] : "";
  const firstBlockTags = [...firstBlock.matchAll(/<([\w.-]+)(?:\s[^>]*)?>/g)].slice(0, 12).map(match => match[1]);
  const diagnostics = {
    root: (xml.match(/<\?xml[^>]*\?>\s*<([^\s>!?]+)/i) || xml.match(/<([^\s>!?]+)/))?.[1] || "inconnu",
    item_entry_tags: itemTagMatches.length,
    first_item_tags: firstBlockTags,
    ...parsed.diagnostics,
    parsed_items: items.length
  };
  return { items, diagnostics, httpStatus: response.status, contentType: response.headers.get("Content-Type") || "non précisé" };
}


const STORY_STOP_WORDS = new Set([
  "avec","dans","pour","apres","avant","chez","contre","entre","vers","plus","moins","tres","tout","tous","toute","toutes",
  "football","foot","match","matches","equipe","club","sport","sports","officiel","officielle",
  "annonce","annoncee","annoncees","annonces","confirme","confirmee","confirmees","confirmer",
  "selon","face","journee","ligue","championnat","coupe","mercato","transfert","transferts",
  "the","and","for","from","with","over","under","into","after","before","their","his","her",
  "its","has","have","was","will","are","is","a","an","to","of","in","on","at","by","as",
  "this","that","these","those","who","what","when","where","why","how","new","says","said",
  "mais","comme","plusieurs","etre","avoir","fait","faire","son","sa","ses",
  "leur","leurs","une","des","les","sur","par","est","sont","ete","aux","qui","que","quoi",
  "dont","pas","non","oui","aussi","alors","ainsi","encore","vient","va","vont"
]);
function normalizeStoryToken(token) {
  let value = token;
  if (value.length > 6) {
    value = value.replace(/(ements|ement|ations|ation|itions|ition|iques|ique|istes|iste)$/,"");
    value = value.replace(/(aient|ions|eraient|eront|ées|ée|es|ers|er|ing|ed)$/,"");
  }
  if (value.length > 5 && value.endsWith("s")) value = value.slice(0, -1);
  return value;
}
function storyTokens(value) {
  return String(value || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .replace(/https?:\/\/\S+/g, " ").replace(/[^a-z0-9]+/g, " ")
    .split(/\s+/).filter(token => token.length >= 3 && !STORY_STOP_WORDS.has(token))
    .map(normalizeStoryToken).filter(token => token.length >= 3);
}
function storySimilarity(left, right) {
  const titleA = new Set(storyTokens(left.title));
  const titleB = new Set(storyTokens(right.title));
  const contextA = new Set(storyTokens(left.description).slice(0, 80));
  const contextB = new Set(storyTokens(right.description).slice(0, 80));
  const combinedA = new Set([...titleA, ...contextA]);
  const combinedB = new Set([...titleB, ...contextB]);
  if (!combinedA.size || !combinedB.size) return 0;
  const titleOverlap = [...titleA].filter(token => titleB.has(token));
  const combinedOverlap = [...combinedA].filter(token => combinedB.has(token));
  if (!combinedOverlap.length) return 0;
  const jaccard = combinedOverlap.length / (combinedA.size + combinedB.size - combinedOverlap.length);
  const containment = combinedOverlap.length / Math.min(combinedA.size, combinedB.size);
  const titleJaccard = titleOverlap.length
    ? titleOverlap.length / (titleA.size + titleB.size - titleOverlap.length)
    : 0;
  const hasDistinctiveTitleMatch = titleOverlap.some(token => token.length >= 5);
  // Les titres restent prioritaires; les descriptions servent de corroboration,
  // sans suffire seules à fusionner deux sujets.
  if (titleOverlap.length >= 2 && titleJaccard >= 0.28) return Math.max(titleJaccard, containment * 0.72);
  if (hasDistinctiveTitleMatch && combinedOverlap.length >= 3 && jaccard >= 0.12) return Math.max(0.47, jaccard);
  return Math.max(jaccard, containment * 0.72);
}
function withinStoryWindow(a, b) {
  const da = Date.parse(a.published_at || a.fetched_at || "");
  const db = Date.parse(b.published_at || b.fetched_at || "");
  if (!Number.isFinite(da) || !Number.isFinite(db)) return true;
  return Math.abs(da - db) <= 72 * 60 * 60 * 1000;
}
function buildStoryClusters(rows) {
  const parents = rows.map((_, index) => index);
  const find = index => {
    while (parents[index] !== index) {
      parents[index] = parents[parents[index]];
      index = parents[index];
    }
    return index;
  };
  const join = (a, b) => {
    const rootA = find(a), rootB = find(b);
    if (rootA !== rootB) parents[rootB] = rootA;
  };
  for (let i = 0; i < rows.length; i++) {
    for (let j = i + 1; j < rows.length; j++) {
      if (!withinStoryWindow(rows[i], rows[j])) continue;
      if (storySimilarity(rows[i].title, rows[j].title) >= 0.46) join(i, j);
    }
  }
  const groups = new Map();
  rows.forEach((row, index) => {
    const root = find(index);
    if (!groups.has(root)) groups.set(root, []);
    groups.get(root).push(row);
  });
  return [...groups.values()].map(items => {
    const sources = [...new Map(items.map(item => [item.source_domain, {
      source_id: item.source_id, source_name: item.source_name, source_domain: item.source_domain
    }])).values()];
    const dates = items.map(item => Date.parse(item.published_at || item.fetched_at || "")).filter(Number.isFinite);
    const latest = dates.length ? new Date(Math.max(...dates)).toISOString() : null;
    const lead = [...items].sort((a, b) =>
      (Date.parse(b.published_at || b.fetched_at || "") || 0) - (Date.parse(a.published_at || a.fetched_at || "") || 0)
    )[0];
    return {
      id: "story-" + items.map(item => item.id).sort().join("-").slice(0, 120),
      headline: lead.title,
      item_count: items.length,
      distinct_sources: sources.length,
      source_diversity: sources.length >= 2 ? "multiple_sources" : "single_source",
      verification_status: "not_verified",
      latest_at: latest,
      sources,
      items: items.map(item => ({
        id: item.id, title: item.title, description: item.description, url: item.url,
        published_at: item.published_at, fetched_at: item.fetched_at,
        source_id: item.source_id, source_name: item.source_name, source_domain: item.source_domain
      }))
    };
  }).sort((a, b) => (b.latest_at || "").localeCompare(a.latest_at || ""));
}

export async function handleEditorialFeedsRequest(request, env, path, user) {
  const match = path.match(/^\/api\/projects\/([^/]+)\/editorial-agent\/(items|clusters|sources\/sync)$/);
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

  if (request.method === "GET" && action === "clusters") {
    const rows = await env.DB.prepare(`
      SELECT id, source_id, source_name, source_domain, title, description, url, published_at, fetched_at
      FROM editorial_items WHERE user_id = ? AND project_id = ?
      ORDER BY COALESCE(published_at, fetched_at) DESC LIMIT 100
    `).bind(user.id, projectId).all();
    const clusters = buildStoryClusters(rows.results || []);
    return Response.json({
      clusters,
      totals: {
        collected_items: (rows.results || []).length,
        story_groups: clusters.length,
        multi_source_groups: clusters.filter(group => group.distinct_sources >= 2).length,
        single_source_groups: clusters.filter(group => group.distinct_sources === 1).length,
        unverified_groups: clusters.length
      },
      note: "Le regroupement repose sur la similarité des titres et une fenêtre temporelle. Plusieurs sources ne signifient pas à elles seules que l'information est vérifiée."
    });
  }
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
        const feed = await fetchFeed(source);
        const items = feed.items;
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
        results.push({ source: source.name, received: items.length, saved, status: items.length ? "ok" : "empty", http_status: feed.httpStatus, content_type: feed.contentType, diagnostics: feed.diagnostics, message: items.length ? "Flux accessible et articles reconnus." : "Flux accessible (HTTP " + feed.httpStatus + "), blocs détectés : " + feed.diagnostics.detected_blocks + ", titres : " + feed.diagnostics.titles_found + ", liens : " + feed.diagnostics.links_found + ", liens HTTPS valides : " + feed.diagnostics.https_links + ", liens rejetés : " + feed.diagnostics.rejected_links + ", premier article : " + (feed.diagnostics.first_item_tags.join(", ") || "aucune balise détectée") + ". Aucun article exploitable n’a été extrait." });
      } catch (error) {
        results.push({ source: source.name, received: 0, saved: 0, status: "error", message: String(error?.message || "Erreur de collecte").slice(0, 180) });
      }
    }
    const total = results.reduce((sum, result) => sum + result.saved, 0);
    return Response.json({ message: "Collecte terminée. Les contenus restent des sources à examiner, pas des faits vérifiés.", saved: total, results });
  }
  return Response.json({ error: "Route de collecte introuvable." }, { status: 404 });
}
