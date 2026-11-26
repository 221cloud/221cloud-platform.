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
  "the","and","for","from","with","over","under","into","after","before","their","his","her","man",
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
const STORY_GENERIC_EVENT_WORDS = new Set([
  "win","wins","winner","winning","won","lose","loses","losing","lost","loss",
  "goal","goals","score","scores","scored","scoring","victory","defeat","draw",
  "beat","beats","beaten","matchday","match","game","games","record","league"
]);
const STORY_MATCH_REPORT_WORDS = new Set([
  "score","scored","scoring","beat","beats","beaten","win","wins","won",
  "victory","defeat","draw","sweep","swept","rout","comeback","thrash",
  "hammer","held","equaliser","equalizer","penalty"
]);
function isMatchReportTitle(tokens) {
  return tokens.some(token => STORY_MATCH_REPORT_WORDS.has(token));
}
function storySimilarity(left, right) {
  const tokensA = storyTokens(left.title);
  const tokensB = storyTokens(right.title);
  const titleA = new Set(tokensA);
  const titleB = new Set(tokensB);
  const sharedTitle = [...titleA].filter(token => titleB.has(token));
  // Un seul nom commun (joueur, entraîneur ou club) ne suffit jamais.
  if (sharedTitle.length < 2) return 0;

  // Un compte rendu de match ne doit pas être fusionné avec un portrait,
  // une analyse ou un article de contexte partageant seulement joueurs/club.
  // Deux comptes rendus doivent aussi partager au moins trois termes de titre,
  // afin d'exiger un ancrage événementiel plus précis.
  const leftIsMatchReport = isMatchReportTitle(tokensA);
  const rightIsMatchReport = isMatchReportTitle(tokensB);
  if (leftIsMatchReport !== rightIsMatchReport) return 0;
  if (leftIsMatchReport && sharedTitle.length < 3) return 0;

  const titleJaccard = sharedTitle.length / (titleA.size + titleB.size - sharedTitle.length);
  const distinctiveSharedTitle = sharedTitle.filter(token => !STORY_GENERIC_EVENT_WORDS.has(token));
  const descriptionA = new Set(storyTokens(left.description).slice(0, 120));
  const descriptionB = new Set(storyTokens(right.description).slice(0, 120));
  const sharedDescription = [...descriptionA].filter(token => descriptionB.has(token));
  const descriptionJaccard = sharedDescription.length
    ? sharedDescription.length / (descriptionA.size + descriptionB.size - sharedDescription.length)
    : 0;

  // Trois mots distinctifs communs dans les titres constituent un signal fort.
  const strongTitleMatch = distinctiveSharedTitle.length >= 3 && titleJaccard >= 0.20;
  // Avec seulement deux mots communs dans les titres, la description doit
  // apporter au moins trois termes supplémentaires concordants.
  const additionalDescriptionOverlap = sharedDescription.filter(token => !sharedTitle.includes(token));
  const corroboratedMatch = distinctiveSharedTitle.length >= 3 &&
    additionalDescriptionOverlap.length >= 3 && descriptionJaccard >= 0.06;
  if (!strongTitleMatch && !corroboratedMatch) return 0;

  // Le score est un indice de rapprochement, jamais une validation factuelle.
  if (strongTitleMatch) return Math.max(0.46, Math.min(1, titleJaccard));
  return Math.max(0.46, Math.min(0.75, 0.42 + descriptionJaccard));
}
function withinStoryWindow(a, b) {
  const da = Date.parse(a.published_at || a.fetched_at || "");
  const db = Date.parse(b.published_at || b.fetched_at || "");
  if (!Number.isFinite(da) || !Number.isFinite(db)) return true;
  return Math.abs(da - db) <= 72 * 60 * 60 * 1000;
}
function buildStoryClusters(rows) {
  // Regroupement conservateur : chaque nouvel article doit être compatible
  // avec tous les articles déjà présents dans le groupe (anti-chaînage).
  const groups = rows.map((_, index) => [index]);
  const groupOf = index => groups.findIndex(group => group.includes(index));
  for (let i = 0; i < rows.length; i++) {
    for (let j = i + 1; j < rows.length; j++) {
      if (!withinStoryWindow(rows[i], rows[j]) || storySimilarity(rows[i], rows[j]) < 0.46) continue;
      const groupA = groupOf(i), groupB = groupOf(j);
      if (groupA < 0 || groupB < 0 || groupA === groupB) continue;
      const compatible = groups[groupA].every(a => groups[groupB].every(b =>
        withinStoryWindow(rows[a], rows[b]) && storySimilarity(rows[a], rows[b]) >= 0.46
      ));
      if (compatible) {
        groups[groupA] = [...groups[groupA], ...groups[groupB]];
        groups.splice(groupB, 1);
      }
    }
  }
  return groups.map(indexes => {
    const items = indexes.map(index => rows[index]);
    const sources = [...new Map(items.map(item => [item.source_domain, {
      source_id: item.source_id, source_name: item.source_name, source_domain: item.source_domain
    }])).values()];
    const dates = items.map(item => Date.parse(item.published_at || item.fetched_at || "")).filter(Number.isFinite);
    const latest = dates.length ? new Date(Math.max(...dates)).toISOString() : null;
    const lead = [...items].sort((a, b) =>
      (Date.parse(b.published_at || b.fetched_at || "") || 0) - (Date.parse(a.published_at || a.fetched_at || "") || 0)
    )[0];
    const pairScores = [];
    for (let i = 0; i < items.length; i++) {
      for (let j = i + 1; j < items.length; j++) pairScores.push(storySimilarity(items[i], items[j]));
    }
    const minimumPairScore = pairScores.length ? Math.min(...pairScores) : 0;
    return {
      id: "story-" + items.map(item => item.id).sort().join("-").slice(0, 120),
      headline: lead.title,
      item_count: items.length,
      distinct_sources: sources.length,
      source_diversity: sources.length >= 2 ? "multiple_sources" : "single_source",
      matching_confidence: items.length < 2 ? "single_article" : minimumPairScore >= 0.60 ? "strong_match" : "review_required",
      matching_score: pairScores.length ? Number(minimumPairScore.toFixed(3)) : null,
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
    const editorialRows = rows.results || [];
    const clusters = buildStoryClusters(editorialRows);
    const crossSourceCandidates = [];
    let crossSourcePairsInWindow = 0;
    for (let i = 0; i < editorialRows.length; i++) {
      for (let j = i + 1; j < editorialRows.length; j++) {
        const left = editorialRows[i], right = editorialRows[j];
        if (left.source_domain === right.source_domain || !withinStoryWindow(left, right)) continue;
        crossSourcePairsInWindow++;
        const score = storySimilarity(left, right);
        if (score >= 0.12) crossSourceCandidates.push({
          score: Number(score.toFixed(3)),
          hours_apart: Math.round(Math.abs(Date.parse(left.published_at || left.fetched_at || "") - Date.parse(right.published_at || right.fetched_at || "")) / 3600000),
          left: { title: left.title, source: left.source_name },
          right: { title: right.title, source: right.source_name }
        });
      }
    }
    crossSourceCandidates.sort((a, b) => b.score - a.score);
    const descriptionsPresent = editorialRows.filter(row => String(row.description || "").trim().length >= 40).length;
    const datedRows = editorialRows.filter(row => Number.isFinite(Date.parse(row.published_at || row.fetched_at || ""))).length;
    return Response.json({
      clusters,
      diagnostics: {
        descriptions_present: descriptionsPresent,
        descriptions_missing_or_short: editorialRows.length - descriptionsPresent,
        dated_articles: datedRows,
        cross_source_pairs_within_72h: crossSourcePairsInWindow,
        best_cross_source_matches: crossSourceCandidates.slice(0, 8)
      },
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
