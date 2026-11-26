const MAX_EDITORIAL_TEXT = 30000;
const EDITORIAL_STATUSES = ["pending_review", "approved", "rejected", "published"];

export async function ensureEditorialAgentSchema(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS editorial_drafts (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 300),
      article TEXT NOT NULL CHECK(length(article) BETWEEN 1 AND 30000),
      summary TEXT NOT NULL DEFAULT '' CHECK(length(summary) <= 2000),
      social_post TEXT NOT NULL DEFAULT '' CHECK(length(social_post) <= 3000),
      category TEXT NOT NULL DEFAULT '' CHECK(length(category) <= 120),
      keywords_json TEXT NOT NULL DEFAULT '[]' CHECK(length(keywords_json) <= 4000),
      sources_json TEXT NOT NULL DEFAULT '[]' CHECK(length(sources_json) <= 12000),
      fact_check_json TEXT NOT NULL DEFAULT '[]' CHECK(length(fact_check_json) <= 12000),
      status TEXT NOT NULL DEFAULT 'pending_review'
        CHECK(status IN ('pending_review','approved','rejected','published')),
      rejection_note TEXT CHECK(rejection_note IS NULL OR length(rejection_note) <= 1000),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      reviewed_at TEXT,
      published_at TEXT,
      published_row_id TEXT
    )
  `).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_editorial_drafts_owner ON editorial_drafts(user_id, project_id, status, created_at DESC)").run();
}

function parseJsonArray(value) {
  try {
    const parsed = JSON.parse(value || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function cleanText(value, max) {
  return String(value ?? "").trim().slice(0, max);
}

export async function handleEditorialAgentRequest(request, env, path, user) {
  const match = path.match(/^\/api\/projects\/([^/]+)\/editorial-agent\/drafts(?:\/([^/]+))?$/);
  if (!match || !["GET", "POST", "PATCH"].includes(request.method)) return null;

  const projectId = decodeURIComponent(match[1]);
  const draftId = match[2] ? decodeURIComponent(match[2]) : null;
  const project = await env.DB.prepare(
    "SELECT id, name, type FROM projects WHERE id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1"
  ).bind(projectId, user.id).first();
  if (!project || project.type !== "application") {
    return Response.json({ error: "Application introuvable ou non autorisée." }, { status: 404 });
  }

  await ensureEditorialAgentSchema(env);

  if (request.method === "GET" && !draftId) {
    const result = await env.DB.prepare(`
      SELECT id, title, article, summary, social_post, category, keywords_json,
             sources_json, fact_check_json, status, rejection_note,
             created_at, updated_at, reviewed_at, published_at, published_row_id
      FROM editorial_drafts
      WHERE user_id = ? AND project_id = ?
      ORDER BY created_at DESC
      LIMIT 100
    `).bind(user.id, projectId).all();
    return Response.json({
      drafts: (result.results || []).map(row => ({
        ...row,
        keywords: parseJsonArray(row.keywords_json),
        sources: parseJsonArray(row.sources_json),
        fact_check: parseJsonArray(row.fact_check_json)
      }))
    });
  }

  if (request.method === "POST" && !draftId) {
    const body = await request.json();
    const title = cleanText(body.title, 300);
    const article = cleanText(body.article, MAX_EDITORIAL_TEXT);
    if (!title || !article) return Response.json({ error: "Le titre et l'article sont obligatoires." }, { status: 400 });
    const asArray = (value, maxItems, maxChars) => {
      if (value === undefined) return "[]";
      if (!Array.isArray(value) || value.length > maxItems) throw new Error("Liste de métadonnées invalide.");
      const safe = value.map(item => {
        if (typeof item === "string") return cleanText(item, maxChars);
        if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error("Élément de métadonnée invalide.");
        return Object.fromEntries(Object.entries(item).slice(0, 12).map(([key, val]) => [cleanText(key, 60), cleanText(val, 1000)]));
      });
      return JSON.stringify(safe);
    };
    let keywordsJson, sourcesJson, factCheckJson;
    try {
      keywordsJson = asArray(body.keywords, 30, 80);
      sourcesJson = asArray(body.sources, 20, 1000);
      factCheckJson = asArray(body.fact_check, 30, 1000);
    } catch (error) {
      return Response.json({ error: error.message }, { status: 400 });
    }
    const id = crypto.randomUUID();
    await env.DB.prepare(`
      INSERT INTO editorial_drafts
        (id,user_id,project_id,title,article,summary,social_post,category,keywords_json,sources_json,fact_check_json,status)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,'pending_review')
    `).bind(
      id, user.id, projectId, title, article,
      cleanText(body.summary, 2000), cleanText(body.social_post, 3000),
      cleanText(body.category, 120), keywordsJson, sourcesJson, factCheckJson
    ).run();
    return Response.json({ message: "Brouillon enregistré pour validation humaine. Il n'est pas publié.", draft: { id, status: "pending_review" } }, { status: 201 });
  }

  if (request.method === "PATCH" && draftId) {
    const body = await request.json();
    const decision = cleanText(body.decision, 20);
    if (!["approve", "reject"].includes(decision)) {
      return Response.json({ error: "Décision invalide. Utilisez approve ou reject." }, { status: 400 });
    }
    const note = cleanText(body.note, 1000);
    const nextStatus = decision === "approve" ? "approved" : "rejected";
    const updated = await env.DB.prepare(`
      UPDATE editorial_drafts
      SET status = ?, rejection_note = ?, reviewed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
      WHERE id = ? AND user_id = ? AND project_id = ? AND status = 'pending_review'
    `).bind(nextStatus, decision === "reject" ? note : null, draftId, user.id, projectId).run();
    if (!updated.meta || updated.meta.changes !== 1) {
      const exists = await env.DB.prepare("SELECT status FROM editorial_drafts WHERE id = ? AND user_id = ? AND project_id = ? LIMIT 1")
        .bind(draftId, user.id, projectId).first();
      if (!exists) return Response.json({ error: "Brouillon introuvable." }, { status: 404 });
      return Response.json({ error: "Ce brouillon a déjà été traité.", status: exists.status }, { status: 409 });
    }
    return Response.json({ message: decision === "approve" ? "Brouillon approuvé. Il n'est pas encore publié." : "Brouillon refusé.", status: nextStatus });
  }

  return Response.json({ error: "Route éditoriale introuvable." }, { status: 404 });
}
