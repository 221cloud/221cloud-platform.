
const ITERATIONS = 100000;
const SESSION_DAYS = 7;
const SESSION_IDLE_MINUTES = 60;
const DATABASE_NAME_MAX = 80;

const STORAGE_LIMIT_BYTES = 1024 * 1024 * 1024;
const MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024;

function json(data, status = 200, extraHeaders = {}) {
  const headers = new Headers(extraHeaders);
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), { status, headers });
}

function base64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function fromBase64(value) {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

async function hashToken(token) {
  const data = new TextEncoder().encode(token);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash), b =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const result = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  return `pbkdf2$${ITERATIONS}$${base64(salt)}$${base64(result)}`;
}

async function verifyPassword(password, stored) {
  try {
    const [algorithm, iterations, salt, expected] = stored.split("$");

    if (algorithm !== "pbkdf2") return false;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const result = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: fromBase64(salt),
        iterations: Number(iterations),
        hash: "SHA-256"
      },
      key,
      256
    );

    const actual = new Uint8Array(result);
    const expectedBytes = fromBase64(expected);

    if (actual.length !== expectedBytes.length) return false;

    let difference = 0;

    for (let i = 0; i < actual.length; i++) {
      difference |= actual[i] ^ expectedBytes[i];
    }

    return difference === 0;
  } catch {
    return false;
  }
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";

  const item = cookies.split(";")
    .map(v => v.trim())
    .find(v => v.startsWith(name + "="));

  return item ? item.slice(name.length + 1) : null;
}

async function createSession(env, userId) {
  const token = randomToken();
  const tokenHash = await hashToken(token);
  const expires = new Date(Date.now() + SESSION_DAYS * 86400000);

  await env.DB.prepare(
    "INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)"
  ).bind(
    crypto.randomUUID(),
    userId,
    tokenHash,
    expires.toISOString()
  ).run();

  return token;
}

function sessionCookie(token) {
  return `221cloud_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 86400}`;
}

async function currentUser(request, env) {
  const token = getCookie(request, "221cloud_session");

  if (!token) return null;

  const tokenHash = await hashToken(token);
  const now = new Date();
  const nowIso = now.toISOString();

  const result = await env.DB.prepare(
    `SELECT users.id, users.email, users.full_name, users.role
     FROM sessions
     JOIN users ON users.id = sessions.user_id
     WHERE sessions.token_hash = ?
       AND sessions.expires_at > ?
       AND users.status = 'active'
     LIMIT 1`
  ).bind(tokenHash, nowIso).first();

  if (!result) return null;

  // Expiration glissante : toute requête authentifiée prolonge la session
  // d'une heure. Après une heure sans activité, le serveur refuse la session.
  const nextExpiry = new Date(now.getTime() + SESSION_IDLE_MINUTES * 60000).toISOString();
  await env.DB.prepare(
    "UPDATE sessions SET expires_at = ? WHERE token_hash = ? AND expires_at > ?"
  ).bind(nextExpiry, tokenHash, nowIso).run();

  return result;
}
async function generateWebsiteSlug(env, projectName) {
  const base = String(projectName || "site")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 50)
    .replace(/-+$/g, "") || "site";

  let slug = base;
  let suffix = 2;

  while (
    await env.DB.prepare(
      "SELECT id FROM website_hostings WHERE slug = ? LIMIT 1"
    ).bind(slug).first()
  ) {
    slug = `${base}-${suffix}`;
    suffix++;
  }

  return slug;
}
async function requireAdmin(request, env) {
  const user = await currentUser(request, env);

  if (!user) {
    return {
      user: null,
      response: json({
        error: "Authentification requise."
      }, 401)
    };
  }

  if (user.role !== "admin") {
    return {
      user: null,
      response: json({
        error: "Accès réservé aux administrateurs."
      }, 403)
    };
  }

  return {
    user,
    response: null
  };
}
const PROJECT_TYPES = ["website", "application", "database", "other"];

function validProjectName(value) {
  return typeof value === "string" &&
    value.trim().length >= 1 &&
    value.trim().length <= 100;
}

function validDatabaseName(value) {
  return typeof value === "string" &&
    value.trim().length >= 1 &&
    value.trim().length <= DATABASE_NAME_MAX;
}

// OUTILS DE SIGNATURE AWS S3 / BACKBLAZE B2

function toHex(buffer) {
  return Array.from(new Uint8Array(buffer), b =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

async function sha256(value) {
  return toHex(await crypto.subtle.digest(
    "SHA-256",
    typeof value === "string"
      ? new TextEncoder().encode(value)
      : value
  ));
}

async function hmac(key, value) {
  const imported = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  return new Uint8Array(await crypto.subtle.sign(
    "HMAC",
    imported,
    new TextEncoder().encode(value)
  ));
}

function awsEncode(value) {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    c => "%" + c.charCodeAt(0).toString(16).toUpperCase()
  );
}

function encodeObjectPath(bucket, key) {
  return "/" + [bucket, ...key.split("/")].map(awsEncode).join("/");
}

async function getSigningKey(secret, date, region) {
  const initialKey = new TextEncoder().encode("AWS4" + secret);

  const dateKey = await hmac(initialKey, date);
  const regionKey = await hmac(dateKey, region);
  const serviceKey = await hmac(regionKey, "s3");

  return hmac(serviceKey, "aws4_request");
}

async function b2Request(env, method, objectKey, body = null, contentType = null) {
  if (
    !env.B2_KEY_ID ||
    !env.B2_APPLICATION_KEY ||
    !env.B2_ENDPOINT ||
    !env.B2_BUCKET_NAME
  ) {
    throw new Error("STORAGE_CONFIGURATION_MISSING");
  }

  const endpoint = new URL(env.B2_ENDPOINT);

  const regionMatch = endpoint.hostname.match(
    /^s3[.-]([a-z0-9-]+)\.backblazeb2\.com$/
  );

  if (!regionMatch) {
    throw new Error("STORAGE_ENDPOINT_INVALID");
  }

  const region = regionMatch[1];
  const now = new Date();

  const amzDate = now.toISOString()
    .replace(/[:-]|\.\d{3}/g, "");

  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = await sha256(body || new Uint8Array());

  const canonicalUri = encodeObjectPath(
    env.B2_BUCKET_NAME,
    objectKey
  );

  const canonicalHeaders =
  `host:${endpoint.host}\n` +
  `x-amz-content-sha256:${payloadHash}\n` +
  `x-amz-date:${amzDate}\n`;

  const signedHeaders = "host;x-amz-content-sha256;x-amz-date";

  const canonicalRequest = [
    method,
    canonicalUri,
    "",
    canonicalHeaders,
    signedHeaders,
    payloadHash
  ].join("\n");

  const scope = `${dateStamp}/${region}/s3/aws4_request`;

  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    scope,
    await sha256(canonicalRequest)
  ].join("\n");

  const signingKey = await getSigningKey(
    env.B2_APPLICATION_KEY,
    dateStamp,
    region
  );

  const signature = toHex(
    await hmac(signingKey, stringToSign)
  );

  const authorization =
    `AWS4-HMAC-SHA256 Credential=${env.B2_KEY_ID}/${scope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const targetUrl = new URL(endpoint.origin);
  targetUrl.pathname = canonicalUri;

  const headers = new Headers({
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": amzDate,
    "Authorization": authorization
  });

  if (contentType) {
    headers.set("Content-Type", contentType);
  }

  const requestBody =
  method === "PUT" && body !== null
    ? new Blob([body], {
        type: contentType || "application/octet-stream"
      })
    : undefined;

return fetch(targetUrl.toString(), {
  method,
  headers,
  body: requestBody
});
}

function storageConfigurationAvailable(env) {
  return Boolean(
    env.B2_KEY_ID &&
    env.B2_APPLICATION_KEY &&
    env.B2_ENDPOINT &&
    env.B2_BUCKET_NAME
  );
}

async function b2NativeAuthorize(env) {
  if (!storageConfigurationAvailable(env)) {
    throw new Error("STORAGE_CONFIGURATION_MISSING");
  }

  const response = await fetch(
    "https://api.backblazeb2.com/b2api/v4/b2_authorize_account",
    {
      headers: {
        Authorization:
          "Basic " +
          btoa(
            env.B2_KEY_ID + ":" + env.B2_APPLICATION_KEY
          )
      }
    }
  );

  const responseText = await response.text();

  if (!response.ok) {
    throw new Error(
      "B2_AUTHORIZATION_FAILED: " + responseText.slice(0, 500)
    );
  }

  const auth = JSON.parse(responseText);
  const storage = auth.apiInfo.storageApi;

  const bucket = storage.allowed.buckets.find(
    item => item.name === env.B2_BUCKET_NAME
  );

  if (!bucket || !bucket.id) {
    throw new Error("B2_BUCKET_NOT_FOUND");
  }

  return {
    apiUrl: storage.apiUrl,
    downloadUrl: storage.downloadUrl,
    authorizationToken: auth.authorizationToken,
    bucketId: bucket.id
  };
}

async function b2NativeJson(auth, action, data) {
  const response = await fetch(
    `${auth.apiUrl}/b2api/v4/${action}`,
    {
      method: "POST",
      headers: {
        Authorization: auth.authorizationToken,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(data)
    }
  );

  const responseText = await response.text();

  if (!response.ok) {
    throw new Error(
      `B2_${action}_FAILED: ${responseText.slice(0, 500)}`
    );
  }

  return JSON.parse(responseText);
}

async function b2NativeUpload(env, objectKey, body, contentType) {
  const auth = await b2NativeAuthorize(env);

  const uploadInfo = await b2NativeJson(
    auth,
    "b2_get_upload_url",
    { bucketId: auth.bucketId }
  );

  const bytes =
    body instanceof Uint8Array
      ? body
      : new Uint8Array(body);

  const digest = await crypto.subtle.digest("SHA-1", bytes);

  const sha1 = Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");

  const response = await fetch(uploadInfo.uploadUrl, {
    method: "POST",
    headers: {
      Authorization: uploadInfo.authorizationToken,
      "X-Bz-File-Name": encodeURIComponent(objectKey),
      "Content-Type": contentType || "application/octet-stream",
      "X-Bz-Content-Sha1": sha1
    },
    body: bytes
  });

  const responseText = await response.text();

  if (!response.ok) {
    throw new Error(
      "B2_UPLOAD_FAILED: " + responseText.slice(0, 500)
    );
  }

  const uploadedResult = JSON.parse(responseText);

  // Conserver l'empreinte calculée localement, indépendamment du format
  // de la réponse B2, afin de pouvoir la vérifier au téléchargement.
  return {
    ...uploadedResult,
    contentSha1: sha1
  };
}

async function b2NativeDownload(env, fileId) {
  const auth = await b2NativeAuthorize(env);

  const url =
    `${auth.downloadUrl}/b2api/v4/b2_download_file_by_id` +
    `?fileId=${encodeURIComponent(fileId)}`;

  return fetch(url, {
    headers: {
      Authorization: auth.authorizationToken
    }
  });
}

async function b2NativeDelete(env, fileId, fileName) {
  const auth = await b2NativeAuthorize(env);

  return b2NativeJson(
    auth,
    "b2_delete_file_version",
    {
      fileId,
      fileName
    }
  );
}

function safeFileName(value) {
  return String(value || "fichier")
    .replace(/[\r\n"]/g, "_")
    .slice(0, 255);
}

async function ensureStorageFoldersSchema(env) {
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS storage_folders (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, parent_id TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)").run();
  const columns = await env.DB.prepare("PRAGMA table_info(cloud_files)").all();
  const columnNames = (columns.results || []).map(column => column.name);
  if (!columnNames.includes("folder_id")) await env.DB.prepare("ALTER TABLE cloud_files ADD COLUMN folder_id TEXT").run();
  if (!columnNames.includes("content_sha1")) await env.DB.prepare("ALTER TABLE cloud_files ADD COLUMN content_sha1 TEXT").run();
  if (!columnNames.includes("deleted_at")) await env.DB.prepare("ALTER TABLE cloud_files ADD COLUMN deleted_at TEXT").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS storage_activity_log (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, action TEXT NOT NULL, file_name TEXT NOT NULL, file_size INTEGER NOT NULL DEFAULT 0, details TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)").run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_storage_activity_user_date ON storage_activity_log(user_id, created_at DESC)").run();
}


async function loginProtectionKeys(request, email) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  return [
    "ip:" + await hashToken(ip),
    "email:" + await hashToken(email)
  ];
}

async function ensureLoginProtectionSchema(env) {
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS login_attempt_limits (
      scope_key TEXT PRIMARY KEY,
      attempts INTEGER NOT NULL DEFAULT 0,
      window_started_at INTEGER NOT NULL,
      blocked_until INTEGER NOT NULL DEFAULT 0
    )`
  ).run();
}

async function getLoginBlock(env, keys) {
  const now = Math.floor(Date.now() / 1000);
  const rows = await env.DB.prepare(
    "SELECT blocked_until FROM login_attempt_limits WHERE scope_key IN (?, ?)"
  ).bind(keys[0], keys[1]).all();
  return (rows.results || []).some(row => Number(row.blocked_until) > now);
}

async function recordLoginFailure(env, keys) {
  const now = Math.floor(Date.now() / 1000);
  const windowSeconds = 15 * 60;
  const blockSeconds = 15 * 60;

  for (let i = 0; i < keys.length; i++) {
    const threshold = i === 0 ? 20 : 8;
    await env.DB.prepare(
      `INSERT INTO login_attempt_limits
        (scope_key, attempts, window_started_at, blocked_until)
       VALUES (?, 1, ?, 0)
       ON CONFLICT(scope_key) DO UPDATE SET
         attempts = CASE
           WHEN login_attempt_limits.window_started_at <= ? THEN 1
           ELSE login_attempt_limits.attempts + 1
         END,
         window_started_at = CASE
           WHEN login_attempt_limits.window_started_at <= ? THEN ?
           ELSE login_attempt_limits.window_started_at
         END,
         blocked_until = CASE
           WHEN (CASE
             WHEN login_attempt_limits.window_started_at <= ? THEN 1
             ELSE login_attempt_limits.attempts + 1
           END) >= ? THEN ?
           ELSE login_attempt_limits.blocked_until
         END`
    ).bind(
      keys[i],
      now,
      now - windowSeconds,
      now - windowSeconds,
      now,
      now - windowSeconds,
      threshold,
      now + blockSeconds
    ).run();
  }

  await env.DB.prepare(
    "DELETE FROM login_attempt_limits WHERE window_started_at < ? AND blocked_until < ?"
  ).bind(now - 86400, now).run();
}

async function clearLoginFailures(env, keys) {
  await env.DB.prepare(
    "DELETE FROM login_attempt_limits WHERE scope_key IN (?, ?)"
  ).bind(keys[0], keys[1]).run();
}


async function ensureAccountSecuritySchema(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS account_security_events (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      action TEXT NOT NULL,
      description TEXT NOT NULL,
      device_info TEXT NOT NULL DEFAULT 'Navigateur inconnu',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS idx_account_security_user_date ON account_security_events(user_id, created_at DESC)"
  ).run();
}

function getGeneralDeviceInfo(request) {
  const ua = request.headers.get("User-Agent") || "";
  let browser = "Navigateur inconnu";
  let system = "Système inconnu";

  if (/Edg\//i.test(ua)) browser = "Edge";
  else if (/OPR\//i.test(ua)) browser = "Opera";
  else if (/CriOS|Chrome\//i.test(ua)) browser = "Chrome";
  else if (/FxiOS|Firefox\//i.test(ua)) browser = "Firefox";
  else if (/Safari\//i.test(ua)) browser = "Safari";

  if (/iPhone|iPad|iPod/i.test(ua)) system = "iOS";
  else if (/Android/i.test(ua)) system = "Android";
  else if (/Windows/i.test(ua)) system = "Windows";
  else if (/Macintosh|Mac OS/i.test(ua)) system = "macOS";
  else if (/Linux/i.test(ua)) system = "Linux";

  return browser + " · " + system;
}

async function recordSecurityEvent(env, userId, action, description, request) {
  try {
    await ensureAccountSecuritySchema(env);
    await env.DB.prepare(
      "INSERT INTO account_security_events (id, user_id, action, description, device_info) VALUES (?, ?, ?, ?, ?)"
    ).bind(
      crypto.randomUUID(),
      userId,
      String(action || "account"),
      String(description || "Activité du compte"),
      getGeneralDeviceInfo(request)
    ).run();
  } catch (error) {
    console.error("ERREUR JOURNAL DE SÉCURITÉ:", error);
  }
}

async function recordStorageActivity(env, userId, action, file, details = "") {
  try {
    await env.DB.prepare(
      "INSERT INTO storage_activity_log (id, user_id, action, file_name, file_size, details) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(
      crypto.randomUUID(),
      userId,
      action,
      String(file?.file_name || "Fichier"),
      Math.max(0, Number(file?.file_size) || 0),
      String(details || "")
    ).run();
  } catch (error) {
    console.error("ERREUR HISTORIQUE STOCKAGE:", error);
  }
}
async function ensureProjectTrashSchema(env) {
  const columns = await env.DB.prepare("PRAGMA table_info(projects)").all();
  const hasDeletedAt = (columns.results || []).some(column => column.name === "deleted_at");
  if (!hasDeletedAt) {
    try {
      await env.DB.prepare("ALTER TABLE projects ADD COLUMN deleted_at TEXT").run();
    } catch (error) {
      const refreshed = await env.DB.prepare("PRAGMA table_info(projects)").all();
      const alreadyAdded = (refreshed.results || []).some(column => column.name === "deleted_at");
      if (!alreadyAdded) throw error;
    }
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/api/health") {
      return json({
        platform: "221Cloud",
        status: "online"
      });
    }

    if (path.startsWith("/api/projects") || path === "/api/databases" || path === "/api/admin/stats") {
      try {
        await ensureProjectTrashSchema(env);
      } catch (error) {
        console.error("ERREUR INITIALISATION CORBEILLE PROJETS:", error);
        return json({ error: "Impossible de vérifier le système de projets." }, 500);
      }
    }
if (path === "/api/admin/stats") {
  const auth = await requireAdmin(request, env);

  if (auth.response) return auth.response;

  const users = await env.DB.prepare(
    "SELECT COUNT(*) AS total FROM users"
  ).first();

  const projects = await env.DB.prepare(
    "SELECT COUNT(*) AS total FROM projects WHERE deleted_at IS NULL"
  ).first();

  const databases = await env.DB.prepare(
    "SELECT COUNT(*) AS total FROM customer_databases"
  ).first();

  const files = await env.DB.prepare(
    `SELECT
       COUNT(*) AS total,
       COALESCE(SUM(file_size), 0) AS storage_used
     FROM cloud_files`
  ).first();

  return json({
    users: users.total,
    projects: projects.total,
    databases: databases.total,
    files: files.total,
    storageUsed: files.storage_used
  });
}
if (path === "/api/admin/users" && request.method === "GET") {
  const auth = await requireAdmin(request, env);

  if (auth.response) return auth.response;

  const result = await env.DB.prepare(
    `SELECT
       id,
       email,
       full_name,
       role,
       status,
       created_at
     FROM users
     ORDER BY created_at DESC`
  ).all();

  return json({
    users: result.results || []
  });
}
if (
  path.startsWith("/api/admin/users/") &&
  request.method === "PATCH"
) {
  const auth = await requireAdmin(request, env);

  if (auth.response) return auth.response;

  const userId = decodeURIComponent(
    path.slice("/api/admin/users/".length)
  );

  const body = await request.json();

  const target = await env.DB.prepare(
    `SELECT id, role, status
     FROM users
     WHERE id = ?
     LIMIT 1`
  ).bind(userId).first();

  if (!target) {
    return json({ error: "Utilisateur introuvable." }, 404);
  }

  const role = body.role === undefined
    ? target.role
    : String(body.role);

  const status = body.status === undefined
    ? target.status
    : String(body.status);

  if (!["admin", "client"].includes(role)) {
    return json({ error: "Rôle invalide." }, 400);
  }

  if (!["active", "suspended"].includes(status)) {
    return json({ error: "Statut invalide." }, 400);
  }

  if (
    target.id === auth.user.id &&
    (role !== "admin" || status !== "active")
  ) {
    return json({
      error: "Vous ne pouvez pas rétrograder ou suspendre votre propre compte."
    }, 403);
  }

  if (
    target.role === "admin" &&
    target.status === "active" &&
    (role !== "admin" || status !== "active")
  ) {
    const admins = await env.DB.prepare(
      `SELECT COUNT(*) AS total
       FROM users
       WHERE role = 'admin' AND status = 'active'`
    ).first();

    if (admins.total <= 1) {
      return json({
        error: "Impossible de modifier le dernier administrateur actif."
      }, 403);
    }
  }

  await env.DB.prepare(
    `UPDATE users
     SET role = ?, status = ?
     WHERE id = ?`
  ).bind(role, status, userId).run();

  return json({
    success: true,
    message: "Utilisateur mis à jour.",
    user: {
      id: userId,
      role,
      status
    }
  });
}
    if (path === "/api/database-test") {
      try {
        const result = await env.DB.prepare(
          "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        ).all();

        return json({
          platform: "221Cloud",
          database: "connected",
          tables: result.results
        });
      } catch (error) {
        console.error("ERREUR DATABASE:", error);
        return json({
          platform: "221Cloud",
          database: "error"
        }, 500);
      }
    }

    // INSCRIPTION
    if (path === "/api/register" && request.method === "POST") {
      try {
        const body = await request.json();

        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");
        const fullName = String(body.full_name || body.name || "").trim();

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return json({ error: "Adresse e-mail invalide." }, 400);
        }

        if (password.length < 12 || password.length > 128) {
          return json({
            error: "Le mot de passe doit contenir entre 12 et 128 caractères."
          }, 400);
        }

        const existing = await env.DB.prepare(
          "SELECT id FROM users WHERE email = ?"
        ).bind(email).first();

        if (existing) {
          return json({
            error: "Cette adresse e-mail est déjà utilisée."
          }, 409);
        }

        const userId = crypto.randomUUID();
        const passwordHash = await hashPassword(password);

        await env.DB.prepare(
          "INSERT INTO users (id, email, full_name, password_hash, role) VALUES (?, ?, ?, ?, 'client')"
        ).bind(
          userId,
          email,
          fullName || null,
          passwordHash
                ).run();

        // Créer automatiquement l'abonnement Free
        await env.DB.prepare(`
          INSERT INTO subscriptions (
            id,
            user_id,
            plan,
            status,
            created_at,
            started_at,
            expires_at,
            auto_renew
          )
          SELECT
            ?,
            ?,
            'free',
            'active',
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP,
            NULL,
            0
          WHERE NOT EXISTS (
            SELECT 1 FROM subscriptions WHERE user_id = ?
          )
        `).bind(
          crypto.randomUUID(),
          userId,
          userId
        ).run();

        const token = await createSession(env, userId);

        return json({
          message: "Compte créé avec succès.",
          user: {
            id: userId,
            email,
            full_name: fullName || null,
            role: "client"
          }
        }, 201, {
          "Set-Cookie": sessionCookie(token)
        });

      } catch (error) {
        console.error("ERREUR INSCRIPTION 221CLOUD:", error);
        return json({
          error: "Impossible de créer le compte."
        }, 500);
      }
    }

    // CONNEXION
    if (path === "/api/login" && request.method === "POST") {
      try {
        const body = await request.json();

        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");

        await ensureLoginProtectionSchema(env);
        const protectionKeys = await loginProtectionKeys(request, email);

        if (await getLoginBlock(env, protectionKeys)) {
          return json({
            error: "Trop de tentatives. Réessaie dans quelques minutes."
          }, 429, { "Retry-After": "900" });
        }

        const user = await env.DB.prepare(
          "SELECT id, email, full_name, role, password_hash FROM users WHERE email = ?"
        ).bind(email).first();

        if (
          !user ||
          !user.password_hash ||
          !(await verifyPassword(password, user.password_hash))
        ) {
          await recordLoginFailure(env, protectionKeys);
          return json({
            error: "E-mail ou mot de passe incorrect."
          }, 401);
        }

        await clearLoginFailures(env, protectionKeys);
        await ensureAccountSecuritySchema(env);
        const currentDeviceInfo = getGeneralDeviceInfo(request);
        const knownEnvironment = await env.DB.prepare(
          "SELECT id FROM account_security_events WHERE user_id = ? AND action IN ('login', 'new_environment_login') AND device_info = ? LIMIT 1"
        ).bind(user.id, currentDeviceInfo).first();
        const loginAction = knownEnvironment ? "login" : "new_environment_login";
        const loginDescription = knownEnvironment
          ? "Connexion réussie"
          : "Connexion depuis un nouvel environnement détecté";
        const token = await createSession(env, user.id);
        await recordSecurityEvent(env, user.id, loginAction, loginDescription, request);

        return json({
          message: "Connexion réussie.",
          user: {
            id: user.id,
            email: user.email,
            full_name: user.full_name,
            role: user.role
          }
        }, 200, {
          "Set-Cookie": sessionCookie(token)
        });

      } catch (error) {
        console.error("ERREUR CONNEXION 221CLOUD:", error);
        return json({
          error: "Impossible de se connecter."
        }, 500);
      }
    }

    // UTILISATEUR CONNECTÉ
    if (path === "/api/me" && request.method === "GET") {
      try {
        const user = await currentUser(request, env);

        if (!user) {
          return json({ error: "Non connecté." }, 401);
        }

        return json({ user });

      } catch (error) {
        console.error("ERREUR SESSION 221CLOUD:", error);
        return json({
          error: "Impossible de vérifier la session."
        }, 500);
      }
    }
if (path === "/api/subscription" && request.method === "GET") {
  try {
    const user = await currentUser(request, env);

    if (!user) {
      return json({ error: "Non connecté." }, 401);
    }

    const subscription = await env.DB.prepare(`
      SELECT
        plan,
        status,
        started_at,
        expires_at,
        auto_renew
      FROM subscriptions
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT 1
    `).bind(user.id).first();

    if (!subscription) {
      return json({
        error: "Aucun abonnement trouvé."
      }, 404);
    }

    return json({ subscription });

  } catch (error) {
    console.error("ERREUR ABONNEMENT 221CLOUD:", error);
    return json({
      error: "Impossible de récupérer l'abonnement."
    }, 500);
  }
}
    // LISTE DES PROJETS
    if (path === "/api/projects" && request.method === "GET") {
      try {
        const user = await currentUser(request, env);

        if (!user) {
          return json({ error: "Vous devez être connecté." }, 401);
        }

        const result = await env.DB.prepare(
          `SELECT id, name, type, status, created_at
           FROM projects
           WHERE user_id = ? AND deleted_at IS NULL
           ORDER BY created_at DESC`
        ).bind(user.id).all();

        return json({
          projects: result.results
        });

      } catch (error) {
        console.error("ERREUR LISTE PROJETS:", error);
        return json({
          error: "Impossible de charger les projets."
        }, 500);
      }
    }

    // CRÉER UN NOUVEAU DÉPLOIEMENT
    const deploymentProjectMatch = path.match(
      /^\/api\/projects\/([^/]+)\/deployments$/
    );

    if (deploymentProjectMatch && request.method === "POST") {
      try {
        const user = await currentUser(request, env);

        if (!user) {
          return json({ error: "Vous devez être connecté." }, 401);
        }

        const projectId = decodeURIComponent(
          deploymentProjectMatch[1]
        );

        const project = await env.DB.prepare(`
          SELECT id, name, type
          FROM projects
          WHERE id = ? AND user_id = ? AND deleted_at IS NULL
        `).bind(projectId, user.id).first();

        if (!project) {
          return json({ error: "Projet introuvable." }, 404);
        }

        if (project.type !== "website") {
          return json({
            error: "Ce projet n'est pas un site web."
          }, 400);
        }

        const hosting = await env.DB.prepare(`
          SELECT id, slug, active_deployment_id
          FROM website_hostings
          WHERE project_id = ? AND user_id = ?
        `).bind(projectId, user.id).first();

        if (!hosting) {
          return json({
            error: "Aucun hébergement n'est associé à ce projet."
          }, 404);
        }

        const deploymentId = crypto.randomUUID();

        await env.DB.prepare(`
          INSERT INTO deployments (
            id, project_id, status
          )
          VALUES (?, ?, 'pending')
        `).bind(deploymentId, projectId).run();

        return json({
          message: "Déploiement préparé.",
          deployment: {
            id: deploymentId,
            project_id: projectId,
            hosting_id: hosting.id,
            slug: hosting.slug,
            status: "pending"
          }
        }, 201);

      } catch (error) {
        console.error("ERREUR CRÉATION DÉPLOIEMENT:", error);
        return json({
          error: "Impossible de préparer le déploiement."
        }, 500);
      }
    }

    // ENVOYER UN FICHIER VERS UN DÉPLOIEMENT
    const deploymentFileMatch = path.match(
      /^\/api\/projects\/([^/]+)\/deployments\/([^/]+)\/files$/
    );

    if (deploymentFileMatch && request.method === "POST") {
      try {
        const user = await currentUser(request, env);

        if (!user) {
          return json({ error: "Vous devez être connecté." }, 401);
        }

        if (!storageConfigurationAvailable(env)) {
          return json({
            error: "Le stockage cloud n'est pas configuré."
          }, 503);
        }

        const projectId = decodeURIComponent(
          deploymentFileMatch[1]
        );

        const deploymentId = decodeURIComponent(
          deploymentFileMatch[2]
        );

        const deployment = await env.DB.prepare(`
          SELECT
            deployments.id,
            deployments.status,
            website_hostings.id AS hosting_id
          FROM deployments
          JOIN projects
            ON projects.id = deployments.project_id
          JOIN website_hostings
            ON website_hostings.project_id = projects.id
          WHERE deployments.id = ?
            AND projects.id = ?
            AND projects.user_id = ?
            AND projects.type = 'website'
            AND projects.deleted_at IS NULL
            AND website_hostings.user_id = ?
          LIMIT 1
        `).bind(
          deploymentId,
          projectId,
          user.id,
          user.id
        ).first();

        if (!deployment) {
          return json({
            error: "Déploiement introuvable."
          }, 404);
        }

        if (deployment.status !== "pending") {
          return json({
            error: "Ce déploiement n'accepte plus de fichiers."
          }, 409);
        }

        const contentType = request.headers.get("Content-Type") || "";

        if (!contentType.toLowerCase().includes("multipart/form-data")) {
          return json({
            error: "Format d'envoi invalide."
          }, 400);
        }

        await ensureStorageFoldersSchema(env);
        const form = await request.formData();
        const file = form.get("file");
        const requestedFolderId = String(form.get("folder_id") || "").trim() || null;
        if (requestedFolderId) {
          const targetFolder = await env.DB.prepare("SELECT id FROM storage_folders WHERE id = ? AND user_id = ? LIMIT 1").bind(requestedFolderId, user.id).first();
          if (!targetFolder) return json({ error: "Dossier de destination introuvable." }, 404);
        }

        if (!file || typeof file.arrayBuffer !== "function") {
          return json({
            error: "Aucun fichier reçu."
          }, 400);
        }

        if (file.size <= 0) {
          return json({
            error: "Le fichier est vide."
          }, 400);
        }

        if (file.size > MAX_FILE_SIZE_BYTES) {
          return json({
            error: "La taille maximale autorisée est de 20 Mo par fichier."
          }, 413);
        }

        // Vérification du chemin du fichier
        const filePath = String(
          form.get("file_path") || file.name || ""
        ).trim();

        const pathParts = filePath.split("/");

        if (
          !filePath ||
          filePath.length > 500 ||
          filePath.startsWith("/") ||
          filePath.includes("\\") ||
          /[\u0000-\u001F\u007F]/.test(filePath) ||
          pathParts.some(part =>
            !part || part === "." || part === ".."
          )
        ) {
          return json({
            error: "Chemin de fichier invalide."
          }, 400);
        }

        // Empêcher les doublons dans un même déploiement
        const existingFile = await env.DB.prepare(`
          SELECT id
          FROM website_files
          WHERE deployment_id = ?
            AND file_path = ?
          LIMIT 1
        `).bind(deploymentId, filePath).first();

        if (existingFile) {
          return json({
            error: "Ce fichier existe déjà dans ce déploiement."
          }, 409);
        }

        // Récupération du forfait
        const subscription = await env.DB.prepare(`
          SELECT plan, status
          FROM subscriptions
          WHERE user_id = ?
          ORDER BY created_at DESC
          LIMIT 1
        `).bind(user.id).first();

        const plan = subscription?.status === "active"
          ? subscription.plan
          : "free";

        const storageLimits = {
          free: 1024 * 1024 * 1024,
          starter: 5 * 1024 * 1024 * 1024,
          pro: 20 * 1024 * 1024 * 1024
        };

        const maxStorage = storageLimits[plan] ?? storageLimits.free;

        // Calcul du stockage privé et des sites web
        const usage = await env.DB.prepare(`
          SELECT
            COALESCE((
              SELECT SUM(file_size)
              FROM cloud_files
              WHERE user_id = ?
            ), 0) +
            COALESCE((
              SELECT SUM(website_files.file_size)
              FROM website_files
              JOIN website_hostings
                ON website_hostings.id = website_files.hosting_id
              WHERE website_hostings.user_id = ?
            ), 0) AS used
        `).bind(user.id, user.id).first();

        const used = Number(usage?.used || 0);

        if (used + file.size > maxStorage) {
          return json({
            error: `Votre forfait ${plan} ne dispose pas d'assez d'espace de stockage.`
          }, 413);
        }

        const buffer = new Uint8Array(
          await file.arrayBuffer()
        );

        const id = crypto.randomUUID();

        const storageKey =
          `websites/${user.id}/${deployment.hosting_id}/${deploymentId}/${filePath}`;

        const mimeType =
          file.type || "application/octet-stream";

        let uploadedFile;

        try {
          uploadedFile = await b2NativeUpload(
            env,
            storageKey,
            buffer,
            mimeType
          );
        } catch (uploadError) {
          console.error(
            "ERREUR ENVOI FICHIER SITE VERS B2:",
            uploadError
          );

          return json({
            error: "Le transfert du fichier du site a échoué."
          }, 502);
        }

        try {
          await env.DB.prepare(`
            INSERT INTO website_files (
              id,
              hosting_id,
              deployment_id,
              file_path,
              file_size,
              mime_type,
              storage_key,
              b2_file_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            id,
            deployment.hosting_id,
            deploymentId,
            filePath,
            file.size,
            mimeType,
            storageKey,
            uploadedFile.fileId
          ).run();

        } catch (databaseError) {
          console.error(
            "ERREUR ENREGISTREMENT FICHIER SITE:",
            databaseError
          );

          try {
            await b2NativeDelete(
              env,
              uploadedFile.fileId,
              uploadedFile.fileName
            );
          } catch (cleanupError) {
            console.error(
              "ERREUR NETTOYAGE FICHIER SITE:",
              cleanupError
            );
          }

          return json({
            error: "Le fichier a été transféré mais son enregistrement a échoué."
          }, 500);
        }

        return json({
          message: "Fichier du site envoyé avec succès.",
          file: {
            id,
            file_path: filePath,
            file_size: file.size,
            mime_type: mimeType,
            folder_id: requestedFolderId
          }
        }, 201);

      } catch (error) {
        console.error(
          "ERREUR ENVOI FICHIER DÉPLOIEMENT:",
          error
        );

        return json({
          error: "Impossible d'envoyer le fichier du site."
        }, 500);
      }
    }

    // LISTER LES FICHIERS D'UNE ANCIENNE VERSION PUBLIÉE
    const deploymentFilesHistoryMatch = path.match(
      /^\/api\/projects\/([^/]+)\/deployments\/([^/]+)\/files$/
    );

    if (deploymentFilesHistoryMatch && request.method === "GET") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        const projectId = decodeURIComponent(deploymentFilesHistoryMatch[1]);
        const deploymentId = decodeURIComponent(deploymentFilesHistoryMatch[2]);
        const deployment = await env.DB.prepare(`
          SELECT d.id, d.status, h.id AS hosting_id
          FROM deployments d
          JOIN projects p ON p.id = d.project_id
          JOIN website_hostings h ON h.project_id = p.id
          WHERE d.id = ? AND p.id = ? AND p.user_id = ?
            AND p.type = 'website' AND p.deleted_at IS NULL AND h.user_id = ?
          LIMIT 1
        `).bind(deploymentId, projectId, user.id, user.id).first();
        if (!deployment) return json({ error: "Déploiement introuvable." }, 404);
        if (deployment.status !== "published") {
          return json({ error: "Seules les versions publiées peuvent être consultées." }, 409);
        }
        const result = await env.DB.prepare(`
          SELECT id, file_path, file_size, mime_type
          FROM website_files
          WHERE hosting_id = ? AND deployment_id = ?
          ORDER BY file_path ASC
        `).bind(deployment.hosting_id, deploymentId).all();
        return json({ files: result.results || [] });
      } catch (error) {
        console.error("ERREUR LISTE FICHIERS ANCIENNE VERSION:", error);
        return json({ error: "Impossible de consulter les fichiers de cette version." }, 500);
      }
    }

    // CLONER LES FICHIERS DU SITE ACTUEL DANS UN DÉPLOIEMENT DE RESTAURATION
    const cloneActiveDeploymentMatch = path.match(
      /^\/api\/projects\/([^/]+)\/deployments\/([^/]+)\/clone-active$/
    );

    if (cloneActiveDeploymentMatch && request.method === "POST") {
      const uploadedCopies = [];
      const insertedIds = [];
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        if (!storageConfigurationAvailable(env)) {
          return json({ error: "Le stockage cloud n'est pas configuré." }, 503);
        }

        const projectId = decodeURIComponent(cloneActiveDeploymentMatch[1]);
        const deploymentId = decodeURIComponent(cloneActiveDeploymentMatch[2]);
        const target = await env.DB.prepare(`
          SELECT d.id, d.status, h.id AS hosting_id, h.active_deployment_id
          FROM deployments d
          JOIN projects p ON p.id = d.project_id
          JOIN website_hostings h ON h.project_id = p.id
          WHERE d.id = ? AND p.id = ? AND p.user_id = ?
            AND p.type = 'website' AND p.deleted_at IS NULL AND h.user_id = ?
          LIMIT 1
        `).bind(deploymentId, projectId, user.id, user.id).first();

        if (!target) return json({ error: "Déploiement introuvable." }, 404);
        if (target.status !== "pending") {
          return json({ error: "Le déploiement n'accepte plus de fichiers." }, 409);
        }
        let cloneRequest = {};
        try { cloneRequest = await request.json(); } catch (e) {}
        const additionalBytes = Math.max(0, Number(cloneRequest.additional_bytes) || 0);
        const sourceDeploymentId = String(cloneRequest.source_deployment_id || target.active_deployment_id || "");
        if (!sourceDeploymentId) return json({ cloned: 0 });
        const sourceDeployment = await env.DB.prepare(`
          SELECT id, status
          FROM deployments
          WHERE id = ? AND project_id = ?
          LIMIT 1
        `).bind(sourceDeploymentId, projectId).first();
        if (!sourceDeployment || sourceDeployment.status !== "published") {
          return json({ error: "La version source doit être une ancienne version publiée de ce site." }, 400);
        }

        const sourceFiles = await env.DB.prepare(`
          SELECT file_path, file_size, mime_type, storage_key, b2_file_id
          FROM website_files
          WHERE hosting_id = ? AND deployment_id = ?
          ORDER BY file_path ASC
        `).bind(target.hosting_id, sourceDeploymentId).all();
        const files = sourceFiles.results || [];
        const cloneBytes = files.reduce((sum, file) => sum + Math.max(0, Number(file.file_size) || 0), 0);

        const subscription = await env.DB.prepare(`
          SELECT plan, status FROM subscriptions
          WHERE user_id = ? ORDER BY created_at DESC LIMIT 1
        `).bind(user.id).first();
        const plan = subscription?.status === "active" ? subscription.plan : "free";
        const storageLimits = {
          free: 1024 * 1024 * 1024,
          starter: 5 * 1024 * 1024 * 1024,
          pro: 20 * 1024 * 1024 * 1024
        };
        const maxStorage = storageLimits[plan] ?? storageLimits.free;
        const usage = await env.DB.prepare(`
          SELECT
            COALESCE((SELECT SUM(file_size) FROM cloud_files WHERE user_id = ?), 0) +
            COALESCE((SELECT SUM(wf.file_size) FROM website_files wf
              JOIN website_hostings wh ON wh.id = wf.hosting_id
              WHERE wh.user_id = ?), 0) AS used
        `).bind(user.id, user.id).first();
        const used = Number(usage?.used || 0);
        if (used + cloneBytes + additionalBytes > maxStorage) {
          return json({ error: "Espace insuffisant pour préparer la nouvelle version du site. Il faut " +
            (cloneBytes + additionalBytes) + " octet(s) supplémentaires." }, 413);
        }

        for (const file of files) {
          let sourceResponse;
          if (file.b2_file_id) {
            sourceResponse = await b2NativeDownload(env, file.b2_file_id);
          } else {
            sourceResponse = await b2Request(env, "GET", file.storage_key);
          }
          if (!sourceResponse.ok) throw new Error("Impossible de copier le fichier actuel : " + file.file_path);
          const bytes = new Uint8Array(await sourceResponse.arrayBuffer());
          if (bytes.length !== Number(file.file_size || 0)) {
            throw new Error("Taille incohérente pour le fichier actuel : " + file.file_path);
          }

          const newKey = `websites/${user.id}/${target.hosting_id}/${deploymentId}/${file.file_path}`;
          const uploaded = await b2NativeUpload(env, newKey, bytes, file.mime_type || "application/octet-stream");
          uploadedCopies.push({ fileId: uploaded.fileId, fileName: uploaded.fileName || newKey });
          const newId = crypto.randomUUID();
          await env.DB.prepare(`
            INSERT INTO website_files (
              id, hosting_id, deployment_id, file_path, file_size,
              mime_type, storage_key, b2_file_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            newId, target.hosting_id, deploymentId, file.file_path,
            file.file_size, file.mime_type, newKey, uploaded.fileId
          ).run();
          insertedIds.push(newId);
        }

        return json({ cloned: insertedIds.length, bytes: cloneBytes });
      } catch (error) {
        console.error("ERREUR COPIE FICHIERS SITE ACTUEL:", error);
        for (const id of insertedIds) {
          try { await env.DB.prepare("DELETE FROM website_files WHERE id = ?").bind(id).run(); } catch (cleanupError) {}
        }
        for (const copy of uploadedCopies) {
          try { await b2NativeDelete(env, copy.fileId, copy.fileName); } catch (cleanupError) {}
        }
        return json({ error: error.message || "Impossible de copier les fichiers du site actuel." }, 500);
      }
    }

    // ANNULER UN DÉPLOIEMENT DE RESTAURATION EN ATTENTE
    const abortDeploymentMatch = path.match(
      /^\/api\/projects\/([^/]+)\/deployments\/([^/]+)$/
    );

    if (abortDeploymentMatch && request.method === "DELETE") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        const projectId = decodeURIComponent(abortDeploymentMatch[1]);
        const deploymentId = decodeURIComponent(abortDeploymentMatch[2]);
        const deployment = await env.DB.prepare(
          "SELECT d.id, d.status FROM deployments d JOIN projects p ON p.id = d.project_id WHERE d.id = ? AND p.id = ? AND p.user_id = ? AND p.type = 'website' AND p.deleted_at IS NULL LIMIT 1"
        ).bind(deploymentId, projectId, user.id).first();
        if (!deployment) return json({ error: "Déploiement introuvable." }, 404);
        if (deployment.status !== "pending") {
          return json({ error: "Seul un déploiement en attente peut être annulé." }, 409);
        }
        const filesResult = await env.DB.prepare(
          "SELECT id, b2_file_id, storage_key FROM website_files WHERE deployment_id = ?"
        ).bind(deploymentId).all();
        for (const file of filesResult.results || []) {
          if (file.b2_file_id) {
            try {
              await b2NativeDelete(env, file.b2_file_id, file.storage_key);
            } catch (cleanupError) {
              console.error("ERREUR SUPPRESSION FICHIER DÉPLOIEMENT ANNULÉ:", cleanupError);
            }
          }
        }
        await env.DB.prepare("DELETE FROM website_files WHERE deployment_id = ?").bind(deploymentId).run();
        await env.DB.prepare("DELETE FROM deployments WHERE id = ? AND status = 'pending'").bind(deploymentId).run();
        return json({ message: "Déploiement en attente annulé." });
      } catch (error) {
        console.error("ERREUR ANNULATION DÉPLOIEMENT:", error);
        return json({ error: "Impossible d'annuler le déploiement en attente." }, 500);
      }
    }

    // PUBLIER UN DÉPLOIEMENT
    const publishDeploymentMatch = path.match(
      /^\/api\/projects\/([^/]+)\/deployments\/([^/]+)\/publish$/
    );

    if (publishDeploymentMatch && request.method === "POST") {
      try {
        const user = await currentUser(request, env);

        if (!user) {
          return json({ error: "Vous devez être connecté." }, 401);
        }

        const projectId = decodeURIComponent(
          publishDeploymentMatch[1]
        );

        const deploymentId = decodeURIComponent(
          publishDeploymentMatch[2]
        );

        const deployment = await env.DB.prepare(`
          SELECT
            deployments.id,
            deployments.status,
            website_hostings.id AS hosting_id,
            website_hostings.slug
          FROM deployments
          JOIN projects
            ON projects.id = deployments.project_id
          JOIN website_hostings
            ON website_hostings.project_id = projects.id
          WHERE deployments.id = ?
            AND projects.id = ?
            AND projects.user_id = ?
            AND projects.type = 'website'
            AND projects.deleted_at IS NULL
            AND website_hostings.user_id = ?
          LIMIT 1
        `).bind(
          deploymentId,
          projectId,
          user.id,
          user.id
        ).first();

        if (!deployment) {
          return json({
            error: "Déploiement introuvable."
          }, 404);
        }

        if (deployment.status !== "pending") {
          return json({
            error: "Ce déploiement n'est pas en attente de publication."
          }, 409);
        }

        // Vérifier la présence du fichier index.html à la racine
        const indexFile = await env.DB.prepare(`
          SELECT id
          FROM website_files
          WHERE hosting_id = ?
            AND deployment_id = ?
            AND file_path = 'index.html'
          LIMIT 1
        `).bind(
          deployment.hosting_id,
          deploymentId
        ).first();

        if (!indexFile) {
          return json({
            error: "Publication impossible : le fichier index.html est absent à la racine du site."
          }, 400);
        }

        const deploymentUrl =
          `https://221cloud-platform.elhadjidame-sall.workers.dev/site/${deployment.slug}`;

        // Activer la nouvelle version sans supprimer les anciennes
        const results = await env.DB.batch([
          env.DB.prepare(`
            UPDATE deployments
            SET status = 'published',
                deployment_url = ?
            WHERE id = ?
              AND project_id = ?
              AND status = 'pending'
          `).bind(
            deploymentUrl,
            deploymentId,
            projectId
          ),

          env.DB.prepare(`
            UPDATE website_hostings
            SET active_deployment_id = ?,
                status = 'active',
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
              AND user_id = ?
              AND EXISTS (
                SELECT 1
                FROM deployments
                WHERE id = ?
                  AND project_id = ?
                  AND status = 'published'
              )
          `).bind(
            deploymentId,
            deployment.hosting_id,
            user.id,
            deploymentId,
            projectId
          )
        ]);

        if (
          !results[0]?.meta?.changes ||
          !results[1]?.meta?.changes
        ) {
          return json({
            error: "La publication n'a pas pu être finalisée."
          }, 409);
        }

        return json({
          message: "Site publié avec succès.",
          deployment: {
            id: deploymentId,
            status: "published",
            url: deploymentUrl
          }
        });

      } catch (error) {
        console.error("ERREUR PUBLICATION SITE:", error);

        return json({
          error: "Impossible de publier le site."
        }, 500);
      }
    }

    // RATTACHER UN HÉBERGEMENT À UN PROJET EXISTANT
    const hostingProjectMatch = path.match(
      /^\/api\/projects\/([^/]+)\/hosting$/
    );
    // CONSULTER LES INFORMATIONS D'UN HÉBERGEMENT
    if (hostingProjectMatch && request.method === "GET") {
      try {
        const user = await currentUser(request, env);

        if (!user) {
          return json({ error: "Vous devez être connecté." }, 401);
        }

        const projectId = decodeURIComponent(hostingProjectMatch[1]);

        const project = await env.DB.prepare(`
          SELECT id, name, type
          FROM projects
          WHERE id = ? AND user_id = ? AND deleted_at IS NULL
        `).bind(projectId, user.id).first();

        if (!project) {
          return json({ error: "Projet introuvable." }, 404);
        }

        if (project.type !== "website") {
          return json({
            error: "Ce projet n'est pas un site web."
          }, 400);
        }

        const hosting = await env.DB.prepare(`
          SELECT
            id,
            slug,
            status,
            active_deployment_id,
            created_at,
            updated_at
          FROM website_hostings
          WHERE project_id = ? AND user_id = ?
        `).bind(projectId, user.id).first();

        const deployments = await env.DB.prepare(`
          SELECT
            d.id,
            d.status,
            d.deployment_url,
            d.created_at,
            COUNT(wf.id) AS file_count
          FROM deployments d
          LEFT JOIN website_files wf
            ON wf.deployment_id = d.id
          WHERE d.project_id = ?
          GROUP BY d.id
          ORDER BY d.created_at DESC
        `).bind(projectId).all();
const websiteFiles = hosting?.active_deployment_id
  ? await env.DB.prepare(`
      SELECT id, file_path, file_size, mime_type
      FROM website_files
      WHERE hosting_id = ?
        AND deployment_id = ?
      ORDER BY file_path ASC
    `).bind(
      hosting.id,
      hosting.active_deployment_id
    ).all()
  : { results: [] };
        return json({
          project: {
            id: project.id,
            name: project.name
          },
          hosting: hosting ? {
            ...hosting,
            url: `https://221cloud-platform.elhadjidame-sall.workers.dev/site/${hosting.slug}`
          } : null,
          deployments: deployments.results || [],
files: websiteFiles.results || []
        });

      } catch (error) {
        console.error("ERREUR CONSULTATION HÉBERGEMENT:", error);

        return json({
          error: "Impossible de récupérer les informations de l'hébergement."
        }, 500);
      }
    }
    
    // SUPPRIMER UN FICHIER DU SITE HÉBERGÉ
    const hostingFileDeleteMatch = path.match(
      /^\/api\/projects\/([^/]+)\/hosting\/files\/([^/]+)$/
    );

    if (hostingFileDeleteMatch && request.method === "DELETE") {
      try {
        const user = await currentUser(request, env);

        if (!user) {
          return json({ error: "Vous devez être connecté." }, 401);
        }

        const projectId = decodeURIComponent(hostingFileDeleteMatch[1]);
        const fileId = decodeURIComponent(hostingFileDeleteMatch[2]);

        const file = await env.DB.prepare(`
          SELECT
            website_files.id,
            website_files.file_path,
            website_files.b2_file_id,
            website_files.storage_key,
            website_files.hosting_id,
            website_files.deployment_id
          FROM website_files
          JOIN website_hostings
            ON website_hostings.id = website_files.hosting_id
          JOIN projects
            ON projects.id = website_hostings.project_id
          WHERE website_files.id = ?
            AND projects.id = ?
            AND projects.user_id = ?
            AND projects.type = 'website'
            AND projects.deleted_at IS NULL
            AND website_hostings.user_id = ?
            AND website_hostings.active_deployment_id = website_files.deployment_id
          LIMIT 1
        `).bind(
          fileId,
          projectId,
          user.id,
          user.id
        ).first();

        if (!file) {
          return json({ error: "Fichier introuvable." }, 404);
        }

        if (file.file_path === "index.html") {
          return json({
            error: "Le fichier index.html ne peut pas être supprimé."
          }, 400);
        }

        if (!file.b2_file_id || !file.storage_key) {
          return json({
            error: "Informations de stockage introuvables."
          }, 409);
        }

        await b2NativeDelete(
          env,
          file.b2_file_id,
          file.storage_key
        );

        await env.DB.prepare(`
          DELETE FROM website_files
          WHERE id = ?
            AND hosting_id = ?
            AND deployment_id = ?
        `).bind(
          fileId,
          file.hosting_id,
          file.deployment_id
        ).run();

        return json({
          message: "Fichier supprimé avec succès."
        });

      } catch (error) {
        console.error("ERREUR SUPPRESSION FICHIER SITE:", error);

        return json({
          error: "Impossible de supprimer le fichier du site."
        }, 500);
      }
    }
// RENOMMER UN FICHIER DU SITE HÉBERGÉ
const hostingFileRenameMatch = path.match(
  /^\/api\/projects\/([^/]+)\/hosting\/files\/([^/]+)\/rename$/
);

if (hostingFileRenameMatch && request.method === "PATCH") {
  try {
    const user = await currentUser(request, env);

    if (!user) {
      return json({ error: "Vous devez être connecté." }, 401);
    }

    const projectId = decodeURIComponent(hostingFileRenameMatch[1]);
    const fileId = decodeURIComponent(hostingFileRenameMatch[2]);
    const body = await request.json();

    const newName = String(body.name || "").trim();

    if (
      !newName ||
      newName.length > 255 ||
      /[\/\\\u0000-\u001F\u007F]/.test(newName) ||
      newName === "." ||
      newName === ".."
    ) {
      return json({ error: "Nom de fichier invalide." }, 400);
    }

    const file = await env.DB.prepare(`
      SELECT
        website_files.id,
        website_files.file_path,
        website_files.hosting_id,
        website_files.deployment_id
      FROM website_files
      JOIN website_hostings
        ON website_hostings.id = website_files.hosting_id
      JOIN projects
        ON projects.id = website_hostings.project_id
      WHERE website_files.id = ?
        AND projects.id = ?
        AND projects.user_id = ?
        AND projects.type = 'website'
        AND projects.deleted_at IS NULL
        AND website_hostings.user_id = ?
        AND website_hostings.active_deployment_id = website_files.deployment_id
      LIMIT 1
    `).bind(
      fileId,
      projectId,
      user.id,
      user.id
    ).first();

    if (!file) {
      return json({ error: "Fichier introuvable." }, 404);
    }

    if (file.file_path === "index.html") {
      return json({
        error: "Le fichier index.html ne peut pas être renommé."
      }, 400);
    }

    const lastSlash = file.file_path.lastIndexOf("/");
    const folder = lastSlash >= 0
      ? file.file_path.slice(0, lastSlash + 1)
      : "";

    const newFilePath = folder + newName;

    if (newFilePath === file.file_path) {
      return json({ message: "Le nom du fichier est inchangé." });
    }

    const existingFile = await env.DB.prepare(`
      SELECT id
      FROM website_files
      WHERE hosting_id = ?
        AND deployment_id = ?
        AND file_path = ?
      LIMIT 1
    `).bind(
      file.hosting_id,
      file.deployment_id,
      newFilePath
    ).first();

    if (existingFile) {
      return json({
        error: "Un fichier portant déjà ce nom existe dans ce dossier."
      }, 409);
    }

    await env.DB.prepare(`
      UPDATE website_files
      SET file_path = ?
      WHERE id = ?
        AND hosting_id = ?
        AND deployment_id = ?
    `).bind(
      newFilePath,
      fileId,
      file.hosting_id,
      file.deployment_id
    ).run();

    return json({
      message: "Fichier renommé avec succès.",
      file_path: newFilePath
    });

  } catch (error) {
    console.error("ERREUR RENOMMAGE FICHIER SITE:", error);

    return json({
      error: "Impossible de renommer le fichier."
    }, 500);
  }
}
// DÉPLACER UN FICHIER DU SITE HÉBERGÉ
const hostingFileMoveMatch = path.match(
  /^\/api\/projects\/([^/]+)\/hosting\/files\/([^/]+)\/move$/
);

if (hostingFileMoveMatch && request.method === "PATCH") {
  try {
    const user = await currentUser(request, env);

    if (!user) {
      return json({ error: "Vous devez être connecté." }, 401);
    }

    const projectId = decodeURIComponent(hostingFileMoveMatch[1]);
    const fileId = decodeURIComponent(hostingFileMoveMatch[2]);
    const body = await request.json();

    const folder = String(body.folder || "").trim();

    if (
      folder.length > 500 ||
      folder.startsWith("/") ||
      folder.endsWith("/") ||
      folder.includes("\\") ||
      /[\u0000-\u001F\u007F]/.test(folder) ||
      folder.split("/").some(part =>
        !part || part === "." || part === ".."
      )
    ) {
      return json({ error: "Dossier de destination invalide." }, 400);
    }

    const file = await env.DB.prepare(`
      SELECT
        website_files.id,
        website_files.file_path,
        website_files.hosting_id,
        website_files.deployment_id
      FROM website_files
      JOIN website_hostings
        ON website_hostings.id = website_files.hosting_id
      JOIN projects
        ON projects.id = website_hostings.project_id
      WHERE website_files.id = ?
        AND projects.id = ?
        AND projects.user_id = ?
        AND projects.type = 'website'
        AND projects.deleted_at IS NULL
        AND website_hostings.user_id = ?
        AND website_hostings.active_deployment_id = website_files.deployment_id
      LIMIT 1
    `).bind(
      fileId,
      projectId,
      user.id,
      user.id
    ).first();

    if (!file) {
      return json({ error: "Fichier introuvable." }, 404);
    }

    if (file.file_path === "index.html") {
      return json({
        error: "Le fichier index.html ne peut pas être déplacé."
      }, 400);
    }

    const fileName = file.file_path.split("/").pop();
    const newFilePath = folder
      ? `${folder}/${fileName}`
      : fileName;

    if (newFilePath === file.file_path) {
      return json({ message: "Le fichier est déjà dans ce dossier." });
    }

    const existingFile = await env.DB.prepare(`
      SELECT id
      FROM website_files
      WHERE hosting_id = ?
        AND deployment_id = ?
        AND file_path = ?
      LIMIT 1
    `).bind(
      file.hosting_id,
      file.deployment_id,
      newFilePath
    ).first();

    if (existingFile) {
      return json({
        error: "Un fichier portant déjà ce nom existe dans ce dossier."
      }, 409);
    }

    await env.DB.prepare(`
      UPDATE website_files
      SET file_path = ?
      WHERE id = ?
        AND hosting_id = ?
        AND deployment_id = ?
    `).bind(
      newFilePath,
      fileId,
      file.hosting_id,
      file.deployment_id
    ).run();

    return json({
      message: "Fichier déplacé avec succès.",
      file_path: newFilePath
    });

  } catch (error) {
    console.error("ERREUR DÉPLACEMENT FICHIER SITE:", error);

    return json({
      error: "Impossible de déplacer le fichier."
    }, 500);
  }
}
    // HÉBERGEMENT : AFFICHER UN SITE WEB PUBLIÉ
    const siteMatch = path.match(/^\/site\/([^/]+)(?:\/(.*))?$/);

    if (siteMatch) {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return new Response("Méthode non autorisée.", {
          status: 405,
          headers: { "Allow": "GET, HEAD" }
        });
      }

      try {
        const slug = decodeURIComponent(siteMatch[1]);
        const rawFilePath = decodeURIComponent(siteMatch[2] || "");

        if (!/^[a-z0-9-]+$/.test(slug)) {
          return new Response("Site introuvable.", { status: 404 });
        }

        if (
          rawFilePath.includes("\\") ||
          /[\u0000-\u001F\u007F]/.test(rawFilePath)
        ) {
          return new Response("Chemin invalide.", { status: 400 });
        }

        const segments = rawFilePath.split("/");

        if (
          segments.some(segment =>
            segment === "." || segment === ".."
          )
        ) {
          return new Response("Chemin invalide.", { status: 400 });
        }

        const filePath =
          rawFilePath === "" || rawFilePath.endsWith("/")
            ? rawFilePath + "index.html"
            : rawFilePath;

        const hosting = await env.DB.prepare(`
          SELECT id, active_deployment_id
          FROM website_hostings
          WHERE slug = ? AND status = 'active'
          LIMIT 1
        `).bind(slug).first();

        if (!hosting || !hosting.active_deployment_id) {
          return new Response("Site introuvable.", { status: 404 });
        }

        const file = await env.DB.prepare(`
          SELECT b2_file_id, mime_type
          FROM website_files
          WHERE hosting_id = ?
            AND deployment_id = ?
            AND file_path = ?
          LIMIT 1
        `).bind(
          hosting.id,
          hosting.active_deployment_id,
          filePath
        ).first();

        if (!file || !file.b2_file_id) {
          return new Response("Fichier introuvable.", { status: 404 });
        }

        const downloadResponse = await b2NativeDownload(
          env,
          file.b2_file_id
        );

        if (!downloadResponse.ok) {
          console.error(
            "ERREUR SERVEUR SITE B2:",
            downloadResponse.status
          );

          return new Response("Impossible de récupérer le fichier.", {
            status: downloadResponse.status === 404 ? 404 : 502
          });
        }

        const headers = new Headers();

        headers.set(
          "Content-Type",
          file.mime_type || "application/octet-stream"
        );
const downloadRequested =
  new URL(request.url).searchParams.get("download") === "1";

if (downloadRequested) {
  headers.set(
    "Content-Disposition",
    `attachment; filename*=UTF-8''${encodeURIComponent(filePath.split("/").pop())}`
  );
}
        headers.set("X-Content-Type-Options", "nosniff");

        headers.set(
          "Cache-Control",
          filePath === "index.html"
            ? "no-store"
            : "public, max-age=300"
        );

        return new Response(
          request.method === "HEAD" ? null : downloadResponse.body,
          {
            status: 200,
            headers
          }
        );

      } catch (error) {
        console.error("ERREUR AFFICHAGE SITE:", error);

        return new Response("Erreur lors du chargement du site.", {
          status: 500
        });
      }
    }

    if (hostingProjectMatch && request.method === "POST") {
      try {
        const user = await currentUser(request, env);

        if (!user) {
          return json({ error: "Vous devez être connecté." }, 401);
        }

        const projectId = decodeURIComponent(hostingProjectMatch[1]);

        const project = await env.DB.prepare(
          `SELECT id, name, type
           FROM projects
           WHERE id = ? AND user_id = ? AND deleted_at IS NULL`
        ).bind(projectId, user.id).first();

        if (!project) {
          return json({ error: "Projet introuvable." }, 404);
        }

        if (project.type !== "website") {
          return json({
            error: "Ce projet n'est pas un site web."
          }, 400);
        }

        let hosting = await env.DB.prepare(
          `SELECT id, slug, status
           FROM website_hostings
           WHERE project_id = ? AND user_id = ?`
        ).bind(projectId, user.id).first();

        if (!hosting) {
          const hostingId = crypto.randomUUID();
          const slug = await generateWebsiteSlug(env, project.name);

          await env.DB.prepare(`
            INSERT INTO website_hostings (
              id, user_id, project_id, slug, status
            )
            VALUES (?, ?, ?, ?, 'draft')
          `).bind(hostingId, user.id, projectId, slug).run();

          hosting = {
            id: hostingId,
            slug,
            status: "draft"
          };
        }

        return json({
          message: "Hébergement associé au projet.",
          hosting: {
            ...hosting,
            url: `https://221cloud-platform.elhadjidame-sall.workers.dev/site/${hosting.slug}`
          }
        });

      } catch (error) {
        console.error("ERREUR HÉBERGEMENT PROJET:", error);
        return json({
          error: "Impossible de préparer l'hébergement."
        }, 500);
      }
    }

    // CRÉATION D'UN PROJET
    if (path === "/api/projects" && request.method === "POST") {
      try {
        const user = await currentUser(request, env);

        if (!user) {
          return json({ error: "Vous devez être connecté." }, 401);
        }

        const body = await request.json();
        const name = String(body.name || "").trim();
        const type = String(body.type || "website");

        if (!validProjectName(name)) {
          return json({
            error: "Le nom du projet doit contenir entre 1 et 100 caractères."
          }, 400);
        }

        if (!PROJECT_TYPES.includes(type)) {
          return json({
            error: "Type de projet invalide."
          }, 400);
        }
        // Vérification de la limite de projets selon l'abonnement
        const subscription = await env.DB.prepare(`
          SELECT plan, status
          FROM subscriptions
          WHERE user_id = ?
          ORDER BY created_at DESC
          LIMIT 1
        `).bind(user.id).first();

        const plan = subscription?.status === "active"
          ? subscription.plan
          : "free";

        const projectLimits = {
          free: 1,
          starter: 5,
          pro: 20
        };

        const maxProjects = projectLimits[plan] ?? 1;

        const projectCount = await env.DB.prepare(`
          SELECT COUNT(*) AS total
          FROM projects
          WHERE user_id = ? AND deleted_at IS NULL
        `).bind(user.id).first();

        if (Number(projectCount?.total || 0) >= maxProjects) {
          return json({
            error: `Votre forfait ${plan} autorise au maximum ${maxProjects} projet(s). Passez à une offre supérieure pour en créer davantage.`
          }, 403);
        }
        const id = crypto.randomUUID();

await env.DB.prepare(
  `INSERT INTO projects (id, user_id, name, type, status)
   VALUES (?, ?, ?, ?, 'pending')`
).bind(id, user.id, name, type).run();

let hosting = null;

if (type === "website") {
  const hostingId = crypto.randomUUID();
  const slug = await generateWebsiteSlug(env, name);

  await env.DB.prepare(`
    INSERT INTO website_hostings (
      id, user_id, project_id, slug, status
    )
    VALUES (?, ?, ?, ?, 'draft')
  `).bind(hostingId, user.id, id, slug).run();

  hosting = {
    id: hostingId,
    slug,
    status: "draft",
    url: `https://221cloud-platform.elhadjidame-sall.workers.dev/site/${slug}`
  };
}

const project = await env.DB.prepare(
  `SELECT id, name, type, status, created_at
   FROM projects WHERE id = ? AND user_id = ?`
).bind(id, user.id).first();

        return json({
          message: "Projet créé avec succès.",
          project,
hosting
        }, 201);

      } catch (error) {
        console.error("ERREUR CREATION PROJET:", error);
        return json({
          error: "Impossible de créer le projet."
        }, 500);
      }
    }

    if (path === "/api/projects/trash" && request.method === "GET") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        const result = await env.DB.prepare(`
          SELECT id, name, type, status, created_at, deleted_at
          FROM projects
          WHERE user_id = ? AND deleted_at IS NOT NULL
          ORDER BY deleted_at DESC
        `).bind(user.id).all();
        return json({ projects: result.results || [] });
      } catch (error) {
        console.error("ERREUR CORBEILLE PROJETS:", error);
        return json({ error: "Impossible de charger la corbeille des projets." }, 500);
      }
    }

    const restoreProjectMatch = path.match(/^\/api\/projects\/([^/]+)\/restore$/);
    if (restoreProjectMatch && request.method === "POST") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        const projectId = decodeURIComponent(restoreProjectMatch[1]);
        const project = await env.DB.prepare(`
          SELECT id, name FROM projects
          WHERE id = ? AND user_id = ? AND deleted_at IS NOT NULL
        `).bind(projectId, user.id).first();
        if (!project) return json({ error: "Projet introuvable dans la corbeille." }, 404);
        await env.DB.prepare(`
          UPDATE projects SET deleted_at = NULL
          WHERE id = ? AND user_id = ? AND deleted_at IS NOT NULL
        `).bind(projectId, user.id).run();
        return json({ message: "Projet restauré avec succès.", project });
      } catch (error) {
        console.error("ERREUR RESTAURATION PROJET:", error);
        return json({ error: "Impossible de restaurer ce projet." }, 500);
      }
    }

    // MODIFICATION ET SUPPRESSION D'UN PROJET
    const projectMatch = path.match(/^\/api\/projects\/([^/]+)$/);

    if (projectMatch) {
      try {
        const user = await currentUser(request, env);

        if (!user) {
          return json({ error: "Vous devez être connecté." }, 401);
        }

        const projectId = decodeURIComponent(projectMatch[1]);

        const existing = await env.DB.prepare(
          `SELECT id, name, type, status, created_at
           FROM projects
           WHERE id = ? AND user_id = ? AND deleted_at IS NULL`
        ).bind(projectId, user.id).first();

        if (!existing) {
          return json({ error: "Projet introuvable." }, 404);
        }

        if (request.method === "PATCH") {
          const body = await request.json();

          const name = body.name === undefined
            ? existing.name
            : String(body.name).trim();

          const type = body.type === undefined
            ? existing.type
            : String(body.type);

          if (!validProjectName(name)) {
            return json({
              error: "Le nom du projet doit contenir entre 1 et 100 caractères."
            }, 400);
          }

          if (!PROJECT_TYPES.includes(type)) {
            return json({
              error: "Type de projet invalide."
            }, 400);
          }

          await env.DB.prepare(
            `UPDATE projects
             SET name = ?, type = ?
             WHERE id = ? AND user_id = ?`
          ).bind(name, type, projectId, user.id).run();

          const updated = await env.DB.prepare(
            `SELECT id, name, type, status, created_at
             FROM projects
             WHERE id = ? AND user_id = ? AND deleted_at IS NULL`
          ).bind(projectId, user.id).first();

          return json({
            message: "Projet modifié avec succès.",
            project: updated
          });
        }

        if (request.method === "DELETE") {
          await env.DB.prepare(`
            UPDATE projects SET deleted_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ? AND deleted_at IS NULL
          `).bind(projectId, user.id).run();

          return json({
            message: "Projet déplacé dans la corbeille. Ses données associées sont conservées."
          });
        }

        return json({ error: "Méthode non autorisée." }, 405);

      } catch (error) {
        console.error("ERREUR GESTION PROJET:", error);
        return json({
          error: "Impossible de traiter cette opération."
        }, 500);
      }
    }

    // LISTE DES BASES DE DONNÉES DU CLIENT
    if (path === "/api/databases" && request.method === "GET") {
      try {
        const user = await currentUser(request, env);

        if (!user) {
          return json({ error: "Vous devez être connecté." }, 401);
        }

        const result = await env.DB.prepare(
          `SELECT
             customer_databases.id,
             customer_databases.name,
             customer_databases.project_id,
             projects.name AS project_name,
             customer_databases.created_at
           FROM customer_databases
           LEFT JOIN projects
             ON projects.id = customer_databases.project_id
             AND projects.user_id = customer_databases.user_id
           WHERE customer_databases.user_id = ?
           ORDER BY customer_databases.created_at DESC`
        ).bind(user.id).all();

        return json({
          databases: result.results
        });

      } catch (error) {
        console.error("ERREUR LISTE BASES:", error);
        return json({
          error: "Impossible de charger les bases de données."
        }, 500);
      }
    }

    // CRÉATION D'UNE BASE LOGIQUE
    if (path === "/api/databases" && request.method === "POST") {
      try {
        const user = await currentUser(request, env);

        if (!user) {
          return json({ error: "Vous devez être connecté." }, 401);
        }

        const body = await request.json();
        const name = String(body.name || "").trim();

        const projectId = body.project_id
          ? String(body.project_id).trim()
          : null;

        if (!validDatabaseName(name)) {
          return json({
            error: "Le nom doit contenir entre 1 et 80 caractères."
          }, 400);
        }

        if (projectId) {
          const project = await env.DB.prepare(
            "SELECT id FROM projects WHERE id = ? AND user_id = ? AND deleted_at IS NULL"
          ).bind(projectId, user.id).first();

          if (!project) {
            return json({
              error: "Le projet associé est introuvable."
            }, 404);
          }
        }

        const existing = await env.DB.prepare(
          "SELECT id FROM customer_databases WHERE user_id = ? AND name = ?"
        ).bind(user.id, name).first();

        if (existing) {
          return json({
            error: "Une base de données porte déjà ce nom."
          }, 409);
        }

        const id = crypto.randomUUID();

        await env.DB.prepare(
          `INSERT INTO customer_databases
           (id, user_id, project_id, name)
           VALUES (?, ?, ?, ?)`
        ).bind(id, user.id, projectId, name).run();

        const database = await env.DB.prepare(
          `SELECT id, name, project_id, created_at
           FROM customer_databases
           WHERE id = ? AND user_id = ?`
        ).bind(id, user.id).first();

        return json({
          message: "Base de données créée avec succès.",
          database
        }, 201);

      } catch (error) {
        console.error("ERREUR CREATION BASE:", error);
        return json({
          error: "Impossible de créer la base de données."
        }, 500);
      }
    }

    // SUPPRESSION D'UNE BASE LOGIQUE
    const databaseMatch = path.match(/^\/api\/databases\/([^/]+)$/);

    if (databaseMatch) {
      if (request.method !== "DELETE") {
        return json({ error: "Méthode non autorisée." }, 405);
      }

      try {
        const user = await currentUser(request, env);

        if (!user) {
          return json({ error: "Vous devez être connecté." }, 401);
        }

        const databaseId = decodeURIComponent(databaseMatch[1]);

        const existing = await env.DB.prepare(
          `SELECT id FROM customer_databases
           WHERE id = ? AND user_id = ?`
        ).bind(databaseId, user.id).first();

        if (!existing) {
          return json({
            error: "Base de données introuvable."
          }, 404);
        }

        await env.DB.prepare(
          "DELETE FROM customer_databases WHERE id = ? AND user_id = ?"
        ).bind(databaseId, user.id).run();

        return json({
          message: "Base de données supprimée avec succès."
        });

      } catch (error) {
        console.error("ERREUR SUPPRESSION BASE:", error);
        return json({
          error: "Impossible de supprimer la base de données."
        }, 500);
      }
    }


    // STOCKAGE : CRÉATION D'UN DOSSIER
    if (path === "/api/storage/folders" && request.method === "POST") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureStorageFoldersSchema(env);
        const body = await request.json();
        const name = String(body.name || "").trim();
        const parentId = String(body.parent_id || "").trim() || null;
        if (!name || name.length > 80 || name.includes("/") || name.includes("\\") || /[\u0000-\u001F\u007F]/.test(name) || name === "." || name === "..") return json({ error: "Nom de dossier invalide." }, 400);
        if (parentId) {
          const parent = await env.DB.prepare("SELECT id FROM storage_folders WHERE id = ? AND user_id = ? LIMIT 1").bind(parentId, user.id).first();
          if (!parent) return json({ error: "Dossier parent introuvable." }, 404);
        }
        const duplicate = await env.DB.prepare("SELECT id FROM storage_folders WHERE user_id = ? AND parent_id IS ? AND name = ? COLLATE NOCASE LIMIT 1").bind(user.id, parentId, name).first();
        if (duplicate) return json({ error: "Un dossier porte déjà ce nom à cet emplacement." }, 409);
        const id = crypto.randomUUID();
        await env.DB.prepare("INSERT INTO storage_folders (id, user_id, name, parent_id) VALUES (?, ?, ?, ?)").bind(id, user.id, name, parentId).run();
        return json({ message: "Dossier créé avec succès.", folder: { id, name, parent_id: parentId } }, 201);
      } catch (error) {
        console.error("ERREUR CRÉATION DOSSIER:", error);
        return json({ error: "Impossible de créer le dossier." }, 500);
      }
    }

    // STOCKAGE : RENOMMAGE ET SUPPRESSION SÉCURISÉE D'UN DOSSIER
    const storageFolderActionMatch = path.match(/^\/api\/storage\/folders\/([^/]+)\/(rename|delete)$/);
    if (storageFolderActionMatch) {
      const action = storageFolderActionMatch[2];
      const expectedMethod = action === "rename" ? "PATCH" : "DELETE";
      if (request.method !== expectedMethod) return json({ error: "Méthode non autorisée." }, 405);
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureStorageFoldersSchema(env);
        const folderId = decodeURIComponent(storageFolderActionMatch[1]);
        const folder = await env.DB.prepare(
          "SELECT id, name, parent_id FROM storage_folders WHERE id = ? AND user_id = ? LIMIT 1"
        ).bind(folderId, user.id).first();
        if (!folder) return json({ error: "Dossier introuvable." }, 404);

        if (action === "rename") {
          const body = await request.json();
          const name = String(body.name || "").trim();
          if (!name || name.length > 80 || name.includes("/") || name.includes("\\") || /[\u0000-\u001F\u007F]/.test(name) || name === "." || name === "..") {
            return json({ error: "Nom de dossier invalide." }, 400);
          }
          const duplicate = await env.DB.prepare(
            "SELECT id FROM storage_folders WHERE user_id = ? AND parent_id IS ? AND name = ? COLLATE NOCASE AND id != ? LIMIT 1"
          ).bind(user.id, folder.parent_id, name, folderId).first();
          if (duplicate) return json({ error: "Un dossier porte déjà ce nom à cet emplacement." }, 409);
          await env.DB.prepare(
            "UPDATE storage_folders SET name = ? WHERE id = ? AND user_id = ?"
          ).bind(name, folderId, user.id).run();
          return json({ message: "Dossier renommé avec succès.", folder: { id: folderId, name } });
        }

        const [fileCount, childCount] = await Promise.all([
          env.DB.prepare("SELECT COUNT(*) AS total FROM cloud_files WHERE user_id = ? AND folder_id = ?").bind(user.id, folderId).first(),
          env.DB.prepare("SELECT COUNT(*) AS total FROM storage_folders WHERE user_id = ? AND parent_id = ?").bind(user.id, folderId).first()
        ]);
        if (Number(fileCount?.total || 0) > 0 || Number(childCount?.total || 0) > 0) {
          return json({ error: "Ce dossier n'est pas vide. Déplacez d'abord ses fichiers et supprimez ou déplacez ses sous-dossiers." }, 409);
        }
        await env.DB.prepare(
          "DELETE FROM storage_folders WHERE id = ? AND user_id = ?"
        ).bind(folderId, user.id).run();
        return json({ message: "Dossier supprimé avec succès." });
      } catch (error) {
        console.error("ERREUR GESTION DOSSIER STOCKAGE:", error);
        return json({ error: "Impossible de modifier ce dossier." }, 500);
      }
    }

    // STOCKAGE : DÉPLACEMENT D'UN FICHIER
    const storageMoveMatch = path.match(/^\/api\/storage\/([^/]+)\/move$/);
    if (storageMoveMatch) {
      if (request.method !== "PATCH") return json({ error: "Méthode non autorisée." }, 405);
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureStorageFoldersSchema(env);
        const fileId = decodeURIComponent(storageMoveMatch[1]);
        const body = await request.json();
        const folderId = String(body.folder_id || "").trim() || null;
        const file = await env.DB.prepare("SELECT id, file_name, file_size, folder_id FROM cloud_files WHERE id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1").bind(fileId, user.id).first();
        if (!file) return json({ error: "Fichier introuvable." }, 404);
        if (folderId) {
          const folder = await env.DB.prepare("SELECT id FROM storage_folders WHERE id = ? AND user_id = ? LIMIT 1").bind(folderId, user.id).first();
          if (!folder) return json({ error: "Dossier de destination introuvable." }, 404);
        }
        const source = file.folder_id
          ? await env.DB.prepare("SELECT name FROM storage_folders WHERE id = ? AND user_id = ? LIMIT 1").bind(file.folder_id, user.id).first()
          : null;
        const destination = folderId
          ? await env.DB.prepare("SELECT name FROM storage_folders WHERE id = ? AND user_id = ? LIMIT 1").bind(folderId, user.id).first()
          : null;
        const sourceName = source?.name || "Racine";
        const destinationName = destination?.name || "Racine";
        if ((file.folder_id || null) === folderId) {
          return json({ message: "Le fichier se trouve déjà à cet emplacement.", folder_id: folderId });
        }
        await env.DB.prepare("UPDATE cloud_files SET folder_id = ? WHERE id = ? AND user_id = ?").bind(folderId, fileId, user.id).run();
        await recordStorageActivity(env, user.id, "move", file, "De : " + sourceName + " → Vers : " + destinationName);
        return json({ message: "Fichier déplacé avec succès.", folder_id: folderId });
      } catch (error) {
        console.error("ERREUR DÉPLACEMENT FICHIER:", error);
        return json({ error: "Impossible de déplacer le fichier." }, 500);
      }
    }

    // STOCKAGE : EXPORT COMPLET DES MÉTADONNÉES
    if (path === "/api/storage/backup" && request.method === "GET") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureStorageFoldersSchema(env);

        const [filesResult, foldersResult, historyResult] = await Promise.all([
          env.DB.prepare(
            `SELECT id, file_name, file_size, mime_type, created_at, folder_id, deleted_at
             FROM cloud_files
             WHERE user_id = ?
             ORDER BY created_at DESC`
          ).bind(user.id).all(),
          env.DB.prepare(
            `SELECT id, name, parent_id, created_at
             FROM storage_folders
             WHERE user_id = ?
             ORDER BY name COLLATE NOCASE ASC`
          ).bind(user.id).all(),
          env.DB.prepare(
            `SELECT id, action, file_name, file_size, details, created_at
             FROM storage_activity_log
             WHERE user_id = ?
             ORDER BY created_at DESC, rowid DESC`
          ).bind(user.id).all()
        ]);

        return json({
          product: "221Cloud",
          backup_type: "storage_metadata",
          schema_version: 1,
          exported_at: new Date().toISOString(),
          contents: {
            files: filesResult.results || [],
            folders: foldersResult.results || [],
            activity_history: historyResult.results || []
          },
          counts: {
            files: (filesResult.results || []).length,
            folders: (foldersResult.results || []).length,
            activities: (historyResult.results || []).length
          },
          note: "Cette sauvegarde contient uniquement les métadonnées. Les contenus des fichiers ne sont pas inclus."
        });
      } catch (error) {
        console.error("ERREUR SAUVEGARDE MÉTADONNÉES STOCKAGE:", error);
        return json({ error: "Impossible de préparer la sauvegarde du stockage." }, 500);
      }
    }

    // STOCKAGE : HISTORIQUE DES ACTIVITÉS
    if (path === "/api/storage/history" && request.method === "GET") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureStorageFoldersSchema(env);
        const url = new URL(request.url);
        const requestedPage = Math.max(1, Number.parseInt(url.searchParams.get("page") || "1", 10) || 1);
        const pageSize = 20;
        const action = url.searchParams.get("action") || "all";
        const search = (url.searchParams.get("search") || "").trim().slice(0, 200);
        const allowedActions = ["upload", "move", "trash", "restore", "permanent_delete"];
        const conditions = ["user_id = ?"];
        const values = [user.id];
        if (allowedActions.includes(action)) {
          conditions.push("action = ?");
          values.push(action);
        }
        if (search) {
          conditions.push("LOWER(file_name) LIKE LOWER(?)");
          values.push("%" + search + "%");
        }
        const where = conditions.join(" AND ");
        const countResult = await env.DB.prepare(
          "SELECT COUNT(*) AS total FROM storage_activity_log WHERE " + where
        ).bind(...values).first();
        const total = Number(countResult?.total || 0);
        const totalPages = Math.max(1, Math.ceil(total / pageSize));
        const page = Math.min(requestedPage, totalPages);
        const offset = (page - 1) * pageSize;
        const result = await env.DB.prepare(
          "SELECT id, action, file_name, file_size, details, created_at FROM storage_activity_log WHERE " +
          where + " ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?"
        ).bind(...values, pageSize, offset).all();
        return json({
          activities: result.results || [],
          pagination: { page, pageSize, total, totalPages }
        });
      } catch (error) {
        console.error("ERREUR HISTORIQUE STOCKAGE:", error);
        return json({ error: "Impossible de charger l'historique du stockage." }, 500);
      }
    }

    // STOCKAGE : LISTE DES FICHIERS ET QUOTA
    if (path === "/api/storage" && request.method === "GET") {
      try {
        const user = await currentUser(request, env);

        if (!user) {
          return json({ error: "Vous devez être connecté." }, 401);
        }

        await ensureStorageFoldersSchema(env);
        const result = await env.DB.prepare(
          `SELECT id, file_name, file_size, mime_type, created_at, folder_id
           FROM cloud_files
           WHERE user_id = ? AND deleted_at IS NULL
           ORDER BY created_at DESC`
        ).bind(user.id).all();
        const folderResult = await env.DB.prepare(
          `SELECT id, name, parent_id, created_at FROM storage_folders
           WHERE user_id = ? ORDER BY name COLLATE NOCASE ASC`
        ).bind(user.id).all();
        const files = result.results || [];
        const folders = folderResult.results || [];
        const trashCount = await env.DB.prepare(
          "SELECT COUNT(*) AS total FROM cloud_files WHERE user_id = ? AND deleted_at IS NOT NULL"
        ).bind(user.id).first();
        const usage = await env.DB.prepare(`
  SELECT
    COALESCE((
      SELECT SUM(file_size)
      FROM cloud_files
      WHERE user_id = ?
    ), 0) +
    COALESCE((
      SELECT SUM(website_files.file_size)
      FROM website_files
      JOIN website_hostings
        ON website_hostings.id = website_files.hosting_id
      WHERE website_hostings.user_id = ?
    ), 0) AS used
`).bind(user.id, user.id).first();

const used = Number(usage?.used || 0);
        // Récupération du forfait actuel
        const subscription = await env.DB.prepare(`
          SELECT plan, status
          FROM subscriptions
          WHERE user_id = ?
          ORDER BY created_at DESC
          LIMIT 1
        `).bind(user.id).first();

        const plan = subscription?.status === "active"
          ? subscription.plan
          : "free";

        // Limites selon le forfait
        const storageLimits = {
          free: 1024 * 1024 * 1024,
          starter: 5 * 1024 * 1024 * 1024,
          pro: 20 * 1024 * 1024 * 1024
        };

        const limit = storageLimits[plan] ?? storageLimits.free;

        const available = Math.max(0, limit - used);

        const usagePercent = Math.min(
          100,
          Math.round((used / limit) * 100)
        );
        return json({
  files,
  folders,
  trashCount: Number(trashCount?.total || 0),
  used,
  limit,
  available,
  usagePercent,
  plan,
  maxFileSize: MAX_FILE_SIZE_BYTES
});

      } catch (error) {
        console.error("ERREUR LISTE STOCKAGE:", error);
        return json({
          error: "Impossible de charger le stockage."
        }, 500);
      }
    }

    
    // STOCKAGE : ENVOI D'UN FICHIER
    if (path === "/api/storage/upload" && request.method === "POST") {
      try {
        const user = await currentUser(request, env);

        if (!user) {
          return json({ error: "Vous devez être connecté." }, 401);
        }

        if (!storageConfigurationAvailable(env)) {
          return json({
            error: "Le stockage cloud n'est pas encore configuré."
          }, 503);
        }

        const contentType = request.headers.get("Content-Type") || "";

        if (!contentType.toLowerCase().includes("multipart/form-data")) {
          return json({ error: "Format d'envoi invalide." }, 400);
        }

        await ensureStorageFoldersSchema(env);
        const form = await request.formData();
        const file = form.get("file");
        const requestedFolderId = String(form.get("folder_id") || "").trim() || null;

        if (requestedFolderId) {
          const targetFolder = await env.DB.prepare(
            "SELECT id FROM storage_folders WHERE id = ? AND user_id = ? LIMIT 1"
          ).bind(requestedFolderId, user.id).first();

          if (!targetFolder) {
            return json({ error: "Dossier de destination introuvable." }, 404);
          }
        }

        if (!file || typeof file.arrayBuffer !== "function") {
          return json({ error: "Aucun fichier reçu." }, 400);
        }

        if (file.size <= 0) {
          return json({ error: "Le fichier est vide." }, 400);
        }

        if (file.size > MAX_FILE_SIZE_BYTES) {
          return json({
            error: "La taille maximale autorisée est de 20 Mo."
          }, 413);
        }

                // Récupération du forfait de l'utilisateur
        const subscription = await env.DB.prepare(`
          SELECT plan, status
          FROM subscriptions
          WHERE user_id = ?
          ORDER BY created_at DESC
          LIMIT 1
        `).bind(user.id).first();

        const plan = subscription?.status === "active"
          ? subscription.plan
          : "free";

        // Quotas de stockage en octets
        const storageLimits = {
          free: 1024 * 1024 * 1024,
          starter: 5 * 1024 * 1024 * 1024,
          pro: 20 * 1024 * 1024 * 1024
        };

        const maxStorage = storageLimits[plan] ?? storageLimits.free;

        // Calcul de l'espace utilisé : cloud privé + hébergement web
const usage = await env.DB.prepare(`
  SELECT
    COALESCE((
      SELECT SUM(file_size)
      FROM cloud_files
      WHERE user_id = ?
    ), 0) +
    COALESCE((
      SELECT SUM(website_files.file_size)
      FROM website_files
      JOIN website_hostings
        ON website_hostings.id = website_files.hosting_id
      WHERE website_hostings.user_id = ?
    ), 0) AS used
`).bind(user.id, user.id).first();

const used = Number(usage?.used || 0);

        // Vérification du quota
        if (used + file.size > maxStorage) {
          const quotaGo = maxStorage / (1024 * 1024 * 1024);

          return json({
            error: `Votre forfait ${plan} autorise ${quotaGo} Go de stockage. Votre espace disponible est insuffisant.`
          }, 413);
        }

        const buffer = new Uint8Array(await file.arrayBuffer());
        console.log("DIAGNOSTIC STOCKAGE :", {
  tailleFichier: file.size,
  tailleBuffer: buffer.byteLength
});
        const id = crypto.randomUUID();
        const objectKey = `${user.id}/${id}`;
        const mimeType = file.type || "application/octet-stream";
        const fileName = safeFileName(file.name);

       
        let uploadedFile;

        try {
          uploadedFile = await b2NativeUpload(
            env,
            objectKey,
            buffer,
            mimeType
          );
        } catch (uploadError) {
          console.error(
            "ERREUR ENVOI BACKBLAZE:",
            uploadError
          );

          return json({
            error: "Le transfert vers le stockage cloud a échoué.",
            diagnostic: String(uploadError.message || uploadError)
          }, 502);
        }

        try {
          await env.DB.prepare(
            `INSERT INTO cloud_files
             (id, user_id, file_name, file_size, mime_type, storage_key, b2_file_id, folder_id, content_sha1)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).bind(
            id,
            user.id,
            fileName,
            file.size,
            mimeType,
            objectKey,
            uploadedFile.fileId,
            requestedFolderId,
            /^[a-f0-9]{40}$/i.test(String(uploadedFile.contentSha1 || "")) ? uploadedFile.contentSha1.toLowerCase() : null
          ).run();

          // Réappliquer explicitement le dossier puis vérifier la valeur persistée.
          await env.DB.prepare(
            "UPDATE cloud_files SET folder_id = ? WHERE id = ? AND user_id = ?"
          ).bind(requestedFolderId, id, user.id).run();

          const savedFile = await env.DB.prepare(
            "SELECT folder_id FROM cloud_files WHERE id = ? AND user_id = ? LIMIT 1"
          ).bind(id, user.id).first();

          if ((savedFile?.folder_id || null) !== requestedFolderId) {
            throw new Error("Le dossier du fichier n'a pas été enregistré correctement.");
          }
          let destinationName = "Racine";
          if (requestedFolderId) {
            const destination = await env.DB.prepare("SELECT name FROM storage_folders WHERE id = ? AND user_id = ? LIMIT 1").bind(requestedFolderId, user.id).first();
            destinationName = destination?.name || "Dossier";
          }
          await recordStorageActivity(env, user.id, "upload", {
            file_name: fileName,
            file_size: file.size
          }, "Ajouté dans : " + destinationName);
        } catch (databaseError) {
          console.error(
            "ERREUR ENREGISTREMENT FICHIER:",
            databaseError
          );

          try {
            await b2NativeDelete(
              env,
              uploadedFile.fileId,
              uploadedFile.fileName
            );
          } catch (cleanupError) {
            console.error(
              "ERREUR NETTOYAGE FICHIER:",
              cleanupError
            );
          }

          return json({
            error: "Le fichier a été transféré mais son enregistrement a échoué."
          }, 500);
        }


        return json({
          message: "Fichier envoyé avec succès.",
          file: {
            id,
            file_name: fileName,
            file_size: file.size,
            mime_type: mimeType,
            folder_id: requestedFolderId
          }
        }, 201);

      } catch (error) {
        console.error("ERREUR ENVOI STOCKAGE:", error);
        return json({
          error: "Impossible d'envoyer le fichier."
        }, 500);
      }
    }


    // STOCKAGE : TÉLÉCHARGEMENT D'UN FICHIER
    // STOCKAGE : TÉLÉCHARGEMENT SÉCURISÉ POUR SAUVEGARDE (ACTIFS ET CORBEILLE)
    const backupDownloadMatch = path.match(
      /^\/api\/storage\/([^/]+)\/backup-download$/
    );

    if (backupDownloadMatch && request.method === "GET") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureStorageFoldersSchema(env);
        if (!storageConfigurationAvailable(env)) {
          return json({ error: "Le stockage cloud n'est pas configuré." }, 503);
        }

        const fileId = decodeURIComponent(backupDownloadMatch[1]);
        const file = await env.DB.prepare(
          `SELECT id, file_name, mime_type, storage_key, b2_file_id
           FROM cloud_files
           WHERE id = ? AND user_id = ?
           LIMIT 1`
        ).bind(fileId, user.id).first();

        if (!file) return json({ error: "Fichier introuvable." }, 404);

        let downloadResponse;
        if (file.b2_file_id) {
          downloadResponse = await b2NativeDownload(env, file.b2_file_id);
        } else {
          downloadResponse = await b2Request(env, "GET", file.storage_key);
        }

        if (!downloadResponse.ok) {
          console.error("ERREUR TÉLÉCHARGEMENT SAUVEGARDE B2:", downloadResponse.status);
          return json({ error: "Impossible de récupérer le fichier " + safeFileName(file.file_name) + "." }, 502);
        }

        const headers = new Headers();
        headers.set("Content-Type", file.mime_type || "application/octet-stream");
        headers.set("Content-Disposition", "attachment; filename*=UTF-8''" + encodeURIComponent(safeFileName(file.file_name)));
        headers.set("Cache-Control", "private, no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        return new Response(downloadResponse.body, { status: 200, headers });
      } catch (error) {
        console.error("ERREUR SAUVEGARDE FICHIER STOCKAGE:", error);
        return json({ error: "Impossible de récupérer un fichier pour la sauvegarde." }, 500);
      }
    }

    // HÉBERGEMENT : TÉLÉCHARGEMENT SÉCURISÉ D'UN FICHIER PUBLIÉ POUR SAUVEGARDE
    const hostingBackupDownloadMatch = path.match(
      /^\/api\/projects\/([^/]+)\/hosting\/files\/([^/]+)\/backup-download$/
    );

    if (hostingBackupDownloadMatch && request.method === "GET") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        if (!storageConfigurationAvailable(env)) {
          return json({ error: "Le stockage cloud n'est pas configuré." }, 503);
        }

        const projectId = decodeURIComponent(hostingBackupDownloadMatch[1]);
        const fileId = decodeURIComponent(hostingBackupDownloadMatch[2]);
        const file = await env.DB.prepare(`
          SELECT
            website_files.id,
            website_files.file_path,
            website_files.file_size,
            website_files.mime_type,
            website_files.storage_key,
            website_files.b2_file_id
          FROM website_files
          JOIN website_hostings
            ON website_hostings.id = website_files.hosting_id
          JOIN projects
            ON projects.id = website_hostings.project_id
          WHERE website_files.id = ?
            AND projects.id = ?
            AND projects.user_id = ?
            AND projects.type = 'website'
            AND projects.deleted_at IS NULL
            AND website_hostings.user_id = ?
            AND website_hostings.active_deployment_id = website_files.deployment_id
          LIMIT 1
        `).bind(fileId, projectId, user.id, user.id).first();

        if (!file) return json({ error: "Fichier publié introuvable." }, 404);

        const downloadResponse = file.b2_file_id
          ? await b2NativeDownload(env, file.b2_file_id)
          : await b2Request(env, "GET", file.storage_key);

        if (!downloadResponse.ok) {
          console.error("ERREUR SAUVEGARDE FICHIER SITE B2:", downloadResponse.status);
          return json({ error: "Impossible de récupérer le fichier publié " + safeFileName(file.file_path) + "." }, 502);
        }

        const headers = new Headers();
        headers.set("Content-Type", file.mime_type || "application/octet-stream");
        headers.set("Content-Disposition", "attachment; filename*=UTF-8''" + encodeURIComponent(safeFileName(file.file_path.split("/").pop())));
        headers.set("Cache-Control", "private, no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-File-Size", String(file.file_size || 0));
        return new Response(downloadResponse.body, { status: 200, headers });
      } catch (error) {
        console.error("ERREUR SAUVEGARDE FICHIER SITE:", error);
        return json({ error: "Impossible de récupérer un fichier du site pour la sauvegarde." }, 500);
      }
    }

    const downloadMatch = path.match(
      /^\/api\/storage\/([^/]+)\/download$/
    );

    if (downloadMatch && request.method === "GET") {
      try {
        const user = await currentUser(request, env);

        if (!user) {
          return json({ error: "Vous devez être connecté." }, 401);
        }

        await ensureStorageFoldersSchema(env);

        if (!storageConfigurationAvailable(env)) {
          return json({
            error: "Le stockage cloud n'est pas configuré."
          }, 503);
        }

        const fileId = decodeURIComponent(downloadMatch[1]);

        const file = await env.DB.prepare(
          `SELECT id, file_name, file_size, mime_type, storage_key, b2_file_id, content_sha1
           FROM cloud_files
           WHERE id = ? AND user_id = ? AND deleted_at IS NULL`
        ).bind(fileId, user.id).first();

        if (!file) {
          return json({ error: "Fichier introuvable." }, 404);
        }

        
        let downloadResponse;

        try {
          if (file.b2_file_id) {
            downloadResponse = await b2NativeDownload(
              env,
              file.b2_file_id
            );
          } else {
            downloadResponse = await b2Request(
              env,
              "GET",
              file.storage_key
            );
          }
        } catch (downloadError) {
          console.error(
            "ERREUR TELECHARGEMENT BACKBLAZE:",
            downloadError
          );

          return json({
            error: "Impossible de récupérer le fichier.",
            diagnostic: String(downloadError.message || downloadError)
          }, 502);
        }

        if (!downloadResponse.ok) {
          const errorDetails = await downloadResponse.text();

          console.error(
            "ERREUR TELECHARGEMENT BACKBLAZE:",
            downloadResponse.status,
            errorDetails.slice(0, 1500)
          );

          return json({
            error: "Impossible de récupérer le fichier."
          }, downloadResponse.status === 404 ? 404 : 502);
        }


        const downloadedBytes = new Uint8Array(await downloadResponse.arrayBuffer());
        if (downloadedBytes.length !== Number(file.file_size || 0)) {
          console.error("INTEGRITÉ STOCKAGE : taille téléchargée incohérente", {
            fileId: file.id,
            expected: Number(file.file_size || 0),
            actual: downloadedBytes.length
          });
          return json({ error: "Le fichier récupéré est incomplet ou altéré. Le téléchargement a été interrompu." }, 502);
        }
        if (file.content_sha1) {
          const actualDigest = await crypto.subtle.digest("SHA-1", downloadedBytes);
          const actualSha1 = toHex(actualDigest);
          if (actualSha1 !== String(file.content_sha1).toLowerCase()) {
            console.error("INTEGRITÉ STOCKAGE : empreinte SHA-1 incorrecte", { fileId: file.id });
            return json({ error: "L'intégrité du fichier n'a pas pu être vérifiée. Le téléchargement a été interrompu." }, 502);
          }
        }

        const headers = new Headers();

        headers.set(
          "Content-Type",
          file.mime_type || "application/octet-stream"
        );

        const previewRequested =
  new URL(request.url).searchParams.get("preview") === "1";
const isImage = String(file.mime_type || "").toLowerCase().startsWith("image/");
const disposition = previewRequested && isImage ? "inline" : "attachment";

headers.set(
  "Content-Disposition",
  `${disposition}; filename*=UTF-8''${encodeURIComponent(file.file_name)}`
);

        headers.set("Cache-Control", "private, no-store");

        return new Response(downloadedBytes, {
          status: 200,
          headers
        });

      } catch (error) {
        console.error("ERREUR TELECHARGEMENT:", error);
        return json({
          error: "Impossible de télécharger le fichier."
        }, 500);
      }
    }


    // STOCKAGE : RENOMMAGE D'UN FICHIER
    const storageRenameMatch = path.match(
      /^\/api\/storage\/([^/]+)\/rename$/
    );

    if (storageRenameMatch) {
      if (request.method !== "PATCH") {
        return json({ error: "Méthode non autorisée." }, 405);
      }

      try {
        const user = await currentUser(request, env);

        if (!user) {
          return json({ error: "Vous devez être connecté." }, 401);
        }

        await ensureStorageFoldersSchema(env);
        const fileId = decodeURIComponent(storageRenameMatch[1]);
        const body = await request.json();
        const fileName = String(body.name || "").trim();

        if (
          !fileName ||
          fileName.length > 255 ||
          fileName === "." ||
          fileName === ".." ||
          fileName.includes("/") ||
          fileName.includes("\\") ||
          /[\u0000-\u001F\u007F]/.test(fileName)
        ) {
          return json({ error: "Nom de fichier invalide." }, 400);
        }

        const file = await env.DB.prepare(
          "SELECT id, file_name FROM cloud_files WHERE id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1"
        ).bind(fileId, user.id).first();

        if (!file) {
          return json({ error: "Fichier introuvable." }, 404);
        }

        if (file.file_name === fileName) {
          return json({ message: "Le fichier porte déjà ce nom." });
        }

        await env.DB.prepare(
          "UPDATE cloud_files SET file_name = ? WHERE id = ? AND user_id = ?"
        ).bind(fileName, fileId, user.id).run();

        return json({
          message: "Fichier renommé avec succès.",
          file_name: fileName
        });

      } catch (error) {
        console.error("ERREUR RENOMMAGE STOCKAGE:", error);
        return json({
          error: "Impossible de renommer le fichier."
        }, 500);
      }
    }

    // STOCKAGE : CORBEILLE DES FICHIERS
    if (path === "/api/storage/trash" && request.method === "GET") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureStorageFoldersSchema(env);
        const result = await env.DB.prepare(
          `SELECT id, file_name, file_size, mime_type, created_at, folder_id, deleted_at
           FROM cloud_files
           WHERE user_id = ? AND deleted_at IS NOT NULL
           ORDER BY deleted_at DESC`
        ).bind(user.id).all();
        return json({ files: result.results || [] });
      } catch (error) {
        console.error("ERREUR CHARGEMENT CORBEILLE:", error);
        return json({ error: "Impossible de charger la corbeille." }, 500);
      }
    }

    // STOCKAGE : RESTAURATION D'UN FICHIER
    const storageRestoreMatch = path.match(/^\/api\/storage\/([^/]+)\/restore$/);
    if (storageRestoreMatch) {
      if (request.method !== "PATCH") return json({ error: "Méthode non autorisée." }, 405);
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureStorageFoldersSchema(env);
        const fileId = decodeURIComponent(storageRestoreMatch[1]);
        const file = await env.DB.prepare(
          "SELECT id, file_name, file_size, folder_id FROM cloud_files WHERE id = ? AND user_id = ? AND deleted_at IS NOT NULL LIMIT 1"
        ).bind(fileId, user.id).first();
        if (!file) return json({ error: "Fichier introuvable dans la corbeille." }, 404);
        const originalFolder = file.folder_id
          ? await env.DB.prepare("SELECT name FROM storage_folders WHERE id = ? AND user_id = ? LIMIT 1").bind(file.folder_id, user.id).first()
          : null;
        if (file.folder_id) {
          const folder = await env.DB.prepare(
            "SELECT id FROM storage_folders WHERE id = ? AND user_id = ? LIMIT 1"
          ).bind(file.folder_id, user.id).first();
          if (!folder) {
            await env.DB.prepare(
              "UPDATE cloud_files SET folder_id = NULL WHERE id = ? AND user_id = ?"
            ).bind(fileId, user.id).run();
          }
        }
        await env.DB.prepare(
          "UPDATE cloud_files SET deleted_at = NULL WHERE id = ? AND user_id = ? AND deleted_at IS NOT NULL"
        ).bind(fileId, user.id).run();
        await recordStorageActivity(env, user.id, "restore", file, "Restauré dans : " + (originalFolder?.name || "Racine"));
        return json({ message: "Fichier restauré avec succès." });
      } catch (error) {
        console.error("ERREUR RESTAURATION FICHIER:", error);
        return json({ error: "Impossible de restaurer ce fichier." }, 500);
      }
    }

    // STOCKAGE : SUPPRESSION DÉFINITIVE D'UN FICHIER DE LA CORBEILLE
    const storagePermanentMatch = path.match(/^\/api\/storage\/([^/]+)\/permanent$/);
    if (storagePermanentMatch) {
      if (request.method !== "DELETE") return json({ error: "Méthode non autorisée." }, 405);
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        if (!storageConfigurationAvailable(env)) {
          return json({ error: "Le stockage cloud n'est pas configuré." }, 503);
        }
        await ensureStorageFoldersSchema(env);
        const fileId = decodeURIComponent(storagePermanentMatch[1]);
        const file = await env.DB.prepare(
          "SELECT id, file_name, file_size, storage_key, b2_file_id FROM cloud_files WHERE id = ? AND user_id = ? AND deleted_at IS NOT NULL LIMIT 1"
        ).bind(fileId, user.id).first();
        if (!file) return json({ error: "Fichier introuvable dans la corbeille." }, 404);
        try {
          if (file.b2_file_id) {
            await b2NativeDelete(env, file.b2_file_id, file.storage_key);
          } else {
            const deleteResponse = await b2Request(env, "DELETE", file.storage_key);
            if (!deleteResponse.ok && deleteResponse.status !== 404) {
              return json({ error: "Impossible de supprimer le fichier du stockage." }, 502);
            }
          }
        } catch (deleteError) {
          console.error("ERREUR SUPPRESSION DÉFINITIVE BACKBLAZE:", deleteError);
          return json({
            error: "Impossible de supprimer définitivement le fichier.",
            diagnostic: String(deleteError.message || deleteError)
          }, 502);
        }
        await env.DB.prepare(
          "DELETE FROM cloud_files WHERE id = ? AND user_id = ? AND deleted_at IS NOT NULL"
        ).bind(fileId, user.id).run();
        await recordStorageActivity(env, user.id, "permanent_delete", file, "Supprimé définitivement depuis la corbeille");
        return json({ message: "Fichier supprimé définitivement." });
      } catch (error) {
        console.error("ERREUR SUPPRESSION DÉFINITIVE:", error);
        return json({ error: "Impossible de supprimer définitivement le fichier." }, 500);
      }
    }

    // STOCKAGE : ENVOI D'UN FICHIER À LA CORBEILLE (SANS EFFACER LE CONTENU)
    const storageMatch = path.match(/^\/api\/storage\/([^/]+)$/);
    if (storageMatch) {
      if (request.method !== "DELETE") return json({ error: "Méthode non autorisée." }, 405);
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureStorageFoldersSchema(env);
        const fileId = decodeURIComponent(storageMatch[1]);
        const file = await env.DB.prepare(
          "SELECT id, file_name, file_size, folder_id FROM cloud_files WHERE id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1"
        ).bind(fileId, user.id).first();
        if (!file) return json({ error: "Fichier introuvable." }, 404);
        const sourceFolder = file.folder_id
          ? await env.DB.prepare("SELECT name FROM storage_folders WHERE id = ? AND user_id = ? LIMIT 1").bind(file.folder_id, user.id).first()
          : null;
        await env.DB.prepare(
          "UPDATE cloud_files SET deleted_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ? AND deleted_at IS NULL"
        ).bind(fileId, user.id).run();
        await recordStorageActivity(env, user.id, "trash", file, "Mis à la corbeille depuis : " + (sourceFolder?.name || "Racine"));
        return json({ message: "Fichier déplacé dans la corbeille." });
      } catch (error) {
        console.error("ERREUR ENVOI CORBEILLE:", error);
        return json({ error: "Impossible de déplacer le fichier dans la corbeille." }, 500);
      }
    }

    // JOURNAL DE SÉCURITÉ DU COMPTE
    if (path === "/api/account/security-log" && request.method === "GET") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);

        await ensureAccountSecuritySchema(env);
        const result = await env.DB.prepare(
          "SELECT id, action, description, device_info, created_at FROM account_security_events WHERE user_id = ? ORDER BY created_at DESC LIMIT 50"
        ).bind(user.id).all();

        return json({ events: result.results || [] });
      } catch (error) {
        console.error("ERREUR LECTURE JOURNAL DE SÉCURITÉ:", error);
        return json({ error: "Impossible de charger le journal de sécurité." }, 500);
      }
    }

    // INFORMATIONS SUR LA SESSION ACTUELLE
    if (path === "/api/account/session-info" && request.method === "GET") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);

        const token = getCookie(request, "221cloud_session");
        if (!token) return json({ error: "Session introuvable." }, 401);
        const tokenHash = await hashToken(token);
        const session = await env.DB.prepare(
          "SELECT expires_at FROM sessions WHERE token_hash = ? AND user_id = ? LIMIT 1"
        ).bind(tokenHash, user.id).first();

        if (!session) return json({ error: "Session introuvable." }, 401);

        return json({
          last_activity_at: new Date().toISOString(),
          expires_at: session.expires_at,
          idle_timeout_minutes: SESSION_IDLE_MINUTES
        });
      } catch (error) {
        console.error("ERREUR INFORMATIONS SESSION:", error);
        return json({ error: "Impossible de charger les informations de session." }, 500);
      }
    }

    // SÉCURITÉ DU COMPTE : CHANGEMENT DE MOT DE PASSE
    if (path === "/api/account/password" && request.method === "POST") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);

        const body = await request.json();
        const currentPassword = String(body.current_password || "");
        const newPassword = String(body.new_password || "");

        if (newPassword.length < 12 || newPassword.length > 128) {
          return json({
            error: "Le nouveau mot de passe doit contenir entre 12 et 128 caractères."
          }, 400);
        }

        const account = await env.DB.prepare(
          "SELECT password_hash FROM users WHERE id = ? LIMIT 1"
        ).bind(user.id).first();

        if (!account?.password_hash || !(await verifyPassword(currentPassword, account.password_hash))) {
          return json({ error: "Le mot de passe actuel est incorrect." }, 401);
        }

        if (await verifyPassword(newPassword, account.password_hash)) {
          return json({
            error: "Choisis un nouveau mot de passe différent de l'ancien."
          }, 400);
        }

        const newPasswordHash = await hashPassword(newPassword);
        const token = getCookie(request, "221cloud_session");
        if (!token) return json({ error: "Session introuvable. Reconnecte-toi." }, 401);
        const tokenHash = await hashToken(token);

        await env.DB.batch([
          env.DB.prepare(
            "UPDATE users SET password_hash = ? WHERE id = ?"
          ).bind(newPasswordHash, user.id),
          env.DB.prepare(
            "DELETE FROM sessions WHERE user_id = ? AND token_hash != ?"
          ).bind(user.id, tokenHash)
        ]);
        await recordSecurityEvent(env, user.id, "password_change", "Mot de passe modifié", request);

        return json({
          message: "Mot de passe modifié. Les autres sessions ont été déconnectées."
        });
      } catch (error) {
        console.error("ERREUR CHANGEMENT MOT DE PASSE:", error);
        return json({ error: "Impossible de modifier le mot de passe." }, 500);
      }
    }

    // SÉCURITÉ DU COMPTE : RÉVOCATION DES AUTRES SESSIONS
    if (path === "/api/account/revoke-sessions" && request.method === "POST") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);

        const token = getCookie(request, "221cloud_session");
        if (!token) return json({ error: "Session introuvable. Reconnecte-toi." }, 401);
        const tokenHash = await hashToken(token);

        const result = await env.DB.prepare(
          "DELETE FROM sessions WHERE user_id = ? AND token_hash != ?"
        ).bind(user.id, tokenHash).run();
        const revoked = Number(result.meta?.changes || 0);
        await recordSecurityEvent(
          env,
          user.id,
          "sessions_revoked",
          revoked + " autre(s) session(s) déconnectée(s)",
          request
        );

        return json({
          message: "Les autres sessions ont été déconnectées.",
          revoked: Number(result.meta?.changes || 0)
        });
      } catch (error) {
        console.error("ERREUR RÉVOCATION DES SESSIONS:", error);
        return json({ error: "Impossible de déconnecter les autres sessions." }, 500);
      }
    }

    // DÉCONNEXION
    if (path === "/api/logout" && request.method === "POST") {
      try {
        const token = getCookie(request, "221cloud_session");

        if (token) {
          const user = await currentUser(request, env);
          if (user) {
            await recordSecurityEvent(env, user.id, "logout", "Déconnexion du compte", request);
          }
          const tokenHash = await hashToken(token);

          await env.DB.prepare(
            "DELETE FROM sessions WHERE token_hash = ?"
          ).bind(tokenHash).run();
        }

        return json(
          { message: "Déconnexion réussie." },
          200,
          {
            "Set-Cookie": "221cloud_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
          }
        );

      } catch (error) {
        console.error("ERREUR DECONNEXION 221CLOUD:", error);
        return json({
          error: "Impossible de se déconnecter."
        }, 500);
      }
    }


    return env.ASSETS.fetch(request);
  }
};
