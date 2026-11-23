
const ITERATIONS = 100000;
const SESSION_DAYS = 7;
const SESSION_IDLE_MINUTES = 60;
const DATABASE_NAME_MAX = 80;

const STORAGE_LIMIT_BYTES = 1024 * 1024 * 1024;
const MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024;

const MAX_UPLOAD_REQUEST_BYTES = MAX_FILE_SIZE_BYTES + 2 * 1024 * 1024;

const MAX_JSON_REQUEST_BYTES = 4 * 1024 * 1024;

// Lit et limite le corps JSON avant son analyse.
// La limite de 4 Mo conserve une marge suffisante pour les imports de données.
async function readLimitedJsonBody(request) {
  const contentLength = Number(request.headers.get("Content-Length") || 0);
  if (contentLength > MAX_JSON_REQUEST_BYTES) {
    const error = new Error("La requête JSON dépasse la limite autorisée de 4 Mo.");
    error.status = 413;
    throw error;
  }
  if (!request.body) return JSON.parse("");

  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_JSON_REQUEST_BYTES) {
        await reader.cancel();
        const error = new Error("La requête JSON dépasse la limite autorisée de 4 Mo.");
        error.status = 413;
        throw error;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return JSON.parse(new TextDecoder().decode(body));
}

// Lit les requêtes multipart avec une limite stricte avant leur analyse.
// La limite inclut le fichier et les champs/formats multipart.
async function readLimitedMultipartForm(request) {
  const contentLength = Number(request.headers.get("Content-Length") || 0);
  if (contentLength > MAX_UPLOAD_REQUEST_BYTES) return null;
  if (!request.body) return null;

  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_UPLOAD_REQUEST_BYTES) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }

  const contentType = request.headers.get("Content-Type");
  return new Response(body, {
    headers: { "Content-Type": contentType }
  }).formData();
}

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

  // Un suffixe aléatoire réduit fortement le risque de collision simultanée.
  // Les adresses des sites déjà existants ne sont jamais modifiées.
  for (let attempt = 0; attempt < 5; attempt++) {
    const suffix = crypto.randomUUID().replace(/-/g, "").slice(0, 8);
    const slug = `${base}-${suffix}`;
    const existing = await env.DB.prepare(
      "SELECT id FROM website_hostings WHERE slug = ? LIMIT 1"
    ).bind(slug).first();

    if (!existing) return slug;
  }

  throw new Error("Impossible de générer une adresse publique.");
}
async function generateApplicationSlug(env, projectName) {
  const base = String(projectName || "application")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 50)
    .replace(/-+$/g, "") || "application";

  // Le suffixe aléatoire évite qu'une publication simultanée portant
  // le même nom choisisse le même slug avant l'insertion en base.
  for (let attempt = 0; attempt < 5; attempt++) {
    const suffix = crypto.randomUUID().replace(/-/g, "").slice(0, 8);
    const slug = `${base}-${suffix}`;
    const existing = await env.DB.prepare(
      "SELECT id FROM application_publications WHERE slug = ? LIMIT 1"
    ).bind(slug).first();
    if (!existing) return slug;
  }

  throw new Error("Impossible de générer une adresse publique unique.");
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

async function ensureCustomerDatabaseStructureSchema(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS customer_database_tables (
      id TEXT PRIMARY KEY,
      database_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      physical_name TEXT NOT NULL UNIQUE,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_customer_database_tables_owner
    ON customer_database_tables(database_id, user_id, created_at)
  `).run();
  await env.DB.prepare(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_customer_database_tables_unique_name
    ON customer_database_tables(database_id, user_id, name COLLATE NOCASE)
  `).run();
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS customer_database_columns (
      id TEXT PRIMARY KEY,
      table_id TEXT NOT NULL,
      database_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      data_type TEXT NOT NULL,
      physical_name TEXT NOT NULL,
      position INTEGER NOT NULL DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(table_id, physical_name)
    )
  `).run();
  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_customer_database_columns_table
    ON customer_database_columns(table_id, user_id, position)
  `).run();
  await env.DB.prepare(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_customer_database_columns_unique_name
    ON customer_database_columns(table_id, user_id, name COLLATE NOCASE)
  `).run();
}

function customerColumnSqlType(type) {
  return ({
    text: "TEXT",
    number: "REAL",
    boolean: "INTEGER",
    date: "TEXT"
  })[type] || null;
}

function safeInternalSqlIdentifier(value) {
  return typeof value === "string" && /^[a-zA-Z][a-zA-Z0-9_]{0,120}$/.test(value);
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


async function loginProtectionKeys(request) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  return ["ip:" + await hashToken(ip)];
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

// Prépare le stockage des inscriptions en attente de vérification e-mail.
// Cette fonction n'est pas encore appelée : aucune table n'est créée en production
// avant l'intégration complète et l'activation contrôlée du parcours.
async function ensureEmailVerificationSchema(env) {
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS pending_email_verifications (
      email TEXT PRIMARY KEY,
      full_name TEXT,
      password_hash TEXT NOT NULL,
      code_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      last_sent_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`
  ).run();

  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS idx_pending_email_verifications_expires ON pending_email_verifications(expires_at)"
  ).run();
}

async function getLoginBlock(env, keys) {
  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(
    "SELECT blocked_until FROM login_attempt_limits WHERE scope_key = ? LIMIT 1"
  ).bind(keys[0]).first();
  return Number(row?.blocked_until || 0) > now;
}

async function recordLoginFailure(env, keys) {
  const now = Math.floor(Date.now() / 1000);
  const windowSeconds = 15 * 60;
  const blockSeconds = 15 * 60;
  const threshold = 20;

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
    keys[0],
    now,
    now - windowSeconds,
    now - windowSeconds,
    now,
    now - windowSeconds,
    threshold,
    now + blockSeconds
  ).run();

  await env.DB.prepare(
    "DELETE FROM login_attempt_limits WHERE window_started_at < ? AND blocked_until < ?"
  ).bind(now - 86400, now).run();
}

async function clearLoginFailures(env, keys) {
  await env.DB.prepare(
    "DELETE FROM login_attempt_limits WHERE scope_key = ?"
  ).bind(keys[0]).run();
}


async function registrationProtectionKey(request) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  return "register:ip:" + await hashToken(ip);
}

async function isRegistrationBlocked(env, key) {
  const row = await env.DB.prepare(
    "SELECT blocked_until FROM login_attempt_limits WHERE scope_key = ? LIMIT 1"
  ).bind(key).first();
  return Number(row?.blocked_until || 0) > Math.floor(Date.now() / 1000);
}

async function recordRegistrationAttempt(env, key) {
  const now = Math.floor(Date.now() / 1000);
  const windowSeconds = 15 * 60;
  const blockSeconds = 15 * 60;
  // Cinq inscriptions sont autorisées par IP sur 15 minutes.
  // La sixième demande déclenche un blocage temporaire.
  await env.DB.prepare(`
    INSERT INTO login_attempt_limits
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
        END) >= 6 THEN ?
        ELSE login_attempt_limits.blocked_until
      END
  `).bind(
    key,
    now,
    now - windowSeconds,
    now - windowSeconds,
    now,
    now - windowSeconds,
    now + blockSeconds
  ).run();
}


async function ensureAdminAuditSchema(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS admin_audit_events (
      id TEXT PRIMARY KEY,
      actor_id TEXT NOT NULL,
      actor_email TEXT NOT NULL,
      target_user_id TEXT NOT NULL,
      target_email TEXT NOT NULL,
      action TEXT NOT NULL,
      old_value TEXT NOT NULL,
      new_value TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit_events(created_at DESC)"
  ).run();
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
async function ensureApplicationFilesSchema(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS application_files (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL,
      file_name TEXT NOT NULL,
      content TEXT NOT NULL DEFAULT '',
      mime_type TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(project_id, file_name)
    )
  `).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS idx_application_files_project ON application_files(project_id, file_name)"
  ).run();
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS application_file_versions (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL,
      file_name TEXT NOT NULL,
      version_number INTEGER NOT NULL,
      content TEXT NOT NULL DEFAULT '',
      mime_type TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(project_id, file_name, version_number)
    )
  `).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS idx_application_file_versions_lookup ON application_file_versions(project_id, file_name, version_number DESC)"
  ).run();
  await ensureApplicationTrashSchema(env);
}

function validApplicationFilePath(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 240) return false;
  if (value.startsWith("/") || value.endsWith("/") || value.includes("\\") || /[%?#]/.test(value)) return false;
  const parts = value.split("/");
  if (parts.length > 8 || parts.some((part, index) => {
    const isGitIgnoreFile = index === parts.length - 1 && part === ".gitignore";
    return !part || part === "." || part === ".." || part.length > 64 ||
      (!isGitIgnoreFile && !/^[A-Za-z0-9][A-Za-z0-9 ._-]*$/.test(part)) ||
      part.endsWith(".") || part.endsWith(" ");
  })) return false;
  const name = parts[parts.length - 1];
  if (/^\.env($|\.)/i.test(name) || /^\.dev\.vars$/i.test(name)) return false;
  return /^(\.gitignore|[^.].*\.(html?|css|m?js|json|svg|txt|md|xml|webmanifest))$/i.test(name);
}

function applicationFileMimeType(fileName) {
  const extension = String(fileName).split(".").pop().toLowerCase();
  return ({
    html: "text/html; charset=utf-8",
    htm: "text/html; charset=utf-8",
    css: "text/css; charset=utf-8",
    js: "text/javascript; charset=utf-8",
    mjs: "text/javascript; charset=utf-8",
    json: "application/json; charset=utf-8",
    svg: "image/svg+xml",
    txt: "text/plain; charset=utf-8",
    md: "text/markdown; charset=utf-8",
    xml: "application/xml; charset=utf-8",
    webmanifest: "application/manifest+json; charset=utf-8",
    gitignore: "text/plain; charset=utf-8"
  })[extension] || "text/plain; charset=utf-8";
}

async function ensureApplicationTrashSchema(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS application_directories (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL,
      directory_path TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(project_id, directory_path)
    )
  `).run();
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS application_trash_items (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL,
      item_type TEXT NOT NULL,
      original_path TEXT NOT NULL,
      deleted_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_application_trash_project ON application_trash_items(project_id, deleted_at DESC)").run();
  for (const tableName of ["application_files", "application_file_versions", "application_directories"]) {
    const columns = await env.DB.prepare("PRAGMA table_info(" + tableName + ")").all();
    const known = new Set((columns.results || []).map(column => column.name));
    if (!known.has("deleted_at")) await env.DB.prepare("ALTER TABLE " + tableName + " ADD COLUMN deleted_at TEXT").run();
    if (!known.has("trash_id")) await env.DB.prepare("ALTER TABLE " + tableName + " ADD COLUMN trash_id TEXT").run();
  }
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_application_files_trash ON application_files(project_id, trash_id)").run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_application_versions_trash ON application_file_versions(project_id, trash_id)").run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_application_directories_trash ON application_directories(project_id, trash_id)").run();
}

async function ensureApplicationDirectoriesSchema(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS application_directories (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL,
      directory_path TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(project_id, directory_path)
    )
  `).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS idx_application_directories_project ON application_directories(project_id, directory_path)"
  ).run();
  await ensureApplicationTrashSchema(env);
}

async function applicationFilePathHasFileConflict(env, projectId, value, includeSelf = false) {
  const segments = String(value).split("/");
  const limit = includeSelf ? segments.length : segments.length - 1;
  for (let index = 1; index <= limit; index++) {
    const candidate = segments.slice(0, index).join("/");
    const file = await env.DB.prepare(
      "SELECT file_name FROM application_files WHERE project_id = ? AND deleted_at IS NULL AND file_name = ? LIMIT 1"
    ).bind(projectId, candidate).first();
    if (file) return candidate;
  }
  return "";
}

async function ensureApplicationPublicationSchema(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS application_publications (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      project_id TEXT NOT NULL UNIQUE,
      slug TEXT NOT NULL UNIQUE,
      active_version_id TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS application_publication_versions (
      id TEXT PRIMARY KEY,
      publication_id TEXT NOT NULL,
      version_number INTEGER NOT NULL,
      index_html TEXT NOT NULL,
      style_css TEXT NOT NULL DEFAULT '',
      script_js TEXT NOT NULL DEFAULT '',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(publication_id, version_number)
    )
  `).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS idx_application_publication_versions ON application_publication_versions(publication_id, version_number DESC)"
  ).run();
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

    // Protection CSRF : les mutations de l'API doivent provenir de la même origine.
    // Les appels du navigateur envoient Origin; Referer sert de repli si Origin est absent.
    if (
      path.startsWith("/api/") &&
      ["POST", "PUT", "PATCH", "DELETE"].includes(request.method.toUpperCase())
    ) {
      const originHeader = request.headers.get("Origin");
      const refererHeader = request.headers.get("Referer");
      let requestOrigin = null;

      try {
        if (originHeader) {
          requestOrigin = new URL(originHeader).origin;
        } else if (refererHeader) {
          requestOrigin = new URL(refererHeader).origin;
        }
      } catch {
        requestOrigin = null;
      }

      if (!requestOrigin || requestOrigin !== url.origin) {
        return json({
          error: "Requête refusée : origine non autorisée."
        }, 403);
      }
    }

    // PUBLICATION D'APPLICATION : SERVIR UNIQUEMENT LA VERSION ACTIVE
    const publicApplicationMatch = path.match(/^\/app\/([a-z0-9-]+)(?:\/(.*))?$/);
    if (publicApplicationMatch && request.method === "GET") {
      try {
        await ensureApplicationPublicationSchema(env);
        const slug = publicApplicationMatch[1];
        const requestedFile = publicApplicationMatch[2];
        if (requestedFile === undefined) {
          return Response.redirect(new URL(`/app/${slug}/`, url), 308);
        }
        const fileName = requestedFile || "index.html";
        if (!validApplicationFilePath(fileName)) {
          return new Response("Fichier introuvable.", { status: 404 });
        }
        const publication = await env.DB.prepare(`
          SELECT versions.index_html, versions.style_css, versions.script_js
          FROM application_publications AS publications
          JOIN application_publication_versions AS versions
            ON versions.id = publications.active_version_id
            AND versions.publication_id = publications.id
          WHERE publications.slug = ?
          LIMIT 1
        `).bind(slug).first();
        if (!publication) return new Response("Application non publiée ou introuvable.", { status: 404 });
        const content = fileName === "index.html"
          ? publication.index_html
          : fileName === "style.css"
            ? publication.style_css
            : publication.script_js;
        const contentType = fileName === "index.html"
          ? "text/html; charset=utf-8"
          : fileName === "style.css"
            ? "text/css; charset=utf-8"
            : "text/javascript; charset=utf-8";
        return new Response(content, {
          headers: {
            "Content-Type": contentType,
            "Cache-Control": "no-cache",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            ...(fileName === "index.html" ? {
              "Content-Security-Policy": "sandbox allow-scripts allow-forms; default-src * data: blob: 'unsafe-inline' 'unsafe-eval'; connect-src *; img-src * data: blob:; style-src * 'unsafe-inline'; script-src * 'unsafe-inline' 'unsafe-eval'; font-src * data:"
            } : {})
          }
        });
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        console.error("ERREUR PUBLICATION APPLICATION:", error);
        return new Response("Publication temporairement indisponible.", { status: 503 });
      }
    }

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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
if (path === "/api/admin/subscriptions" && request.method === "GET") {
  const auth = await requireAdmin(request, env);
  if (auth.response) return auth.response;

  const result = await env.DB.prepare(`
    SELECT
      u.id AS user_id,
      u.full_name,
      u.email,
      latest.plan,
      latest.status,
      latest.started_at,
      latest.expires_at,
      latest.auto_renew,
      latest.created_at AS subscription_created_at,
      CASE
        WHEN latest.id IS NULL THEN 'free'
        WHEN LOWER(latest.status) = 'active'
          AND (latest.expires_at IS NULL OR datetime(latest.expires_at) > CURRENT_TIMESTAMP)
        THEN LOWER(latest.plan)
        ELSE 'free'
      END AS effective_plan,
      CASE
        WHEN LOWER(latest.status) = 'active'
          AND latest.expires_at IS NOT NULL
          AND datetime(latest.expires_at) <= CURRENT_TIMESTAMP
        THEN 'expired'
        ELSE LOWER(COALESCE(latest.status, 'inactive'))
      END AS effective_status
    FROM users u
    LEFT JOIN subscriptions latest
      ON latest.user_id = u.id
      AND latest.id = (
        SELECT s.id
        FROM subscriptions s
        WHERE s.user_id = u.id
        ORDER BY datetime(s.created_at) DESC, s.id DESC
        LIMIT 1
      )
    ORDER BY u.created_at DESC
  `).all();

  const subscriptions = result.results || [];
  const summary = {
    free: 0,
    starter: 0,
    pro: 0,
    active: 0,
    expired: 0
  };

  for (const item of subscriptions) {
    const status = String(item.effective_status || "inactive").toLowerCase();
    const plan = String(item.effective_plan || "free").toLowerCase();

    if (Object.prototype.hasOwnProperty.call(summary, plan)) {
      summary[plan] += 1;
    } else {
      summary.free += 1;
    }

    if (status === "active") summary.active += 1;
    if (status === "expired") summary.expired += 1;
  }

  return json({
    subscriptions,
    summary
  });
}
if (path.startsWith("/api/admin/subscriptions/") && request.method === "GET") {
  const auth = await requireAdmin(request, env);
  if (auth.response) return auth.response;

  const userId = decodeURIComponent(
    path.slice("/api/admin/subscriptions/".length)
  );

  if (!userId || userId.includes("/")) {
    return json({ error: "Identifiant utilisateur invalide." }, 400);
  }

  const user = await env.DB.prepare(
    `SELECT id, full_name, email, role, status, created_at
     FROM users
     WHERE id = ?
     LIMIT 1`
  ).bind(userId).first();

  if (!user) {
    return json({ error: "Utilisateur introuvable." }, 404);
  }

  const result = await env.DB.prepare(
    `SELECT
       id,
       plan,
       status,
       CASE
         WHEN LOWER(status) = 'active'
           AND expires_at IS NOT NULL
           AND datetime(expires_at) <= CURRENT_TIMESTAMP
         THEN 'expired'
         ELSE LOWER(status)
       END AS effective_status,
       started_at,
       expires_at,
       auto_renew,
       created_at
     FROM subscriptions
     WHERE user_id = ?
     ORDER BY datetime(created_at) DESC, id DESC
     LIMIT 100`
  ).bind(userId).all();

  return json({
    user,
    history: result.results || []
  });
}
if (path === "/api/admin/audit" && request.method === "GET") {
  const auth = await requireAdmin(request, env);
  if (auth.response) return auth.response;

  await ensureAdminAuditSchema(env);
  const result = await env.DB.prepare(`
    SELECT
      id, actor_email, target_email, action,
      old_value, new_value, created_at
    FROM admin_audit_events
    ORDER BY created_at DESC
    LIMIT 100
  `).all();

  return json({ events: result.results || [] });
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

  let body;
  try {
    body = await readLimitedJsonBody(request);
  } catch (error) {
    if (error?.status === 413) {
      return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
    }
    throw error;
  }

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

  const changedFields = [];
  if (role !== target.role) changedFields.push(["role", target.role, role]);
  if (status !== target.status) changedFields.push(["status", target.status, status]);

  await env.DB.prepare(
    `UPDATE users
     SET role = ?, status = ?
     WHERE id = ?`
  ).bind(role, status, userId).run();

  if (changedFields.length) {
    try {
      await ensureAdminAuditSchema(env);
      const targetEmail = await env.DB.prepare(
        "SELECT email FROM users WHERE id = ? LIMIT 1"
      ).bind(userId).first();
      for (const [field, oldValue, newValue] of changedFields) {
        await env.DB.prepare(`
          INSERT INTO admin_audit_events
            (id, actor_id, actor_email, target_user_id, target_email, action, old_value, new_value)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          crypto.randomUUID(),
          auth.user.id,
          String(auth.user.email || "Administrateur"),
          userId,
          String(targetEmail?.email || "Compte inconnu"),
          field === "role" ? "role_changed" : "status_changed",
          String(oldValue),
          String(newValue)
        ).run();
      }
    } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
      console.error("ERREUR JOURNAL ADMINISTRATION:", error);
    }
  }

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
      const auth = await requireAdmin(request, env);
      if (auth.response) return auth.response;

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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        console.error("ERREUR DATABASE:", error);
        return json({
          platform: "221Cloud",
          database: "error"
        }, 500);
      }
    }

    // Les inscriptions sont réactivées sans vérification de possession de l'adresse e-mail.
    // Les utilisateurs doivent saisir une adresse qu'ils contrôlent.
    const REGISTRATION_ENABLED = true;

    // INSCRIPTION
    if (path === "/api/register" && request.method === "POST") {
      if (!REGISTRATION_ENABLED) {
        return json({
          error: "Les nouvelles inscriptions sont temporairement suspendues."
        }, 503);
      }

      try {
        await ensureLoginProtectionSchema(env);
        const registrationKey = await registrationProtectionKey(request);
        if (await isRegistrationBlocked(env, registrationKey)) {
          return json({
            error: "Trop de demandes d'inscription. Réessaie dans 15 minutes."
          }, 429, { "Retry-After": "900" });
        }
        await recordRegistrationAttempt(env, registrationKey);
        if (await isRegistrationBlocked(env, registrationKey)) {
          return json({
            error: "Trop de demandes d'inscription. Réessaie dans 15 minutes."
          }, 429, { "Retry-After": "900" });
        }

        const body = await readLimitedJsonBody(request);
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");
        const fullName = String(body.full_name || body.name || "").trim();

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return json({ error: "Adresse e-mail invalide." }, 400);
        }

        if (fullName.length < 2 || fullName.length > 80) {
          return json({
            error: "Le nom complet doit contenir entre 2 et 80 caractères."
          }, 400);
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

        // D1 batch exécute les deux opérations dans une transaction :
        // aucun compte ne reste créé sans son abonnement Free.
        await env.DB.batch([
          env.DB.prepare(
            "INSERT INTO users (id, email, full_name, password_hash, role) VALUES (?, ?, ?, ?, 'client')"
          ).bind(userId, email, fullName, passwordHash),
          env.DB.prepare(`
            INSERT INTO subscriptions (
              id, user_id, plan, status, created_at, started_at, expires_at, auto_renew
            )
            VALUES (?, ?, 'free', 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, NULL, 0)
          `).bind(crypto.randomUUID(), userId)
        ]);

        const token = await createSession(env, userId);

        return json({
          message: "Compte créé avec succès.",
          user: {
            id: userId,
            email,
            full_name: fullName,
            role: "client"
          }
        }, 201, {
          "Set-Cookie": sessionCookie(token)
        });

      } catch (error) {
        if (error?.status === 413) {
          return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        }
        if (String(error?.message || "").includes("UNIQUE constraint failed: users.email")) {
          return json({ error: "Cette adresse e-mail est déjà utilisée." }, 409);
        }
        console.error("ERREUR INSCRIPTION 221CLOUD:", error);
        return json({
          error: "Impossible de créer le compte."
        }, 500);
      }
    }

    // CONNEXION
    if (path === "/api/login" && request.method === "POST") {
      try {
        const body = await readLimitedJsonBody(request);

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
          "SELECT id, email, full_name, role, status, password_hash FROM users WHERE email = ?"
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
        if (user.status !== "active") {
          return json({
            error: "Ce compte est suspendu. Contacte l'administration pour obtenir de l'aide."
          }, 403);
        }

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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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

    const subscriptionHistoryResult = await env.DB.prepare(`
      SELECT
        plan,
        status,
        CASE
          WHEN LOWER(status) = 'active'
            AND expires_at IS NOT NULL
            AND datetime(expires_at) <= CURRENT_TIMESTAMP
          THEN 'expired'
          ELSE LOWER(status)
        END AS effective_status,
        CASE
          WHEN LOWER(status) = 'active'
            AND (expires_at IS NULL OR datetime(expires_at) > CURRENT_TIMESTAMP)
          THEN LOWER(plan)
          ELSE 'free'
        END AS effective_plan,
        created_at,
        started_at,
        expires_at,
        auto_renew
      FROM subscriptions
      WHERE user_id = ?
      ORDER BY datetime(created_at) DESC, id DESC
      LIMIT 50
    `).bind(user.id).all();

    const subscriptionHistory = subscriptionHistoryResult.results || [];
    const latestSubscription = subscriptionHistory[0] || null;
    const subscription = latestSubscription
      ? {
          ...latestSubscription,
          plan: latestSubscription.effective_plan,
          status: latestSubscription.effective_status
        }
      : null;

    if (!subscription) {
      return json({
        error: "Aucun abonnement trouvé."
      }, 404);
    }

    const plan = String(subscription.plan || "free").toLowerCase();

    const planLimits = {
      free: { storage_bytes: 1024 * 1024 * 1024, projects: 1 },
      starter: { storage_bytes: 5 * 1024 * 1024 * 1024, projects: 5 },
      pro: { storage_bytes: 20 * 1024 * 1024 * 1024, projects: 20 }
    };
    const limits = planLimits[plan] || planLimits.free;

    const storageUsage = await env.DB.prepare(`
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

    const projectUsage = await env.DB.prepare(`
      SELECT COUNT(*) AS total
      FROM projects
      WHERE user_id = ? AND deleted_at IS NULL
    `).bind(user.id).first();

    return json({
      subscription,
      history: subscriptionHistory,
      limits,
      usage: {
        storage_bytes: Number(storageUsage?.used || 0),
        projects: Number(projectUsage?.total || 0)
      }
    });

  } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        const form = await readLimitedMultipartForm(request);
        if (!form) {
          return json({
            error: "La requête d'envoi dépasse la limite autorisée de 22 Mo."
          }, 413);
        }
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
          SELECT
            plan,
            status,
            expires_at,
            CASE
              WHEN LOWER(status) = 'active'
                AND (expires_at IS NULL OR datetime(expires_at) > CURRENT_TIMESTAMP)
              THEN LOWER(plan)
              ELSE 'free'
            END AS effective_plan
          FROM subscriptions
          WHERE user_id = ?
          ORDER BY datetime(created_at) DESC, id DESC
          LIMIT 1
        `).bind(user.id).first();

        const plan = String(subscription?.effective_plan || "free").toLowerCase();

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
          const insertResult = await env.DB.prepare(`
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
            SELECT ?, ?, ?, ?, ?, ?, ?, ?
            WHERE EXISTS (
              SELECT 1
              FROM deployments d
              JOIN website_hostings h ON h.project_id = d.project_id
              WHERE d.id = ?
                AND d.project_id = ?
                AND d.status = 'pending'
                AND h.id = ?
                AND h.user_id = ?
            )
          `).bind(
            id,
            deployment.hosting_id,
            deploymentId,
            filePath,
            file.size,
            mimeType,
            storageKey,
            uploadedFile.fileId,
            deploymentId,
            projectId,
            deployment.hosting_id,
            user.id
          ).run();

          if (!insertResult?.meta?.changes) {
            try {
              await b2NativeDelete(env, uploadedFile.fileId, uploadedFile.fileName);
            } catch (cleanupError) {
              console.error("ERREUR NETTOYAGE FICHIER APRÈS CHANGEMENT DE STATUT:", cleanupError);
            }
            return json({
              error: "Ce déploiement n'accepte plus de fichiers. Le transfert a été annulé."
            }, 409);
          }

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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        try { cloneRequest = await readLimitedJsonBody(request); } catch (error) { if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413); }
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
          SELECT
            plan,
            status,
            expires_at,
            CASE
              WHEN LOWER(status) = 'active'
                AND (expires_at IS NULL OR datetime(expires_at) > CURRENT_TIMESTAMP)
              THEN LOWER(plan)
              ELSE 'free'
            END AS effective_plan
          FROM subscriptions
          WHERE user_id = ?
          ORDER BY datetime(created_at) DESC, id DESC
          LIMIT 1
        `).bind(user.id).first();
        const plan = String(subscription?.effective_plan || "free").toLowerCase();
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
          const insertResult = await env.DB.prepare(`
            INSERT INTO website_files (
              id, hosting_id, deployment_id, file_path, file_size,
              mime_type, storage_key, b2_file_id
            )
            SELECT ?, ?, ?, ?, ?, ?, ?, ?
            WHERE EXISTS (
              SELECT 1
              FROM deployments d
              JOIN website_hostings h ON h.project_id = d.project_id
              WHERE d.id = ?
                AND d.project_id = ?
                AND d.status = 'pending'
                AND h.id = ?
                AND h.user_id = ?
            )
          `).bind(
            newId, target.hosting_id, deploymentId, file.file_path,
            file.file_size, file.mime_type, newKey, uploaded.fileId,
            deploymentId, projectId, target.hosting_id, user.id
          ).run();
          if (!insertResult?.meta?.changes) {
            throw new Error("Le déploiement a changé de statut pendant la restauration.");
          }
          insertedIds.push(newId);
        }

        return json({ cloned: insertedIds.length, bytes: cloneBytes });
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
    const body = await readLimitedJsonBody(request);

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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
    const body = await readLimitedJsonBody(request);

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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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

        // Les sites clients partagent le domaine technique de 221Cloud.
        // Le sandbox CSP leur donne une origine opaque : leurs scripts ne
        // peuvent donc pas accéder aux cookies, au stockage local ou aux API
        // authentifiées de l'espace client sur ce même domaine.
        headers.set(
          "Content-Security-Policy",
          "sandbox allow-scripts allow-forms allow-popups allow-downloads allow-modals allow-top-navigation-by-user-activation"
        );

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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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

        const body = await readLimitedJsonBody(request);
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
          SELECT
            plan,
            status,
            expires_at,
            CASE
              WHEN LOWER(status) = 'active'
                AND (expires_at IS NULL OR datetime(expires_at) > CURRENT_TIMESTAMP)
              THEN LOWER(plan)
              ELSE 'free'
            END AS effective_plan
          FROM subscriptions
          WHERE user_id = ?
          ORDER BY datetime(created_at) DESC, id DESC
          LIMIT 1
        `).bind(user.id).first();

        const plan = String(subscription?.effective_plan || "free").toLowerCase();

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
const projectInsert = env.DB.prepare(
  `INSERT INTO projects (id, user_id, name, type, status)
   VALUES (?, ?, ?, ?, 'pending')`
).bind(id, user.id, name, type);

let hosting = null;

if (type === "website") {
  const hostingId = crypto.randomUUID();
  const slug = await generateWebsiteSlug(env, name);
  const hostingInsert = env.DB.prepare(`
    INSERT INTO website_hostings (
      id, user_id, project_id, slug, status
    )
    VALUES (?, ?, ?, ?, 'draft')
  `).bind(hostingId, user.id, id, slug);

  // Les deux insertions sont atomiques : aucun projet orphelin.
  await env.DB.batch([projectInsert, hostingInsert]);

  hosting = {
    id: hostingId,
    slug,
    status: "draft",
    url: `https://221cloud-platform.elhadjidame-sall.workers.dev/site/${slug}`
  };
} else {
  await projectInsert.run();
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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

        const subscription = await env.DB.prepare(`
          SELECT
            plan,
            status,
            expires_at,
            CASE
              WHEN LOWER(status) = 'active'
                AND (expires_at IS NULL OR datetime(expires_at) > CURRENT_TIMESTAMP)
              THEN LOWER(plan)
              ELSE 'free'
            END AS effective_plan
          FROM subscriptions
          WHERE user_id = ?
          ORDER BY datetime(created_at) DESC, id DESC
          LIMIT 1
        `).bind(user.id).first();
        const plan = String(subscription?.effective_plan || "free").toLowerCase();
        const projectLimits = { free: 1, starter: 5, pro: 20 };
        const maxProjects = projectLimits[plan] ?? 1;
        const activeCount = await env.DB.prepare(`
          SELECT COUNT(*) AS total
          FROM projects
          WHERE user_id = ? AND deleted_at IS NULL
        `).bind(user.id).first();

        if (Number(activeCount?.total || 0) >= maxProjects) {
          return json({
            error: `Votre forfait ${plan} autorise au maximum ${maxProjects} projet(s) actif(s). Libérez une place ou changez de forfait avant de restaurer ce projet.`
          }, 403);
        }

        // Le contrôle du quota est répété dans la même instruction que la restauration.
        // Ainsi, deux restaurations simultanées ne peuvent pas consommer la même place.
        const restoreResult = await env.DB.prepare(`
          UPDATE projects SET deleted_at = NULL
          WHERE id = ? AND user_id = ? AND deleted_at IS NOT NULL
            AND (
              SELECT COUNT(*) FROM projects
              WHERE user_id = ? AND deleted_at IS NULL
            ) < ?
        `).bind(projectId, user.id, user.id, maxProjects).run();

        if (!Number(restoreResult?.meta?.changes || 0)) {
          const currentProject = await env.DB.prepare(`
            SELECT id FROM projects
            WHERE id = ? AND user_id = ? AND deleted_at IS NOT NULL
          `).bind(projectId, user.id).first();
          if (!currentProject) {
            return json({ error: "Ce projet a déjà été restauré ou n'est plus disponible dans la corbeille." }, 409);
          }
          const latestActiveCount = await env.DB.prepare(`
            SELECT COUNT(*) AS total FROM projects
            WHERE user_id = ? AND deleted_at IS NULL
          `).bind(user.id).first();
          if (Number(latestActiveCount?.total || 0) >= maxProjects) {
            return json({
              error: `Votre forfait ${plan} autorise au maximum ${maxProjects} projet(s) actif(s). Libérez une place ou changez de forfait avant de restaurer ce projet.`
            }, 403);
          }
          return json({ error: "La restauration n'a pas pu être effectuée. Actualisez la page puis réessayez." }, 409);
        }

        return json({ message: "Projet restauré avec succès.", project });
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        console.error("ERREUR RESTAURATION PROJET:", error);
        return json({ error: "Impossible de restaurer ce projet." }, 500);
      }
    }


    // APPLICATIONS : CONSULTER L'ÉTAT DE PUBLICATION
    const applicationPublicationMatch = path.match(/^\/api\/projects\/([^/]+)\/application-publication$/);
    if (applicationPublicationMatch && request.method === "GET") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureApplicationPublicationSchema(env);
        const projectId = decodeURIComponent(applicationPublicationMatch[1]);
        const project = await env.DB.prepare(
          "SELECT id FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL LIMIT 1"
        ).bind(projectId, user.id).first();
        if (!project) return json({ error: "Application introuvable." }, 404);
        const publication = await env.DB.prepare(`
          SELECT id, slug, active_version_id, created_at, updated_at
          FROM application_publications
          WHERE project_id = ? AND user_id = ?
          LIMIT 1
        `).bind(projectId, user.id).first();
        if (!publication) return json({ publication: null });
        const version = await env.DB.prepare(
          "SELECT version_number, created_at FROM application_publication_versions WHERE id = ? AND publication_id = ? LIMIT 1"
        ).bind(publication.active_version_id, publication.id).first();
        return json({
          publication: {
            ...publication,
            version_number: version?.version_number || null,
            published_at: version?.created_at || publication.updated_at,
            url: `https://221cloud-platform.elhadjidame-sall.workers.dev/app/${publication.slug}/`
          }
        });
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        console.error("ERREUR ÉTAT PUBLICATION APPLICATION:", error);
        return json({ error: "Impossible de charger l'état de publication." }, 500);
      }
    }

    // APPLICATIONS : PUBLIER UNE VERSION ENREGISTRÉE
    if (applicationPublicationMatch && request.method === "POST") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureApplicationPublicationSchema(env);
        await ensureApplicationFilesSchema(env);
        const projectId = decodeURIComponent(applicationPublicationMatch[1]);
        const project = await env.DB.prepare(
          "SELECT id, name FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL LIMIT 1"
        ).bind(projectId, user.id).first();
        if (!project) return json({ error: "Application introuvable." }, 404);
        const files = await env.DB.prepare(
          "SELECT file_name, content FROM application_files WHERE project_id = ?"
        ).bind(projectId).all();
        const fileMap = Object.fromEntries((files.results || []).map(file => [file.file_name, file.content || ""]));
        if (!fileMap["index.html"] || !fileMap["index.html"].trim()) {
          return json({ error: "Le fichier index.html est vide. Ajoutez une page avant de publier." }, 400);
        }
        const indexHtml = fileMap["index.html"];
        const styleCss = fileMap["style.css"] || "";
        const scriptJs = fileMap["script.js"] || "";
        const totalSize = new TextEncoder().encode(indexHtml).length +
          new TextEncoder().encode(styleCss).length +
          new TextEncoder().encode(scriptJs).length;
        if (totalSize > 1048576) return json({ error: "L'application dépasse la limite de publication de 1 Mo." }, 413);

        let publication = await env.DB.prepare(
          "SELECT id, slug FROM application_publications WHERE project_id = ? AND user_id = ? LIMIT 1"
        ).bind(projectId, user.id).first();
        const isNewPublication = !publication;
        if (!publication) {
          publication = {
            id: crypto.randomUUID(),
            slug: await generateApplicationSlug(env, project.name)
          };
        }
        const versionId = crypto.randomUUID();
        const versionInsert = env.DB.prepare(`
          INSERT INTO application_publication_versions
            (id, publication_id, version_number, index_html, style_css, script_js)
          SELECT ?, ?, COALESCE(MAX(version_number), 0) + 1, ?, ?, ?
          FROM application_publication_versions
          WHERE publication_id = ?
            AND EXISTS (
              SELECT 1 FROM projects
              WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL
            )
        `).bind(versionId, publication.id, indexHtml, styleCss, scriptJs, publication.id, projectId, user.id);
        const publicationWrite = isNewPublication
          ? env.DB.prepare(`
              INSERT INTO application_publications
                (id, user_id, project_id, slug, active_version_id)
              SELECT ?, ?, ?, ?, ?
              WHERE EXISTS (
                SELECT 1 FROM projects
                WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL
              )
            `).bind(publication.id, user.id, projectId, publication.slug, versionId, projectId, user.id)
          : env.DB.prepare(
              "UPDATE application_publications SET active_version_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ? AND EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL)"
            ).bind(versionId, publication.id, user.id, projectId, user.id);
        await env.DB.batch([versionInsert, publicationWrite]);
        const publishedVersion = await env.DB.prepare(
          "SELECT version_number FROM application_publication_versions WHERE id = ? AND publication_id = ? LIMIT 1"
        ).bind(versionId, publication.id).first();
        const versionNumber = Number(publishedVersion?.version_number || 0);
        if (!versionNumber) return json({ error: "Cette application a été déplacée dans la corbeille. La publication a été annulée." }, 409);
        const publishedUrl = `https://221cloud-platform.elhadjidame-sall.workers.dev/app/${publication.slug}/`;
        return json({
          message: isNewPublication ? "Application publiée avec succès." : "Nouvelle version publiée avec succès.",
          publication: {
            id: publication.id,
            slug: publication.slug,
            version_number: versionNumber,
            published_at: new Date().toISOString(),
            url: publishedUrl
          }
        });
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        const errorMessage = String(error?.message || "");
        if (
          errorMessage.includes("Impossible de générer une adresse publique unique") ||
          errorMessage.includes("UNIQUE constraint failed")
        ) {
          console.warn("CONFLIT DE PUBLICATION APPLICATION:", errorMessage);
          return json({
            error: "La publication rencontre un conflit temporaire. Aucune nouvelle adresse n'a pu être réservée. Attendez quelques instants puis réessayez."
          }, 409);
        }
        console.error("ERREUR PUBLICATION APPLICATION:", error);
        return json({ error: "Impossible de publier l'application pour le moment. Vérifiez votre connexion et réessayez." }, 500);
      }
    }

    // APPLICATIONS : CRÉER UN DOSSIER
    const applicationFoldersMatch = path.match(/^\/api\/projects\/([^/]+)\/application-folders$/);
    if (applicationFoldersMatch && request.method === "POST") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureApplicationFilesSchema(env);
        await ensureApplicationDirectoriesSchema(env);
        const projectId = decodeURIComponent(applicationFoldersMatch[1]);
        const project = await env.DB.prepare(
          "SELECT id FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL LIMIT 1"
        ).bind(projectId, user.id).first();
        if (!project) return json({ error: "Application introuvable." }, 404);
        const body = await readLimitedJsonBody(request);
        const directoryPath = String(body.directory_path || "");
        if (!validApplicationFilePath(directoryPath + "/placeholder.txt")) {
          return json({ error: "Nom ou chemin de dossier invalide." }, 400);
        }
        const conflictingFilePath = await applicationFilePathHasFileConflict(env, projectId, directoryPath, true);
        if (conflictingFilePath) {
          return json({ error: "Un fichier existe déjà sur ce chemin ou sur l'un de ses niveaux parents : " + conflictingFilePath }, 409);
        }
        const segments = directoryPath.split("/");
        const paths = segments.map((_, index) => segments.slice(0, index + 1).join("/"));
        const existing = await env.DB.prepare(
          "SELECT directory_path FROM application_directories WHERE project_id = ? AND deleted_at IS NULL"
        ).bind(projectId).all();
        const known = new Set((existing.results || []).map(item => item.directory_path));
        for (const directory of paths) {
          if (known.has(directory)) continue;
          await env.DB.prepare(
            "INSERT OR IGNORE INTO application_directories (id, project_id, directory_path) SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL)"
          ).bind(crypto.randomUUID(), projectId, directory, projectId, user.id).run();
        }
        return json({ message: "Dossier créé.", directory_path: directoryPath }, 201);
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        console.error("ERREUR CRÉATION DOSSIER APPLICATION:", error);
        return json({ error: "Impossible de créer ce dossier." }, 500);
      }
    }

    // APPLICATIONS : CRÉER UN FICHIER
    if (path.match(/^\/api\/projects\/([^/]+)\/application-files$/) && request.method === "POST") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureApplicationFilesSchema(env);
        await ensureApplicationDirectoriesSchema(env);
        const projectId = decodeURIComponent(path.match(/^\/api\/projects\/([^/]+)\/application-files$/)[1]);
        const project = await env.DB.prepare(
          "SELECT id FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL LIMIT 1"
        ).bind(projectId, user.id).first();
        if (!project) return json({ error: "Application introuvable." }, 404);
        const body = await readLimitedJsonBody(request);
        const fileName = String(body.file_name || "");
        if (!validApplicationFilePath(fileName)) return json({ error: "Nom ou chemin de fichier non autorisé." }, 400);
        const existing = await env.DB.prepare(
          "SELECT file_name FROM application_files WHERE project_id = ? AND file_name = ? LIMIT 1"
        ).bind(projectId, fileName).first();
        if (existing) return json({ error: "Ce fichier existe déjà." }, 409);
        const existingDirectory = await env.DB.prepare(
          "SELECT directory_path FROM application_directories WHERE project_id = ? AND directory_path = ? LIMIT 1"
        ).bind(projectId, fileName).first();
        if (existingDirectory) return json({ error: "Un dossier porte déjà ce nom." }, 409);
        const conflictingParentFile = await applicationFilePathHasFileConflict(env, projectId, fileName, false);
        if (conflictingParentFile) {
          return json({ error: "Un fichier empêche la création de ce chemin : " + conflictingParentFile }, 409);
        }
        const count = await env.DB.prepare(
          "SELECT COUNT(*) AS total FROM application_files WHERE project_id = ?"
        ).bind(projectId).first();
        if (Number(count?.total || 0) >= 50) return json({ error: "Cette application est limitée à 50 fichiers pour le moment." }, 413);
        const mimeType = applicationFileMimeType(fileName);
        const versionId = crypto.randomUUID();
        await env.DB.batch([
          env.DB.prepare(
            "INSERT INTO application_files (id, project_id, file_name, content, mime_type) SELECT ?, ?, ?, '', ? WHERE EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL)"
          ).bind(crypto.randomUUID(), projectId, fileName, mimeType, projectId, user.id),
          env.DB.prepare(
            "INSERT INTO application_file_versions (id, project_id, file_name, version_number, content, mime_type) SELECT ?, ?, ?, 1, '', ? WHERE EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL)"
          ).bind(versionId, projectId, fileName, mimeType, projectId, user.id)
        ]);
        const saved = await env.DB.prepare(
          "SELECT file_name FROM application_files WHERE project_id = ? AND file_name = ? LIMIT 1"
        ).bind(projectId, fileName).first();
        if (!saved) return json({ error: "L'application a changé d'état. Le fichier n'a pas été créé." }, 409);
        const parentParts = fileName.split("/").slice(0, -1);
        for (let index = 0; index < parentParts.length; index++) {
          const directory = parentParts.slice(0, index + 1).join("/");
          await env.DB.prepare(
            "INSERT OR IGNORE INTO application_directories (id, project_id, directory_path) SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL)"
          ).bind(crypto.randomUUID(), projectId, directory, projectId, user.id).run();
        }
        return json({ message: "Fichier créé.", file_name: fileName, version_number: 1 }, 201);
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        console.error("ERREUR CRÉATION FICHIER APPLICATION:", error);
        return json({ error: "Impossible de créer ce fichier." }, 500);
      }
    }

    // APPLICATIONS : LISTER LES FICHIERS DU PROJET
    const applicationFilesMatch = path.match(/^\/api\/projects\/([^/]+)\/application-files$/);
    if (applicationFilesMatch && request.method === "GET") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureApplicationFilesSchema(env);
        const projectId = decodeURIComponent(applicationFilesMatch[1]);
        const project = await env.DB.prepare(
          "SELECT id FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL LIMIT 1"
        ).bind(projectId, user.id).first();
        if (!project) return json({ error: "Application introuvable." }, 404);

        let files = await env.DB.prepare(
          "SELECT file_name, content, mime_type, created_at, updated_at FROM application_files WHERE project_id = ? AND deleted_at IS NULL ORDER BY file_name ASC"
        ).bind(projectId).all();

        const anyStoredFiles = await env.DB.prepare(
          "SELECT COUNT(*) AS total FROM application_files WHERE project_id = ?"
        ).bind(projectId).first();
        if (!Number(anyStoredFiles?.total || 0)) {
          const starterFiles = [
            ["index.html", [
              "<!doctype html>",
              "<html lang=\"fr\">",
              "<head>",
              "  <meta charset=\"utf-8\">",
              "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
              "  <title>Ma première application</title>",
              "  <link rel=\"stylesheet\" href=\"style.css\">",
              "</head>",
              "<body>",
              "  <main>",
              "    <h1>Bienvenue dans 221Cloud !</h1>",
              "    <p>Votre application web commence ici.</p>",
              "    <button id=\"helloButton\">Cliquez ici</button>",
              "    <p id=\"message\"></p>",
              "  </main>",
              "  <script src=\"script.js\"></script>",
              "</body>",
              "</html>"
            ].join("\n"), "text/html; charset=utf-8"],
            ["style.css", [
              "body {",
              "  margin: 0;",
              "  min-height: 100vh;",
              "  display: grid;",
              "  place-items: center;",
              "  font-family: Arial, sans-serif;",
              "  background: #f3f5f9;",
              "  color: #172033;",
              "}",
              "main {",
              "  max-width: 560px;",
              "  padding: 40px;",
              "  text-align: center;",
              "  background: white;",
              "  border-radius: 18px;",
              "  box-shadow: 0 12px 36px rgba(0,0,0,.08);",
              "}",
              "button {",
              "  padding: 12px 18px;",
              "  border: 0;",
              "  border-radius: 8px;",
              "  background: #2457d6;",
              "  color: white;",
              "  cursor: pointer;",
              "}"
            ].join("\n"), "text/css"],
            ["script.js", [
              "document.getElementById(\"helloButton\").addEventListener(\"click\", () => {",
              "  document.getElementById(\"message\").textContent = \"Bravo ! Votre JavaScript fonctionne.\";",
              "});"
            ].join("\n"), "text/javascript"]
          ];
          for (const [fileName, content, mimeType] of starterFiles) {
            await env.DB.prepare(
              "INSERT OR IGNORE INTO application_files (id, project_id, file_name, content, mime_type) SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL)"
            ).bind(crypto.randomUUID(), projectId, fileName, content, mimeType, projectId, user.id).run();
          }
          files = await env.DB.prepare(
            "SELECT file_name, content, mime_type, created_at, updated_at FROM application_files WHERE project_id = ? ORDER BY file_name ASC"
          ).bind(projectId).all();
        }
        for (const file of (files.results || [])) {
          const existingVersion = await env.DB.prepare(
            "SELECT id FROM application_file_versions WHERE project_id = ? AND file_name = ? LIMIT 1"
          ).bind(projectId, file.file_name).first();
          if (!existingVersion) {
            await env.DB.prepare(
              "INSERT OR IGNORE INTO application_file_versions (id, project_id, file_name, version_number, content, mime_type) SELECT ?, ?, ?, 1, ?, ? WHERE EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL)"
            ).bind(crypto.randomUUID(), projectId, file.file_name, file.content || "", file.mime_type, projectId, user.id).run();
          }
        }
        const stillActive = await env.DB.prepare(
          "SELECT id FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL LIMIT 1"
        ).bind(projectId, user.id).first();
        if (!stillActive) return json({ error: "Cette application a été déplacée dans la corbeille." }, 404);
        await ensureApplicationDirectoriesSchema(env);
        const directories = await env.DB.prepare(
          "SELECT directory_path, created_at FROM application_directories WHERE project_id = ? AND deleted_at IS NULL ORDER BY directory_path ASC"
        ).bind(projectId).all();
        return json({ files: files.results || [], directories: directories.results || [] });
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        console.error("ERREUR FICHIERS APPLICATION:", error);
        return json({ error: "Impossible de charger les fichiers de l'application." }, 500);
      }
    }

    // APPLICATIONS : ENREGISTRER UN FICHIER HTML, CSS OU JAVASCRIPT
    const applicationFileMatch = path.match(/^\/api\/projects\/([^/]+)\/application-files\/([^/]+)$/);
    if (applicationFileMatch && request.method === "PUT") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureApplicationFilesSchema(env);
        await ensureApplicationDirectoriesSchema(env);
        const projectId = decodeURIComponent(applicationFileMatch[1]);
        const fileName = decodeURIComponent(applicationFileMatch[2]);
        if (!validApplicationFilePath(fileName)) {
          return json({ error: "Nom de fichier non autorisé." }, 400);
        }
        const project = await env.DB.prepare(
          "SELECT id FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL LIMIT 1"
        ).bind(projectId, user.id).first();
        if (!project) return json({ error: "Application introuvable." }, 404);
        const trashedFile = await env.DB.prepare(
          "SELECT id FROM application_files WHERE project_id = ? AND file_name = ? AND deleted_at IS NOT NULL LIMIT 1"
        ).bind(projectId, fileName).first();
        if (trashedFile) return json({ error: "Ce fichier se trouve dans la corbeille. Restaurez-le avant de le modifier." }, 409);
        const directoryConflict = await env.DB.prepare(
          "SELECT directory_path FROM application_directories WHERE project_id = ? AND directory_path = ? LIMIT 1"
        ).bind(projectId, fileName).first();
        if (directoryConflict) return json({ error: "Un dossier porte déjà ce nom." }, 409);
        const parentFileConflict = await applicationFilePathHasFileConflict(env, projectId, fileName, false);
        if (parentFileConflict) return json({ error: "Un fichier empêche l'enregistrement de ce chemin : " + parentFileConflict }, 409);
        const body = await readLimitedJsonBody(request);
        const content = typeof body.content === "string" ? body.content : null;
        if (content === null) return json({ error: "Contenu de fichier invalide." }, 400);
        const size = new TextEncoder().encode(content).length;
        if (size > 262144) return json({ error: "Chaque fichier est limité à 256 Ko." }, 413);
        const usage = await env.DB.prepare(
          "SELECT COALESCE(SUM(length(CAST(content AS BLOB))), 0) AS total FROM application_files WHERE project_id = ? AND file_name <> ?"
        ).bind(projectId, fileName).first();
        if (Number(usage?.total || 0) + size > 1048576) {
          return json({ error: "L'espace de code de cette application est limité à 1 Mo pour le moment." }, 413);
        }
        const mimeType = applicationFileMimeType(fileName);
        const nextFileVersionId = crypto.randomUUID();
        await env.DB.batch([
          env.DB.prepare(
            "INSERT INTO application_files (id, project_id, file_name, content, mime_type, created_at, updated_at) SELECT ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP WHERE EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL) ON CONFLICT(project_id, file_name) DO UPDATE SET content = excluded.content, mime_type = excluded.mime_type, updated_at = CURRENT_TIMESTAMP"
          ).bind(crypto.randomUUID(), projectId, fileName, content, mimeType, projectId, user.id),
          env.DB.prepare(
            "INSERT INTO application_file_versions (id, project_id, file_name, version_number, content, mime_type) SELECT ?, ?, ?, COALESCE(MAX(version_number), 0) + 1, ?, ? FROM application_file_versions WHERE project_id = ? AND file_name = ? AND EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL)"
          ).bind(nextFileVersionId, projectId, fileName, content, mimeType, projectId, fileName, projectId, user.id),
          env.DB.prepare(
            "DELETE FROM application_file_versions WHERE project_id = ? AND file_name = ? AND version_number NOT IN (SELECT version_number FROM application_file_versions WHERE project_id = ? AND file_name = ? ORDER BY version_number DESC LIMIT 30) AND EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL)"
          ).bind(projectId, fileName, projectId, fileName, projectId, user.id)
        ]);
        const savedVersion = await env.DB.prepare(
          "SELECT version_number FROM application_file_versions WHERE id = ? AND project_id = ? AND file_name = ? LIMIT 1"
        ).bind(nextFileVersionId, projectId, fileName).first();
        const nextVersion = Number(savedVersion?.version_number || 0);
        if (!nextVersion) return json({ error: "Cette application a été déplacée dans la corbeille. Aucune modification n'a été enregistrée." }, 409);
        return json({ message: "Fichier enregistré et version conservée.", file_name: fileName, size, version_number: nextVersion });
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        console.error("ERREUR ENREGISTREMENT FICHIER APPLICATION:", error);
        return json({ error: "Impossible d'enregistrer ce fichier." }, 500);
      }
    }

    // APPLICATIONS : CONSULTER L'HISTORIQUE DES VERSIONS D'UN FICHIER
    const applicationVersionsMatch = path.match(/^\/api\/projects\/([^/]+)\/application-files\/([^/]+)\/versions$/);
    if (applicationVersionsMatch && request.method === "GET") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureApplicationFilesSchema(env);
        const projectId = decodeURIComponent(applicationVersionsMatch[1]);
        const fileName = decodeURIComponent(applicationVersionsMatch[2]);
        if (!validApplicationFilePath(fileName)) {
          return json({ error: "Nom de fichier non autorisé." }, 400);
        }
        const project = await env.DB.prepare(
          "SELECT id FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL LIMIT 1"
        ).bind(projectId, user.id).first();
        if (!project) return json({ error: "Application introuvable." }, 404);
        const versions = await env.DB.prepare(
          "SELECT id, version_number, length(CAST(content AS BLOB)) AS size, created_at FROM application_file_versions WHERE project_id = ? AND file_name = ? AND deleted_at IS NULL ORDER BY version_number DESC LIMIT 30"
        ).bind(projectId, fileName).all();
        return json({ versions: versions.results || [] });
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        console.error("ERREUR HISTORIQUE VERSIONS APPLICATION:", error);
        return json({ error: "Impossible de charger l'historique de ce fichier." }, 500);
      }
    }

    // APPLICATIONS : RESTAURER UNE VERSION PRÉCÉDENTE
    const applicationRestoreVersionMatch = path.match(/^\/api\/projects\/([^/]+)\/application-files\/([^/]+)\/restore$/);
    if (applicationRestoreVersionMatch && request.method === "POST") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureApplicationFilesSchema(env);
        const projectId = decodeURIComponent(applicationRestoreVersionMatch[1]);
        const fileName = decodeURIComponent(applicationRestoreVersionMatch[2]);
        if (!validApplicationFilePath(fileName)) {
          return json({ error: "Nom de fichier non autorisé." }, 400);
        }
        const project = await env.DB.prepare(
          "SELECT id FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL LIMIT 1"
        ).bind(projectId, user.id).first();
        if (!project) return json({ error: "Application introuvable." }, 404);
        const body = await readLimitedJsonBody(request);
        const versionId = String(body.version_id || "");
        if (!versionId) return json({ error: "Version non indiquée." }, 400);
        const version = await env.DB.prepare(
          "SELECT id, content, mime_type, version_number FROM application_file_versions WHERE id = ? AND project_id = ? AND file_name = ? LIMIT 1"
        ).bind(versionId, projectId, fileName).first();
        if (!version) return json({ error: "Cette version est introuvable." }, 404);
        const contentSize = new TextEncoder().encode(version.content || "").length;
        if (contentSize > 262144) return json({ error: "Cette version dépasse la limite autorisée." }, 413);
        const usage = await env.DB.prepare(
          "SELECT COALESCE(SUM(length(CAST(content AS BLOB))), 0) AS total FROM application_files WHERE project_id = ? AND file_name <> ?"
        ).bind(projectId, fileName).first();
        if (Number(usage?.total || 0) + contentSize > 1048576) {
          return json({ error: "La restauration dépasserait la limite de 1 Mo." }, 413);
        }
        const restoredVersionId = crypto.randomUUID();
        await env.DB.batch([
          env.DB.prepare(
            "INSERT INTO application_files (id, project_id, file_name, content, mime_type, created_at, updated_at) SELECT ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP WHERE EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL) ON CONFLICT(project_id, file_name) DO UPDATE SET content = excluded.content, mime_type = excluded.mime_type, updated_at = CURRENT_TIMESTAMP"
          ).bind(crypto.randomUUID(), projectId, fileName, version.content, version.mime_type, projectId, user.id),
          env.DB.prepare(
            "INSERT INTO application_file_versions (id, project_id, file_name, version_number, content, mime_type) SELECT ?, ?, ?, COALESCE(MAX(version_number), 0) + 1, ?, ? FROM application_file_versions WHERE project_id = ? AND file_name = ? AND EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL)"
          ).bind(restoredVersionId, projectId, fileName, version.content, version.mime_type, projectId, fileName, projectId, user.id),
          env.DB.prepare(
            "DELETE FROM application_file_versions WHERE project_id = ? AND file_name = ? AND version_number NOT IN (SELECT version_number FROM application_file_versions WHERE project_id = ? AND file_name = ? ORDER BY version_number DESC LIMIT 30) AND EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL)"
          ).bind(projectId, fileName, projectId, fileName, projectId, user.id)
        ]);
        const restoredVersion = await env.DB.prepare(
          "SELECT version_number FROM application_file_versions WHERE id = ? AND project_id = ? AND file_name = ? LIMIT 1"
        ).bind(restoredVersionId, projectId, fileName).first();
        const nextVersion = Number(restoredVersion?.version_number || 0);
        if (!nextVersion) return json({ error: "Cette application a été déplacée dans la corbeille. La version n'a pas été restaurée." }, 409);
        return json({
          message: "Version restaurée. Une nouvelle version a été conservée dans l'historique.",
          file: { file_name: fileName, content: version.content, mime_type: version.mime_type, version_number: nextVersion }
        });
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        console.error("ERREUR RESTAURATION VERSION APPLICATION:", error);
        return json({ error: "Impossible de restaurer cette version." }, 500);
      }
    }


    // APPLICATIONS : LISTER LA CORBEILLE
    const applicationTrashListMatch = path.match(/^\/api\/projects\/([^/]+)\/application-trash$/);
    if (applicationTrashListMatch && request.method === "GET") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureApplicationFilesSchema(env);
        await ensureApplicationDirectoriesSchema(env);
        const projectId = decodeURIComponent(applicationTrashListMatch[1]);
        const project = await env.DB.prepare("SELECT id FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL LIMIT 1").bind(projectId, user.id).first();
        if (!project) return json({ error: "Application introuvable." }, 404);
        const items = await env.DB.prepare("SELECT id, item_type, original_path, deleted_at FROM application_trash_items WHERE project_id = ? ORDER BY deleted_at DESC").bind(projectId).all();
        const result = [];
        for (const item of (items.results || [])) {
          const [files, directories] = await Promise.all([
            env.DB.prepare("SELECT COUNT(*) AS total FROM application_files WHERE project_id = ? AND trash_id = ?").bind(projectId, item.id).first(),
            env.DB.prepare("SELECT COUNT(*) AS total FROM application_directories WHERE project_id = ? AND trash_id = ?").bind(projectId, item.id).first()
          ]);
          result.push({ ...item, file_count: Number(files?.total || 0), directory_count: Number(directories?.total || 0) });
        }
        return json({ items: result });
      } catch (error) {
        console.error("ERREUR CORBEILLE APPLICATION:", error);
        return json({ error: "Impossible de charger la corbeille de cette application." }, 500);
      }
    }

    // APPLICATIONS : DÉPLACER UN FICHIER OU DOSSIER DANS LA CORBEILLE
    const applicationTrashMoveMatch = path.match(/^\/api\/projects\/([^/]+)\/application-items\/trash$/);
    if (applicationTrashMoveMatch && request.method === "POST") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureApplicationFilesSchema(env);
        await ensureApplicationDirectoriesSchema(env);
        const projectId = decodeURIComponent(applicationTrashMoveMatch[1]);
        const project = await env.DB.prepare("SELECT id FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL LIMIT 1").bind(projectId, user.id).first();
        if (!project) return json({ error: "Application introuvable." }, 404);
        const body = await readLimitedJsonBody(request);
        const itemType = String(body.item_type || "");
        const itemPath = String(body.path || "");
        const validPath = itemType === "folder" ? validApplicationFilePath(itemPath + "/placeholder.txt") : itemType === "file" && validApplicationFilePath(itemPath);
        if (!validPath || !["file", "folder"].includes(itemType)) return json({ error: "Type ou chemin invalide." }, 400);
        const trashId = crypto.randomUUID();
        if (itemType === "file") {
          const file = await env.DB.prepare("SELECT id FROM application_files WHERE project_id = ? AND file_name = ? AND deleted_at IS NULL LIMIT 1").bind(projectId, itemPath).first();
          if (!file) return json({ error: "Fichier introuvable." }, 404);
          await env.DB.batch([
            env.DB.prepare("INSERT INTO application_trash_items (id, project_id, item_type, original_path) SELECT ?, ?, 'file', ? WHERE EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL)").bind(trashId, projectId, itemPath, projectId, user.id),
            env.DB.prepare("UPDATE application_files SET deleted_at = CURRENT_TIMESTAMP, trash_id = ? WHERE project_id = ? AND file_name = ? AND deleted_at IS NULL").bind(trashId, projectId, itemPath),
            env.DB.prepare("UPDATE application_file_versions SET deleted_at = CURRENT_TIMESTAMP, trash_id = ? WHERE project_id = ? AND file_name = ? AND deleted_at IS NULL").bind(trashId, projectId, itemPath)
          ]);
        } else {
          const [directory, childDirectory, childFile] = await Promise.all([
            env.DB.prepare("SELECT id FROM application_directories WHERE project_id = ? AND directory_path = ? AND deleted_at IS NULL LIMIT 1").bind(projectId, itemPath).first(),
            env.DB.prepare("SELECT id FROM application_directories WHERE project_id = ? AND deleted_at IS NULL AND substr(directory_path, 1, ?) = ? LIMIT 1").bind(projectId, itemPath.length + 1, itemPath + "/").first(),
            env.DB.prepare("SELECT id FROM application_files WHERE project_id = ? AND deleted_at IS NULL AND substr(file_name, 1, ?) = ? LIMIT 1").bind(projectId, itemPath.length + 1, itemPath + "/").first()
          ]);
          if (!directory && !childDirectory && !childFile) return json({ error: "Dossier introuvable ou déjà dans la corbeille." }, 404);
          await env.DB.batch([
            env.DB.prepare("INSERT INTO application_trash_items (id, project_id, item_type, original_path) SELECT ?, ?, 'folder', ? WHERE EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL)").bind(trashId, projectId, itemPath, projectId, user.id),
            env.DB.prepare("UPDATE application_directories SET deleted_at = CURRENT_TIMESTAMP, trash_id = ? WHERE project_id = ? AND deleted_at IS NULL AND (directory_path = ? OR substr(directory_path, 1, ?) = ?)").bind(trashId, projectId, itemPath, itemPath.length + 1, itemPath + "/"),
            env.DB.prepare("UPDATE application_files SET deleted_at = CURRENT_TIMESTAMP, trash_id = ? WHERE project_id = ? AND deleted_at IS NULL AND substr(file_name, 1, ?) = ?").bind(trashId, projectId, itemPath.length + 1, itemPath + "/"),
            env.DB.prepare("UPDATE application_file_versions SET deleted_at = CURRENT_TIMESTAMP, trash_id = ? WHERE project_id = ? AND deleted_at IS NULL AND substr(file_name, 1, ?) = ?").bind(trashId, projectId, itemPath.length + 1, itemPath + "/")
          ]);
        }
        return json({ message: "Élément déplacé dans la corbeille.", trash_id: trashId });
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        console.error("ERREUR MISE EN CORBEILLE APPLICATION:", error);
        return json({ error: "Impossible de déplacer cet élément dans la corbeille." }, 500);
      }
    }

    // APPLICATIONS : RESTAURER UN ÉLÉMENT DE LA CORBEILLE
    const applicationTrashRestoreMatch = path.match(/^\/api\/projects\/([^/]+)\/application-trash\/([^/]+)\/restore$/);
    if (applicationTrashRestoreMatch && request.method === "POST") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureApplicationFilesSchema(env);
        await ensureApplicationDirectoriesSchema(env);
        const projectId = decodeURIComponent(applicationTrashRestoreMatch[1]);
        const trashId = decodeURIComponent(applicationTrashRestoreMatch[2]);
        const project = await env.DB.prepare("SELECT id FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL LIMIT 1").bind(projectId, user.id).first();
        if (!project) return json({ error: "Application introuvable." }, 404);
        const item = await env.DB.prepare("SELECT id, item_type, original_path FROM application_trash_items WHERE id = ? AND project_id = ? LIMIT 1").bind(trashId, projectId).first();
        if (!item) return json({ error: "Élément introuvable dans la corbeille." }, 404);
        const [restoredFilesResult, restoredDirectoriesResult, activeFilesResult, activeDirectoriesResult] = await Promise.all([
          env.DB.prepare("SELECT file_name FROM application_files WHERE project_id = ? AND trash_id = ? AND deleted_at IS NOT NULL").bind(projectId, trashId).all(),
          env.DB.prepare("SELECT directory_path FROM application_directories WHERE project_id = ? AND trash_id = ? AND deleted_at IS NOT NULL").bind(projectId, trashId).all(),
          env.DB.prepare("SELECT file_name FROM application_files WHERE project_id = ? AND deleted_at IS NULL").bind(projectId).all(),
          env.DB.prepare("SELECT directory_path FROM application_directories WHERE project_id = ? AND deleted_at IS NULL").bind(projectId).all()
        ]);
        const restoredFiles = (restoredFilesResult.results || []).map(row => row.file_name);
        const restoredDirectories = (restoredDirectoriesResult.results || []).map(row => row.directory_path);
        const activeFiles = (activeFilesResult.results || []).map(row => row.file_name);
        const activeDirectories = (activeDirectoriesResult.results || []).map(row => row.directory_path);
        const isSameOrBelow = (candidate, parent) => candidate === parent || candidate.startsWith(parent + "/");
        let pathConflict = false;

        // Un fichier ne peut pas occuper le chemin d'un autre fichier/dossier,
        // ni servir de parent à un élément qui doit être restauré.
        for (const activePath of activeFiles) {
          if (restoredFiles.some(restoredPath =>
            activePath === restoredPath || isSameOrBelow(restoredPath, activePath) ||
            isSameOrBelow(activePath, restoredPath)
          )) {
            pathConflict = true;
            break;
          }
          if (restoredDirectories.some(restoredPath =>
            activePath === restoredPath || isSameOrBelow(restoredPath, activePath)
          )) {
            pathConflict = true;
            break;
          }
        }

        if (!pathConflict) {
          for (const activePath of activeDirectories) {
            if (restoredFiles.some(restoredPath =>
              activePath === restoredPath || isSameOrBelow(activePath, restoredPath)
            )) {
              pathConflict = true;
              break;
            }
            if (restoredDirectories.includes(activePath)) {
              pathConflict = true;
              break;
            }
          }
        }

        if (pathConflict) {
          return json({
            error: "Un fichier ou dossier utilise déjà un chemin nécessaire à cette restauration. Renommez l’élément concerné avant de réessayer."
          }, 409);
        }
        await env.DB.batch([
          env.DB.prepare("UPDATE application_files SET deleted_at = NULL, trash_id = NULL WHERE project_id = ? AND trash_id = ?").bind(projectId, trashId),
          env.DB.prepare("UPDATE application_file_versions SET deleted_at = NULL, trash_id = NULL WHERE project_id = ? AND trash_id = ?").bind(projectId, trashId),
          env.DB.prepare("UPDATE application_directories SET deleted_at = NULL, trash_id = NULL WHERE project_id = ? AND trash_id = ?").bind(projectId, trashId),
          env.DB.prepare("DELETE FROM application_trash_items WHERE id = ? AND project_id = ?").bind(trashId, projectId)
        ]);
        return json({ message: "Élément restauré avec son contenu et son historique." });
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        console.error("ERREUR RESTAURATION CORBEILLE APPLICATION:", error);
        return json({ error: "Impossible de restaurer cet élément." }, 500);
      }
    }

    // APPLICATIONS : RENOMMER UN FICHIER OU UN DOSSIER
    const applicationRenameMatch = path.match(/^\/api\/projects\/([^/]+)\/application-items\/rename$/);
    if (applicationRenameMatch && request.method === "POST") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureApplicationFilesSchema(env);
        await ensureApplicationDirectoriesSchema(env);
        const projectId = decodeURIComponent(applicationRenameMatch[1]);
        const project = await env.DB.prepare(
          "SELECT id FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL LIMIT 1"
        ).bind(projectId, user.id).first();
        if (!project) return json({ error: "Application introuvable." }, 404);
        const body = await readLimitedJsonBody(request);
        const itemType = String(body.item_type || "");
        const oldPath = String(body.old_path || "");
        const newPath = String(body.new_path || "");
        const validOld = itemType === "folder"
          ? validApplicationFilePath(oldPath + "/placeholder.txt")
          : validApplicationFilePath(oldPath);
        const validNew = itemType === "folder"
          ? validApplicationFilePath(newPath + "/placeholder.txt")
          : validApplicationFilePath(newPath);
        if (!["file", "folder"].includes(itemType) || !validOld || !validNew) {
          return json({ error: "Type ou chemin invalide." }, 400);
        }
        if (oldPath === newPath || (itemType === "folder" && newPath.startsWith(oldPath + "/"))) {
          return json({ error: "Ce nouveau chemin n'est pas autorisé." }, 400);
        }
        const [fileRows, directoryRows] = await Promise.all([
          env.DB.prepare("SELECT file_name, deleted_at FROM application_files WHERE project_id = ?").bind(projectId).all(),
          env.DB.prepare("SELECT directory_path, deleted_at FROM application_directories WHERE project_id = ?").bind(projectId).all()
        ]);
        // Les chemins supprimés restent réservés tant que la corbeille conserve
        // les lignes (contraintes UNIQUE), mais ne doivent jamais être renommés.
        const files = (fileRows.results || []).map(row => row.file_name);
        const dirs = (directoryRows.results || []).map(row => row.directory_path);
        const activeFiles = (fileRows.results || []).filter(row => !row.deleted_at).map(row => row.file_name);
        const activeDirs = (directoryRows.results || []).filter(row => !row.deleted_at).map(row => row.directory_path);
        const sourceExists = itemType === "file"
          ? activeFiles.includes(oldPath)
          : activeDirs.includes(oldPath) || activeDirs.some(name => name.startsWith(oldPath + "/")) || activeFiles.some(name => name.startsWith(oldPath + "/"));
        if (!sourceExists) return json({ error: "Fichier ou dossier introuvable." }, 404);
        const movingFiles = itemType === "file" ? [oldPath] : activeFiles.filter(name => name.startsWith(oldPath + "/"));
        const movingDirs = itemType === "folder" ? activeDirs.filter(name => name === oldPath || name.startsWith(oldPath + "/")) : [];
        const mapPath = value => itemType === "file" ? newPath : newPath + value.slice(oldPath.length);
        const movingFileSet = new Set(movingFiles);
        const movingDirSet = new Set(movingDirs);
        const targetsFiles = movingFiles.map(mapPath);
        const targetsDirs = movingDirs.map(mapPath);
        const collision =
          targetsFiles.some(name => (files.includes(name) && !movingFileSet.has(name)) || (dirs.includes(name) && !movingDirSet.has(name))) ||
          targetsDirs.some(name => (dirs.includes(name) && !movingDirSet.has(name)) || (files.includes(name) && !movingFileSet.has(name)));
        if (collision) return json({ error: "Un fichier ou dossier existe déjà sur le nouveau chemin." }, 409);
        const parent = newPath.includes("/") ? newPath.split("/").slice(0, -1).join("/") : "";
        if (parent && files.includes(parent) && !movingFileSet.has(parent)) {
          return json({ error: "Un fichier bloque le dossier parent du nouveau chemin." }, 409);
        }
        if (itemType === "file") {
          await env.DB.batch([
            env.DB.prepare("UPDATE application_files SET file_name = ?, mime_type = ?, updated_at = CURRENT_TIMESTAMP WHERE project_id = ? AND file_name = ? AND deleted_at IS NULL")
              .bind(newPath, applicationFileMimeType(newPath), projectId, oldPath),
            env.DB.prepare("UPDATE application_file_versions SET file_name = ?, mime_type = ? WHERE project_id = ? AND file_name = ? AND deleted_at IS NULL")
              .bind(newPath, applicationFileMimeType(newPath), projectId, oldPath)
          ]);
        } else {
          await env.DB.batch([
            env.DB.prepare("UPDATE application_directories SET directory_path = ? WHERE project_id = ? AND directory_path = ? AND deleted_at IS NULL")
              .bind(newPath, projectId, oldPath),
            env.DB.prepare("UPDATE application_directories SET directory_path = ? || substr(directory_path, ?) WHERE project_id = ? AND deleted_at IS NULL AND substr(directory_path, 1, ?) = ?")
              .bind(newPath, oldPath.length + 1, projectId, oldPath.length + 1, oldPath + "/"),
            env.DB.prepare("UPDATE application_files SET file_name = ? || substr(file_name, ?), updated_at = CURRENT_TIMESTAMP WHERE project_id = ? AND deleted_at IS NULL AND substr(file_name, 1, ?) = ?")
              .bind(newPath, oldPath.length + 1, projectId, oldPath.length + 1, oldPath + "/"),
            env.DB.prepare("UPDATE application_file_versions SET file_name = ? || substr(file_name, ?) WHERE project_id = ? AND deleted_at IS NULL AND substr(file_name, 1, ?) = ?")
              .bind(newPath, oldPath.length + 1, projectId, oldPath.length + 1, oldPath + "/")
          ]);
        }
        if (parent) {
          const parts = parent.split("/");
          for (let i = 0; i < parts.length; i++) {
            const parentPath = parts.slice(0, i + 1).join("/");
            await env.DB.prepare(
              "INSERT OR IGNORE INTO application_directories (id, project_id, directory_path) SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL)"
            ).bind(crypto.randomUUID(), projectId, parentPath, projectId, user.id).run();
          }
        }
        return json({ message: "Élément renommé.", old_path: oldPath, new_path: newPath });
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        console.error("ERREUR RENOMMAGE ÉLÉMENT APPLICATION:", error);
        return json({ error: "Impossible de renommer cet élément." }, 500);
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
          const body = await readLimitedJsonBody(request);

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

          const updateResult = await env.DB.prepare(
            `UPDATE projects
             SET name = ?, type = ?
             WHERE id = ? AND user_id = ? AND deleted_at IS NULL`
          ).bind(name, type, projectId, user.id).run();

          if (!Number(updateResult?.meta?.changes || 0)) {
            return json({ error: "Ce projet n'est plus disponible ou a été déplacé dans la corbeille." }, 404);
          }

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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
             CASE
               WHEN projects.deleted_at IS NOT NULL THEN projects.name || ' (dans la corbeille)'
               ELSE projects.name
             END AS project_name,
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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

        const body = await readLimitedJsonBody(request);
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
          "SELECT id FROM customer_databases WHERE user_id = ? AND name = ? COLLATE NOCASE"
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        console.error("ERREUR CREATION BASE:", error);
        return json({
          error: "Impossible de créer la base de données."
        }, 500);
      }
    }

    // SUPPRESSION SÉCURISÉE D'UNE TABLE CLIENT
    const databaseTableDeleteMatch = path.match(/^\/api\/databases\/([^/]+)\/tables\/([^/]+)$/);
    if (databaseTableDeleteMatch) {
      if (request.method !== "DELETE") return json({ error: "Méthode non autorisée." }, 405);
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureCustomerDatabaseStructureSchema(env);
        const databaseId = decodeURIComponent(databaseTableDeleteMatch[1]);
        const tableId = decodeURIComponent(databaseTableDeleteMatch[2]);
        const database = await env.DB.prepare(
          `SELECT cd.id
           FROM customer_databases cd
           LEFT JOIN projects p
             ON p.id = cd.project_id
             AND p.user_id = cd.user_id
           WHERE cd.id = ?
             AND cd.user_id = ?
             AND (
               cd.project_id IS NULL
               OR (p.id IS NOT NULL AND p.deleted_at IS NULL)
             )
           LIMIT 1`
        ).bind(databaseId, user.id).first();
        if (!database) return json({ error: "Base de données introuvable." }, 404);
        const table = await env.DB.prepare(
          "SELECT id, name, physical_name FROM customer_database_tables WHERE id = ? AND database_id = ? AND user_id = ? LIMIT 1"
        ).bind(tableId, databaseId, user.id).first();
        if (!table || !safeInternalSqlIdentifier(table.physical_name)) {
          return json({ error: "Table introuvable." }, 404);
        }
        const body = await readLimitedJsonBody(request);
        if (String(body.confirm_name || "").trim() !== table.name) {
          return json({ error: "Confirmation invalide. Le nom exact de la table est requis." }, 400);
        }
        await env.DB.batch([
          env.DB.prepare(`DROP TABLE IF EXISTS "${table.physical_name}"`),
          env.DB.prepare(
            "DELETE FROM customer_database_columns WHERE table_id = ? AND database_id = ? AND user_id = ?"
          ).bind(tableId, databaseId, user.id),
          env.DB.prepare(
            "DELETE FROM customer_database_tables WHERE id = ? AND database_id = ? AND user_id = ?"
          ).bind(tableId, databaseId, user.id)
        ]);
        return json({ message: "Table et ses données supprimées définitivement." });
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        console.error("ERREUR SUPPRESSION TABLE CLIENT:", error);
        return json({ error: "Impossible de supprimer cette table." }, 500);
      }
    }

    // DONNÉES DES TABLES CLIENT : LECTURE, AJOUT, MODIFICATION ET SUPPRESSION
    const databaseRowsMatch = path.match(/^\/api\/databases\/([^/]+)\/tables\/([^/]+)\/rows(?:\/([^/]+))?$/);
    if (databaseRowsMatch) {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureCustomerDatabaseStructureSchema(env);
        const databaseId = decodeURIComponent(databaseRowsMatch[1]);
        const tableId = decodeURIComponent(databaseRowsMatch[2]);
        const rowId = databaseRowsMatch[3] ? decodeURIComponent(databaseRowsMatch[3]) : null;
        const database = await env.DB.prepare(
          `SELECT cd.id
           FROM customer_databases cd
           LEFT JOIN projects p
             ON p.id = cd.project_id
             AND p.user_id = cd.user_id
           WHERE cd.id = ?
             AND cd.user_id = ?
             AND (
               cd.project_id IS NULL
               OR (p.id IS NOT NULL AND p.deleted_at IS NULL)
             )
           LIMIT 1`
        ).bind(databaseId, user.id).first();
        if (!database) return json({ error: "Base de données introuvable." }, 404);
        const table = await env.DB.prepare(
          "SELECT id, physical_name FROM customer_database_tables WHERE id = ? AND database_id = ? AND user_id = ? LIMIT 1"
        ).bind(tableId, databaseId, user.id).first();
        if (!table || !safeInternalSqlIdentifier(table.physical_name)) {
          return json({ error: "Table introuvable." }, 404);
        }
        const columnResult = await env.DB.prepare(
          "SELECT name, data_type, physical_name, position FROM customer_database_columns WHERE table_id = ? AND database_id = ? AND user_id = ? ORDER BY position ASC"
        ).bind(tableId, databaseId, user.id).all();
        const columns = columnResult.results || [];
        if (columns.some(column => !safeInternalSqlIdentifier(column.physical_name))) {
          return json({ error: "Structure de colonne invalide." }, 500);
        }
        const quoteIdentifier = value => '"' + String(value).replace(/"/g, '""') + '"';
        const validateValues = values => {
          if (!values || typeof values !== "object" || Array.isArray(values)) {
            return { error: "Les valeurs de la ligne sont invalides." };
          }
          const allowed = new Map(columns.map(column => [column.name, column]));
          const entries = Object.entries(values);
          if (!entries.length) return { error: "Renseignez au moins une valeur." };
          if (entries.length > columns.length || entries.some(([name]) => !allowed.has(name))) {
            return { error: "Une ou plusieurs colonnes sont inconnues." };
          }
          const normalized = [];
          for (const [name, raw] of entries) {
            const column = allowed.get(name);
            if (raw === null || raw === "") {
              normalized.push([column, null]);
              continue;
            }
            if (column.data_type === "text") {
              if (typeof raw !== "string" || raw.length > 5000) return { error: "Le champ « " + name + " » doit être un texte de 5 000 caractères maximum." };
              normalized.push([column, raw]);
            } else if (column.data_type === "number") {
              if (
                typeof raw !== "number" &&
                (typeof raw !== "string" || raw.trim() === "")
              ) {
                return { error: "Le champ « " + name + " » doit contenir un nombre valide." };
              }
              const number = typeof raw === "number" ? raw : Number(raw.trim());
              if (!Number.isFinite(number)) return { error: "Le champ « " + name + " » doit contenir un nombre valide." };
              normalized.push([column, number]);
            } else if (column.data_type === "boolean") {
              if (![true, false, 1, 0, "1", "0"].includes(raw)) return { error: "Le champ « " + name + " » doit être oui ou non." };
              normalized.push([column, raw === true || raw === 1 || raw === "1" ? 1 : 0]);
            } else if (column.data_type === "date") {
              const date = String(raw);
              const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date);
              let validDate = false;
              if (match) {
                const year = Number(match[1]);
                const month = Number(match[2]);
                const day = Number(match[3]);
                const parsed = new Date(Date.UTC(year, month - 1, day));
                validDate =
                  month >= 1 && month <= 12 &&
                  day >= 1 &&
                  parsed.getUTCFullYear() === year &&
                  parsed.getUTCMonth() === month - 1 &&
                  parsed.getUTCDate() === day;
              }
              if (!validDate) {
                return { error: "Le champ « " + name + " » doit être une date réelle au format AAAA-MM-JJ." };
              }
              normalized.push([column, date]);
            } else {
              return { error: "Type de colonne non pris en charge." };
            }
          }
          return { entries: normalized };
        };

        if (!rowId && request.method === "GET") {
          const url = new URL(request.url);
          const limit = Math.min(50, Math.max(1, Number.parseInt(url.searchParams.get("limit") || "20", 10) || 20));
          const offset = Math.max(0, Number.parseInt(url.searchParams.get("offset") || "0", 10) || 0);
          const search = String(url.searchParams.get("q") || "").trim().slice(0, 100);
          const requestedSort = String(url.searchParams.get("sort") || "created_at");
          const sortColumn = requestedSort === "created_at"
            ? null
            : columns.find(column => column.name === requestedSort) || null;
          const sortDirection = String(url.searchParams.get("direction") || "desc").toLowerCase() === "asc" ? "ASC" : "DESC";
          const orderExpression = sortColumn
            ? quoteIdentifier(sortColumn.physical_name)
            : quoteIdentifier("created_at");
          const whereParts = [];
          const bindings = [];
          if (search && columns.length) {
            whereParts.push("(" + columns.map(column => "CAST(" + quoteIdentifier(column.physical_name) + " AS TEXT) LIKE ?").join(" OR ") + ")");
            for (let i = 0; i < columns.length; i++) bindings.push("%" + search + "%");
          }
          const whereSql = whereParts.length ? " WHERE " + whereParts.join(" AND ") : "";
          const count = await env.DB.prepare(
            "SELECT COUNT(*) AS total FROM " + quoteIdentifier(table.physical_name) + whereSql
          ).bind(...bindings).first();
          const selectColumns = columns.map(column =>
            quoteIdentifier(column.physical_name) + " AS " + quoteIdentifier(column.name)
          );
          const selectSql = ["row_id", "created_at", ...selectColumns].map(quoteIdentifier).join(", ");
          const result = await env.DB.prepare(
            "SELECT " + selectSql + " FROM " + quoteIdentifier(table.physical_name) + whereSql +
            " ORDER BY " + orderExpression + " " + sortDirection + ", created_at DESC, row_id DESC LIMIT ? OFFSET ?"
          ).bind(...bindings, limit, offset).all();
          return json({
            rows: result.results || [],
            total: Number(count?.total || 0),
            limit,
            offset,
            columns: columns.map(column => ({ name: column.name, data_type: column.data_type }))
          });
        }

        if (rowId === "import" && request.method === "POST") {
          const body = await readLimitedJsonBody(request);
          const rows = body.rows;
          if (!Array.isArray(rows) || rows.length < 1 || rows.length > 500) {
            return json({ error: "Le fichier doit contenir entre 1 et 500 lignes de données par import." }, 400);
          }
          if (!columns.length) {
            return json({ error: "Ajoutez au moins une colonne à cette table avant l'import." }, 400);
          }
          const preparedRows = [];
          const rowErrors = [];
          for (let index = 0; index < rows.length; index++) {
            const source = rows[index];
            if (!source || typeof source !== "object" || Array.isArray(source)) {
              rowErrors.push({ row: index + 1, error: "Ligne invalide." });
              continue;
            }
            const sourceColumns = Object.keys(source);
            const hasUnknownColumns = sourceColumns.some(name =>
              !columns.some(column => column.name === name)
            );
            const hasMissingColumns = columns.some(column =>
              !Object.prototype.hasOwnProperty.call(source, column.name)
            );
            if (hasUnknownColumns || hasMissingColumns) {
              rowErrors.push({
                row: index + 1,
                error: "Les colonnes du fichier CSV doivent correspondre exactement à celles de la table."
              });
              continue;
            }
            const values = {};
            for (const column of columns) {
              values[column.name] = Object.prototype.hasOwnProperty.call(source, column.name)
                ? source[column.name]
                : null;
            }
            const checked = validateValues(values);
            if (checked.error) {
              rowErrors.push({ row: index + 1, error: checked.error });
              continue;
            }
            preparedRows.push(checked.entries);
          }
          if (rowErrors.length) {
            return json({
              error: "Aucune ligne n'a été importée : certaines valeurs doivent être corrigées.",
              imported: 0,
              invalid_rows: rowErrors.slice(0, 20),
              invalid_count: rowErrors.length
            }, 400);
          }
          const insertStatements = preparedRows.map(entries => {
            const newRowId = crypto.randomUUID();
            const names = entries.map(([column]) => quoteIdentifier(column.physical_name));
            const placeholders = entries.map(() => "?");
            return env.DB.prepare(
              "INSERT INTO " + quoteIdentifier(table.physical_name) +
              " (row_id, " + names.join(", ") + ") VALUES (?, " + placeholders.join(", ") + ")"
            ).bind(newRowId, ...entries.map(([, value]) => value));
          });
          for (let start = 0; start < insertStatements.length; start += 50) {
            await env.DB.batch(insertStatements.slice(start, start + 50));
          }
          return json({
            message: "Import CSV terminé.",
            imported: preparedRows.length,
            invalid_count: 0
          }, 201);
        }

        if (!rowId && request.method === "POST") {
          const body = await readLimitedJsonBody(request);
          const checked = validateValues(body.values);
          if (checked.error) return json({ error: checked.error }, 400);
          const newRowId = crypto.randomUUID();
          const names = checked.entries.map(([column]) => quoteIdentifier(column.physical_name));
          const placeholders = checked.entries.map(() => "?");
          await env.DB.prepare(
            "INSERT INTO " + quoteIdentifier(table.physical_name) +
            " (row_id, " + names.join(", ") + ") VALUES (?, " + placeholders.join(", ") + ")"
          ).bind(newRowId, ...checked.entries.map(([, value]) => value)).run();
          return json({ message: "Ligne ajoutée avec succès.", row_id: newRowId }, 201);
        }

        if (rowId && request.method === "PATCH") {
          const body = await readLimitedJsonBody(request);
          const checked = validateValues(body.values);
          if (checked.error) return json({ error: checked.error }, 400);
          const assignments = checked.entries.map(([column]) => quoteIdentifier(column.physical_name) + " = ?");
          const result = await env.DB.prepare(
            "UPDATE " + quoteIdentifier(table.physical_name) + " SET " + assignments.join(", ") +
            " WHERE row_id = ?"
          ).bind(...checked.entries.map(([, value]) => value), rowId).run();
          if (!Number(result.meta?.changes || 0)) return json({ error: "Ligne introuvable." }, 404);
          return json({ message: "Ligne modifiée avec succès." });
        }

        if (rowId && request.method === "DELETE") {
          const result = await env.DB.prepare(
            "DELETE FROM " + quoteIdentifier(table.physical_name) + " WHERE row_id = ?"
          ).bind(rowId).run();
          if (!Number(result.meta?.changes || 0)) return json({ error: "Ligne introuvable." }, 404);
          return json({ message: "Ligne supprimée définitivement." });
        }
        return json({ error: "Méthode non autorisée." }, 405);
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        console.error("ERREUR DONNÉES TABLE CLIENT:", error);
        return json({ error: "Impossible de traiter les données de cette table." }, 500);
      }
    }

    // STRUCTURE DES BASES CLIENT : TABLES ET COLONNES
    const databaseTablesMatch = path.match(/^\/api\/databases\/([^/]+)\/tables$/);
    const databaseColumnsMatch = path.match(/^\/api\/databases\/([^/]+)\/tables\/([^/]+)\/columns$/);

    if (databaseTablesMatch || databaseColumnsMatch) {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureCustomerDatabaseStructureSchema(env);

        const databaseId = decodeURIComponent(
          (databaseTablesMatch || databaseColumnsMatch)[1]
        );
        const database = await env.DB.prepare(
          `SELECT cd.id
           FROM customer_databases cd
           LEFT JOIN projects p
             ON p.id = cd.project_id
             AND p.user_id = cd.user_id
           WHERE cd.id = ?
             AND cd.user_id = ?
             AND (
               cd.project_id IS NULL
               OR (p.id IS NOT NULL AND p.deleted_at IS NULL)
             )
           LIMIT 1`
        ).bind(databaseId, user.id).first();
        if (!database) return json({ error: "Base de données introuvable." }, 404);

        if (databaseTablesMatch) {
          if (request.method === "GET") {
            const result = await env.DB.prepare(
              `SELECT id, name, created_at
               FROM customer_database_tables
               WHERE database_id = ? AND user_id = ?
               ORDER BY created_at ASC, name COLLATE NOCASE ASC`
            ).bind(databaseId, user.id).all();
            return json({ tables: result.results || [] });
          }

          if (request.method !== "POST") {
            return json({ error: "Méthode non autorisée." }, 405);
          }

          const body = await readLimitedJsonBody(request);
          const name = String(body.name || "").trim();
          if (!validDatabaseName(name)) {
            return json({ error: "Le nom de la table doit contenir entre 1 et 80 caractères." }, 400);
          }

          const duplicate = await env.DB.prepare(
            "SELECT id FROM customer_database_tables WHERE database_id = ? AND user_id = ? AND name = ? COLLATE NOCASE LIMIT 1"
          ).bind(databaseId, user.id, name).first();
          if (duplicate) return json({ error: "Une table porte déjà ce nom dans cette base." }, 409);

          const id = crypto.randomUUID();
          const physicalName = "cdb_" + databaseId.replace(/-/g, "") + "_" + id.replace(/-/g, "");
          if (!safeInternalSqlIdentifier(physicalName)) {
            return json({ error: "Impossible de préparer la table." }, 500);
          }

          await env.DB.batch([
            env.DB.prepare(
              `CREATE TABLE "${physicalName}" (
                row_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
              )`
            ),
            env.DB.prepare(
              `INSERT INTO customer_database_tables
               (id, database_id, user_id, name, physical_name)
               VALUES (?, ?, ?, ?, ?)`
            ).bind(id, databaseId, user.id, name, physicalName)
          ]);

          return json({
            message: "Table créée avec succès.",
            table: { id, name, created_at: new Date().toISOString() }
          }, 201);
        }

        if (request.method !== "GET" && request.method !== "POST") {
          return json({ error: "Méthode non autorisée." }, 405);
        }

        const tableId = decodeURIComponent(databaseColumnsMatch[2]);
        const table = await env.DB.prepare(
          `SELECT id, physical_name FROM customer_database_tables
           WHERE id = ? AND database_id = ? AND user_id = ? LIMIT 1`
        ).bind(tableId, databaseId, user.id).first();
        if (!table || !safeInternalSqlIdentifier(table.physical_name)) {
          return json({ error: "Table introuvable." }, 404);
        }

        if (request.method === "GET") {
          const result = await env.DB.prepare(
            `SELECT id, name, data_type, position, created_at
             FROM customer_database_columns
             WHERE table_id = ? AND database_id = ? AND user_id = ?
             ORDER BY position ASC, created_at ASC`
          ).bind(tableId, databaseId, user.id).all();
          return json({ columns: result.results || [] });
        }

        const body = await readLimitedJsonBody(request);
        const name = String(body.name || "").trim();
        const dataType = String(body.data_type || "text").trim().toLowerCase();
        const sqlType = customerColumnSqlType(dataType);
        if (!validDatabaseName(name)) {
          return json({ error: "Le nom de la colonne doit contenir entre 1 et 80 caractères." }, 400);
        }
        if (!sqlType) {
          return json({ error: "Type invalide. Choisissez texte, nombre, booléen ou date." }, 400);
        }

        const columnCount = await env.DB.prepare(
          "SELECT COUNT(*) AS total FROM customer_database_columns WHERE table_id = ? AND user_id = ?"
        ).bind(tableId, user.id).first();
        if (Number(columnCount?.total || 0) >= 50) {
          return json({ error: "Une table peut contenir au maximum 50 colonnes personnalisées." }, 400);
        }

        const duplicate = await env.DB.prepare(
          "SELECT id FROM customer_database_columns WHERE table_id = ? AND user_id = ? AND name = ? COLLATE NOCASE LIMIT 1"
        ).bind(tableId, user.id, name).first();
        if (duplicate) return json({ error: "Une colonne porte déjà ce nom dans cette table." }, 409);

        const columnId = crypto.randomUUID();
        const physicalColumn = "col_" + columnId.replace(/-/g, "");
        const position = Number(columnCount?.total || 0);

        await env.DB.batch([
          env.DB.prepare(
            `ALTER TABLE "${table.physical_name}" ADD COLUMN "${physicalColumn}" ${sqlType}`
          ),
          env.DB.prepare(
            `INSERT INTO customer_database_columns
             (id, table_id, database_id, user_id, name, data_type, physical_name, position)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
          ).bind(
            columnId, tableId, databaseId, user.id, name, dataType, physicalColumn, position
          )
        ]);

        return json({
          message: "Colonne ajoutée avec succès.",
          column: {
            id: columnId, name, data_type: dataType, position,
            created_at: new Date().toISOString()
          }
        }, 201);
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        if (String(error?.message || "").includes("UNIQUE constraint failed")) {
          return json({ error: "Un élément portant déjà ce nom existe dans cette base ou cette table." }, 409);
        }
        console.error("ERREUR STRUCTURE BASE CLIENT:", error);
        return json({ error: "Impossible de traiter la structure de cette base de données." }, 500);
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
          `SELECT cd.id, cd.name
           FROM customer_databases cd
           LEFT JOIN projects p
             ON p.id = cd.project_id
             AND p.user_id = cd.user_id
           WHERE cd.id = ?
             AND cd.user_id = ?
             AND (
               cd.project_id IS NULL
               OR (p.id IS NOT NULL AND p.deleted_at IS NULL)
             )`
        ).bind(databaseId, user.id).first();

        if (!existing) {
          return json({
            error: "Base de données introuvable."
          }, 404);
        }

        const body = await readLimitedJsonBody(request);
        if (typeof body.confirm_name !== "string" || body.confirm_name.trim() !== existing.name) {
          return json({
            error: "Confirmation invalide. Le nom exact de la base est requis."
          }, 400);
        }

        await ensureCustomerDatabaseStructureSchema(env);
        const tableCount = await env.DB.prepare(
          "SELECT COUNT(*) AS total FROM customer_database_tables WHERE database_id = ? AND user_id = ?"
        ).bind(databaseId, user.id).first();
        if (Number(tableCount?.total || 0) > 0) {
          return json({
            error: "Cette base contient des tables. Supprimez d'abord ses tables depuis son espace de gestion."
          }, 409);
        }

        await env.DB.prepare(
          "DELETE FROM customer_databases WHERE id = ? AND user_id = ?"
        ).bind(databaseId, user.id).run();

        return json({
          message: "Base de données supprimée avec succès."
        });

      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        const body = await readLimitedJsonBody(request);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
          const body = await readLimitedJsonBody(request);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        const body = await readLimitedJsonBody(request);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
          SELECT
            plan,
            status,
            expires_at,
            CASE
              WHEN LOWER(status) = 'active'
                AND (expires_at IS NULL OR datetime(expires_at) > CURRENT_TIMESTAMP)
              THEN LOWER(plan)
              ELSE 'free'
            END AS effective_plan
          FROM subscriptions
          WHERE user_id = ?
          ORDER BY datetime(created_at) DESC, id DESC
          LIMIT 1
        `).bind(user.id).first();

        const plan = String(subscription?.effective_plan || "free").toLowerCase();

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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        const form = await readLimitedMultipartForm(request);
        if (!form) {
          return json({
            error: "La requête d'envoi dépasse la limite autorisée de 22 Mo."
          }, 413);
        }
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
          SELECT
            plan,
            status,
            expires_at,
            CASE
              WHEN LOWER(status) = 'active'
                AND (expires_at IS NULL OR datetime(expires_at) > CURRENT_TIMESTAMP)
              THEN LOWER(plan)
              ELSE 'free'
            END AS effective_plan
          FROM subscriptions
          WHERE user_id = ?
          ORDER BY datetime(created_at) DESC, id DESC
          LIMIT 1
        `).bind(user.id).first();

        const plan = String(subscription?.effective_plan || "free").toLowerCase();

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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
          `SELECT id, file_name, file_size, mime_type, storage_key, b2_file_id, content_sha1
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

        const downloadedBytes = new Uint8Array(await downloadResponse.arrayBuffer());
        if (downloadedBytes.length !== Number(file.file_size || 0)) {
          console.error("INTEGRITÉ SAUVEGARDE STOCKAGE : taille incohérente", {
            fileId: file.id,
            expected: Number(file.file_size || 0),
            actual: downloadedBytes.length
          });
          return json({ error: "Le fichier récupéré pour la sauvegarde est incomplet ou altéré." }, 502);
        }
        if (file.content_sha1) {
          const actualDigest = await crypto.subtle.digest("SHA-1", downloadedBytes);
          const actualSha1 = toHex(actualDigest);
          if (actualSha1 !== String(file.content_sha1).toLowerCase()) {
            console.error("INTEGRITÉ SAUVEGARDE STOCKAGE : empreinte SHA-1 incorrecte", { fileId: file.id });
            return json({ error: "L'intégrité du fichier n'a pas pu être vérifiée pour la sauvegarde." }, 502);
          }
        }

        const headers = new Headers();
        headers.set("Content-Type", file.mime_type || "application/octet-stream");
        headers.set("Content-Disposition", "attachment; filename*=UTF-8''" + encodeURIComponent(safeFileName(file.file_name)));
        headers.set("Cache-Control", "private, no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        return new Response(downloadedBytes, { status: 200, headers });
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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

        const downloadedBytes = new Uint8Array(await downloadResponse.arrayBuffer());
        if (downloadedBytes.length !== Number(file.file_size || 0)) {
          console.error("INTEGRITÉ SAUVEGARDE SITE : taille incohérente", {
            fileId: file.id,
            expected: Number(file.file_size || 0),
            actual: downloadedBytes.length
          });
          return json({ error: "Le fichier du site récupéré pour la sauvegarde est incomplet ou altéré." }, 502);
        }

        const headers = new Headers();
        headers.set("Content-Type", file.mime_type || "application/octet-stream");
        headers.set("Content-Disposition", "attachment; filename*=UTF-8''" + encodeURIComponent(safeFileName(file.file_path.split("/").pop())));
        headers.set("Cache-Control", "private, no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-File-Size", String(file.file_size || 0));
        return new Response(downloadedBytes, { status: 200, headers });
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
const safePreviewMimeTypes = new Set([
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/webp",
  "image/avif"
]);
const normalizedMimeType = String(file.mime_type || "").toLowerCase().split(";")[0].trim();
const isSafePreviewImage = safePreviewMimeTypes.has(normalizedMimeType);
const disposition = previewRequested && isSafePreviewImage ? "inline" : "attachment";

headers.set(
  "Content-Disposition",
  `${disposition}; filename*=UTF-8''${encodeURIComponent(safeFileName(file.file_name))}`
);

        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("Cache-Control", "private, no-store");

        return new Response(downloadedBytes, {
          status: 200,
          headers
        });

      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        const body = await readLimitedJsonBody(request);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        console.error("ERREUR INFORMATIONS SESSION:", error);
        return json({ error: "Impossible de charger les informations de session." }, 500);
      }
    }

    // SÉCURITÉ DU COMPTE : CHANGEMENT DE MOT DE PASSE
    if (path === "/api/account/password" && request.method === "POST") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);

        const body = await readLimitedJsonBody(request);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
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
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        console.error("ERREUR DECONNEXION 221CLOUD:", error);
        return json({
          error: "Impossible de se déconnecter."
        }, 500);
      }
    }


    return env.ASSETS.fetch(request);
  }
};
