
const ITERATIONS = 100000;
const SESSION_DAYS = 7;
const SESSION_IDLE_MINUTES = 60;
const DATABASE_NAME_MAX = 80;

const STORAGE_LIMIT_BYTES = 1024 * 1024 * 1024;
const MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024;

const PLAN_LIMITS = Object.freeze({
  free: Object.freeze({ storage_bytes: 1024 * 1024 * 1024, projects: 1 }),
  starter: Object.freeze({ storage_bytes: 5 * 1024 * 1024 * 1024, projects: 5 }),
  pro: Object.freeze({ storage_bytes: 20 * 1024 * 1024 * 1024, projects: 20 })
});

function getPlanLimits(plan) {
  return PLAN_LIMITS[String(plan || "free").toLowerCase()] || PLAN_LIMITS.free;
}

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

const currentUserCache = new WeakMap();

async function currentUser(request, env) {
  if (currentUserCache.has(request)) return currentUserCache.get(request);

  const lookup = (async () => {
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
  })();

  currentUserCache.set(request, lookup);
  return lookup;
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

  // Répare une éventuelle ancienne collision de positions avant d'imposer
  // leur unicité. Le batch rend la migration atomique dans D1.
  const positionIndex = await env.DB.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'index' AND name = ? LIMIT 1"
  ).bind("idx_customer_database_columns_unique_position").first();
  if (!positionIndex) {
    await env.DB.batch([
      env.DB.prepare(`
        WITH ranked AS (
          SELECT id,
                 ROW_NUMBER() OVER (
                   PARTITION BY table_id, user_id
                   ORDER BY position ASC, created_at ASC, id ASC
                 ) - 1 AS next_position
          FROM customer_database_columns
        )
        UPDATE customer_database_columns
        SET position = (
          SELECT next_position FROM ranked
          WHERE ranked.id = customer_database_columns.id
        )
        WHERE id IN (
          SELECT id FROM ranked
          WHERE ranked.next_position != customer_database_columns.position
        )
      `),
      env.DB.prepare(`
        CREATE UNIQUE INDEX IF NOT EXISTS idx_customer_database_columns_unique_position
        ON customer_database_columns(table_id, user_id, position)
      `)
    ]);
  }

  // La limite est imposée dans SQLite pour résister aux ajouts simultanés.
  await env.DB.prepare(`
    CREATE TRIGGER IF NOT EXISTS trg_customer_database_columns_limit
    BEFORE INSERT ON customer_database_columns
    WHEN (
      SELECT COUNT(*)
      FROM customer_database_columns
      WHERE table_id = NEW.table_id AND user_id = NEW.user_id
    ) >= 50
    BEGIN
      SELECT RAISE(ABORT, 'CUSTOMER_DATABASE_COLUMN_LIMIT');
    END
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

async function ensureStorageQuotaReservationsSchema(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS storage_quota_reservations (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      reserved_bytes INTEGER NOT NULL CHECK (reserved_bytes > 0),
      expires_at INTEGER NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS idx_storage_quota_reservations_owner_expiry ON storage_quota_reservations(user_id, expires_at)"
  ).run();
}

async function reserveStorageQuota(env, userId, bytes, maxStorage) {
  const amount = Number(bytes);
  const limit = Number(maxStorage);
  if (!Number.isSafeInteger(amount) || amount <= 0 || !Number.isSafeInteger(limit) || limit <= 0) {
    return null;
  }

  await ensureStorageQuotaReservationsSchema(env);
  await env.DB.prepare(
    "DELETE FROM storage_quota_reservations WHERE expires_at <= unixepoch()"
  ).run();

  const reservationId = crypto.randomUUID();
  const result = await env.DB.prepare(`
    INSERT INTO storage_quota_reservations (id, user_id, reserved_bytes, expires_at)
    SELECT ?, ?, ?, unixepoch() + 1800
    WHERE
      COALESCE((SELECT SUM(file_size) FROM cloud_files WHERE user_id = ?), 0) +
      COALESCE((
        SELECT SUM(wf.file_size)
        FROM website_files wf
        JOIN website_hostings wh ON wh.id = wf.hosting_id
        WHERE wh.user_id = ?
      ), 0) +
      COALESCE((
        SELECT SUM(reserved_bytes)
        FROM storage_quota_reservations
        WHERE user_id = ? AND expires_at > unixepoch()
      ), 0) + ? <= ?
  `).bind(
    reservationId,
    userId,
    amount,
    userId,
    userId,
    userId,
    amount,
    limit
  ).run();

  return result?.meta?.changes ? reservationId : null;
}

async function releaseStorageQuotaReservation(env, reservationId) {
  if (!reservationId) return;
  await env.DB.prepare(
    "DELETE FROM storage_quota_reservations WHERE id = ?"
  ).bind(reservationId).run();
}

async function ensureStorageFoldersSchema(env) {
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS storage_folders (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, parent_id TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)").run();
  const ensureStorageColumn = async columnName => {
    const columns = await env.DB.prepare("PRAGMA table_info(cloud_files)").all();
    if ((columns.results || []).some(column => column.name === columnName)) return;
    try {
      await env.DB.prepare("ALTER TABLE cloud_files ADD COLUMN " + columnName + " TEXT").run();
    } catch (error) {
      // Une autre instance du Worker peut avoir ajouté la colonne entre-temps.
      const refreshed = await env.DB.prepare("PRAGMA table_info(cloud_files)").all();
      const alreadyAdded = (refreshed.results || []).some(column => column.name === columnName);
      if (!alreadyAdded) throw error;
    }
  };
  await ensureStorageColumn("folder_id");
  await ensureStorageColumn("content_sha1");
  await ensureStorageColumn("deleted_at");
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

let apiRateLimitSchemaPromise = null;
let apiRateLimitLastCleanupHour = 0;

async function ensureApiRateLimitSchema(env) {
  if (!apiRateLimitSchemaPromise) {
    apiRateLimitSchemaPromise = env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS api_rate_limits (
        scope_key TEXT PRIMARY KEY,
        window_started_at INTEGER NOT NULL,
        request_count INTEGER NOT NULL DEFAULT 0
      )
    `).run().catch(error => {
      apiRateLimitSchemaPromise = null;
      throw error;
    });
  }
  await apiRateLimitSchemaPromise;
}

async function incrementApiRateLimit(env, scopeKey, limit) {
  await ensureApiRateLimitSchema(env);
  const now = Math.floor(Date.now() / 1000);
  const windowSeconds = 60;
  const row = await env.DB.prepare(`
    INSERT INTO api_rate_limits (scope_key, window_started_at, request_count)
    VALUES (?, ?, 1)
    ON CONFLICT(scope_key) DO UPDATE SET
      request_count = CASE
        WHEN api_rate_limits.window_started_at <= ? THEN 1
        ELSE api_rate_limits.request_count + 1
      END,
      window_started_at = CASE
        WHEN api_rate_limits.window_started_at <= ? THEN ?
        ELSE api_rate_limits.window_started_at
      END
    RETURNING request_count, window_started_at
  `).bind(scopeKey, now, now - windowSeconds, now - windowSeconds, now).first();

  const count = Number(row?.request_count || 0);
  const startedAt = Number(row?.window_started_at || now);
  return {
    allowed: count <= limit,
    limit,
    remaining: Math.max(0, limit - count),
    retryAfter: Math.max(1, startedAt + windowSeconds - now)
  };
}

async function enforceApiRateLimit(request, env, user) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const ipKey = "ip:" + await hashToken(ip);
  const ipLimit = await incrementApiRateLimit(env, ipKey, 300);

  if (!ipLimit.allowed) {
    return json({
      error: "Trop de requêtes API depuis cette adresse. Réessaie dans quelques instants."
    }, 429, {
      "Retry-After": String(ipLimit.retryAfter),
      "RateLimit-Limit": String(ipLimit.limit),
      "RateLimit-Remaining": "0",
      "RateLimit-Reset": String(ipLimit.retryAfter)
    });
  }

  if (user?.id) {
    const userKey = "user:" + await hashToken(user.id);
    const userLimit = await incrementApiRateLimit(env, userKey, 240);
    if (!userLimit.allowed) {
      return json({
        error: "La limite de requêtes API de ce compte est atteinte. Réessaie dans quelques instants."
      }, 429, {
        "Retry-After": String(userLimit.retryAfter),
        "RateLimit-Limit": String(userLimit.limit),
        "RateLimit-Remaining": "0",
        "RateLimit-Reset": String(userLimit.retryAfter)
      });
    }
  }

  const currentHour = Math.floor(Date.now() / 3600000);
  if (currentHour !== apiRateLimitLastCleanupHour) {
    apiRateLimitLastCleanupHour = currentHour;
    try {
      await env.DB.prepare(
        "DELETE FROM api_rate_limits WHERE window_started_at < ?"
      ).bind(Math.floor(Date.now() / 1000) - 86400).run();
    } catch (error) {
      apiRateLimitLastCleanupHour = 0;
      console.error("ERREUR NETTOYAGE LIMITES API:", error);
    }
  }

  return null;
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
let automationTasksSchemaPromise = null;

async function ensureAutomationTasksSchema(env) {
  if (!automationTasksSchemaPromise) {
    automationTasksSchemaPromise = (async () => {
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS automation_tasks (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL,
          project_id TEXT NOT NULL,
          task_type TEXT NOT NULL CHECK (length(task_type) BETWEEN 1 AND 80),
          payload_json TEXT NOT NULL DEFAULT '{}' CHECK (length(payload_json) <= 16384),
          status TEXT NOT NULL DEFAULT 'pending'
            CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
          scheduled_at INTEGER NOT NULL,
          attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
          max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 10),
          lock_token TEXT,
          locked_until INTEGER,
          last_error TEXT CHECK (last_error IS NULL OR length(last_error) <= 1000),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          completed_at TEXT,
          cancelled_at TEXT,
          started_at TEXT,
          duration_ms INTEGER CHECK (duration_ms IS NULL OR duration_ms >= 0),
          CHECK (
            (status = 'running' AND lock_token IS NOT NULL AND locked_until IS NOT NULL)
            OR
            (status != 'running' AND lock_token IS NULL AND locked_until IS NULL)
          )
        )
      `).run();
      await env.DB.prepare(
        "CREATE INDEX IF NOT EXISTS idx_automation_tasks_due ON automation_tasks(status, scheduled_at, locked_until)"
      ).run();
      await env.DB.prepare(
        "CREATE INDEX IF NOT EXISTS idx_automation_tasks_project_owner ON automation_tasks(user_id, project_id, created_at DESC)"
      ).run();
      const ensureAutomationColumn = async (columnName, definition) => {
        const columns = await env.DB.prepare("PRAGMA table_info(automation_tasks)").all();
        if ((columns.results || []).some(column => column.name === columnName)) return;
        try {
          await env.DB.prepare("ALTER TABLE automation_tasks ADD COLUMN " + columnName + " " + definition).run();
        } catch (error) {
          // Une autre instance du Worker peut avoir ajouté la colonne entre-temps.
          const refreshed = await env.DB.prepare("PRAGMA table_info(automation_tasks)").all();
          const alreadyAdded = (refreshed.results || []).some(column => column.name === columnName);
          if (!alreadyAdded) throw error;
        }
      };
      await ensureAutomationColumn("result_json", "TEXT");
      await ensureAutomationColumn("started_at", "TEXT");
      await ensureAutomationColumn("duration_ms", "INTEGER");
      await ensureAutomationColumn("recovery_count", "INTEGER NOT NULL DEFAULT 0");
    })().catch(error => {
      automationTasksSchemaPromise = null;
      throw error;
    });
  }
  return automationTasksSchemaPromise;
}

async function ensureAssistantAccessSchema(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS assistant_access_tokens (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      label TEXT NOT NULL,
      scopes TEXT NOT NULL DEFAULT '["projects:read","applications:read","files:read"]',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      expires_at TEXT,
      last_used_at TEXT,
      revoked_at TEXT
    )
  `).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS idx_assistant_access_user ON assistant_access_tokens(user_id, created_at DESC)"
  ).run();
}

async function authenticateAssistantAccess(request, env) {
  const authorization = request.headers.get("Authorization") || "";
  const match = authorization.match(/^Bearer (221c_[a-f0-9]{64}|221oauth_[a-f0-9]{64})$/i);
  if (!match) return null;

  const tokenHash = await hashToken(match[1]);
  if (match[1].startsWith("221oauth_")) {
    await ensureOAuthSchema(env);
    const expectedResource = new URL("/mcp", request.url).href;
    const oauthAccess = await env.DB.prepare(
      "SELECT token_hash, user_id, scope FROM oauth_access_tokens WHERE token_hash = ? AND revoked_at IS NULL AND datetime(expires_at) > CURRENT_TIMESTAMP AND resource = ? LIMIT 1"
    ).bind(tokenHash, expectedResource).first();
    if (!oauthAccess) return null;
    await env.DB.prepare(
      "UPDATE oauth_access_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE token_hash = ? AND revoked_at IS NULL"
    ).bind(tokenHash).run();
    return {
      id: tokenHash,
      user_id: oauthAccess.user_id,
      scopes: String(oauthAccess.scope || "").split(" ").filter(scope => scope && scope !== "offline_access")
    };
  }

  await ensureAssistantAccessSchema(env);
  const access = await env.DB.prepare(
    "SELECT id, user_id, scopes FROM assistant_access_tokens WHERE token_hash = ? AND revoked_at IS NULL AND (expires_at IS NULL OR datetime(expires_at) > CURRENT_TIMESTAMP) LIMIT 1"
  ).bind(tokenHash).first();
  if (!access) return null;
  await env.DB.prepare(
    "UPDATE assistant_access_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE id = ? AND revoked_at IS NULL"
  ).bind(access.id).run();
  let scopes = [];
  try { scopes = JSON.parse(access.scopes || "[]"); } catch { return null; }
  return { id: access.id, user_id: access.user_id, scopes };
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
    for (const columnName of ["deleted_at", "trash_id"]) {
      const columns = await env.DB.prepare("PRAGMA table_info(" + tableName + ")").all();
      const known = new Set((columns.results || []).map(column => column.name));
      if (known.has(columnName)) continue;
      try {
        await env.DB.prepare("ALTER TABLE " + tableName + " ADD COLUMN " + columnName + " TEXT").run();
      } catch (error) {
        // Une autre requête peut avoir ajouté la colonne entre PRAGMA et ALTER TABLE.
        const refreshed = await env.DB.prepare("PRAGMA table_info(" + tableName + ")").all();
        const alreadyAdded = (refreshed.results || []).some(column => column.name === columnName);
        if (!alreadyAdded) throw error;
      }
    }
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


async function ensureApplicationDatabaseConnectionSchema(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS application_database_connections (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      project_id TEXT NOT NULL UNIQUE,
      database_id TEXT NOT NULL UNIQUE,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_application_database_connections_owner
    ON application_database_connections(user_id, project_id)
  `).run();
}


async function ensureApplicationDatabasePermissionsSchema(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS application_database_table_permissions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      database_id TEXT NOT NULL,
      table_id TEXT NOT NULL,
      can_read INTEGER NOT NULL DEFAULT 0 CHECK (can_read IN (0, 1)),
      can_create INTEGER NOT NULL DEFAULT 0 CHECK (can_create IN (0, 1)),
      can_update INTEGER NOT NULL DEFAULT 0 CHECK (can_update IN (0, 1)),
      can_delete INTEGER NOT NULL DEFAULT 0 CHECK (can_delete IN (0, 1)),
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(project_id, table_id)
    )
  `).run();
  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_application_db_permissions_owner
    ON application_database_table_permissions(user_id, project_id, database_id)
  `).run();
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

async function executeProjectHealthCheck(env, task) {
  await ensureProjectTrashSchema(env);
  await ensureApplicationFilesSchema(env);
  await ensureApplicationPublicationSchema(env);

  const project = await env.DB.prepare(
    "SELECT id, user_id FROM projects WHERE id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1"
  ).bind(task.project_id, task.user_id).first();

  if (!project) {
    return {
      status: "unavailable",
      checked_at: new Date().toISOString(),
      message: "Le projet n'existe plus ou n'est plus accessible."
    };
  }

  const [files, publication] = await Promise.all([
    env.DB.prepare(
      "SELECT COUNT(*) AS total FROM application_files WHERE project_id = ?"
    ).bind(task.project_id).first(),
    env.DB.prepare(`
      SELECT publications.slug, publications.active_version_id,
             versions.id AS verified_version_id
      FROM application_publications AS publications
      LEFT JOIN application_publication_versions AS versions
        ON versions.id = publications.active_version_id
       AND versions.publication_id = publications.id
      WHERE publications.project_id = ? AND publications.user_id = ?
      LIMIT 1
    `).bind(task.project_id, task.user_id).first()
  ]);

  const fileCount = Number(files?.total || 0);
  const isPublished = Boolean(publication?.slug && publication?.verified_version_id);

  return {
    status: "checked",
    checked_at: new Date().toISOString(),
    project_id: task.project_id,
    checks: {
      project_accessible: true,
      application_files_count: fileCount,
      publication_exists: Boolean(publication),
      publication_version_valid: isPublished
    },
    summary: fileCount === 0
      ? "Projet accessible, mais aucun fichier d'application n'est enregistré."
      : "Projet accessible et fichiers d'application recensés."
  };
}

async function runAutomationScheduler(env, scheduledTime) {
  await ensureAutomationTasksSchema(env);

  const maxTasksPerRun = 5;
  const expiredCheckTime = Math.floor(Date.now() / 1000);

  await env.DB.prepare(`
    UPDATE automation_tasks
    SET status = 'failed',
        recovery_count = recovery_count + 1,
        lock_token = NULL,
        locked_until = NULL,
        last_error = 'Verrou expiré après la dernière tentative.',
        completed_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
    WHERE status = 'running'
      AND locked_until <= ?
      AND attempts >= max_attempts
  `).bind(expiredCheckTime).run();

  for (let processed = 0; processed < maxTasksPerRun; processed++) {
    const attemptStartedAt = Date.now();
    const now = Math.floor(attemptStartedAt / 1000);
    const lockToken = crypto.randomUUID();
    const lockUntil = now + 120;

    const claimed = await env.DB.prepare(`
      UPDATE automation_tasks
      SET recovery_count = recovery_count + CASE
            WHEN status = 'running' AND locked_until <= ? THEN 1 ELSE 0 END,
          status = 'running',
          lock_token = ?,
          locked_until = ?,
          attempts = attempts + 1,
          started_at = ?,
          duration_ms = NULL,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = (
        SELECT id
        FROM automation_tasks
        WHERE scheduled_at <= ?
          AND attempts < max_attempts
          AND (
            status = 'pending'
            OR (status = 'running' AND locked_until <= ?)
          )
        ORDER BY scheduled_at ASC, created_at ASC
        LIMIT 1
      )
        AND attempts < max_attempts
        AND (
          status = 'pending'
          OR (status = 'running' AND locked_until <= ?)
        )
    `).bind(
      now,
      lockToken,
      lockUntil,
      new Date(attemptStartedAt).toISOString(),
      now,
      now,
      now
    ).run();

    if (!claimed.meta || Number(claimed.meta.changes || 0) !== 1) break;

    const task = await env.DB.prepare(
      "SELECT id, user_id, project_id, task_type, attempts, max_attempts FROM automation_tasks WHERE lock_token = ? AND status = 'running' LIMIT 1"
    ).bind(lockToken).first();

    if (!task) break;

    try {
      if (task.task_type !== "project_health_check") {
        throw new Error("Type de tâche non autorisé par le moteur.");
      }

      const result = await executeProjectHealthCheck(env, task);
      await env.DB.prepare(`
        UPDATE automation_tasks
        SET status = 'completed',
            result_json = ?,
            duration_ms = ?,
            last_error = NULL,
            lock_token = NULL,
            locked_until = NULL,
            completed_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND status = 'running' AND lock_token = ?
      `).bind(
        JSON.stringify(result),
        Math.max(0, Date.now() - attemptStartedAt),
        task.id,
        lockToken
      ).run();
    } catch (error) {
      const message = String(error?.message || "Erreur d'exécution").slice(0, 1000);
      const canRetry = Number(task.attempts) < Number(task.max_attempts);
      await env.DB.prepare(`
        UPDATE automation_tasks
        SET status = ?,
            scheduled_at = CASE WHEN ? = 1 THEN ? ELSE scheduled_at END,
            last_error = ?,
            duration_ms = ?,
            completed_at = CASE WHEN ? = 1 THEN CURRENT_TIMESTAMP ELSE NULL END,
            lock_token = NULL,
            locked_until = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND status = 'running' AND lock_token = ?
      `).bind(
        canRetry ? "pending" : "failed",
        canRetry ? 1 : 0,
        now + 60,
        message,
        Math.max(0, Date.now() - attemptStartedAt),
        canRetry ? 0 : 1,
        task.id,
        lockToken
      ).run();
      console.error("ERREUR EXÉCUTION AUTOMATISATION:", {
        taskId: task.id,
        attempt: task.attempts,
        retry: canRetry,
        error: message
      });
    }
  }
}



const OAUTH_ALLOWED_SCOPES = ["projects:read", "applications:read", "files:read", "offline_access"];

async function ensureOAuthSchema(env) {
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS oauth_clients (client_id TEXT PRIMARY KEY, client_name TEXT NOT NULL, redirect_uris TEXT NOT NULL, grant_types TEXT NOT NULL, response_types TEXT NOT NULL, token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none', created_at TEXT DEFAULT CURRENT_TIMESTAMP)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS oauth_authorization_codes (code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, user_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, code_challenge TEXT NOT NULL, scope TEXT NOT NULL, resource TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT)").run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_oauth_codes_expiry ON oauth_authorization_codes(expires_at)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS oauth_access_tokens (token_hash TEXT PRIMARY KEY, family_id TEXT NOT NULL, client_id TEXT NOT NULL, user_id TEXT NOT NULL, scope TEXT NOT NULL, resource TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT, last_used_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)").run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_oauth_access_family ON oauth_access_tokens(family_id)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (token_hash TEXT PRIMARY KEY, family_id TEXT NOT NULL, client_id TEXT NOT NULL, user_id TEXT NOT NULL, scope TEXT NOT NULL, resource TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)").run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_oauth_refresh_family ON oauth_refresh_tokens(family_id)").run();
}

function oauthHtmlEscape(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}

function oauthHtmlResponse(html, status = 200) {
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer"
    }
  });
}

function oauthLoginPage() {
  return oauthHtmlResponse('<!doctype html><html lang="fr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connexion 221Cloud</title><body style="font:16px system-ui;max-width:440px;margin:10vh auto;padding:24px;color:#182230"><h1>Connexion à 221Cloud</h1><p>Connecte-toi pour autoriser l’accès à tes projets.</p><form id="login"><label>E-mail<br><input id="email" type="email" autocomplete="username" required style="box-sizing:border-box;width:100%;padding:12px;margin:8px 0 16px"></label><label>Mot de passe<br><input id="password" type="password" autocomplete="current-password" required style="box-sizing:border-box;width:100%;padding:12px;margin:8px 0 16px"></label><button style="padding:12px 18px">Se connecter</button></form><p id="error" role="alert"></p><script>document.getElementById("login").addEventListener("submit",async e=>{e.preventDefault();const error=document.getElementById("error");error.textContent="Connexion…";try{const r=await fetch("/api/login",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:document.getElementById("email").value,password:document.getElementById("password").value})});const d=await r.json();if(!r.ok)throw new Error(d.error||"Connexion impossible");location.reload()}catch(x){error.textContent=x.message}})</script></body></html>');
}

async function oauthAuthorizePage(request, env) {
  const url = new URL(request.url);
  const params = request.method === "POST"
    ? await readLimitedJsonBody(request).catch(() => ({}))
    : Object.fromEntries(url.searchParams.entries());

  const clientId = String(params.client_id || "");
  const redirectUri = String(params.redirect_uri || "");
  const state = String(params.state || "");
  const challenge = String(params.code_challenge || "");
  const challengeMethod = String(params.code_challenge_method || "");
  const resource = String(params.resource || "");
  const scope = String(params.scope || "projects:read applications:read files:read");
  const scopes = [...new Set(scope.split(/\s+/).filter(Boolean))];
  const invalid = message => json({ error: message }, 400, { "Cache-Control": "no-store" });

  if (!clientId || !redirectUri || !state || state.length > 512 ||
      !/^[A-Za-z0-9_-]{43,128}$/.test(challenge) || challengeMethod !== "S256") {
    return invalid("Paramètres OAuth invalides.");
  }
  if (resource !== new URL("/mcp", url.origin).href) return invalid("Ressource OAuth invalide.");
  if (!scopes.length || scopes.some(scopeName => !OAUTH_ALLOWED_SCOPES.includes(scopeName))) {
    return invalid("Scopes OAuth non autorisés.");
  }

  await ensureOAuthSchema(env);
  const client = await env.DB.prepare("SELECT client_id, client_name, redirect_uris FROM oauth_clients WHERE client_id = ? LIMIT 1").bind(clientId).first();
  if (!client) return invalid("Client OAuth inconnu.");
  let redirectUris = [];
  try { redirectUris = JSON.parse(client.redirect_uris || "[]"); } catch {}
  if (!redirectUris.includes(redirectUri)) return invalid("Adresse de retour non autorisée.");

  const user = await currentUser(request, env);
  if (!user) return oauthLoginPage();

  if (request.method === "GET") {
    const scopeLabels = {
      "projects:read": "Consulter la liste et les détails de tes projets",
      "applications:read": "Consulter les informations de tes applications",
      "files:read": "Lire les fichiers autorisés de tes applications",
      "offline_access": "Maintenir la connexion avec des jetons renouvelables"
    };
    const labels = scopes.map(s => "<li>" + oauthHtmlEscape(scopeLabels[s] || s) + "</li>").join("");
    const payload = JSON.stringify({
      client_id: clientId, redirect_uri: redirectUri, state,
      code_challenge: challenge, code_challenge_method: "S256",
      resource, scope: scopes.join(" ")
    }).replace(/</g, "\\u003c");
    const html = '<!doctype html><html lang="fr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Autoriser l’accès — 221Cloud</title><body style="font:16px system-ui;max-width:560px;margin:8vh auto;padding:24px;color:#182230"><h1>Autoriser une connexion</h1><p><strong>' + oauthHtmlEscape(client.client_name) + '</strong> demande à accéder à ton espace 221Cloud.</p><p>Compte connecté : ' + oauthHtmlEscape(user.email || user.full_name || "ton compte") + '</p><ul>' + labels + '</ul><p><strong>Lecture uniquement :</strong> aucune modification, suppression ou publication n’est autorisée.</p><button id="allow" style="padding:12px 18px">Autoriser</button> <button id="deny" style="padding:12px 18px">Refuser</button><p id="error" role="alert"></p><script>const payload=' + payload + ';async function decide(approved){const error=document.getElementById("error");error.textContent="Traitement…";try{const r=await fetch("/oauth/authorize",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({...payload,decision:approved?"approve":"deny"})});const d=await r.json();if(!r.ok)throw new Error(d.error||"Demande refusée");location.assign(d.redirect_uri)}catch(e){error.textContent=e.message}}document.getElementById("allow").onclick=()=>decide(true);document.getElementById("deny").onclick=()=>decide(false)</script></body></html>';
    return oauthHtmlResponse(html);
  }

  const origin = request.headers.get("Origin");
  if (!origin || origin !== url.origin) return json({ error: "Origine non autorisée." }, 403);
  if (params.decision === "deny") {
    const denied = new URL(redirectUri);
    denied.searchParams.set("error", "access_denied");
    denied.searchParams.set("state", state);
    denied.searchParams.set("iss", url.origin);
    return json({ redirect_uri: denied.href }, 200, { "Cache-Control": "no-store" });
  }
  if (params.decision !== "approve") return invalid("Décision OAuth invalide.");

  const code = "221code_" + randomToken();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  await env.DB.prepare("INSERT INTO oauth_authorization_codes (code_hash, client_id, user_id, redirect_uri, code_challenge, scope, resource, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(await hashToken(code), clientId, user.id, redirectUri, challenge, scopes.join(" "), resource, expiresAt).run();
  const callback = new URL(redirectUri);
  callback.searchParams.set("code", code);
  callback.searchParams.set("state", state);
  callback.searchParams.set("iss", url.origin);
  return json({ redirect_uri: callback.href }, 200, { "Cache-Control": "no-store" });
}

async function oauthRegisterClient(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const limit = await incrementApiRateLimit(env, "oauth-register:" + await hashToken(ip), 20);
  if (!limit.allowed) return json({ error: "registration_limit_exceeded" }, 429, { "Retry-After": String(limit.retryAfter) });
  let body;
  try { body = await readLimitedJsonBody(request); } catch {
    return json({ error: "invalid_client_metadata" }, 400);
  }
  const redirectUris = body.redirect_uris;
  if (!Array.isArray(redirectUris) || redirectUris.length < 1 || redirectUris.length > 10) {
    return json({ error: "invalid_redirect_uri" }, 400);
  }
  const normalized = [];
  for (const candidate of redirectUris) {
    if (typeof candidate !== "string" || candidate.length > 2048) return json({ error: "invalid_redirect_uri" }, 400);
    try {
      const parsed = new URL(candidate);
      const localHttp = parsed.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
      if ((!localHttp && parsed.protocol !== "https:") || parsed.username || parsed.password || parsed.hash) {
        return json({ error: "invalid_redirect_uri" }, 400);
      }
      if (!normalized.includes(candidate)) normalized.push(candidate);
    } catch {
      return json({ error: "invalid_redirect_uri" }, 400);
    }
  }
  const grantTypes = Array.isArray(body.grant_types) ? body.grant_types : ["authorization_code", "refresh_token"];
  const responseTypes = Array.isArray(body.response_types) ? body.response_types : ["code"];
  if (!grantTypes.includes("authorization_code") || grantTypes.some(g => !["authorization_code", "refresh_token"].includes(g)) ||
      !responseTypes.includes("code") || responseTypes.some(r => r !== "code") ||
      (body.token_endpoint_auth_method && body.token_endpoint_auth_method !== "none")) {
    return json({ error: "invalid_client_metadata" }, 400);
  }
  await ensureOAuthSchema(env);
  const clientId = "221client_" + randomToken();
  const clientName = String(body.client_name || "Client MCP").slice(0, 100);
  await env.DB.prepare("INSERT INTO oauth_clients (client_id, client_name, redirect_uris, grant_types, response_types, token_endpoint_auth_method) VALUES (?, ?, ?, ?, ?, 'none')")
    .bind(clientId, clientName, JSON.stringify(normalized), JSON.stringify(grantTypes), JSON.stringify(responseTypes)).run();
  return json({
    client_id: clientId,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    client_name: clientName,
    redirect_uris: normalized,
    grant_types: grantTypes,
    response_types: responseTypes,
    token_endpoint_auth_method: "none"
  }, 201, { "Cache-Control": "no-store" });
}

async function issueOAuthTokens(env, clientId, userId, scope, resource, familyId = crypto.randomUUID()) {
  const accessToken = "221oauth_" + randomToken();
  const refreshToken = "221refresh_" + randomToken();
  const accessExpires = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  const refreshExpires = new Date(Date.now() + 30 * 86400000).toISOString();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO oauth_access_tokens (token_hash, family_id, client_id, user_id, scope, resource, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .bind(await hashToken(accessToken), familyId, clientId, userId, scope, resource, accessExpires),
    env.DB.prepare("INSERT INTO oauth_refresh_tokens (token_hash, family_id, client_id, user_id, scope, resource, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .bind(await hashToken(refreshToken), familyId, clientId, userId, scope, resource, refreshExpires)
  ]);
  return { access_token: accessToken, token_type: "Bearer", expires_in: 3600, refresh_token: refreshToken, scope };
}

async function oauthTokenEndpoint(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const limit = await incrementApiRateLimit(env, "oauth-token:" + await hashToken(ip), 60);
  if (!limit.allowed) return json({ error: "slow_down" }, 429, { "Retry-After": String(limit.retryAfter) });
  const contentType = request.headers.get("Content-Type") || "";
  if (!contentType.toLowerCase().includes("application/x-www-form-urlencoded")) {
    return json({ error: "invalid_request", error_description: "Form URL encoded body required." }, 400);
  }
  const raw = await request.text();
  if (raw.length > 16384) return json({ error: "invalid_request" }, 413);
  const form = new URLSearchParams(raw);
  const clientId = form.get("client_id") || "";
  const grantType = form.get("grant_type") || "";
  const resource = form.get("resource") || "";
  const expectedResource = new URL("/mcp", request.url).href;
  if (!clientId || resource !== expectedResource) return json({ error: "invalid_request", error_description: "client_id and valid resource are required." }, 400);
  await ensureOAuthSchema(env);
  const client = await env.DB.prepare("SELECT client_id FROM oauth_clients WHERE client_id = ? LIMIT 1").bind(clientId).first();
  if (!client) return json({ error: "invalid_client" }, 401);
  if (form.get("client_secret") || form.get("client_assertion")) return json({ error: "invalid_client" }, 401);

  if (grantType === "authorization_code") {
    const code = form.get("code") || "";
    const redirectUri = form.get("redirect_uri") || "";
    const verifier = form.get("code_verifier") || "";
    if (!/^221code_[a-f0-9]{64}$/i.test(code) || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) {
      return json({ error: "invalid_grant" }, 400);
    }
    const codeHash = await hashToken(code);
    const authorization = await env.DB.prepare("SELECT * FROM oauth_authorization_codes WHERE code_hash = ? AND client_id = ? AND redirect_uri = ? AND resource = ? AND used_at IS NULL AND datetime(expires_at) > CURRENT_TIMESTAMP LIMIT 1")
      .bind(codeHash, clientId, redirectUri, resource).first();
    if (!authorization) return json({ error: "invalid_grant" }, 400);
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    const challenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    if (challenge !== authorization.code_challenge) return json({ error: "invalid_grant" }, 400);
    const consumed = await env.DB.prepare("UPDATE oauth_authorization_codes SET used_at = CURRENT_TIMESTAMP WHERE code_hash = ? AND used_at IS NULL AND datetime(expires_at) > CURRENT_TIMESTAMP")
      .bind(codeHash).run();
    if (!consumed.meta?.changes) return json({ error: "invalid_grant" }, 400);
    const tokens = await issueOAuthTokens(env, clientId, authorization.user_id, authorization.scope, resource);
    return json(tokens, 200, { "Cache-Control": "no-store", Pragma: "no-cache" });
  }

  if (grantType === "refresh_token") {
    const refreshToken = form.get("refresh_token") || "";
    if (!/^221refresh_[a-f0-9]{64}$/i.test(refreshToken)) return json({ error: "invalid_grant" }, 400);
    const tokenHash = await hashToken(refreshToken);
    const existing = await env.DB.prepare("SELECT * FROM oauth_refresh_tokens WHERE token_hash = ? AND client_id = ? AND resource = ? LIMIT 1")
      .bind(tokenHash, clientId, resource).first();
    if (!existing) return json({ error: "invalid_grant" }, 400);
    if (existing.revoked_at) {
      await env.DB.batch([
        env.DB.prepare("UPDATE oauth_refresh_tokens SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP) WHERE family_id = ?").bind(existing.family_id),
        env.DB.prepare("UPDATE oauth_access_tokens SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP) WHERE family_id = ?").bind(existing.family_id)
      ]);
      return json({ error: "invalid_grant" }, 400);
    }
    if (new Date(existing.expires_at).getTime() <= Date.now()) return json({ error: "invalid_grant" }, 400);
    const requestedScope = form.get("scope");
    if (requestedScope) {
      const requested = requestedScope.split(/\s+/).filter(Boolean);
      const granted = String(existing.scope || "").split(/\s+/).filter(Boolean);
      if (requested.some(s => !granted.includes(s))) return json({ error: "invalid_scope" }, 400);
    }
    const consumed = await env.DB.prepare("UPDATE oauth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE token_hash = ? AND revoked_at IS NULL AND datetime(expires_at) > CURRENT_TIMESTAMP")
      .bind(tokenHash).run();
    if (!consumed.meta?.changes) return json({ error: "invalid_grant" }, 400);
    const tokens = await issueOAuthTokens(env, clientId, existing.user_id, existing.scope, resource, existing.family_id);
    return json(tokens, 200, { "Cache-Control": "no-store", Pragma: "no-cache" });
  }
  return json({ error: "unsupported_grant_type" }, 400);
}

function oauthMetadata(request) {
  const origin = new URL(request.url).origin;
  const issuer = origin;
  const resource = new URL("/mcp", origin).href;
  const path = new URL(request.url).pathname;
  if (path === "/.well-known/oauth-protected-resource") {
    return json({
      resource,
      authorization_servers: [issuer],
      scopes_supported: OAUTH_ALLOWED_SCOPES,
      bearer_methods_supported: ["header"],
      resource_name: "221Cloud"
    }, 200, { "Cache-Control": "public, max-age=300" });
  }
  return json({
    issuer,
    authorization_endpoint: origin + "/oauth/authorize",
    token_endpoint: origin + "/oauth/token",
    registration_endpoint: origin + "/oauth/register",
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: OAUTH_ALLOWED_SCOPES,
    authorization_response_iss_parameter_supported: true
  }, 200, { "Cache-Control": "public, max-age=300" });
}

async function handleOAuthRequest(request, env, path) {
  if (path === "/.well-known/oauth-protected-resource" || path === "/.well-known/oauth-authorization-server") {
    if (request.method !== "GET") return json({ error: "Method not allowed." }, 405, { Allow: "GET" });
    return oauthMetadata(request);
  }
  if (path === "/oauth/register") {
    if (request.method !== "POST") return json({ error: "Method not allowed." }, 405, { Allow: "POST" });
    return oauthRegisterClient(request, env);
  }
  if (path === "/oauth/authorize") {
    if (!["GET", "POST"].includes(request.method)) return json({ error: "Method not allowed." }, 405, { Allow: "GET, POST" });
    return oauthAuthorizePage(request, env);
  }
  if (path === "/oauth/token") {
    if (request.method !== "POST") return json({ error: "Method not allowed." }, 405, { Allow: "POST" });
    return oauthTokenEndpoint(request, env);
  }
  return null;
}

async function handleAssistantMcpRequest(request, env) {
  if (request.method !== "POST") {
    return json({ error: "Le serveur MCP accepte les requêtes POST JSON." }, 405, {
      "Allow": "POST",
      "WWW-Authenticate": "Bearer"
    });
  }

  const access = await authenticateAssistantAccess(request, env);
  if (!access) {
    return json({ error: "Clé d'accès invalide, expirée ou révoquée." }, 401, {
      "WWW-Authenticate": "Bearer"
    });
  }

  const rateLimit = await incrementApiRateLimit(
    env,
    "mcp-token:" + await hashToken(access.id),
    120
  );
  if (!rateLimit.allowed) {
    return json({ error: "Limite de requêtes MCP atteinte. Réessaie plus tard." }, 429, {
      "Retry-After": String(rateLimit.retryAfter)
    });
  }

  let message;
  try {
    message = await readLimitedJsonBody(request);
  } catch {
    return json({ error: "Corps JSON MCP invalide ou trop volumineux." }, 400);
  }

  if (!message || message.jsonrpc !== "2.0" || typeof message.method !== "string") {
    return json({
      jsonrpc: "2.0",
      id: message?.id ?? null,
      error: { code: -32600, message: "Requête JSON-RPC invalide." }
    }, 400);
  }

  const hasId = Object.prototype.hasOwnProperty.call(message, "id");
  const requestId = hasId ? message.id : null;
  const response = (result, status = 200) =>
    json({ jsonrpc: "2.0", id: requestId, result }, status);
  const rpcError = (code, messageText, status = 200) =>
    json({
      jsonrpc: "2.0",
      id: requestId,
      error: { code, message: messageText }
    }, status);

  if (message.method === "notifications/initialized" ||
      message.method === "notifications/cancelled") {
    return new Response(null, { status: 202 });
  }

  if (!hasId) return new Response(null, { status: 202 });

  if (message.method === "initialize") {
    const requestedVersion = message.params?.protocolVersion;
    const supportedVersions = ["2025-03-26", "2025-06-18"];
    const protocolVersion = supportedVersions.includes(requestedVersion)
      ? requestedVersion
      : "2025-03-26";
    return response({
      protocolVersion,
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: "221cloud-assistant", version: "1.0.0" },
      instructions: "Serveur 221Cloud en lecture seule. Les outils ne donnent accès qu’aux projets appartenant au propriétaire de la clé. Aucun outil ne modifie, supprime ou publie des données."
    });
  }

  if (message.method === "ping") return response({});

  if (message.method === "tools/list") {
    return response({
      tools: [
        {
          name: "list_projects",
          description: "Liste les projets 221Cloud appartenant au titulaire de cette clé.",
          inputSchema: { type: "object", properties: {}, additionalProperties: false }
        },
        {
          name: "get_project",
          description: "Consulte les informations d’un projet appartenant au titulaire de cette clé.",
          inputSchema: {
            type: "object",
            properties: { project_id: { type: "string", minLength: 1 } },
            required: ["project_id"],
            additionalProperties: false
          }
        },
        {
          name: "list_application_files",
          description: "Liste les fichiers autorisés d’une application appartenant au titulaire de cette clé.",
          inputSchema: {
            type: "object",
            properties: { project_id: { type: "string", minLength: 1 } },
            required: ["project_id"],
            additionalProperties: false
          }
        },
        {
          name: "read_application_file",
          description: "Lit un fichier autorisé d’une application appartenant au titulaire de cette clé. Les fichiers secrets et extensions non autorisées sont refusés.",
          inputSchema: {
            type: "object",
            properties: {
              project_id: { type: "string", minLength: 1 },
              path: { type: "string", minLength: 1, maxLength: 240 }
            },
            required: ["project_id", "path"],
            additionalProperties: false
          }
        }
      ]
    });
  }

  if (message.method !== "tools/call") {
    return rpcError(-32601, "Méthode MCP inconnue.");
  }

  const toolName = message.params?.name;
  const args = message.params?.arguments || {};
  const toolResult = data => response({
    content: [{ type: "text", text: JSON.stringify(data) }],
    structuredContent: data,
    isError: false
  });
  const toolFailure = textValue => response({
    content: [{ type: "text", text: textValue }],
    isError: true
  });

  try {
    if (toolName === "list_projects") {
      if (!access.scopes.includes("projects:read")) return toolFailure("Autorisation projects:read manquante.");
      const result = await env.DB.prepare(
        "SELECT id, name, type, status, created_at FROM projects WHERE user_id = ? AND deleted_at IS NULL ORDER BY created_at DESC"
      ).bind(access.user_id).all();
      return toolResult({ projects: result.results || [] });
    }

    if (toolName === "get_project") {
      if (!access.scopes.includes("projects:read")) return toolFailure("Autorisation projects:read manquante.");
      const projectId = String(args.project_id || "");
      if (!projectId || projectId.length > 200) return toolFailure("Identifiant de projet invalide.");
      const project = await env.DB.prepare(
        "SELECT id, name, type, status, created_at FROM projects WHERE id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1"
      ).bind(projectId, access.user_id).first();
      if (!project) return toolFailure("Projet introuvable ou non autorisé.");
      return toolResult({ project });
    }

    if (toolName === "list_application_files" || toolName === "read_application_file") {
      if (!access.scopes.includes("applications:read") || !access.scopes.includes("files:read")) {
        return toolFailure("Autorisations applications:read et files:read requises.");
      }
      const projectId = String(args.project_id || "");
      if (!projectId || projectId.length > 200) return toolFailure("Identifiant de projet invalide.");
      const project = await env.DB.prepare(
        "SELECT id FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL LIMIT 1"
      ).bind(projectId, access.user_id).first();
      if (!project) return toolFailure("Application introuvable ou non autorisée.");

      await ensureApplicationFilesSchema(env);
      await ensureApplicationDirectoriesSchema(env);

      if (toolName === "read_application_file") {
        const filePath = args.path;
        if (!validApplicationFilePath(filePath)) return toolFailure("Chemin de fichier non autorisé.");
        const file = await env.DB.prepare(
          "SELECT file_name, content, mime_type, updated_at FROM application_files WHERE project_id = ? AND file_name = ? AND deleted_at IS NULL LIMIT 1"
        ).bind(projectId, filePath).first();
        if (!file) return toolFailure("Fichier introuvable.");
        return toolResult({ file });
      }

      const [files, directories] = await Promise.all([
        env.DB.prepare(
          "SELECT file_name, mime_type, created_at, updated_at FROM application_files WHERE project_id = ? AND deleted_at IS NULL ORDER BY file_name ASC"
        ).bind(projectId).all(),
        env.DB.prepare(
          "SELECT directory_path, created_at FROM application_directories WHERE project_id = ? AND deleted_at IS NULL ORDER BY directory_path ASC"
        ).bind(projectId).all()
      ]);
      return toolResult({
        project_id: projectId,
        files: files.results || [],
        directories: directories.results || []
      });
    }

    return rpcError(-32602, "Outil MCP inconnu ou arguments invalides.");
  } catch (error) {
    console.error("ERREUR SERVEUR MCP ASSISTANT:", error);
    return toolFailure("Impossible de traiter cette demande MCP.");
  }
}

export default {
  async scheduled(controller, env, ctx) {
    ctx.waitUntil(runAutomationScheduler(env, controller?.scheduledTime || Date.now()));
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Métadonnées et points de terminaison OAuth 2.1 pour le serveur MCP 221Cloud.
    if (
      path === "/.well-known/oauth-protected-resource" ||
      path === "/.well-known/oauth-authorization-server" ||
      path === "/oauth/register" ||
      path === "/oauth/authorize" ||
      path === "/oauth/token"
    ) {
      try {
        const oauthResponse = await handleOAuthRequest(request, env, path);
        if (oauthResponse) return oauthResponse;
      } catch (error) {
        console.error("ERREUR OAUTH 221CLOUD:", error);
        return json({ error: "OAuth temporairement indisponible." }, 500, { "Cache-Control": "no-store" });
      }
    }

    // Serveur MCP distant : accès strictement en lecture via une clé personnelle.
    if (path === "/mcp") {
      try {
        return await handleAssistantMcpRequest(request, env);
      } catch (error) {
        console.error("ERREUR ENDPOINT MCP:", error);
        return json({ error: "Serveur MCP temporairement indisponible." }, 500);
      }
    }

    // Limitation générale : les routes de connexion et d'inscription gardent
    // leurs protections spécifiques déjà en place.
    if (
      path.startsWith("/api/") &&
      !["/api/health", "/api/login", "/api/register"].includes(path)
    ) {
      try {
        const rateLimitUser = await currentUser(request, env);
        const rateLimitResponse = await enforceApiRateLimit(request, env, rateLimitUser);
        if (rateLimitResponse) return rateLimitResponse;
      } catch (error) {
        console.error("ERREUR LIMITATION API:", error);
        return json({ error: "Protection API temporairement indisponible." }, 503);
      }
    }

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

    // GESTION DES ACCÈS DÉVELOPPEUR : CRÉATION ET RÉVOCATION DES CLÉS
    if (path === "/api/assistant-access/tokens") {
      if (!["GET", "POST"].includes(request.method)) {
        return json({ error: "Méthode non autorisée." }, 405);
      }
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureAssistantAccessSchema(env);

        if (request.method === "GET") {
          const result = await env.DB.prepare(`
            SELECT id, label, scopes, created_at, expires_at, last_used_at, revoked_at
            FROM assistant_access_tokens
            WHERE user_id = ?
            ORDER BY created_at DESC
          `).bind(user.id).all();
          return json({ tokens: result.results || [] });
        }

        const body = await readLimitedJsonBody(request);
        const label = String(body.label || "Accès assistant").trim().slice(0, 60);
        const requestedDays = Number(body.expires_in_days ?? 90);
        if (!label) return json({ error: "Donnez un nom à cet accès." }, 400);
        if (!Number.isInteger(requestedDays) || requestedDays < 1 || requestedDays > 365) {
          return json({ error: "La durée doit être comprise entre 1 et 365 jours." }, 400);
        }

        const id = crypto.randomUUID();
        const secret = "221c_" + randomToken();
        const expiresAt = new Date(Date.now() + requestedDays * 86400000).toISOString();
        await env.DB.prepare(`
          INSERT INTO assistant_access_tokens (id, user_id, token_hash, label, scopes, expires_at)
          VALUES (?, ?, ?, ?, ?, ?)
        `).bind(
          id, user.id, await hashToken(secret), label,
          JSON.stringify(["projects:read", "applications:read", "files:read"]),
          expiresAt
        ).run();

        return json({
          message: "Clé d'accès créée. Copiez-la maintenant : elle ne sera plus affichée.",
          token: secret,
          access: { id, label, scopes: ["projects:read", "applications:read", "files:read"], expires_at: expiresAt }
        }, 201);
      } catch (error) {
        console.error("ERREUR GESTION ACCÈS ASSISTANT:", error);
        return json({ error: "Impossible de gérer cet accès développeur." }, 500);
      }
    }

    const assistantRevokeMatch = path.match(/^\/api\/assistant-access\/tokens\/([a-f0-9-]+)\/revoke$/i);
    if (assistantRevokeMatch && request.method === "POST") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureAssistantAccessSchema(env);
        const result = await env.DB.prepare(`
          UPDATE assistant_access_tokens
          SET revoked_at = CURRENT_TIMESTAMP
          WHERE id = ? AND user_id = ? AND revoked_at IS NULL
        `).bind(assistantRevokeMatch[1], user.id).run();
        if (!result.meta?.changes) return json({ error: "Accès introuvable ou déjà révoqué." }, 404);
        return json({ message: "Accès développeur révoqué." });
      } catch (error) {
        console.error("ERREUR RÉVOCATION ACCÈS ASSISTANT:", error);
        return json({ error: "Impossible de révoquer cet accès." }, 500);
      }
    }

    // API ASSISTANT : LECTURE STRICTEMENT LIMITÉE AUX PROJETS DU PROPRIÉTAIRE DE LA CLÉ
    if (path.startsWith("/api/assistant/v1/")) {
      if (request.method !== "GET") return json({ error: "Cette API est en lecture seule." }, 405);
      try {
        const access = await authenticateAssistantAccess(request, env);
        if (!access) return json({ error: "Clé d'accès invalide, expirée ou révoquée." }, 401);

        if (path === "/api/assistant/v1/projects") {
          if (!access.scopes.includes("projects:read")) return json({ error: "Autorisation insuffisante." }, 403);
          const result = await env.DB.prepare(`
            SELECT id, name, type, status, created_at
            FROM projects
            WHERE user_id = ? AND deleted_at IS NULL
            ORDER BY created_at DESC
          `).bind(access.user_id).all();
          return json({ projects: result.results || [] });
        }

        const assistantProjectMatch = path.match(/^\/api\/assistant\/v1\/projects\/([^/]+)$/);
        if (assistantProjectMatch) {
          if (!access.scopes.includes("projects:read")) return json({ error: "Autorisation insuffisante." }, 403);
          const projectId = decodeURIComponent(assistantProjectMatch[1]);
          const project = await env.DB.prepare(`
            SELECT id, name, type, status, created_at
            FROM projects
            WHERE id = ? AND user_id = ? AND deleted_at IS NULL
            LIMIT 1
          `).bind(projectId, access.user_id).first();
          if (!project) return json({ error: "Projet introuvable." }, 404);
          return json({ project });
        }

        const assistantFilesMatch = path.match(/^\/api\/assistant\/v1\/projects\/([^/]+)\/files$/);
        if (assistantFilesMatch) {
          if (!access.scopes.includes("applications:read") || !access.scopes.includes("files:read")) {
            return json({ error: "Autorisation insuffisante." }, 403);
          }
          await ensureApplicationFilesSchema(env);
          await ensureApplicationDirectoriesSchema(env);
          const projectId = decodeURIComponent(assistantFilesMatch[1]);
          const project = await env.DB.prepare(`
            SELECT id FROM projects
            WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL
            LIMIT 1
          `).bind(projectId, access.user_id).first();
          if (!project) return json({ error: "Application introuvable." }, 404);

          const requestedPath = url.searchParams.get("path");
          if (requestedPath !== null) {
            if (!validApplicationFilePath(requestedPath)) {
              return json({ error: "Chemin de fichier non autorisé." }, 400);
            }
            const file = await env.DB.prepare(`
              SELECT file_name, content, mime_type, updated_at
              FROM application_files
              WHERE project_id = ? AND file_name = ? AND deleted_at IS NULL
              LIMIT 1
            `).bind(projectId, requestedPath).first();
            if (!file) return json({ error: "Fichier introuvable." }, 404);
            return json({ file });
          }

          const [files, directories] = await Promise.all([
            env.DB.prepare(`
              SELECT file_name, mime_type, created_at, updated_at
              FROM application_files
              WHERE project_id = ? AND deleted_at IS NULL
              ORDER BY file_name ASC
            `).bind(projectId).all(),
            env.DB.prepare(`
              SELECT directory_path, created_at
              FROM application_directories
              WHERE project_id = ? AND deleted_at IS NULL
              ORDER BY directory_path ASC
            `).bind(projectId).all()
          ]);
          return json({ files: files.results || [], directories: directories.results || [] });
        }

        return json({ error: "Route assistant introuvable." }, 404);
      } catch (error) {
        console.error("ERREUR API ASSISTANT:", error);
        return json({ error: "Impossible de traiter cette demande de lecture." }, 500);
      }
    }

    // API PUBLIQUE DES APPLICATIONS : LECTURE DES TABLES EXPLICITEMENT AUTORISÉES
    const publicApplicationDataMatch = path.match(/^\/api\/public\/applications\/([a-z0-9-]+)\/tables\/([^/]+)\/rows$/);
    if (publicApplicationDataMatch) {
      if (request.method !== "GET") {
        return json({ error: "Méthode non autorisée." }, 405);
      }
      try {
        await ensureApplicationPublicationSchema(env);
        await ensureApplicationDatabaseConnectionSchema(env);
        await ensureApplicationDatabasePermissionsSchema(env);
        await ensureCustomerDatabaseStructureSchema(env);

        const slug = publicApplicationDataMatch[1];
        const tableId = decodeURIComponent(publicApplicationDataMatch[2]);
        const publication = await env.DB.prepare(`
          SELECT publications.id, publications.project_id, publications.user_id,
                 connections.database_id
          FROM application_publications AS publications
          JOIN application_publication_versions AS versions
            ON versions.id = publications.active_version_id
           AND versions.publication_id = publications.id
          JOIN projects
            ON projects.id = publications.project_id
           AND projects.user_id = publications.user_id
           AND projects.type = 'application'
           AND projects.deleted_at IS NULL
          JOIN application_database_connections AS connections
            ON connections.project_id = publications.project_id
           AND connections.user_id = publications.user_id
          WHERE publications.slug = ?
          LIMIT 1
        `).bind(slug).first();

        if (!publication) {
          return json({ error: "Application publiée introuvable." }, 404);
        }

        const table = await env.DB.prepare(`
          SELECT tables.id, tables.name, tables.physical_name
          FROM customer_database_tables AS tables
          JOIN application_database_table_permissions AS permissions
            ON permissions.table_id = tables.id
           AND permissions.project_id = ?
           AND permissions.user_id = ?
           AND permissions.database_id = ?
           AND permissions.can_read = 1
          WHERE tables.id = ?
            AND tables.database_id = ?
            AND tables.user_id = ?
          LIMIT 1
        `).bind(
          publication.project_id, publication.user_id, publication.database_id,
          tableId, publication.database_id, publication.user_id
        ).first();

        if (!table || !safeInternalSqlIdentifier(table.physical_name)) {
          return json({ error: "Lecture publique non autorisée pour cette table." }, 403);
        }

        const columnResult = await env.DB.prepare(`
          SELECT name, data_type, physical_name, position
          FROM customer_database_columns
          WHERE table_id = ? AND database_id = ? AND user_id = ?
          ORDER BY position ASC
        `).bind(tableId, publication.database_id, publication.user_id).all();
        const columns = columnResult.results || [];
        if (columns.some(column => !safeInternalSqlIdentifier(column.physical_name))) {
          return json({ error: "Structure de colonne invalide." }, 500);
        }

        const quoteIdentifier = value => '"' + String(value).replace(/"/g, '""') + '"';
        const url = new URL(request.url);
        const limit = Math.min(50, Math.max(1, Number.parseInt(url.searchParams.get("limit") || "20", 10) || 20));
        const offset = Math.min(1000000, Math.max(0, Number.parseInt(url.searchParams.get("offset") || "0", 10) || 0));
        const selectColumns = columns.map(column =>
          quoteIdentifier(column.physical_name) + " AS " + quoteIdentifier(column.name)
        );
        const selectSql = [quoteIdentifier("row_id"), quoteIdentifier("created_at"), ...selectColumns].join(", ");
        const physicalTable = quoteIdentifier(table.physical_name);

        // Si la table possède une colonne de statut, seuls les contenus publiés
        // sont exposés par l'API publique. Les brouillons restent privés.
        const statusColumn = columns.find(column =>
          ["statut", "status"].includes(String(column.name || "").trim().toLowerCase())
        );
        const publicFilter = statusColumn
          ? " WHERE LOWER(TRIM(COALESCE(" + quoteIdentifier(statusColumn.physical_name) + ", ''))) IN ('publié', 'publie', 'published')"
          : "";
        const count = await env.DB.prepare(
          "SELECT COUNT(*) AS total FROM " + physicalTable + publicFilter
        ).first();
        const result = await env.DB.prepare(
          "SELECT " + selectSql + " FROM " + physicalTable + publicFilter +
          " ORDER BY created_at DESC, row_id DESC LIMIT ? OFFSET ?"
        ).bind(limit, offset).all();

        return json({
          table: { id: table.id, name: table.name },
          rows: result.results || [],
          total: Number(count?.total || 0),
          limit,
          offset,
          columns: columns.map(column => ({
            name: column.name,
            data_type: column.data_type
          }))
        }, 200, { "Cache-Control": "no-store" });
      } catch (error) {
        console.error("ERREUR LECTURE PUBLIQUE BASE APPLICATION:", error);
        return json({ error: "Impossible de charger les données publiques de cette application." }, 500);
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

    const limits = getPlanLimits(plan);

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
    // GESTION DES TÂCHES PROGRAMMÉES (aucune exécution dans ce lot)
    const projectAutomationTasksMatch = path.match(
      /^\/api\/projects\/([^/]+)\/automation-tasks$/
    );

    if (projectAutomationTasksMatch && ["GET", "POST"].includes(request.method)) {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);

        const projectId = decodeURIComponent(projectAutomationTasksMatch[1]);
        await ensureAutomationTasksSchema(env);

        const project = await env.DB.prepare(
          "SELECT id FROM projects WHERE id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1"
        ).bind(projectId, user.id).first();

        if (!project) return json({ error: "Projet introuvable." }, 404);

        if (request.method === "GET") {
          const result = await env.DB.prepare(`
            SELECT id, project_id, task_type, payload_json, result_json, status,
                   scheduled_at, attempts, max_attempts, last_error,
                   created_at, updated_at, completed_at, cancelled_at,
                   started_at, duration_ms, recovery_count
            FROM automation_tasks
            WHERE project_id = ? AND user_id = ?
            ORDER BY created_at DESC, scheduled_at DESC
            LIMIT 100
          `).bind(projectId, user.id).all();

          return json({
            tasks: (result.results || []).map(task => ({
              ...task,
              payload: (() => {
                try { return JSON.parse(task.payload_json || "{}"); }
                catch { return {}; }
              })(),
              result: (() => {
                try { return task.result_json ? JSON.parse(task.result_json) : null; }
                catch { return null; }
              })()
            }))
          });
        }

        const body = await readLimitedJsonBody(request);
        const taskType = String(body.task_type || "").trim();
        if (taskType !== "project_health_check") {
          return json({
            error: "Type de tâche non disponible. Le type autorisé actuellement est project_health_check."
          }, 400);
        }

        const payload = body.payload === undefined ? {} : body.payload;
        if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
          return json({ error: "Les paramètres doivent être un objet JSON." }, 400);
        }

        let payloadJson;
        try { payloadJson = JSON.stringify(payload); }
        catch { return json({ error: "Paramètres JSON invalides." }, 400); }
        if (new TextEncoder().encode(payloadJson).length > 16384) {
          return json({ error: "Les paramètres dépassent 16 Ko." }, 413);
        }

        const scheduledAtDate = new Date(body.scheduled_at);
        const scheduledAt = Math.floor(scheduledAtDate.getTime() / 1000);
        const nowSeconds = Math.floor(Date.now() / 1000);
        if (
          !Number.isFinite(scheduledAt) ||
          scheduledAt <= nowSeconds ||
          scheduledAt > nowSeconds + 365 * 24 * 60 * 60
        ) {
          return json({
            error: "La date doit être future et ne pas dépasser un an."
          }, 400);
        }

        const requestedMaxAttempts = body.max_attempts === undefined
          ? 3
          : Number(body.max_attempts);
        if (
          !Number.isInteger(requestedMaxAttempts) ||
          requestedMaxAttempts < 1 ||
          requestedMaxAttempts > 10
        ) {
          return json({ error: "Le nombre de tentatives doit être compris entre 1 et 10." }, 400);
        }

        const taskId = crypto.randomUUID();
        const inserted = await env.DB.prepare(`
          INSERT INTO automation_tasks (
            id, user_id, project_id, task_type, payload_json, status,
            scheduled_at, attempts, max_attempts, lock_token, locked_until,
            last_error, created_at, updated_at, completed_at, cancelled_at
          )
          SELECT ?, ?, ?, ?, ?, 'pending', ?, 0, ?, NULL, NULL,
                 NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, NULL, NULL
          WHERE EXISTS (
            SELECT 1 FROM projects
            WHERE id = ? AND user_id = ? AND deleted_at IS NULL
          )
          AND (
            SELECT COUNT(*) FROM automation_tasks
            WHERE project_id = ? AND user_id = ? AND status = 'pending'
          ) < 50
          AND (
            SELECT COUNT(*) FROM automation_tasks
            WHERE user_id = ? AND status = 'pending'
          ) < 200
        `).bind(
          taskId, user.id, projectId, taskType, payloadJson,
          scheduledAt, requestedMaxAttempts,
          projectId, user.id, projectId, user.id, user.id
        ).run();

        if (!inserted.meta || inserted.meta.changes !== 1) {
          const [projectStillOwned, projectPending, accountPending] = await Promise.all([
            env.DB.prepare(
              "SELECT id FROM projects WHERE id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1"
            ).bind(projectId, user.id).first(),
            env.DB.prepare(
              "SELECT COUNT(*) AS total FROM automation_tasks WHERE project_id = ? AND user_id = ? AND status = 'pending'"
            ).bind(projectId, user.id).first(),
            env.DB.prepare(
              "SELECT COUNT(*) AS total FROM automation_tasks WHERE user_id = ? AND status = 'pending'"
            ).bind(user.id).first()
          ]);
          if (!projectStillOwned) return json({ error: "Projet introuvable." }, 404);
          return json({
            error: "Limite de tâches en attente atteinte.",
            limits: { per_project: 50, per_account: 200 },
            usage: {
              project_pending: Number(projectPending?.total || 0),
              account_pending: Number(accountPending?.total || 0)
            }
          }, 429);
        }

        return json({
          message: "Vérification de projet programmée. Elle sera exécutée automatiquement par le planificateur.",
          task: {
            id: taskId,
            project_id: projectId,
            task_type: taskType,
            payload,
            status: "pending",
            scheduled_at: scheduledAt,
            attempts: 0,
            max_attempts: requestedMaxAttempts
          }
        }, 201);
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée." }, 413);
        console.error("ERREUR TÂCHES PROGRAMMÉES:", error);
        return json({ error: "Impossible de gérer les tâches du projet." }, 500);
      }
    }

    const automationTaskMatch = path.match(
      /^\/api\/automation-tasks\/([^/]+)$/
    );

    if (automationTaskMatch && request.method === "DELETE") {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);

        const taskId = decodeURIComponent(automationTaskMatch[1]);
        await ensureAutomationTasksSchema(env);

        const cancelled = await env.DB.prepare(`
          UPDATE automation_tasks
          SET status = 'cancelled',
              cancelled_at = CURRENT_TIMESTAMP,
              updated_at = CURRENT_TIMESTAMP
          WHERE id = ? AND user_id = ? AND status = 'pending'
        `).bind(taskId, user.id).run();

        if (cancelled.meta && cancelled.meta.changes === 1) {
          return json({ message: "Tâche annulée." });
        }

        const task = await env.DB.prepare(
          "SELECT id, status FROM automation_tasks WHERE id = ? AND user_id = ? LIMIT 1"
        ).bind(taskId, user.id).first();

        if (!task) return json({ error: "Tâche introuvable." }, 404);
        return json({
          error: "Seules les tâches en attente peuvent être annulées.",
          status: task.status
        }, 409);
      } catch (error) {
        console.error("ERREUR ANNULATION TÂCHE:", error);
        return json({ error: "Impossible d'annuler cette tâche." }, 500);
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
      let storageReservationId = null;
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

        const maxStorage = getPlanLimits(plan).storage_bytes;



        // Réservation atomique du quota avant le transfert vers B2.
        storageReservationId = await reserveStorageQuota(env, user.id, file.size, maxStorage);
        if (!storageReservationId) {
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
      } finally {
        if (storageReservationId) {
          try {
            await releaseStorageQuotaReservation(env, storageReservationId);
          } catch (releaseError) {
            console.error("ERREUR LIBÉRATION RÉSERVATION STOCKAGE:", releaseError);
          }
        }
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
      let storageReservationId = null;
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
        const maxStorage = getPlanLimits(plan).storage_bytes;

        // Réserver atomiquement les octets copiés et l'espace prévu pour les nouveaux fichiers.
        const bytesToReserve = cloneBytes + additionalBytes;
        if (bytesToReserve > 0) {
          storageReservationId = await reserveStorageQuota(env, user.id, bytesToReserve, maxStorage);
          if (!storageReservationId) {
            return json({ error: "Espace insuffisant pour préparer la nouvelle version du site. Il faut " +
              bytesToReserve + " octet(s) supplémentaires." }, 413);
          }
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
      } finally {
        if (storageReservationId) {
          try {
            await releaseStorageQuotaReservation(env, storageReservationId);
          } catch (releaseError) {
            console.error("ERREUR LIBÉRATION RÉSERVATION STOCKAGE:", releaseError);
          }
        }
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

        const maxProjects = getPlanLimits(plan).projects;



        const id = crypto.randomUUID();
const projectInsert = env.DB.prepare(
  `INSERT INTO projects (id, user_id, name, type, status)
   SELECT ?, ?, ?, ?, 'pending'
   WHERE (
     SELECT COUNT(*) FROM projects
     WHERE user_id = ? AND deleted_at IS NULL
   ) < ?`
).bind(id, user.id, name, type, user.id, maxProjects);

let hosting = null;

if (type === "website") {
  const hostingId = crypto.randomUUID();
  const slug = await generateWebsiteSlug(env, name);
  const hostingInsert = env.DB.prepare(`
    INSERT INTO website_hostings (
      id, user_id, project_id, slug, status
    )
    SELECT ?, ?, ?, ?, 'draft'
    WHERE EXISTS (
      SELECT 1 FROM projects
      WHERE id = ? AND user_id = ? AND deleted_at IS NULL
    )
  `).bind(hostingId, user.id, id, slug, id, user.id);

  // Les deux insertions sont atomiques ; l'hébergement n'est créé
  // que si l'insertion du projet a effectivement respecté le quota.
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

if (!project) {
  return json({
    error: `Votre forfait ${plan} autorise au maximum ${maxProjects} projet(s). Passez à une offre supérieure pour en créer davantage.`
  }, 403);
}

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
        const maxProjects = getPlanLimits(plan).projects;

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

    // APPLICATIONS : LIAISON SÉCURISÉE À UNE BASE DE DONNÉES
    const applicationDatabaseMatch = path.match(/^\/api\/projects\/([^/]+)\/application-database$/);
    if (applicationDatabaseMatch && ["GET", "PUT"].includes(request.method)) {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureApplicationDatabaseConnectionSchema(env);
        const projectId = decodeURIComponent(applicationDatabaseMatch[1]);
        const project = await env.DB.prepare(
          "SELECT id, name FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL LIMIT 1"
        ).bind(projectId, user.id).first();
        if (!project) return json({ error: "Application introuvable." }, 404);

        if (request.method === "GET") {
          const connection = await env.DB.prepare(`
            SELECT connections.database_id, databases.name AS database_name,
                   connections.created_at, connections.updated_at
            FROM application_database_connections AS connections
            JOIN customer_databases AS databases
              ON databases.id = connections.database_id
             AND databases.user_id = connections.user_id
            WHERE connections.project_id = ? AND connections.user_id = ?
            LIMIT 1
          `).bind(projectId, user.id).first();
          return json({ connection: connection || null });
        }

        const body = await readLimitedJsonBody(request);
        const databaseId = body.database_id === null || body.database_id === ""
          ? null
          : String(body.database_id || "").trim();

        if (!databaseId) {
          await env.DB.prepare(
            "DELETE FROM application_database_connections WHERE project_id = ? AND user_id = ?"
          ).bind(projectId, user.id).run();
          return json({ message: "La base de données a été déconnectée.", connection: null });
        }

        const database = await env.DB.prepare(`
          SELECT id, name, project_id
          FROM customer_databases
          WHERE id = ? AND user_id = ?
            AND (project_id IS NULL OR project_id = ?)
          LIMIT 1
        `).bind(databaseId, user.id, projectId).first();
        if (!database) {
          return json({
            error: "Base introuvable, appartenant à un autre compte ou déjà associée à un autre projet."
          }, 404);
        }

        await env.DB.prepare(`
          INSERT INTO application_database_connections
            (id, user_id, project_id, database_id)
          SELECT ?, ?, ?, ?
          WHERE EXISTS (
            SELECT 1 FROM projects
            WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL
          )
          AND EXISTS (
            SELECT 1 FROM customer_databases
            WHERE id = ? AND user_id = ?
              AND (project_id IS NULL OR project_id = ?)
          )
          ON CONFLICT(project_id) DO UPDATE SET
            database_id = excluded.database_id,
            updated_at = CURRENT_TIMESTAMP
        `).bind(
          crypto.randomUUID(), user.id, projectId, databaseId,
          projectId, user.id, databaseId, user.id, projectId
        ).run();

        const saved = await env.DB.prepare(`
          SELECT connections.database_id, databases.name AS database_name,
                 connections.created_at, connections.updated_at
          FROM application_database_connections AS connections
          JOIN customer_databases AS databases
            ON databases.id = connections.database_id
           AND databases.user_id = connections.user_id
          WHERE connections.project_id = ? AND connections.user_id = ?
          LIMIT 1
        `).bind(projectId, user.id).first();

        if (!saved) return json({ error: "La liaison n'a pas pu être enregistrée. Actualisez puis réessayez." }, 409);
        return json({
          message: "Base de données reliée à l'application.",
          connection: saved
        });
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        const message = String(error?.message || "");
        if (message.includes("UNIQUE constraint failed")) {
          return json({ error: "Cette base est déjà reliée à une autre application." }, 409);
        }
        console.error("ERREUR LIAISON BASE APPLICATION:", error);
        return json({ error: "Impossible de gérer la liaison avec cette base de données." }, 500);
      }
    }

    // APPLICATIONS : AUTORISATIONS PAR TABLE DE LA BASE RELIÉE
    const applicationDatabasePermissionsMatch = path.match(/^\/api\/projects\/([^/]+)\/application-database-permissions$/);
    if (applicationDatabasePermissionsMatch && ["GET", "PUT"].includes(request.method)) {
      try {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Vous devez être connecté." }, 401);
        await ensureApplicationDatabaseConnectionSchema(env);
        await ensureApplicationDatabasePermissionsSchema(env);
        await ensureCustomerDatabaseStructureSchema(env);
        const projectId = decodeURIComponent(applicationDatabasePermissionsMatch[1]);
        const project = await env.DB.prepare(
          "SELECT id FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL LIMIT 1"
        ).bind(projectId, user.id).first();
        if (!project) return json({ error: "Application introuvable." }, 404);

        const connection = await env.DB.prepare(`
          SELECT database_id
          FROM application_database_connections
          WHERE project_id = ? AND user_id = ?
          LIMIT 1
        `).bind(projectId, user.id).first();
        if (!connection) {
          return json({ error: "Reliez d'abord une base de données à cette application." }, 409);
        }

        if (request.method === "GET") {
          const tableResult = await env.DB.prepare(`
            SELECT tables.id, tables.name,
                   COALESCE(permissions.can_read, 0) AS can_read,
                   COALESCE(permissions.can_create, 0) AS can_create,
                   COALESCE(permissions.can_update, 0) AS can_update,
                   COALESCE(permissions.can_delete, 0) AS can_delete
            FROM customer_database_tables AS tables
            LEFT JOIN application_database_table_permissions AS permissions
              ON permissions.table_id = tables.id
             AND permissions.project_id = ?
             AND permissions.user_id = ?
             AND permissions.database_id = ?
            WHERE tables.database_id = ? AND tables.user_id = ?
            ORDER BY tables.created_at ASC, tables.name COLLATE NOCASE ASC
          `).bind(
            projectId, user.id, connection.database_id,
            connection.database_id, user.id
          ).all();
          return json({
            database_id: connection.database_id,
            tables: (tableResult.results || []).map(table => ({
              id: table.id,
              name: table.name,
              permissions: {
                read: Number(table.can_read) === 1,
                create: Number(table.can_create) === 1,
                update: Number(table.can_update) === 1,
                delete: Number(table.can_delete) === 1
              }
            }))
          });
        }

        const body = await readLimitedJsonBody(request);
        if (!Array.isArray(body.permissions) || body.permissions.length > 200) {
          return json({ error: "La liste des autorisations est invalide (200 tables maximum)." }, 400);
        }
        const seenTableIds = new Set();
        const normalized = [];
        for (const item of body.permissions) {
          if (!item || typeof item !== "object" || Array.isArray(item)) {
            return json({ error: "Une autorisation de table est invalide." }, 400);
          }
          const tableId = String(item.table_id || "").trim();
          if (!tableId || seenTableIds.has(tableId)) {
            return json({ error: "Identifiant de table manquant ou répété." }, 400);
          }
          seenTableIds.add(tableId);
          for (const key of ["read", "create", "update", "delete"]) {
            if (typeof item[key] !== "boolean") {
              return json({ error: "Chaque autorisation doit être un booléen explicite." }, 400);
            }
          }
          normalized.push({
            table_id: tableId,
            read: item.read,
            create: item.create,
            update: item.update,
            delete: item.delete
          });
        }

        if (normalized.length) {
          const placeholders = normalized.map(() => "?").join(",");
          const ownedTables = await env.DB.prepare(
            "SELECT id FROM customer_database_tables WHERE database_id = ? AND user_id = ? AND id IN (" + placeholders + ")"
          ).bind(connection.database_id, user.id, ...normalized.map(item => item.table_id)).all();
          if ((ownedTables.results || []).length !== normalized.length) {
            return json({ error: "Une ou plusieurs tables ne font pas partie de la base reliée." }, 400);
          }
        }

        const statements = [
          env.DB.prepare(
            "DELETE FROM application_database_table_permissions WHERE project_id = ? AND user_id = ?"
          ).bind(projectId, user.id)
        ];
        for (const item of normalized) {
          if (!item.read && !item.create && !item.update && !item.delete) continue;
          statements.push(env.DB.prepare(`
            INSERT INTO application_database_table_permissions
              (id, user_id, project_id, database_id, table_id, can_read, can_create, can_update, can_delete)
            SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?
            WHERE EXISTS (
              SELECT 1 FROM application_database_connections
              WHERE project_id = ? AND user_id = ? AND database_id = ?
            )
            AND EXISTS (
              SELECT 1 FROM customer_database_tables
              WHERE id = ? AND database_id = ? AND user_id = ?
            )
          `).bind(
            crypto.randomUUID(), user.id, projectId, connection.database_id, item.table_id,
            item.read ? 1 : 0, item.create ? 1 : 0, item.update ? 1 : 0, item.delete ? 1 : 0,
            projectId, user.id, connection.database_id,
            item.table_id, connection.database_id, user.id
          ));
        }
        await env.DB.batch(statements);
        return json({ message: "Autorisations enregistrées. Elles restent inactives tant que l'accès runtime sécurisé n'est pas activé." });
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        console.error("ERREUR AUTORISATIONS BASE APPLICATION:", error);
        return json({ error: "Impossible d'enregistrer les autorisations de la base." }, 500);
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
        const [directoryRows, fileRows] = await Promise.all([
          env.DB.prepare("SELECT directory_path, deleted_at FROM application_directories WHERE project_id = ?")
            .bind(projectId).all(),
          env.DB.prepare("SELECT file_name, deleted_at FROM application_files WHERE project_id = ?")
            .bind(projectId).all()
        ]);
        const directories = directoryRows.results || [];
        const files = fileRows.results || [];

        // Les chemins supprimés restent réservés par les contraintes UNIQUE.
        // Ne pas créer à l'identique d'un dossier supprimé ni sous un parent
        // supprimé ou un fichier placé dans la corbeille.
        for (const candidate of paths) {
          const trashedDirectory = directories.find(row =>
            row.deleted_at && (candidate === row.directory_path || candidate.startsWith(row.directory_path + "/"))
          );
          if (trashedDirectory) {
            return json({ error: "Un dossier situé dans la corbeille réserve ce chemin : " + trashedDirectory.directory_path + ". Restaurez-le ou videz-le avant de continuer." }, 409);
          }
          const trashedFile = files.find(row =>
            row.deleted_at && (candidate === row.file_name || candidate.startsWith(row.file_name + "/"))
          );
          if (trashedFile) {
            return json({ error: "Un fichier situé dans la corbeille bloque ce chemin : " + trashedFile.file_name + "." }, 409);
          }
        }

        const statements = paths.map(directory => env.DB.prepare(
          "INSERT OR IGNORE INTO application_directories (id, project_id, directory_path) SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL)"
        ).bind(crypto.randomUUID(), projectId, directory, projectId, user.id));
        await env.DB.batch(statements);

        const savedDirectories = await env.DB.prepare(
          "SELECT directory_path FROM application_directories WHERE project_id = ? AND deleted_at IS NULL"
        ).bind(projectId).all();
        const savedPaths = new Set((savedDirectories.results || []).map(item => item.directory_path));
        if (paths.some(directory => !savedPaths.has(directory))) {
          return json({ error: "Le dossier n'a pas pu être créé intégralement. Aucun succès n'a été confirmé." }, 409);
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
        if (!validApplicationFilePath(fileName)) {
          return json({ error: "Nom ou chemin de fichier non autorisé." }, 400);
        }

        const [fileRows, directoryRows] = await Promise.all([
          env.DB.prepare("SELECT file_name, deleted_at FROM application_files WHERE project_id = ?")
            .bind(projectId).all(),
          env.DB.prepare("SELECT directory_path, deleted_at FROM application_directories WHERE project_id = ?")
            .bind(projectId).all()
        ]);
        const files = fileRows.results || [];
        const directories = directoryRows.results || [];

        const existingFile = files.find(row => row.file_name === fileName);
        if (existingFile) {
          return json({
            error: existingFile.deleted_at
              ? "Ce fichier existe dans la corbeille. Restaurez-le ou videz la corbeille avant de réutiliser ce chemin."
              : "Ce fichier existe déjà."
          }, 409);
        }

        const existingDirectory = directories.find(row => row.directory_path === fileName);
        if (existingDirectory) {
          return json({
            error: existingDirectory.deleted_at
              ? "Un dossier situé dans la corbeille réserve ce chemin."
              : "Un dossier porte déjà ce nom."
          }, 409);
        }

        const parentParts = fileName.split("/").slice(0, -1);
        const parentPaths = parentParts.map((_, index) => parentParts.slice(0, index + 1).join("/"));
        for (const candidate of parentPaths) {
          const blockingFile = files.find(row =>
            candidate === row.file_name || candidate.startsWith(row.file_name + "/")
          );
          if (blockingFile) {
            return json({
              error: (blockingFile.deleted_at ? "Un fichier dans la corbeille" : "Un fichier") +
                " bloque ce dossier parent : " + blockingFile.file_name + "."
            }, 409);
          }
          const trashedDirectory = directories.find(row =>
            row.deleted_at && (candidate === row.directory_path || candidate.startsWith(row.directory_path + "/"))
          );
          if (trashedDirectory) {
            return json({
              error: "Un dossier situé dans la corbeille réserve ce chemin : " +
                trashedDirectory.directory_path + ". Restaurez-le ou videz-le avant de continuer."
            }, 409);
          }
        }

        const trashedDirectoryAncestor = directories.find(row =>
          row.deleted_at && (fileName === row.directory_path || fileName.startsWith(row.directory_path + "/"))
        );
        if (trashedDirectoryAncestor) {
          return json({
            error: "Un dossier situé dans la corbeille réserve ce chemin : " +
              trashedDirectoryAncestor.directory_path + ". Restaurez-le ou videz-le avant de continuer."
          }, 409);
        }

        const descendantFile = files.find(row => row.file_name.startsWith(fileName + "/"));
        if (descendantFile) {
          return json({
            error: "Un fichier existe déjà sous ce chemin : " + descendantFile.file_name + "."
          }, 409);
        }
        const descendantDirectory = directories.find(row => row.directory_path.startsWith(fileName + "/"));
        if (descendantDirectory) {
          return json({
            error: "Un dossier existe déjà sous ce chemin : " + descendantDirectory.directory_path + "."
          }, 409);
        }

        const count = await env.DB.prepare(
          "SELECT COUNT(*) AS total FROM application_files WHERE project_id = ?"
        ).bind(projectId).first();
        if (Number(count?.total || 0) >= 50) {
          return json({ error: "Cette application est limitée à 50 fichiers pour le moment." }, 413);
        }

        const mimeType = applicationFileMimeType(fileName);
        const fileId = crypto.randomUUID();
        const versionId = crypto.randomUUID();
        const statements = parentPaths.map(directory => env.DB.prepare(
          "INSERT OR IGNORE INTO application_directories (id, project_id, directory_path) SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL) AND NOT EXISTS (SELECT 1 FROM application_directories WHERE project_id = ? AND deleted_at IS NOT NULL AND (? = directory_path OR ? LIKE directory_path || '/%')) AND NOT EXISTS (SELECT 1 FROM application_files WHERE project_id = ? AND (? = file_name OR ? LIKE file_name || '/%'))"
        ).bind(
          crypto.randomUUID(), projectId, directory, projectId, user.id,
          projectId, directory, directory, projectId, directory, directory
        ));

        const parentConditions = parentPaths.map(() =>
          "AND EXISTS (SELECT 1 FROM application_directories WHERE project_id = ? AND directory_path = ? AND deleted_at IS NULL)"
        ).join(" ");
        const fileInsertSql =
          "INSERT INTO application_files (id, project_id, file_name, content, mime_type) " +
          "SELECT ?, ?, ?, '', ? WHERE EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL) " +
          "AND NOT EXISTS (SELECT 1 FROM application_files WHERE project_id = ? AND file_name = ?) " +
          "AND NOT EXISTS (SELECT 1 FROM application_files WHERE project_id = ? AND ? LIKE file_name || '/%') " +
          "AND NOT EXISTS (SELECT 1 FROM application_directories WHERE project_id = ? AND (directory_path = ? OR directory_path LIKE ? || '/%')) " +
          "AND NOT EXISTS (SELECT 1 FROM application_directories WHERE project_id = ? AND deleted_at IS NOT NULL AND (? = directory_path OR ? LIKE directory_path || '/%')) " +
          parentConditions;
        const fileInsertValues = [
          fileId, projectId, fileName, mimeType, projectId, user.id,
          projectId, fileName, projectId, fileName,
          projectId, fileName, fileName,
          projectId, fileName, fileName
        ];
        for (const directory of parentPaths) {
          fileInsertValues.push(projectId, directory);
        }
        statements.push(
          env.DB.prepare(fileInsertSql).bind(...fileInsertValues),
          env.DB.prepare(
            "INSERT INTO application_file_versions (id, project_id, file_name, version_number, content, mime_type) SELECT ?, ?, ?, 1, '', ? WHERE EXISTS (SELECT 1 FROM application_files WHERE id = ? AND project_id = ?)"
          ).bind(versionId, projectId, fileName, mimeType, fileId, projectId)
        );

        await env.DB.batch(statements);

        const [savedFile, savedVersion, savedDirectories] = await Promise.all([
          env.DB.prepare("SELECT id FROM application_files WHERE id = ? AND project_id = ? AND deleted_at IS NULL")
            .bind(fileId, projectId).first(),
          env.DB.prepare("SELECT id FROM application_file_versions WHERE id = ? AND project_id = ? AND deleted_at IS NULL")
            .bind(versionId, projectId).first(),
          parentPaths.length
            ? env.DB.prepare("SELECT directory_path FROM application_directories WHERE project_id = ? AND deleted_at IS NULL")
                .bind(projectId).all()
            : Promise.resolve({ results: [] })
        ]);

        const savedPaths = new Set((savedDirectories.results || []).map(row => row.directory_path));
        if (!savedFile || !savedVersion || parentPaths.some(directory => !savedPaths.has(directory))) {
          return json({
            error: "Le chemin est déjà réservé ou la création complète du fichier n'a pas pu être confirmée."
          }, 409);
        }

        return json({ message: "Fichier créé.", file_name: fileName, version_number: 1 }, 201);
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        if (String(error?.message || "").toLowerCase().includes("unique")) {
          return json({ error: "Ce chemin vient d'être utilisé ou réservé. Actualisez l'explorateur avant de réessayer." }, 409);
        }
        console.error("ERREUR CRÉATION FICHIER APPLICATION:", error);
        return json({ error: "Impossible de créer le fichier." }, 500);
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
          "SELECT id, content, mime_type, version_number FROM application_file_versions WHERE id = ? AND project_id = ? AND file_name = ? AND deleted_at IS NULL LIMIT 1"
        ).bind(versionId, projectId, fileName).first();
        if (!version) return json({ error: "Cette version est introuvable ou se trouve dans la corbeille." }, 404);
        const trashedFile = await env.DB.prepare(
          "SELECT id FROM application_files WHERE project_id = ? AND file_name = ? AND deleted_at IS NOT NULL LIMIT 1"
        ).bind(projectId, fileName).first();
        if (trashedFile) {
          return json({ error: "Ce fichier se trouve dans la corbeille. Restaurez-le avant de restaurer une ancienne version." }, 409);
        }
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
            "INSERT INTO application_files (id, project_id, file_name, content, mime_type, created_at, updated_at) SELECT ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP WHERE EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL) AND NOT EXISTS (SELECT 1 FROM application_files WHERE project_id = ? AND file_name = ? AND deleted_at IS NOT NULL) ON CONFLICT(project_id, file_name) DO UPDATE SET content = excluded.content, mime_type = excluded.mime_type, updated_at = CURRENT_TIMESTAMP"
          ).bind(crypto.randomUUID(), projectId, fileName, version.content, version.mime_type, projectId, user.id, projectId, fileName),
          env.DB.prepare(
            "INSERT INTO application_file_versions (id, project_id, file_name, version_number, content, mime_type) SELECT ?, ?, ?, COALESCE(MAX(version_number), 0) + 1, ?, ? FROM application_file_versions WHERE project_id = ? AND file_name = ? AND EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL) AND NOT EXISTS (SELECT 1 FROM application_files WHERE project_id = ? AND file_name = ? AND deleted_at IS NOT NULL)"
          ).bind(restoredVersionId, projectId, fileName, version.content, version.mime_type, projectId, fileName, projectId, user.id, projectId, fileName),
          env.DB.prepare(
            "DELETE FROM application_file_versions WHERE project_id = ? AND file_name = ? AND version_number NOT IN (SELECT version_number FROM application_file_versions WHERE project_id = ? AND file_name = ? ORDER BY version_number DESC LIMIT 30) AND EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL)"
          ).bind(projectId, fileName, projectId, fileName, projectId, user.id)
        ]);
        const restoredVersion = await env.DB.prepare(
          "SELECT version_number FROM application_file_versions WHERE id = ? AND project_id = ? AND file_name = ? AND deleted_at IS NULL LIMIT 1"
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
        const [items, fileCounts, directoryCounts] = await Promise.all([
          env.DB.prepare("SELECT id, item_type, original_path, deleted_at FROM application_trash_items WHERE project_id = ? ORDER BY deleted_at DESC").bind(projectId).all(),
          env.DB.prepare("SELECT trash_id, COUNT(*) AS total FROM application_files WHERE project_id = ? AND trash_id IS NOT NULL GROUP BY trash_id").bind(projectId).all(),
          env.DB.prepare("SELECT trash_id, COUNT(*) AS total FROM application_directories WHERE project_id = ? AND trash_id IS NOT NULL GROUP BY trash_id").bind(projectId).all()
        ]);
        const fileCountByTrashId = new Map((fileCounts.results || []).map(row => [row.trash_id, Number(row.total || 0)]));
        const directoryCountByTrashId = new Map((directoryCounts.results || []).map(row => [row.trash_id, Number(row.total || 0)]));
        const result = (items.results || []).map(item => ({
          ...item,
          file_count: fileCountByTrashId.get(item.id) || 0,
          directory_count: directoryCountByTrashId.get(item.id) || 0
        }));
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
        let expectedFileIds = [];
        let expectedVersionIds = [];
        let expectedDirectoryIds = [];

        if (itemType === "file") {
          const [file, versions] = await Promise.all([
            env.DB.prepare("SELECT id FROM application_files WHERE project_id = ? AND file_name = ? AND deleted_at IS NULL LIMIT 1").bind(projectId, itemPath).first(),
            env.DB.prepare("SELECT id FROM application_file_versions WHERE project_id = ? AND file_name = ? AND deleted_at IS NULL").bind(projectId, itemPath).all()
          ]);
          if (!file) return json({ error: "Fichier introuvable." }, 404);
          expectedFileIds = [file.id];
          expectedVersionIds = (versions.results || []).map(row => row.id);
          await env.DB.batch([
            env.DB.prepare("INSERT INTO application_trash_items (id, project_id, item_type, original_path) SELECT ?, ?, 'file', ? WHERE EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL) AND EXISTS (SELECT 1 FROM application_files WHERE project_id = ? AND file_name = ? AND deleted_at IS NULL)").bind(trashId, projectId, itemPath, projectId, user.id, projectId, itemPath),
            env.DB.prepare("UPDATE application_files SET deleted_at = CURRENT_TIMESTAMP, trash_id = ? WHERE project_id = ? AND file_name = ? AND deleted_at IS NULL").bind(trashId, projectId, itemPath),
            env.DB.prepare("UPDATE application_file_versions SET deleted_at = CURRENT_TIMESTAMP, trash_id = ? WHERE project_id = ? AND file_name = ? AND deleted_at IS NULL").bind(trashId, projectId, itemPath)
          ]);
        } else {
          const [directories, files, versions] = await Promise.all([
            env.DB.prepare("SELECT id, directory_path FROM application_directories WHERE project_id = ? AND deleted_at IS NULL AND (directory_path = ? OR substr(directory_path, 1, ?) = ?)").bind(projectId, itemPath, itemPath.length + 1, itemPath + "/").all(),
            env.DB.prepare("SELECT id, file_name FROM application_files WHERE project_id = ? AND deleted_at IS NULL AND substr(file_name, 1, ?) = ?").bind(projectId, itemPath.length + 1, itemPath + "/").all(),
            env.DB.prepare("SELECT id, file_name FROM application_file_versions WHERE project_id = ? AND deleted_at IS NULL AND substr(file_name, 1, ?) = ?").bind(projectId, itemPath.length + 1, itemPath + "/").all()
          ]);
          expectedDirectoryIds = (directories.results || []).map(row => row.id);
          expectedFileIds = (files.results || []).map(row => row.id);
          expectedVersionIds = (versions.results || []).map(row => row.id);
          if (!expectedDirectoryIds.length && !expectedFileIds.length) {
            return json({ error: "Dossier introuvable ou déjà dans la corbeille." }, 404);
          }
          await env.DB.batch([
            env.DB.prepare("INSERT INTO application_trash_items (id, project_id, item_type, original_path) SELECT ?, ?, 'folder', ? WHERE EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL) AND (EXISTS (SELECT 1 FROM application_directories WHERE project_id = ? AND deleted_at IS NULL AND (directory_path = ? OR substr(directory_path, 1, ?) = ?)) OR EXISTS (SELECT 1 FROM application_files WHERE project_id = ? AND deleted_at IS NULL AND substr(file_name, 1, ?) = ?))").bind(trashId, projectId, itemPath, projectId, user.id, projectId, itemPath, itemPath.length + 1, itemPath + "/", projectId, itemPath.length + 1, itemPath + "/"),
            env.DB.prepare("UPDATE application_directories SET deleted_at = CURRENT_TIMESTAMP, trash_id = ? WHERE project_id = ? AND deleted_at IS NULL AND (directory_path = ? OR substr(directory_path, 1, ?) = ?)").bind(trashId, projectId, itemPath, itemPath.length + 1, itemPath + "/"),
            env.DB.prepare("UPDATE application_files SET deleted_at = CURRENT_TIMESTAMP, trash_id = ? WHERE project_id = ? AND deleted_at IS NULL AND substr(file_name, 1, ?) = ?").bind(trashId, projectId, itemPath.length + 1, itemPath + "/"),
            env.DB.prepare("UPDATE application_file_versions SET deleted_at = CURRENT_TIMESTAMP, trash_id = ? WHERE project_id = ? AND deleted_at IS NULL AND substr(file_name, 1, ?) = ?").bind(trashId, projectId, itemPath.length + 1, itemPath + "/")
          ]);
        }

        // Confirmer que chaque ligne repérée avant le déplacement porte bien le même identifiant de corbeille.
        const [trashItem, movedFiles, movedVersions, movedDirectories] = await Promise.all([
          env.DB.prepare("SELECT id FROM application_trash_items WHERE id = ? AND project_id = ? AND item_type = ? AND original_path = ? LIMIT 1").bind(trashId, projectId, itemType, itemPath).first(),
          env.DB.prepare("SELECT id FROM application_files WHERE project_id = ? AND trash_id = ? AND deleted_at IS NOT NULL").bind(projectId, trashId).all(),
          env.DB.prepare("SELECT id FROM application_file_versions WHERE project_id = ? AND trash_id = ? AND deleted_at IS NOT NULL").bind(projectId, trashId).all(),
          env.DB.prepare("SELECT id FROM application_directories WHERE project_id = ? AND trash_id = ? AND deleted_at IS NOT NULL").bind(projectId, trashId).all()
        ]);
        const sameIds = (expected, actual) => {
          const actualIds = (actual.results || []).map(row => row.id);
          return expected.length === actualIds.length && expected.every(id => actualIds.includes(id));
        };
        if (!trashItem || !sameIds(expectedFileIds, movedFiles) ||
            !sameIds(expectedVersionIds, movedVersions) ||
            !sameIds(expectedDirectoryIds, movedDirectories)) {
          return json({
            error: "Le déplacement n'a pas pu être entièrement confirmé. L'élément reste récupérable dans la corbeille ; actualisez la liste avant de réessayer."
          }, 409);
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
        const project = await env.DB.prepare(
          "SELECT id FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL LIMIT 1"
        ).bind(projectId, user.id).first();
        if (!project) return json({ error: "Application introuvable." }, 404);

        const item = await env.DB.prepare(
          "SELECT id, item_type, original_path FROM application_trash_items WHERE id = ? AND project_id = ? LIMIT 1"
        ).bind(trashId, projectId).first();
        if (!item) return json({ error: "Élément introuvable dans la corbeille ou déjà restauré." }, 404);
        if (!["file", "folder"].includes(item.item_type) || !item.original_path) {
          return json({ error: "Les informations de cet élément de corbeille sont invalides." }, 409);
        }

        const [filesResult, directoriesResult, versionsResult, activeFilesResult, activeDirectoriesResult] = await Promise.all([
          env.DB.prepare(
            "SELECT file_name FROM application_files WHERE project_id = ? AND trash_id = ? AND deleted_at IS NOT NULL"
          ).bind(projectId, trashId).all(),
          env.DB.prepare(
            "SELECT directory_path FROM application_directories WHERE project_id = ? AND trash_id = ? AND deleted_at IS NOT NULL"
          ).bind(projectId, trashId).all(),
          env.DB.prepare(
            "SELECT id, file_name FROM application_file_versions WHERE project_id = ? AND trash_id = ? AND deleted_at IS NOT NULL"
          ).bind(projectId, trashId).all(),
          env.DB.prepare(
            "SELECT file_name FROM application_files WHERE project_id = ? AND deleted_at IS NULL"
          ).bind(projectId).all(),
          env.DB.prepare(
            "SELECT directory_path FROM application_directories WHERE project_id = ? AND deleted_at IS NULL"
          ).bind(projectId).all()
        ]);

        const restoredFiles = (filesResult.results || []).map(row => row.file_name);
        const restoredDirectories = (directoriesResult.results || []).map(row => row.directory_path);
        const restoredVersionIds = (versionsResult.results || []).map(row => row.id);
        const restoredVersionPaths = (versionsResult.results || []).map(row => row.file_name);
        const activeFiles = (activeFilesResult.results || []).map(row => row.file_name);
        const activeDirectories = (activeDirectoriesResult.results || []).map(row => row.directory_path);
        const isSameOrBelow = (candidate, parent) => candidate === parent || candidate.startsWith(parent + "/");
        const requiredParentPaths = new Set();
        const addParentPaths = filePath => {
          const segments = String(filePath || "").split("/").filter(Boolean);
          for (let index = 1; index < segments.length; index++) {
            requiredParentPaths.add(segments.slice(0, index).join("/"));
          }
        };
        for (const filePath of restoredFiles) addParentPaths(filePath);
        for (const directoryPath of restoredDirectories) addParentPaths(directoryPath);
        addParentPaths(item.original_path);
        const requiredParentPathList = [...requiredParentPaths];

        if (item.item_type === "file") {
          if (restoredFiles.length !== 1 || restoredFiles[0] !== item.original_path || restoredDirectories.length) {
            return json({ error: "Le contenu de cet élément de corbeille est incomplet ou incohérent." }, 409);
          }
          if (restoredVersionPaths.some(fileName => fileName !== item.original_path)) {
            return json({ error: "L'historique de ce fichier contient un chemin incohérent." }, 409);
          }
        } else {
          const validFolderFiles = restoredFiles.every(fileName => fileName.startsWith(item.original_path + "/"));
          const validFolderDirectories = restoredDirectories.every(directoryPath => isSameOrBelow(directoryPath, item.original_path));
          const validFolderVersions = restoredVersionPaths.every(fileName => fileName.startsWith(item.original_path + "/"));
          if ((!restoredFiles.length && !restoredDirectories.length) || !validFolderFiles || !validFolderDirectories || !validFolderVersions) {
            return json({ error: "Le contenu de ce dossier dans la corbeille est incomplet ou incohérent." }, 409);
          }
        }

        if (restoredVersionIds.length && restoredVersionPaths.some(fileName => !restoredFiles.includes(fileName))) {
          return json({ error: "L'historique contient une version sans fichier correspondant." }, 409);
        }

        if (requiredParentPathList.length) {
          const deletedParent = await env.DB.prepare(
            "SELECT directory_path FROM application_directories WHERE project_id = ? AND directory_path IN (SELECT value FROM json_each(?)) AND deleted_at IS NOT NULL AND (trash_id IS NULL OR trash_id != ?) LIMIT 1"
          ).bind(projectId, JSON.stringify(requiredParentPathList), trashId).first();
          if (deletedParent) {
            return json({
              error: "Un dossier parent nécessaire est encore dans la corbeille. Restaurez d'abord ce dossier parent, puis réessayez."
            }, 409);
          }
        }

        // Première vérification lisible pour fournir un message précis avant écriture.
        let pathConflict = false;
        for (const activePath of activeFiles) {
          if (restoredFiles.some(restoredPath =>
            activePath === restoredPath ||
            isSameOrBelow(restoredPath, activePath) ||
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
            ) || restoredDirectories.includes(activePath)) {
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

        // Le même garde-fou SQL est réévalué dans le batch atomique.
        // Les lignes du lot en cours sont exclues des conflits grâce à leur trash_id.
        const restoreGuardSql = [
          "EXISTS (SELECT 1 FROM application_trash_items ti WHERE ti.id = ? AND ti.project_id = ? AND ti.item_type = ? AND ti.original_path = ?)",
          "AND NOT EXISTS (",
          "SELECT 1 FROM application_files af",
          "WHERE af.project_id = ? AND af.deleted_at IS NULL AND (af.trash_id IS NULL OR af.trash_id != ?)",
          "AND (",
          "EXISTS (SELECT 1 FROM application_files rf WHERE rf.project_id = ? AND rf.trash_id = ? AND rf.deleted_at IS NOT NULL AND (af.file_name = rf.file_name OR substr(rf.file_name, 1, length(af.file_name) + 1) = af.file_name || '/' OR substr(af.file_name, 1, length(rf.file_name) + 1) = rf.file_name || '/'))",
          "OR EXISTS (SELECT 1 FROM application_directories rd WHERE rd.project_id = ? AND rd.trash_id = ? AND rd.deleted_at IS NOT NULL AND (af.file_name = rd.directory_path OR substr(rd.directory_path, 1, length(af.file_name) + 1) = af.file_name || '/'))",
          "))",
          "AND NOT EXISTS (",
          "SELECT 1 FROM application_directories ad",
          "WHERE ad.project_id = ? AND ad.deleted_at IS NULL AND (ad.trash_id IS NULL OR ad.trash_id != ?)",
          "AND (",
          "EXISTS (SELECT 1 FROM application_files rf WHERE rf.project_id = ? AND rf.trash_id = ? AND rf.deleted_at IS NOT NULL AND (ad.directory_path = rf.file_name OR substr(ad.directory_path, 1, length(rf.file_name) + 1) = rf.file_name || '/'))",
          "OR EXISTS (SELECT 1 FROM application_directories rd WHERE rd.project_id = ? AND rd.trash_id = ? AND rd.deleted_at IS NOT NULL AND ad.directory_path = rd.directory_path)",
          "))",
          "AND NOT EXISTS (",
          "SELECT 1 FROM application_directories pd",
          "WHERE pd.project_id = ? AND pd.directory_path IN (SELECT value FROM json_each(?))",
          "AND pd.deleted_at IS NOT NULL AND (pd.trash_id IS NULL OR pd.trash_id != ?)",
          ")"
        ].join(" ");
        const restoreGuardBindings = () => [
          trashId, projectId, item.item_type, item.original_path,
          projectId, trashId,
          projectId, trashId, projectId, trashId,
          projectId, trashId,
          projectId, trashId, projectId, trashId,
          projectId, JSON.stringify(requiredParentPathList), trashId
        ];

        const postRestoreGuardSql = [
          "EXISTS (SELECT 1 FROM application_trash_items WHERE id = ? AND project_id = ?)"
        ].join(" ");
        const postRestoreGuardBindings = () => [
          trashId, projectId
        ];

        await env.DB.batch([
          env.DB.prepare(
            "UPDATE application_files SET deleted_at = NULL WHERE project_id = ? AND trash_id = ? AND deleted_at IS NOT NULL AND (" + restoreGuardSql + ")"
          ).bind(projectId, trashId, ...restoreGuardBindings()),
          env.DB.prepare(
            "UPDATE application_file_versions SET deleted_at = NULL WHERE project_id = ? AND trash_id = ? AND deleted_at IS NOT NULL AND (" + restoreGuardSql + ")"
          ).bind(projectId, trashId, ...restoreGuardBindings()),
          env.DB.prepare(
            "UPDATE application_directories SET deleted_at = NULL WHERE project_id = ? AND trash_id = ? AND deleted_at IS NOT NULL AND (" + restoreGuardSql + ")"
          ).bind(projectId, trashId, ...restoreGuardBindings()),
          env.DB.prepare(
            "UPDATE application_files SET trash_id = NULL WHERE project_id = ? AND trash_id = ? AND deleted_at IS NULL AND (" + postRestoreGuardSql + ")"
          ).bind(projectId, trashId, ...postRestoreGuardBindings()),
          env.DB.prepare(
            "UPDATE application_file_versions SET trash_id = NULL WHERE project_id = ? AND trash_id = ? AND deleted_at IS NULL AND (" + postRestoreGuardSql + ")"
          ).bind(projectId, trashId, ...postRestoreGuardBindings()),
          env.DB.prepare(
            "UPDATE application_directories SET trash_id = NULL WHERE project_id = ? AND trash_id = ? AND deleted_at IS NULL AND (" + postRestoreGuardSql + ")"
          ).bind(projectId, trashId, ...postRestoreGuardBindings()),
          env.DB.prepare(
            "DELETE FROM application_trash_items WHERE id = ? AND project_id = ? AND NOT EXISTS (SELECT 1 FROM application_files WHERE project_id = ? AND trash_id = ?) AND NOT EXISTS (SELECT 1 FROM application_file_versions WHERE project_id = ? AND trash_id = ?) AND NOT EXISTS (SELECT 1 FROM application_directories WHERE project_id = ? AND trash_id = ?)"
          ).bind(trashId, projectId, projectId, trashId, projectId, trashId, projectId, trashId)
        ]);

        // Relecture après transaction : aucune réussite n'est annoncée si un élément manque.
        const [remainingTrashItem, activeFilesAfter, activeDirectoriesAfter, activeVersionsAfter] = await Promise.all([
          env.DB.prepare(
            "SELECT id FROM application_trash_items WHERE id = ? AND project_id = ? LIMIT 1"
          ).bind(trashId, projectId).first(),
          restoredFiles.length
            ? env.DB.prepare("SELECT COUNT(*) AS total FROM application_files WHERE project_id = ? AND deleted_at IS NULL AND file_name IN (SELECT value FROM json_each(?))").bind(projectId, JSON.stringify(restoredFiles)).first()
            : Promise.resolve({ total: 0 }),
          restoredDirectories.length
            ? env.DB.prepare("SELECT COUNT(*) AS total FROM application_directories WHERE project_id = ? AND deleted_at IS NULL AND directory_path IN (SELECT value FROM json_each(?))").bind(projectId, JSON.stringify(restoredDirectories)).first()
            : Promise.resolve({ total: 0 }),
          restoredVersionIds.length
            ? env.DB.prepare("SELECT COUNT(*) AS total FROM application_file_versions WHERE project_id = ? AND deleted_at IS NULL AND id IN (SELECT value FROM json_each(?))").bind(projectId, JSON.stringify(restoredVersionIds)).first()
            : Promise.resolve({ total: 0 })
        ]);

        const filesRestored = Number(activeFilesAfter?.total || 0) === restoredFiles.length;
        const directoriesRestored = Number(activeDirectoriesAfter?.total || 0) === restoredDirectories.length;
        const versionsRestored = Number(activeVersionsAfter?.total || 0) === restoredVersionIds.length;
        if (remainingTrashItem || !filesRestored || !directoriesRestored || !versionsRestored) {
          return json({
            error: "La restauration n'a pas été confirmée. L'élément est conservé dans la corbeille ; actualisez puis réessayez."
          }, 409);
        }

        return json({ message: "Élément restauré avec son contenu et son historique." });
      } catch (error) {
        if (error?.status === 413) return json({ error: "La requête JSON dépasse la limite autorisée de 4 Mo." }, 413);
        const errorMessage = String(error?.message || "");
        if (errorMessage.includes("UNIQUE constraint failed")) {
          return json({ error: "Un conflit de chemin empêche la restauration. Renommez l'élément concerné puis réessayez." }, 409);
        }
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
        const parentParts = parent ? parent.split("/") : [];
        const parentPaths = parentParts.map((_, index) => parentParts.slice(0, index + 1).join("/"));
        if (parent && files.includes(parent) && !movingFileSet.has(parent)) {
          return json({ error: "Un fichier bloque le dossier parent du nouveau chemin." }, 409);
        }
        const trashedParent = (directoryRows.results || []).find(row =>
          row.deleted_at && parentPaths.includes(row.directory_path)
        );
        if (trashedParent) {
          return json({
            error: "Un dossier parent de destination est dans la corbeille : " +
              trashedParent.directory_path + ". Restaurez-le avant de renommer cet élément."
          }, 409);
        }

        const versionRows = await env.DB.prepare(
          "SELECT id FROM application_file_versions WHERE project_id = ? AND deleted_at IS NULL AND file_name IN (SELECT value FROM json_each(?))"
        ).bind(projectId, JSON.stringify(movingFiles)).all();
        const expectedVersionCount = (versionRows.results || []).length;
        const parentGuardSql =
          "AND NOT EXISTS (SELECT 1 FROM application_directories pd WHERE pd.project_id = ? AND pd.deleted_at IS NOT NULL AND pd.directory_path IN (SELECT value FROM json_each(?)))";
        const parentGuardBindings = () => [projectId, JSON.stringify(parentPaths)];

        if (itemType === "file") {
          await env.DB.batch([
            env.DB.prepare("UPDATE application_files SET file_name = ?, mime_type = ?, updated_at = CURRENT_TIMESTAMP WHERE project_id = ? AND file_name = ? AND deleted_at IS NULL " + parentGuardSql)
              .bind(newPath, applicationFileMimeType(newPath), projectId, oldPath, ...parentGuardBindings()),
            env.DB.prepare("UPDATE application_file_versions SET file_name = ?, mime_type = ? WHERE project_id = ? AND file_name = ? AND deleted_at IS NULL " + parentGuardSql)
              .bind(newPath, applicationFileMimeType(newPath), projectId, oldPath, ...parentGuardBindings())
          ]);
        } else {
          await env.DB.batch([
            env.DB.prepare("UPDATE application_directories SET directory_path = ? WHERE project_id = ? AND directory_path = ? AND deleted_at IS NULL " + parentGuardSql)
              .bind(newPath, projectId, oldPath, ...parentGuardBindings()),
            env.DB.prepare("UPDATE application_directories SET directory_path = ? || substr(directory_path, ?) WHERE project_id = ? AND deleted_at IS NULL AND substr(directory_path, 1, ?) = ? " + parentGuardSql)
              .bind(newPath, oldPath.length + 1, projectId, oldPath.length + 1, oldPath + "/", ...parentGuardBindings()),
            env.DB.prepare("UPDATE application_files SET file_name = ? || substr(file_name, ?), updated_at = CURRENT_TIMESTAMP WHERE project_id = ? AND deleted_at IS NULL AND substr(file_name, 1, ?) = ? " + parentGuardSql)
              .bind(newPath, oldPath.length + 1, projectId, oldPath.length + 1, oldPath + "/", ...parentGuardBindings()),
            env.DB.prepare("UPDATE application_file_versions SET file_name = ? || substr(file_name, ?) WHERE project_id = ? AND deleted_at IS NULL AND substr(file_name, 1, ?) = ? " + parentGuardSql)
              .bind(newPath, oldPath.length + 1, projectId, oldPath.length + 1, oldPath + "/", ...parentGuardBindings())
          ]);
        }
        if (parent) {
          for (const parentPath of parentPaths) {
            await env.DB.prepare(
              "INSERT OR IGNORE INTO application_directories (id, project_id, directory_path) SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM projects WHERE id = ? AND user_id = ? AND type = 'application' AND deleted_at IS NULL) AND NOT EXISTS (SELECT 1 FROM application_directories WHERE project_id = ? AND directory_path = ? AND deleted_at IS NOT NULL)"
            ).bind(crypto.randomUUID(), projectId, parentPath, projectId, user.id, projectId, parentPath).run();
          }
        }

        const [renamedFiles, renamedDirectories, renamedVersions] = await Promise.all([
          targetsFiles.length
            ? env.DB.prepare("SELECT COUNT(*) AS total FROM application_files WHERE project_id = ? AND deleted_at IS NULL AND file_name IN (SELECT value FROM json_each(?))")
                .bind(projectId, JSON.stringify(targetsFiles)).first()
            : Promise.resolve({ total: 0 }),
          targetsDirs.length
            ? env.DB.prepare("SELECT COUNT(*) AS total FROM application_directories WHERE project_id = ? AND deleted_at IS NULL AND directory_path IN (SELECT value FROM json_each(?))")
                .bind(projectId, JSON.stringify(targetsDirs)).first()
            : Promise.resolve({ total: 0 }),
          targetsFiles.length
            ? env.DB.prepare("SELECT COUNT(*) AS total FROM application_file_versions WHERE project_id = ? AND deleted_at IS NULL AND file_name IN (SELECT value FROM json_each(?))")
                .bind(projectId, JSON.stringify(targetsFiles)).first()
            : Promise.resolve({ total: 0 })
        ]);
        const renameConfirmed =
          Number(renamedFiles?.total || 0) === targetsFiles.length &&
          Number(renamedDirectories?.total || 0) === targetsDirs.length &&
          Number(renamedVersions?.total || 0) === expectedVersionCount;
        if (!renameConfirmed) {
          return json({
            error: "Le renommage n'a pas pu être confirmé complètement. Actualisez l'explorateur avant de réessayer."
          }, 409);
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
          // Un seul batch D1 garantit l'atomicité de tout l'import :
          // si une insertion échoue, toutes les lignes de cet import sont annulées.
          await env.DB.batch(insertStatements);
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
        const nextPosition = await env.DB.prepare(
          "SELECT COALESCE(MAX(position), -1) + 1 AS next_position FROM customer_database_columns WHERE table_id = ? AND user_id = ?"
        ).bind(tableId, user.id).first();
        const position = Number(nextPosition?.next_position || 0);

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
        if (String(error?.message || "").includes("CUSTOMER_DATABASE_COLUMN_LIMIT")) {
          return json({ error: "Une table peut contenir au maximum 50 colonnes personnalisées." }, 400);
        }
        if (String(error?.message || "").includes("customer_database_columns.position")) {
          return json({ error: "Une autre colonne vient d'être ajoutée simultanément. Actualisez la liste et réessayez." }, 409);
        }
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
        const maxStorage = getPlanLimits(plan).storage_bytes;

        const limit = getPlanLimits(plan).storage_bytes;

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
      let storageReservationId = null;
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
        const maxStorage = getPlanLimits(plan).storage_bytes;



        // Réservation atomique du quota avant le transfert vers B2.
        storageReservationId = await reserveStorageQuota(env, user.id, file.size, maxStorage);
        if (!storageReservationId) {
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
      } finally {
        if (storageReservationId) {
          try {
            await releaseStorageQuotaReservation(env, storageReservationId);
          } catch (releaseError) {
            console.error("ERREUR LIBÉRATION RÉSERVATION STOCKAGE:", releaseError);
          }
        }
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
