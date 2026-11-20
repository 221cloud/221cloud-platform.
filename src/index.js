
const ITERATIONS = 100000;
const SESSION_DAYS = 7;
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

  const result = await env.DB.prepare(
    `SELECT users.id, users.email, users.full_name, users.role
     FROM sessions
     JOIN users ON users.id = sessions.user_id
     WHERE sessions.token_hash = ? AND sessions.expires_at > ?
     LIMIT 1`
  ).bind(tokenHash, new Date().toISOString()).first();

  return result || null;
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

  return JSON.parse(responseText);
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

        const user = await env.DB.prepare(
          "SELECT id, email, full_name, role, password_hash FROM users WHERE email = ?"
        ).bind(email).first();

        if (
          !user ||
          !user.password_hash ||
          !(await verifyPassword(password, user.password_hash))
        ) {
          return json({
            error: "E-mail ou mot de passe incorrect."
          }, 401);
        }

        const token = await createSession(env, user.id);

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
           WHERE user_id = ?
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

        const id = crypto.randomUUID();

        await env.DB.prepare(
          `INSERT INTO projects (id, user_id, name, type, status)
           VALUES (?, ?, ?, ?, 'pending')`
        ).bind(id, user.id, name, type).run();

        const project = await env.DB.prepare(
          `SELECT id, name, type, status, created_at
           FROM projects WHERE id = ? AND user_id = ?`
        ).bind(id, user.id).first();

        return json({
          message: "Projet créé avec succès.",
          project
        }, 201);

      } catch (error) {
        console.error("ERREUR CREATION PROJET:", error);
        return json({
          error: "Impossible de créer le projet."
        }, 500);
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
           WHERE id = ? AND user_id = ?`
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
             WHERE id = ? AND user_id = ?`
          ).bind(projectId, user.id).first();

          return json({
            message: "Projet modifié avec succès.",
            project: updated
          });
        }

        if (request.method === "DELETE") {
          await env.DB.prepare(
            "DELETE FROM projects WHERE id = ? AND user_id = ?"
          ).bind(projectId, user.id).run();

          return json({
            message: "Projet supprimé avec succès."
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
            "SELECT id FROM projects WHERE id = ? AND user_id = ?"
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

    // STOCKAGE : LISTE DES FICHIERS ET QUOTA
    if (path === "/api/storage" && request.method === "GET") {
      try {
        const user = await currentUser(request, env);

        if (!user) {
          return json({ error: "Vous devez être connecté." }, 401);
        }

        const result = await env.DB.prepare(
          `SELECT id, file_name, file_size, mime_type, created_at
           FROM cloud_files
           WHERE user_id = ?
           ORDER BY created_at DESC`
        ).bind(user.id).all();

        const files = result.results || [];
        const used = files.reduce(
          (total, file) => total + Number(file.file_size || 0),
          0
        );

        return json({
          files,
          used,
          limit: STORAGE_LIMIT_BYTES,
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

        const form = await request.formData();
        const file = form.get("file");

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

        const usage = await env.DB.prepare(
          "SELECT COALESCE(SUM(file_size), 0) AS used FROM cloud_files WHERE user_id = ?"
        ).bind(user.id).first();

        const used = Number(usage?.used || 0);

        if (used + file.size > STORAGE_LIMIT_BYTES) {
          return json({
            error: "Votre quota de stockage de 1 Go est atteint."
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
             (id, user_id, file_name, file_size, mime_type, storage_key, b2_file_id)
             VALUES (?, ?, ?, ?, ?, ?, ?)`
          ).bind(
            id,
            user.id,
            fileName,
            file.size,
            mimeType,
            objectKey,
            uploadedFile.fileId
          ).run();
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
            mime_type: mimeType
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
    const downloadMatch = path.match(
      /^\/api\/storage\/([^/]+)\/download$/
    );

    if (downloadMatch && request.method === "GET") {
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

        const fileId = decodeURIComponent(downloadMatch[1]);

        const file = await env.DB.prepare(
          `SELECT id, file_name, mime_type, storage_key
           FROM cloud_files
           WHERE id = ? AND user_id = ?`
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

        }

        const headers = new Headers();

        headers.set(
          "Content-Type",
          file.mime_type || "application/octet-stream"
        );

        headers.set(
          "Content-Disposition",
          `attachment; filename*=UTF-8''${encodeURIComponent(file.file_name)}`
        );

        headers.set("Cache-Control", "private, no-store");

        return new Response(downloadResponse.body, {
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

    // STOCKAGE : SUPPRESSION D'UN FICHIER
    const storageMatch = path.match(/^\/api\/storage\/([^/]+)$/);

    if (storageMatch) {
      if (request.method !== "DELETE") {
        return json({ error: "Méthode non autorisée." }, 405);
      }

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

        const fileId = decodeURIComponent(storageMatch[1]);

        const file = await env.DB.prepare(
          `SELECT id, storage_key
           FROM cloud_files
           WHERE id = ? AND user_id = ?`
        ).bind(fileId, user.id).first();

        if (!file) {
          return json({ error: "Fichier introuvable." }, 404);
        }

        const deleteResponse = await b2Request(
          env,
          "DELETE",
          file.storage_key
        );

        if (!deleteResponse.ok && deleteResponse.status !== 404) {
          const errorDetails = await deleteResponse.text();

          console.error(
            "ERREUR SUPPRESSION BACKBLAZE:",
            deleteResponse.status,
            errorDetails.slice(0, 1500)
          );

          return json({
            error: "Impossible de supprimer le fichier du stockage."
          }, 502);
        }

        await env.DB.prepare(
          "DELETE FROM cloud_files WHERE id = ? AND user_id = ?"
        ).bind(fileId, user.id).run();

        return json({
          message: "Fichier supprimé avec succès."
        });

      } catch (error) {
        console.error("ERREUR SUPPRESSION STOCKAGE:", error);
        return json({
          error: "Impossible de supprimer le fichier."
        }, 500);
      }
    }

    // DÉCONNEXION
    if (path === "/api/logout" && request.method === "POST") {
      try {
        const token = getCookie(request, "221cloud_session");

        if (token) {
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
