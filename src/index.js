
const ITERATIONS = 100000;
const SESSION_DAYS = 7;

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

        // MODIFIER
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

        // SUPPRIMER
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
