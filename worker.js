// Homeschool tracker — Cloudflare Worker API (no framework, no build step).
// Routes live under /api/*; everything else is served from /public by the assets binding.

const COOKIE = "hs_session";
const SESSION_DAYS = 90;
const enc = new TextEncoder();

// ---------- helpers ----------
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", ...headers } });
class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const bad = (m) => { throw new HttpError(400, m); };
const notFound = (w = "Record") => { throw new HttpError(404, `${w} not found`); };
const forbidden = () => { throw new HttpError(403, "Not allowed"); };
const str = (v) => (typeof v === "string" && v.trim() ? v.trim() : null);
const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const randomHex = (n = 16) => { const a = new Uint8Array(n); crypto.getRandomValues(a); return toHex(a.buffer); };
const parseJSON = (s, fallback) => { try { return JSON.parse(s); } catch { return fallback; } };

async function hashPin(pin, salt) {
  const key = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 100000 }, key, 256);
  return toHex(bits);
}
async function verifyPin(pin, salt, hash) {
  const h = await hashPin(pin, salt);
  if (h.length !== hash.length) return false;
  let d = 0;
  for (let i = 0; i < h.length; i++) d |= h.charCodeAt(i) ^ hash.charCodeAt(i);
  return d === 0;
}
function getCookie(req, name) {
  const c = req.headers.get("cookie") || "";
  for (const part of c.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return decodeURIComponent(v.join("="));
  }
  return null;
}

// ---------- auth ----------
async function bootstrap(env) {
  const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
  if (row && row.n > 0) return;
  const pin = env.ADMIN_PASSWORD || "1234";
  const salt = randomHex();
  await env.DB.prepare("INSERT INTO users (name, role, pin_hash, pin_salt) VALUES ('Parent', 'parent', ?, ?)").bind(await hashPin(pin, salt), salt).run();
}
async function sessionUser(env, req) {
  const token = getCookie(req, COOKIE);
  if (!token) return null;
  const u = await env.DB.prepare(
    `SELECT u.id, u.name, u.role, u.student_id FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token = ? AND s.expires_at > datetime('now') AND u.active = 1`).bind(token).first();
  return u || null;
}
const canSeeStudent = (user, studentId) => user.role === "parent" || Number(user.student_id) === Number(studentId);

// ---------- data shaping ----------
async function loadWeek(env, id) {
  const w = await env.DB.prepare("SELECT * FROM weeks WHERE id = ?").bind(id).first();
  if (!w) notFound("Week");
  const { results: tasks } = await env.DB.prepare("SELECT * FROM tasks WHERE week_id = ? ORDER BY day, sort, id").bind(id).all();
  const { results: comments } = await env.DB.prepare(
    "SELECT c.* FROM comments c JOIN tasks t ON t.id = c.task_id WHERE t.week_id = ? ORDER BY c.id").bind(id).all();
  const byTask = {};
  for (const c of comments) (byTask[c.task_id] ||= []).push(c);
  return {
    id: w.id, student_id: w.student_id, num: w.num, title: w.title, notes: w.notes, created_at: w.created_at,
    days: parseJSON(w.days, ["Day 1", "Day 2", "Day 3", "Day 4"]),
    subjects: parseJSON(w.subjects, []),
    tasks: tasks.map((t) => ({ ...t, done: !!t.done, comments: byTask[t.id] || [] })),
  };
}
async function weekAccess(env, user, weekId) {
  const w = await env.DB.prepare("SELECT id, student_id FROM weeks WHERE id = ?").bind(weekId).first();
  if (!w) notFound("Week");
  if (!canSeeStudent(user, w.student_id)) forbidden();
  return w;
}
async function taskAccess(env, user, taskId) {
  const t = await env.DB.prepare("SELECT t.*, w.student_id FROM tasks t JOIN weeks w ON w.id = t.week_id WHERE t.id = ?").bind(taskId).first();
  if (!t) notFound("Assignment");
  if (!canSeeStudent(user, t.student_id)) forbidden();
  return t;
}

// ---------- router ----------
async function handleApi(req, env) {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api/, "");
  const m = req.method;
  const body = m === "POST" || m === "PUT" ? await req.json().catch(() => ({})) : {};
  const seg = path.split("/").filter(Boolean);

  // --- public ---
  if (m === "GET" && path === "/me") {
    await bootstrap(env);
    const user = await sessionUser(env, req);
    const { results: users } = await env.DB.prepare("SELECT id, name, role, student_id FROM users WHERE active = 1 ORDER BY role DESC, name").all();
    let students = [];
    if (user) {
      const q = user.role === "parent"
        ? env.DB.prepare("SELECT * FROM students WHERE active = 1 ORDER BY sort, name")
        : env.DB.prepare("SELECT * FROM students WHERE active = 1 AND id = ?").bind(user.student_id);
      students = (await q.all()).results;
    }
    return json({ user, users, students, familyName: env.FAMILY_NAME || "Our Homeschool" });
  }
  if (m === "POST" && path === "/login") {
    await bootstrap(env);
    const row = await env.DB.prepare("SELECT * FROM users WHERE id = ? AND active = 1").bind(Number(body.user_id)).first();
    if (!row || !body.pin || !(await verifyPin(String(body.pin), row.pin_salt, row.pin_hash))) throw new HttpError(401, "Wrong PIN");
    const token = randomHex(32);
    const expires = new Date(Date.now() + SESSION_DAYS * 86400000);
    await env.DB.prepare("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)").bind(token, row.id, expires.toISOString()).run();
    const secure = url.protocol === "https:" ? "; Secure" : "";
    return json({ ok: true }, 200, { "set-cookie": `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Expires=${expires.toUTCString()}${secure}` });
  }
  if (m === "POST" && path === "/logout") {
    const token = getCookie(req, COOKIE);
    if (token) await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
    return json({ ok: true }, 200, { "set-cookie": `${COOKIE}=; Path=/; HttpOnly; Max-Age=0` });
  }

  // --- everything below needs a session ---
  const user = await sessionUser(env, req);
  if (!user) throw new HttpError(401, "Not signed in");
  const isParent = user.role === "parent";

  // students
  if (m === "POST" && path === "/students") {
    if (!isParent) forbidden();
    const name = str(body.name) || bad("Name required");
    const r = await env.DB.prepare("INSERT INTO students (name, grade, color, sort) VALUES (?, ?, ?, ?) RETURNING *")
      .bind(name, str(body.grade) || "", str(body.color) || "#1F6F5C", Number(body.sort) || 0).first();
    return json(r, 201);
  }
  if (m === "PUT" && seg[0] === "students" && seg.length === 2) {
    if (!isParent) forbidden();
    const s = await env.DB.prepare("SELECT * FROM students WHERE id = ?").bind(Number(seg[1])).first();
    if (!s) notFound("Child");
    await env.DB.prepare("UPDATE students SET name = ?, grade = ?, color = ?, sort = ?, active = ? WHERE id = ?")
      .bind(str(body.name) || s.name, body.grade === undefined ? s.grade : String(body.grade), str(body.color) || s.color,
        body.sort === undefined ? s.sort : Number(body.sort), body.active === undefined ? s.active : body.active ? 1 : 0, s.id).run();
    return json({ ok: true });
  }

  // family members (logins)
  if (m === "GET" && path === "/users") {
    if (!isParent) forbidden();
    const { results } = await env.DB.prepare("SELECT id, name, role, student_id, active, created_at FROM users ORDER BY active DESC, role DESC, name").all();
    return json(results);
  }
  if (m === "POST" && path === "/users") {
    if (!isParent) forbidden();
    const name = str(body.name) || bad("Name required");
    const pin = String(body.pin || "");
    if (pin.length < 4) bad("PIN must be at least 4 characters");
    const role = body.role === "student" ? "student" : "parent";
    const studentId = role === "student" ? Number(body.student_id) || bad("Pick which child this login is for") : null;
    const salt = randomHex();
    const r = await env.DB.prepare("INSERT INTO users (name, role, student_id, pin_hash, pin_salt) VALUES (?, ?, ?, ?, ?) RETURNING id, name, role, student_id, active")
      .bind(name, role, studentId, await hashPin(pin, salt), salt).first();
    return json(r, 201);
  }
  if (m === "PUT" && seg[0] === "users" && seg.length === 2) {
    const id = Number(seg[1]);
    const self = id === user.id;
    if (!isParent && !self) forbidden();
    const ex = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first();
    if (!ex) notFound("Member");
    let name = ex.name, role = ex.role, studentId = ex.student_id, active = ex.active;
    if (isParent) {
      name = str(body.name) || ex.name;
      role = body.role === "student" || body.role === "parent" ? body.role : ex.role;
      studentId = role === "student" ? (body.student_id === undefined ? ex.student_id : Number(body.student_id)) : null;
      active = body.active === undefined ? ex.active : body.active ? 1 : 0;
      if (self && (role !== "parent" || !active)) bad("You can't demote or deactivate yourself");
    }
    let pinHash = ex.pin_hash, salt = ex.pin_salt;
    if (body.pin) {
      if (String(body.pin).length < 4) bad("PIN must be at least 4 characters");
      salt = randomHex();
      pinHash = await hashPin(String(body.pin), salt);
      await env.DB.prepare("DELETE FROM sessions WHERE user_id = ? AND token <> ?").bind(id, getCookie(req, COOKIE) || "").run();
    }
    await env.DB.prepare("UPDATE users SET name = ?, role = ?, student_id = ?, active = ?, pin_hash = ?, pin_salt = ? WHERE id = ?")
      .bind(name, role, studentId, active, pinHash, salt, id).run();
    return json({ ok: true });
  }

  // weeks
  if (m === "GET" && seg[0] === "students" && seg[2] === "weeks" && seg.length === 3) {
    const sid = Number(seg[1]);
    if (!canSeeStudent(user, sid)) forbidden();
    const { results } = await env.DB.prepare(
      `SELECT w.id, w.num, w.title, w.created_at,
              (SELECT COUNT(*) FROM tasks t WHERE t.week_id = w.id) AS total,
              (SELECT COUNT(*) FROM tasks t WHERE t.week_id = w.id AND t.done = 1) AS done
       FROM weeks w WHERE w.student_id = ? ORDER BY w.num DESC`).bind(sid).all();
    return json(results);
  }
  if (m === "POST" && seg[0] === "students" && seg[2] === "weeks" && seg.length === 3) {
    if (!isParent) forbidden();
    const sid = Number(seg[1]);
    const student = await env.DB.prepare("SELECT id FROM students WHERE id = ? AND active = 1").bind(sid).first();
    if (!student) notFound("Child");
    let num = Number(body.num);
    if (!num) {
      const mx = await env.DB.prepare("SELECT MAX(num) AS n FROM weeks WHERE student_id = ?").bind(sid).first();
      num = (mx && mx.n ? mx.n : 0) + 1;
    }
    const dup = await env.DB.prepare("SELECT id FROM weeks WHERE student_id = ? AND num = ?").bind(sid, num).first();
    if (dup) bad(`Week ${num} already exists`);
    let days = Array.isArray(body.days) && body.days.length ? body.days : ["Day 1", "Day 2", "Day 3", "Day 4"];
    let subjects = Array.isArray(body.subjects) ? body.subjects : [];
    let copyTasks = [];
    if (body.copy_from) {
      const src = await weekAccess(env, user, Number(body.copy_from));
      const full = await loadWeek(env, src.id);
      days = full.days; subjects = full.subjects;
      if (body.copy_tasks) copyTasks = full.tasks;
    }
    const w = await env.DB.prepare("INSERT INTO weeks (student_id, num, title, days, subjects) VALUES (?, ?, ?, ?, ?) RETURNING id")
      .bind(sid, num, str(body.title) || `Week ${num}`, JSON.stringify(days), JSON.stringify(subjects)).first();
    if (copyTasks.length) {
      const stmt = env.DB.prepare("INSERT INTO tasks (week_id, subject_id, day, text, kind, sort) VALUES (?, ?, ?, ?, ?, ?)");
      await env.DB.batch(copyTasks.map((t) => stmt.bind(w.id, t.subject_id, t.day, t.text.replace(/Week\s+\d+/g, `Week ${num}`), t.kind, t.sort)));
    }
    return json(await loadWeek(env, w.id), 201);
  }
  if (seg[0] === "weeks" && seg.length === 2) {
    const id = Number(seg[1]);
    await weekAccess(env, user, id);
    if (m === "GET") return json(await loadWeek(env, id));
    if (m === "PUT") {
      if (!isParent) forbidden();
      const w = await loadWeek(env, id);
      const days = Array.isArray(body.days) && body.days.length ? body.days.map(String) : w.days;
      const subjects = Array.isArray(body.subjects) ? body.subjects : w.subjects;
      await env.DB.prepare("UPDATE weeks SET title = ?, days = ?, subjects = ?, notes = ? WHERE id = ?")
        .bind(str(body.title) || w.title, JSON.stringify(days), JSON.stringify(subjects), body.notes === undefined ? w.notes : String(body.notes), id).run();
      if (days.length < w.days.length) await env.DB.prepare("DELETE FROM tasks WHERE week_id = ? AND day >= ?").bind(id, days.length).run();
      return json(await loadWeek(env, id));
    }
    if (m === "DELETE") {
      if (!isParent) forbidden();
      await env.DB.batch([
        env.DB.prepare("DELETE FROM comments WHERE task_id IN (SELECT id FROM tasks WHERE week_id = ?)").bind(id),
        env.DB.prepare("DELETE FROM tasks WHERE week_id = ?").bind(id),
        env.DB.prepare("DELETE FROM weeks WHERE id = ?").bind(id),
      ]);
      return json({ ok: true });
    }
  }
  // bulk import: replace nothing, just append tasks (used when loading a planner page)
  if (m === "POST" && seg[0] === "weeks" && seg[2] === "tasks" && seg.length === 3) {
    const id = Number(seg[1]);
    await weekAccess(env, user, id);
    const items = Array.isArray(body.tasks) ? body.tasks : [body];
    if (!items.length) bad("Nothing to add");
    if (!isParent && items.length > 1) forbidden();
    const stmt = env.DB.prepare("INSERT INTO tasks (week_id, subject_id, day, text, kind, done, done_by, done_at, sort) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    await env.DB.batch(items.map((t, i) => {
      const text = str(t.text) || bad("Assignment text required");
      return stmt.bind(id, String(t.subject_id || ""), Number(t.day) || 0, text, t.kind === "bring" ? "bring" : "task",
        t.done ? 1 : 0, t.done ? (t.done_by || user.name) : null, t.done ? new Date().toISOString() : null, Number(t.sort) || i);
    }));
    return json(await loadWeek(env, id), 201);
  }

  // tasks
  if (seg[0] === "tasks" && seg.length >= 2) {
    const t = await taskAccess(env, user, Number(seg[1]));
    if (m === "POST" && seg[2] === "done") {
      const done = !!body.done;
      await env.DB.prepare("UPDATE tasks SET done = ?, done_by = ?, done_at = ? WHERE id = ?")
        .bind(done ? 1 : 0, done ? user.name : null, done ? new Date().toISOString() : null, t.id).run();
      return json({ ok: true });
    }
    if (m === "POST" && seg[2] === "comments") {
      const text = str(body.body) || bad("Write something first");
      const r = await env.DB.prepare("INSERT INTO comments (task_id, user_id, author, body) VALUES (?, ?, ?, ?) RETURNING *")
        .bind(t.id, user.id, user.name, text).first();
      return json(r, 201);
    }
    if (m === "PUT" && seg.length === 2) {
      // students may edit text of their own tasks? Keep it parent-only except notes via comments.
      if (!isParent) forbidden();
      await env.DB.prepare("UPDATE tasks SET text = ?, subject_id = ?, day = ?, kind = ?, sort = ? WHERE id = ?")
        .bind(str(body.text) || t.text, body.subject_id === undefined ? t.subject_id : String(body.subject_id),
          body.day === undefined ? t.day : Number(body.day), body.kind === "bring" ? "bring" : body.kind === "task" ? "task" : t.kind,
          body.sort === undefined ? t.sort : Number(body.sort), t.id).run();
      return json({ ok: true });
    }
    if (m === "DELETE" && seg.length === 2) {
      if (!isParent) forbidden();
      await env.DB.batch([
        env.DB.prepare("DELETE FROM comments WHERE task_id = ?").bind(t.id),
        env.DB.prepare("DELETE FROM tasks WHERE id = ?").bind(t.id),
      ]);
      return json({ ok: true });
    }
  }
  if (m === "DELETE" && seg[0] === "comments" && seg.length === 2) {
    const c = await env.DB.prepare("SELECT * FROM comments WHERE id = ?").bind(Number(seg[1])).first();
    if (!c) notFound("Comment");
    if (!isParent && c.user_id !== user.id) forbidden();
    await env.DB.prepare("DELETE FROM comments WHERE id = ?").bind(c.id).run();
    return json({ ok: true });
  }

  // family overview for parents: each child's current-week progress
  if (m === "GET" && path === "/overview") {
    if (!isParent) forbidden();
    const { results } = await env.DB.prepare(
      `SELECT s.id AS student_id, s.name, s.grade, s.color, w.id AS week_id, w.num, w.title,
              (SELECT COUNT(*) FROM tasks t WHERE t.week_id = w.id) AS total,
              (SELECT COUNT(*) FROM tasks t WHERE t.week_id = w.id AND t.done = 1) AS done
       FROM students s LEFT JOIN weeks w ON w.id = (SELECT id FROM weeks WHERE student_id = s.id ORDER BY num DESC LIMIT 1)
       WHERE s.active = 1 ORDER BY s.sort, s.name`).all();
    return json(results);
  }

  throw new HttpError(404, "No such route");
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(req);
    try {
      return await handleApi(req, env);
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      console.error(e);
      return json({ error: "Server error: " + (e && e.message ? e.message : String(e)) }, 500);
    }
  },
};
