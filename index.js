const SESSION_DAYS = 7;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const cookie = getCookie(request.headers.get("Cookie") || "", "dsm_session");

    if (url.pathname === "/api/me") {
      const user = cookie ? await getSessionUser(env.DB, cookie) : null;
      return json({ authenticated: !!user, user: user ? publicUser(user) : null });
    }

    if (url.pathname === "/api/login" && request.method === "POST") {
      try {
        const body = await request.json();
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");
        if (!email || !password) return json({ error: "Correo y contraseña son obligatorios." }, 400);

        const user = await env.DB.prepare("SELECT * FROM users WHERE lower(email)=? AND active=1").bind(email).first();
        if (!user) return json({ error: "Credenciales incorrectas." }, 401);

        const ok = await verifyPassword(password, user.password_salt, user.password_hash);
        if (!ok) return json({ error: "Credenciales incorrectas." }, 401);

        const sessionId = crypto.randomUUID();
        const expires = Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400;
        await env.DB.prepare("INSERT INTO sessions (id,user_id,expires_at) VALUES (?,?,?)")
          .bind(sessionId, user.id, expires).run();

        return new Response(JSON.stringify({ ok: true, user: publicUser(user) }), {
          headers: {
            "content-type": "application/json",
            "set-cookie": `dsm_session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`
          }
        });
      } catch {
        return json({ error: "No se pudo iniciar sesión." }, 400);
      }
    }

    if (url.pathname === "/api/logout" && request.method === "POST") {
      if (cookie) await env.DB.prepare("DELETE FROM sessions WHERE id=?").bind(cookie).run();
      return new Response(JSON.stringify({ ok: true }), {
        headers: {
          "content-type": "application/json",
          "set-cookie": "dsm_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
        }
      });
    }

    if (url.pathname === "/api/setup-admin" && request.method === "POST") {
      const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
      if (Number(count?.n || 0) > 0) return json({ error: "El usuario administrador ya fue creado." }, 409);

      try {
        const body = await request.json();
        const email = String(body.email || "").trim().toLowerCase();
        const name = String(body.name || "").trim();
        const password = String(body.password || "");
        if (!email || !name || password.length < 8) {
          return json({ error: "Nombre, correo y una contraseña de al menos 8 caracteres son obligatorios." }, 400);
        }

        const { salt, hash } = await hashPassword(password);
        const id = crypto.randomUUID();
        await env.DB.prepare(
          "INSERT INTO users (id,email,name,role,password_hash,password_salt,active) VALUES (?,?,?,?,?,?,1)"
        ).bind(id,email,name,"admin",hash,salt).run();

        return json({ ok: true, user: { id, email, name, role: "admin" } });
      } catch {
        return json({ error: "No se pudo crear el administrador." }, 400);
      }
    }

    if (url.pathname === "/" || url.pathname === "") {
      return new Response(APP_HTML, { headers: { "content-type": "text/html; charset=UTF-8" } });
    }

    return new Response("Not found", { status: 404 });
  }
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=UTF-8" }
  });
}

function publicUser(u) {
  return { id: u.id, email: u.email, name: u.name, role: u.role };
}

function getCookie(header, name) {
  const item = header.split(";").map(x => x.trim()).find(x => x.startsWith(name + "="));
  return item ? decodeURIComponent(item.slice(name.length + 1)) : null;
}

async function getSessionUser(db, sid) {
  const now = Math.floor(Date.now() / 1000);
  const row = await db.prepare(
    "SELECT u.id,u.email,u.name,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at>? AND u.active=1"
  ).bind(sid, now).first();
  return row || null;
}

function b64(bytes) {
  let s = "";
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i += 0x8000) s += String.fromCharCode(...arr.subarray(i, i + 0x8000));
  return btoa(s);
}

function unb64(s) {
  const bin = atob(s);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

async function hashPassword(password, saltBytes = null) {
  const salt = saltBytes || crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, 256);
  return { salt: b64(salt), hash: b64(bits) };
}

async function verifyPassword(password, salt, expected) {
  const { hash } = await hashPassword(password, unb64(salt));
  return hash === expected;
}

const APP_HTML = `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DentalSM</title>
<style>
body{margin:0;background:#f5f7fb;color:#172033;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{max-width:480px;margin:8vh auto;padding:20px}.box{background:white;border:1px solid #e5e9f0;border-radius:20px;padding:28px;box-shadow:0 8px 30px #0000000b}
h1{color:#1769e0;margin:0 0 6px}.muted{color:#667085}label{display:block;margin:18px 0 7px;font-weight:650}
input{width:100%;padding:13px;border:1px solid #d7dce5;border-radius:10px;font-size:16px;box-sizing:border-box}
button{width:100%;margin-top:20px;padding:13px;border:0;border-radius:10px;background:#1769e0;color:white;font-size:16px;font-weight:700}
.error{color:#b42318;margin-top:14px}.ok{color:#087443;margin-top:14px}
.hidden{display:none}.user{background:#f7f9fc;padding:18px;border-radius:12px;margin-top:20px}
</style></head><body><main><div class="box">
<h1>DentalSM</h1><p class="muted">Acceso seguro a tu clínica</p>
<div id="login">
<label>Correo</label><input id="email" type="email" autocomplete="username">
<label>Contraseña</label><input id="password" type="password" autocomplete="current-password">
<button onclick="login()">Iniciar sesión</button><div id="msg"></div>
</div>
<div id="home" class="hidden"><h2>Bienvenida a DentalSM</h2><div class="user" id="who"></div><button onclick="logout()">Cerrar sesión</button></div>
</div></main>
<script>
async function check(){const r=await fetch('/api/me');const d=await r.json();if(d.authenticated){document.querySelector('#login').classList.add('hidden');document.querySelector('#home').classList.remove('hidden');document.querySelector('#who').textContent=d.user.name+' · '+d.user.role;}}
async function login(){const msg=document.querySelector('#msg');msg.className='';msg.textContent='';const r=await fetch('/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:email.value,password:password.value})});const d=await r.json();if(!r.ok){msg.className='error';msg.textContent=d.error;return}location.reload();}
async function logout(){await fetch('/api/logout',{method:'POST'});location.reload()}check();
</script></body></html>`;
