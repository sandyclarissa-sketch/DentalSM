/*
 DentalSM — siguiente versión
 Mantiene login/sesiones y añade:
 - creación inicial de administradora
 - panel privado básico
 - pacientes
 - citas
 - roles
 - odontograma reservado para expediente, no para el inicio

 Requiere las tablas users y sessions ya creadas.
*/

const SESSION_DAYS = 7;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const sessionId = getCookie(request.headers.get("Cookie") || "", "dsm_session");

    if (url.pathname === "/" && request.method === "GET") {
      return html(APP_HTML);
    }

    if (url.pathname === "/api/me" && request.method === "GET") {
      const user = sessionId ? await getSessionUser(env.DB, sessionId) : null;
      return json({ authenticated: !!user, user: user ? publicUser(user) : null });
    }

    if (url.pathname === "/api/setup-admin" && request.method === "POST") {
      const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
      if (Number(count?.n || 0) > 0) return json({ error: "La configuración inicial ya fue realizada." }, 409);

      const body = await safeJson(request);
      const email = String(body.email || "").trim().toLowerCase();
      const name = String(body.name || "").trim();
      const password = String(body.password || "");
      if (!email || !name || password.length < 8) {
        return json({ error: "Nombre, correo y contraseña de al menos 8 caracteres son obligatorios." }, 400);
      }

      const { salt, hash } = await hashPassword(password);
      const id = crypto.randomUUID();
      await env.DB.prepare(
        "INSERT INTO users (id,email,name,role,password_hash,password_salt,active) VALUES (?,?,?,?,?,?,1)"
      ).bind(id, email, name, "admin", hash, salt).run();

      return json({ ok: true });
    }

    if (url.pathname === "/api/login" && request.method === "POST") {
      const body = await safeJson(request);
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");
      const user = await env.DB.prepare("SELECT * FROM users WHERE lower(email)=? AND active=1")
        .bind(email).first();

      if (!user || !(await verifyPassword(password, user.password_salt, user.password_hash))) {
        return json({ error: "Correo o contraseña incorrectos." }, 401);
      }

      const sid = crypto.randomUUID();
      const expires = Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400;
      await env.DB.prepare("INSERT INTO sessions (id,user_id,expires_at) VALUES (?,?,?)")
        .bind(sid, user.id, expires).run();

      return new Response(JSON.stringify({ ok: true, user: publicUser(user) }), {
        headers: {
          "content-type": "application/json",
          "set-cookie": `dsm_session=${sid}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`
        }
      });
    }

    if (url.pathname === "/api/logout" && request.method === "POST") {
      if (sessionId) await env.DB.prepare("DELETE FROM sessions WHERE id=?").bind(sessionId).run();
      return new Response(JSON.stringify({ ok: true }), {
        headers: {
          "content-type": "application/json",
          "set-cookie": "dsm_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
        }
      });
    }

    const user = sessionId ? await getSessionUser(env.DB, sessionId) : null;
    if (!user) return json({ error: "No autorizado." }, 401);

    if (url.pathname === "/api/patients" && request.method === "GET") {
      const result = await env.DB.prepare(
        "SELECT id,full_name,phone,email,birth_date,created_at FROM patients ORDER BY created_at DESC"
      ).all();
      return json(result.results || []);
    }

    if (url.pathname === "/api/patients" && request.method === "POST") {
      if (!["admin","doctor","secretary"].includes(user.role)) return json({ error: "Sin permiso." }, 403);
      const body = await safeJson(request);
      const fullName = String(body.full_name || "").trim();
      if (!fullName) return json({ error: "El nombre del paciente es obligatorio." }, 400);

      const id = crypto.randomUUID();
      await env.DB.prepare(
        "INSERT INTO patients (id,full_name,phone,email,birth_date,created_at) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)"
      ).bind(
        id, fullName,
        String(body.phone || "").trim(),
        String(body.email || "").trim(),
        String(body.birth_date || "").trim()
      ).run();

      return json({ ok: true, id });
    }

    if (url.pathname === "/api/appointments" && request.method === "GET") {
      const result = await env.DB.prepare(
        "SELECT id,patient_id,starts_at,ends_at,status,notes FROM appointments ORDER BY starts_at ASC"
      ).all();
      return json(result.results || []);
    }

    return json({ error: "No encontrado." }, 404);
  }
};

async function safeJson(request) {
  try { return await request.json(); } catch { return {}; }
}

function html(body) {
  return new Response(body, { headers: { "content-type": "text/html; charset=UTF-8" } });
}
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status, headers: { "content-type": "application/json; charset=UTF-8" }
  });
}
function publicUser(u) {
  return { id: u.id, email: u.email, name: u.name, role: u.role };
}
function getCookie(header, name) {
  const item = header.split(";").map(x => x.trim()).find(x => x.startsWith(name + "="));
  return item ? decodeURIComponent(xAfter(item, name + "=")) : null;
}
function xAfter(s, prefix) { return s.slice(prefix.length); }

async function getSessionUser(db, sid) {
  const now = Math.floor(Date.now() / 1000);
  return await db.prepare(
    "SELECT u.id,u.email,u.name,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at>? AND u.active=1"
  ).bind(sid, now).first();
}
function b64(bytes) {
  const a = new Uint8Array(bytes); let s = "";
  for (let i=0;i<a.length;i+=0x8000) s += String.fromCharCode(...a.subarray(i,i+0x8000));
  return btoa(s);
}
function unb64(s) {
  const b=atob(s), a=new Uint8Array(b.length);
  for(let i=0;i<b.length;i++) a[i]=b.charCodeAt(i);
  return a;
}
async function hashPassword(password, saltBytes = null) {
  const salt = saltBytes || crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:100000,hash:"SHA-256"}, key, 256);
  return {salt:b64(salt), hash:b64(bits)};
}
async function verifyPassword(password, salt, expected) {
  const {hash}=await hashPassword(password,unb64(salt));
  return hash===expected;
}

const APP_HTML = `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DentalSM</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f5f7fb;color:#172033}
header{background:#fff;border-bottom:1px solid #e5e9f0;padding:16px 20px;position:sticky;top:0;z-index:2}.brand{font-size:23px;font-weight:800;color:#1769e0}
main{max-width:1050px;margin:auto;padding:22px}.card{background:#fff;border:1px solid #e5e9f0;border-radius:16px;padding:22px;margin-bottom:16px}
h1,h2{margin-top:0}.muted{color:#667085}label{display:block;margin:14px 0 6px;font-weight:650}
input{width:100%;padding:12px;border:1px solid #d7dce5;border-radius:10px;font-size:16px}button{border:0;border-radius:10px;padding:12px 16px;background:#1769e0;color:#fff;font-weight:700;margin-top:14px}
button.secondary{background:#eef3fb;color:#1769e0}.error{color:#b42318;margin-top:12px}.ok{color:#087443;margin-top:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}.hidden{display:none}
.nav{display:flex;gap:8px;flex-wrap:wrap;margin:15px 0}.nav button{margin:0}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid #eef0f4}
</style></head><body>
<header><div class="brand">DentalSM</div></header>
<main>
<section id="setup" class="card hidden"><h1>Configuración inicial</h1><p class="muted">Crea la primera cuenta Administradora. Tu contraseña se envía directamente a DentalSM y no se muestra aquí.</p>
<label>Nombre</label><input id="setupName"><label>Correo</label><input id="setupEmail" value="smdental99@gmail.com"><label>Contraseña</label><input id="setupPass" type="password" minlength="8"><button onclick="setup()">Crear administradora</button><div id="setupMsg"></div></section>
<section id="login" class="card hidden"><h1>Acceso seguro</h1><p class="muted">Ingresa a tu clínica.</p>
<label>Correo</label><input id="email" type="email" value="smdental99@gmail.com"><label>Contraseña</label><input id="password" type="password"><button onclick="login()">Iniciar sesión</button><div id="loginMsg"></div></section>
<section id="app" class="hidden"><div class="card"><h1>Panel DentalSM</h1><p id="welcome" class="muted"></p>
<div class="nav"><button onclick="show('dashboard')">Inicio</button><button onclick="show('patients')">Pacientes</button><button onclick="show('agenda')">Agenda</button><button class="secondary" onclick="logout()">Cerrar sesión</button></div></div>
<div id="dashboard" class="card"><h2>Inicio</h2><p class="muted">El odontograma no está en el inicio. Se integrará dentro del expediente del paciente.</p><div class="grid"><div><b>Pacientes</b><p class="muted">Gestión de pacientes y expedientes.</p></div><div><b>Agenda</b><p class="muted">Citas de la clínica.</p></div><div><b>Usuarios</b><p class="muted">Roles y permisos.</p></div></div></div>
<div id="patients" class="card hidden"><h2>Pacientes</h2><button onclick="loadPatients()">Actualizar</button><div id="patientsList" class="muted">Sin cargar.</div></div>
<div id="agenda" class="card hidden"><h2>Agenda</h2><button onclick="loadAgenda()">Actualizar</button><div id="agendaList" class="muted">Sin cargar.</div></div>
</section>
</main>
<script>
let me=null;
async function api(path,opt){const r=await fetch(path,opt);const d=await r.json().catch(()=>({}));return {r,d}}
async function init(){const {d}=await api('/api/me');if(d.authenticated){me=d.user;openApp();return}
const probe=await api('/api/setup-admin',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({})});
document.querySelector('#setup').classList.toggle('hidden',probe.r.status!==400);
document.querySelector('#login').classList.toggle('hidden',probe.r.status===409||probe.r.status===401?false:probe.r.status!==409);
}
function openApp(){document.querySelector('#setup').classList.add('hidden');document.querySelector('#login').classList.add('hidden');document.querySelector('#app').classList.remove('hidden');document.querySelector('#welcome').textContent=me.name+' · '+me.role}
async function setup(){const msg=document.querySelector('#setupMsg');const {r,d}=await api('/api/setup-admin',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:setupName.value,email:setupEmail.value,password:setupPass.value})});msg.className=r.ok?'ok':'error';msg.textContent=r.ok?'Administrador creado. Ya puedes iniciar sesión.':d.error||'No se pudo crear.';if(r.ok){setupPass.value;document.querySelector('#setup').classList.add('hidden');document.querySelector('#login').classList.remove('hidden')}}
async function login(){const msg=document.querySelector('#loginMsg');const {r,d}=await api('/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:email.value,password:password.value})});if(!r.ok){msg.className='error';msg.textContent=d.error||'No se pudo iniciar sesión';return}location.reload()}
async function logout(){await fetch('/api/logout',{method:'POST'});location.reload()}
function show(id){for(const x of ['dashboard','patients','agenda'])document.querySelector('#'+x).classList.toggle('hidden',x!==id);if(id==='patients')loadPatients();if(id==='agenda')loadAgenda()}
async function loadPatients(){const {d}=await api('/api/patients');patientsList.innerHTML=Array.isArray(d)&&d.length?'<table><tr><th>Nombre</th><th>Teléfono</th><th>Correo</th></tr>'+d.map(p=>'<tr><td>'+esc(p.full_name)+'</td><td>'+esc(p.phone||'')+'</td><td>'+esc(p.email||'')+'</td></tr>').join('')+'</table>':'Aún no hay pacientes.'}
async function loadAgenda(){const {d}=await api('/api/appointments');agendaList.innerHTML=Array.isArray(d)&&d.length?'<table><tr><th>Paciente</th><th>Inicio</th><th>Estado</th></tr>'+d.map(a=>'<tr><td>'+esc(a.patient_id)+'</td><td>'+esc(a.starts_at)+'</td><td>'+esc(a.status||'')+'</td></tr>').join('')+'</table>':'Aún no hay citas.'}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
init();
</script></body></html>`;
