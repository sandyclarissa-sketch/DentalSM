export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const sid = getCookie(request.headers.get("Cookie") || "", "dsm_session");

    if (url.pathname === "/" && request.method === "GET")
      return new Response(HTML, {headers: {"content-type":"text/html;charset=UTF-8"}});

    if (url.pathname === "/api/me") {
      const u = sid ? await sessionUser(env.DB, sid) : null;
      return json({authenticated:!!u, user:u && publicUser(u)});
    }

    if (url.pathname === "/api/setup-admin" && request.method === "POST") {
      const c = await env.DB.prepare("SELECT COUNT(*) n FROM users").first();
      if (Number(c?.n || 0) > 0) return json({error:"La configuración inicial ya fue realizada."},409);
      const b = await body(request);
      if (!b.name || !b.email || String(b.password||"").length < 8)
        return json({error:"Nombre, correo y contraseña de al menos 8 caracteres son obligatorios."},400);
      const {salt,hash} = await hashPassword(String(b.password));
      await env.DB.prepare(
        "INSERT INTO users (id,email,name,role,password_hash,password_salt,active) VALUES (?,?,?,?,?,?,1)"
      ).bind(crypto.randomUUID(),String(b.email).trim().toLowerCase(),String(b.name).trim(),"admin",hash,salt).run();
      return json({ok:true});
    }

    if (url.pathname === "/api/login" && request.method === "POST") {
      const b = await body(request);
      const u = await env.DB.prepare("SELECT * FROM users WHERE lower(email)=? AND active=1")
        .bind(String(b.email||"").trim().toLowerCase()).first();
      if (!u || !(await verify(String(b.password||""),u.password_salt,u.password_hash)))
        return json({error:"Correo o contraseña incorrectos."},401);
      const token = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO sessions (id,user_id,expires_at) VALUES (?,?,?)")
        .bind(token,u.id,Math.floor(Date.now()/1000)+604800).run();
      return new Response(JSON.stringify({ok:true,user:publicUser(u)}),{
        headers:{"content-type":"application/json","set-cookie":`dsm_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`}
      });
    }

    if (url.pathname === "/api/logout" && request.method === "POST") {
      if (sid) await env.DB.prepare("DELETE FROM sessions WHERE id=?").bind(sid).run();
      return new Response('{"ok":true}',{
        headers:{"content-type":"application/json","set-cookie":"dsm_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"}
      });
    }

    const user = sid ? await sessionUser(env.DB,sid) : null;
    if (!user) return json({error:"No autorizado."},401);

    if (url.pathname === "/api/patients" && request.method === "GET") {
      const r = await env.DB.prepare(
        "SELECT id,full_name,phone,email,birth_date,created_at FROM patients ORDER BY created_at DESC"
      ).all();
      return json(r.results || []);
    }

    if (url.pathname === "/api/patients" && request.method === "POST") {
      if (!["admin","doctor","secretary"].includes(user.role)) return json({error:"Sin permiso."},403);
      const b = await body(request);
      const name = String(b.full_name||"").trim();
      if (!name) return json({error:"El nombre completo es obligatorio."},400);
      const id = crypto.randomUUID();
      await env.DB.prepare(
        "INSERT INTO patients (id,full_name,phone,email,birth_date,created_at) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)"
      ).bind(id,name,String(b.phone||"").trim(),String(b.email||"").trim(),String(b.birth_date||"").trim()).run();
      return json({ok:true,id});
    }

    if (url.pathname.startsWith("/api/patients/") && request.method === "GET") {
      const id = url.pathname.split("/").pop();
      const p = await env.DB.prepare(
        "SELECT id,full_name,phone,email,birth_date,created_at FROM patients WHERE id=?"
      ).bind(id).first();
      return p ? json(p) : json({error:"Paciente no encontrado."},404);
    }

    if (url.pathname === "/api/appointments" && request.method === "GET") {
      const r = await env.DB.prepare(
        "SELECT a.id,a.patient_id,p.full_name,a.starts_at,a.ends_at,a.status,a.notes FROM appointments a LEFT JOIN patients p ON p.id=a.patient_id ORDER BY a.starts_at"
      ).all();
      return json(r.results || []);
    }

    return json({error:"No encontrado."},404);
  }
};

async function body(r){try{return await r.json()}catch{return{}}}
function json(x,s=200){return new Response(JSON.stringify(x),{status:s,headers:{"content-type":"application/json"}})}
function publicUser(u){return{id:u.id,email:u.email,name:u.name,role:u.role}}
function getCookie(h,n){const x=h.split(";").map(x=>x.trim()).find(x=>x.startsWith(n+"="));return x?decodeURIComponent(x.slice(n.length+1)):null}
async function sessionUser(db,s){
  return db.prepare("SELECT u.id,u.email,u.name,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at>? AND u.active=1")
    .bind(s,Math.floor(Date.now()/1000)).first()
}
function b64(a){let s="";for(const x of new Uint8Array(a))s+=String.fromCharCode(x);return btoa(s)}
function unb64(s){const b=atob(s),a=new Uint8Array(b.length);for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a}
async function hashPassword(p,salt){
  salt=salt||crypto.getRandomValues(new Uint8Array(16));
  const k=await crypto.subtle.importKey("raw",new TextEncoder().encode(p),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:100000,hash:"SHA-256"},k,256);
  return {salt:b64(salt),hash:b64(bits)}
}
async function verify(p,s,h){return (await hashPassword(p,unb64(s))).hash===h}

const HTML = `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DentalSM</title><style>
*{box-sizing:border-box}body{margin:0;background:#f5f7fb;color:#172033;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
header{background:white;border-bottom:1px solid #e5e9f0;padding:18px 22px}.brand{font-size:24px;font-weight:800;color:#1769e0}
main{max-width:1050px;margin:auto;padding:22px}.card{background:white;border:1px solid #e5e9f0;border-radius:16px;padding:22px;margin-bottom:16px}
h1,h2,h3{margin-top:0}.muted{color:#667085}label{display:block;font-weight:650;margin:12px 0 6px}
input{width:100%;padding:12px;border:1px solid #d7dce5;border-radius:10px;font-size:16px}
button{border:0;border-radius:10px;padding:12px 16px;background:#1769e0;color:white;font-weight:700;margin:7px 5px 7px 0}
.secondary{background:#eef3fb;color:#1769e0}.hidden{display:none}.error{color:#b42318}.ok{color:#087443}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.formgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.patient{border:1px solid #e5e9f0;border-radius:12px;padding:15px;margin-top:12px}.patient b{font-size:18px}
</style></head><body><header><div class="brand">DentalSM</div></header><main>

<section id="setup" class="card hidden"><h1>Configuración inicial</h1><p class="muted">Crea la primera cuenta Administradora.</p>
<label>Nombre</label><input id="setupName"><label>Correo</label><input id="setupEmail" value="smdental99@gmail.com"><label>Contraseña</label><input id="setupPass" type="password">
<button onclick="setupAdmin()">Crear administradora</button><p id="setupMsg"></p></section>

<section id="login" class="card hidden"><h1>Acceso seguro</h1><label>Correo</label><input id="email" value="smdental99@gmail.com"><label>Contraseña</label><input id="password" type="password">
<button onclick="loginUser()">Iniciar sesión</button><p id="loginMsg"></p></section>

<section id="app" class="hidden"><div class="card"><h1>Panel DentalSM</h1><p id="welcome" class="muted"></p>
<button onclick="show('home')">Inicio</button><button onclick="show('patients')">Pacientes</button><button onclick="show('agenda')">Agenda</button><button class="secondary" onclick="logout()">Cerrar sesión</button></div>

<div id="home" class="card"><h2>Inicio</h2><p class="muted">El odontograma estará dentro del expediente de cada paciente.</p>
<div class="grid"><div><h3>Pacientes</h3><p class="muted">Registro y expedientes clínicos.</p></div><div><h3>Agenda</h3><p class="muted">Citas de la clínica.</p></div><div><h3>Usuarios</h3><p class="muted">Roles y permisos.</p></div></div></div>

<div id="patients" class="card hidden"><h2>Pacientes</h2><button onclick="toggleForm()">+ Nuevo paciente</button><button class="secondary" onclick="loadPatients()">Actualizar</button>
<div id="newPatient" class="patient hidden"><h3>Nuevo paciente</h3><div class="formgrid">
<div><label>Nombre completo *</label><input id="pName"></div><div><label>Fecha de nacimiento</label><input id="pBirth" type="date"></div>
<div><label>Teléfono</label><input id="pPhone" type="tel"></div><div><label>Correo</label><input id="pEmail" type="email"></div></div>
<button onclick="createPatient()">Guardar paciente</button><button class="secondary" onclick="toggleForm()">Cancelar</button><p id="patientMsg"></p></div>
<div id="patientsList" style="margin-top:16px" class="muted">Sin cargar.</div></div>

<div id="detail" class="card hidden"><button class="secondary" onclick="show('patients')">← Volver</button><h2 id="dName"></h2><p id="dInfo" class="muted"></p>
<div class="patient"><h3>Expediente</h3><p class="muted">Aquí irá el expediente clínico y el odontograma.</p><button onclick="alert('El odontograma será el siguiente módulo.')">🦷 Odontograma</button></div></div>

<div id="agenda" class="card hidden"><h2>Agenda</h2><button onclick="loadAgenda()">Actualizar</button><div id="agendaList" class="muted"></div></div>
</section></main>

<script>
let me;
async function api(p,o){const r=await fetch(p,o),d=await r.json().catch(()=>({}));return{r,d}}
async function init(){const x=await api('/api/me');if(x.d.authenticated){me=x.d.user;openApp();return}document.querySelector('#login').classList.remove('hidden');}
function openApp(){
  document.getElementById('setup').classList.add('hidden');
  document.getElementById('login').classList.add('hidden');
  document.getElementById('app').classList.remove('hidden');
  document.getElementById('welcome').textContent=me.name+' · '+me.role;
}
async function setupAdmin(){const x=await api('/api/setup-admin',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:setupName.value,email:setupEmail.value,password:setupPass.value})});setupMsg.className=x.r.ok?'ok':'error';setupMsg.textContent=x.r.ok?'Administrador creado. Ya puedes iniciar sesión.':x.d.error||'Error';if(x.r.ok){document.querySelector('#setup').classList.add('hidden');document.querySelector('#login').classList.remove('hidden')}}
async function loginUser(){const x=await api('/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:email.value,password:password.value})});if(!x.r.ok){loginMsg.className='error';loginMsg.textContent=x.d.error||'Error';return}location.reload()}
async function logout(){await fetch('/api/logout',{method:'POST'});location.reload()}
function show(id){for(const x of ['home','patients','agenda','detail'])document.querySelector('#'+x).classList.toggle('hidden',x!==id);if(id==='patients')loadPatients();if(id==='agenda')loadAgenda()}
function toggleForm(){newPatient.classList.toggle('hidden')}
async function createPatient(){if(!pName.value.trim()){patientMsg.className='error';patientMsg.textContent='El nombre completo es obligatorio.';return}
const x=await api('/api/patients',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({full_name:pName.value,birth_date:pBirth.value,phone:pPhone.value,email:pEmail.value})});
if(!x.r.ok){patientMsg.className='error';patientMsg.textContent=x.d.error||'No se pudo guardar.';return}
patientMsg.className='ok';patientMsg.textContent='Paciente guardado correctamente.';pName.value=pBirth.value=pPhone.value=pEmail.value='';setTimeout(()=>{newPatient.classList.add('hidden');patientMsg.textContent='';loadPatients()},600)}
async function loadPatients(){const x=await api('/api/patients');if(!Array.isArray(x.d)||!x.d.length){patientsList.innerHTML='Aún no hay pacientes.';return}
patientsList.innerHTML=x.d.map(p=>'<div class="patient"><b>'+esc(p.full_name)+'</b><div class="muted">'+esc(p.phone||'Sin teléfono')+' · '+esc(p.email||'Sin correo')+'</div><button onclick="openPatient(\\''+p.id+'\\')">Abrir expediente</button></div>').join('')}
async function openPatient(id){const x=await api('/api/patients/'+encodeURIComponent(id));if(!x.r.ok)return alert(x.d.error||'Error');dName.textContent=x.d.full_name;dInfo.textContent=(x.d.phone||'Sin teléfono')+' · '+(x.d.email||'Sin correo')+' · '+(x.d.birth_date||'Sin fecha');show('detail')}
async function loadAgenda(){const x=await api('/api/appointments');agendaList.innerHTML=Array.isArray(x.d)&&x.d.length?x.d.map(a=>'<p><b>'+esc(a.full_name||a.patient_id)+'</b> · '+esc(a.starts_at)+'</p>').join(''):'Aún no hay citas.'}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
init();
</script></body></html>`;
