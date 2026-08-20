export default {
async fetch(request, env) {
const url = new URL(request.url);
const sid = getCookie(request.headers.get("Cookie") || "", "dsm_session");
if (url.pathname === "/" && request.method === "GET") {
return new Response(HTML, {
headers: { "content-type": "text/html;charset=UTF-8" }
});
if (url.pathname === "/api/me" && request.method === "GET") {
const u = sid ? await sessionUser(env.DB, sid) : null;
return json({ authenticated: !!u, user: u ? publicUser(u) : null });
}
}
if (url.pathname === "/api/setup-admin" && request.method === "POST") {
const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
if (Number(c?.n || 0) > 0) {
return json({ error: "La configuración inicial ya fue realizada." }, 409);
}
const b = await body(request);
const name = String(b.name || "").trim();
const email = String(b.email || "").trim().toLowerCase();
const password = String(b.password || "");
if (!name || !email || password.length < 8) {
return json({ error: "Nombre, correo y contraseña de al menos 8 caracteres son obligatorios." }, 400);
}
const { salt, hash } = await hashPassword(password);
await env.DB.prepare(
"INSERT INTO users (id,email,name,role,password_hash,password_salt,active) VALUES (?,?,?,?,?,?,1)"
).bind(crypto.randomUUID(), email, name, "admin", hash, salt).run();
return json({ ok: true });
}
if (url.pathname === "/api/login" && request.method === "POST") {
const b = await body(request);
const email = String(b.email || "").trim().toLowerCase();
const password = String(b.password || "");
const u = await env.DB.prepare(
"SELECT * FROM users WHERE lower(email)=? AND active=1"
).bind(email).first();
if (!u || !(await verify(password, u.password_salt, u.password_hash))) {
return json({ error: "Correo o contraseña incorrectos." }, 401);
}
const token = crypto.randomUUID();
await env.DB.prepare(
"INSERT INTO sessions (id,user_id,expires_at) VALUES (?,?,?)"
).bind(token, u.id, Math.floor(Date.now() / 1000) + 604800).run();
return new Response(JSON.stringify({ ok: true, user: publicUser(u) }), {
headers: {
"content-type": "application/json",
"set-cookie": "dsm_session=" + token + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800"
}
});
}
if (url.pathname === "/api/logout" && request.method === "POST") {
if (sid) {
await env.DB.prepare("DELETE FROM sessions WHERE id=?").bind(sid).run();
}
return new Response(JSON.stringify({ ok: true }), {
headers: {
"content-type": "application/json",
"set-cookie": "dsm_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
}
});
}
const user = sid ? await sessionUser(env.DB, sid) : null;
if (!user) return json({ error: "No autorizado." }, 401);
if (url.pathname === "/api/patients" && request.method === "GET") {
const r = await env.DB.prepare(
"SELECT id,full_name,phone,email,birth_date,created_at FROM patients ORDER BY created_at DESC"
).all();
return json(r.results || []);
}
if (url.pathname === "/api/patients" && request.method === "POST") {
if (!["admin", "doctor", "secretary"].includes(user.role)) {
return json({ error: "Sin permiso." }, 403);
}
const b = await body(request);
const name = String(b.full_name || "").trim();
if (!name) return json({ error: "El nombre completo es obligatorio." }, 400);
const id = crypto.randomUUID();
await env.DB.prepare(
).bind(
id,
name,
String(b.phone || "").trim(),
String(b.email || "").trim(),
String(b.birth_date || "").trim()
).run();
"INSERT INTO patients (id,full_name,phone,email,birth_date,created_at) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)"
return json({ ok: true, id });
}
if (url.pathname.startsWith("/api/patients/") && request.method === "GET") {
const id = decodeURIComponent(url.pathname.split("/").pop());
const p = await env.DB.prepare(
"SELECT id,full_name,phone,email,birth_date,created_at FROM patients WHERE id=?"
).bind(id).first();
return p ? json(p) : json({ error: "Paciente no encontrado." }, 404);
}
if (url.pathname === "/api/odontogram" && request.method === "GET") {
const patientId = url.searchParams.get("patient_id");
if (!patientId) return json({ error: "Falta patient_id." }, 400);
const r = await env.DB.prepare(
"SELECT id,patient_id,tooth,status,notes,updated_at FROM odontogram WHERE patient_id=? ORDER BY CAST(tooth AS
INTEGER)"
).bind(patientId).all();
return json(r.results || []);
}
if (url.pathname === "/api/odontogram" && request.method === "POST") {
if (!["admin", "doctor"].includes(user.role)) {
return json({ error: "Solo admin y doctor pueden modificar el odontograma." }, 403);
}
const b = await body(request);
const patientId = String(b.patient_id || "").trim();
const tooth = String(b.tooth || "").trim();
const status = String(b.status || "sano").trim();
const notes = String(b.notes || "").trim();
const allowed = ["sano", "caries", "restauracion", "ausente", "extraccion", "endodoncia", "corona", "implante",
"fractura", "otro"];
if (!patientId || !tooth) return json({ error: "Paciente y diente son obligatorios." }, 400);
if (!allowed.includes(status)) return json({ error: "Estado dental no válido." }, 400);
const patient = await env.DB.prepare("SELECT id FROM patients WHERE id=?").bind(patientId).first();
if (!patient) return json({ error: "Paciente no encontrado." }, 404);
const rowId = patientId + ":" + tooth;
await env.DB.prepare(
"INSERT INTO odontogram (id,patient_id,tooth,status,notes,updated_at) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP) ON
CONFLICT(id) DO UPDATE SET status=excluded.status,notes=excluded.notes,updated_at=CURRENT_TIMESTAMP"
).bind(rowId, patientId, tooth, status, notes).run();
return json({ ok: true, tooth, status, notes });
}
if (url.pathname === "/api/appointments" && request.method === "GET") {
const r = await env.DB.prepare(
"SELECT a.id,a.patient_id,p.full_name,a.starts_at,a.ends_at,a.status,a.notes FROM appointments a LEFT JOIN pat
ients p ON p.id=a.patient_id ORDER BY a.starts_at"
).all();
return json(r.results || []);
}
return json({ error: "No encontrado." }, 404);
}
async function body(request) {
try { return await request.json(); } catch { return {}; }
};
}
function json(data, status = 200) {
return new Response(JSON.stringify(data), {
status,
headers: { "content-type": "application/json;charset=UTF-8" }
});
}
function publicUser(u) {
return { id: u.id, email: u.email, name: u.name, role: u.role };
}
function getCookie(header, name) {
const item = header.split(";").map(x => x.trim()).find(x => x.startsWith(name + "="));
return item ? decodeURIComponent(item.slice(name.length + 1)) : null;
}
async function sessionUser(db, sessionId) {
return db.prepare(
AND u.active=1"
).bind(sessionId, Math.floor(Date.now() / 1000)).first();
"SELECT u.id,u.email,u.name,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at>?
}
function b64(bytes) {
let s = "";
for (const x of new Uint8Array(bytes)) s += String.fromCharCode(x);
return btoa(s);
}
function unb64(value) {
const b = atob(value);
const a = new Uint8Array(b.length);
for (let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
return a;
}
async function hashPassword(password, salt) {
salt = salt || crypto.getRandomValues(new Uint8Array(16));
const key = await crypto.subtle.importKey(
"raw",
new TextEncoder().encode(password),
"PBKDF2",
false,
["deriveBits"]
);
const bits = await crypto.subtle.deriveBits(
{ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
key,
256
);
return { salt: b64(salt), hash: b64(bits) };
}
async function verify(password, salt, hash) {
return (await hashPassword(password, unb64(salt))).hash === hash;
}
const HTML = `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DentalSM</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#f5f7fb;color:#172033;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
header{background:#fff;border-bottom:1px solid #e5e9f0;padding:18px 22px}
.brand{font-size:28px;font-weight:800;color:#1769e0}
main{max-width:1050px;margin:auto;padding:18px}
.card{background:#fff;border:1px solid #e5e9f0;border-radius:16px;padding:20px;margin-bottom:16px}
h1,h2,h3{margin-top:0}
.muted{color:#667085}
label{display:block;font-weight:650;margin:12px 0 6px}
input,textarea,select{width:100%;padding:12px;border:1px solid #d7dce5;border-radius:10px;font-size:16px;font-family:i
nherit}
textarea{min-height:90px;resize:vertical}
button{border:0;border-radius:10px;padding:12px 16px;background:#1769e0;color:#fff;font-weight:700;margin:7px 5px 7px
0;cursor:pointer}
.secondary{background:#eef3fb;color:#1769e0}
.hidden{display:none!important}
.error{color:#b42318}
.ok{color:#087443}
.grid,.formgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.patient{border:1px solid #e5e9f0;border-radius:12px;padding:15px;margin-top:12px}
.patient b{font-size:18px}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
.odontogram-box{margin-top:20px;padding:16px;border:1px solid #e5e9f0;border-radius:16px;background:#fafbfe}
.teeth-row{display:grid;grid-template-columns:repeat(16,minmax(36px,1fr));gap:6px;margin:14px 0}
.tooth{min-height:62px;margin:0;padding:6px 2px;background:#fff;color:#172033;border:2px solid #b8c1cf;border-radius:1
0px;font-size:12px}
.tooth.selected{border:3px solid #1769e0;background:#eef4ff}
.tooth.caries{border-color:#e5484d;background:#fff1f1}
.tooth.restauracion{border-color:#f59e0b;background:#fff8e7}
.tooth.ausente{border-color:#6b7280;background:#eef0f3}
.tooth.extraccion{border-color:#dc2626;background:#ffe4e6}
.tooth.endodoncia{border-color:#7c3aed;background:#f3e8ff}
.tooth.corona{border-color:#0891b2;background:#e6fffb}
.tooth.implante{border-color:#2563eb;background:#eaf2ff}
.tooth.fractura{border-color:#c2410c;background:#fff1e8}
.tooth.otro{border-color:#64748b;background:#f1f5f9}
.tooth-number{display:block;font-size:14px;font-weight:800}
.tooth-status{display:block;margin-top:4px;font-size:9px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.status-options{display:grid;grid-template-columns:repeat(auto-fit,minmax(125px,1fr));gap:8px}
.status-button{margin:0;background:#fff;color:#172033;border:1px solid #d7dce5}
.status-button.active{background:#1769e0;color:#fff;border-color:#1769e0}
@media(max-width:700px){
main{padding:10px}
.card{padding:15px}
.teeth-row{grid-template-columns:repeat(8,minmax(34px,1fr))}
}
</style>
</head>
<body>
<main>
<header><div class="brand">DentalSM</div></header>
<section id="setup" class="card hidden">
<h1>Configuración inicial</h1>
<p class="muted">Crea la primera cuenta Administradora.</p>
<label>Nombre</label><input id="setupName">
<label>Correo</label><input id="setupEmail" value="smdental99@gmail.com">
<label>Contraseña</label><input id="setupPass" type="password">
<button id="setupBtn" onclick="setupAdmin()">Crear administradora</button>
<p id="setupMsg"></p>
</section>
<section id="login" class="card">
<h1>Acceso seguro</h1>
<p class="muted">Entra a tu cuenta de DentalSM.</p>
<label>Correo</label><input id="email" type="email" value="smdental99@gmail.com" autocomplete="username">
<label>Contraseña</label><input id="password" type="password" autocomplete="current-password">
<button onclick="loginUser()">Iniciar sesión</button>
<p id="loginMsg"></p>
</section>
<section id="app" class="hidden">
<div class="card">
<div class="topbar">
<div><h1>Panel DentalSM</h1><p id="welcome" class="muted"></p></div>
<div>
<button onclick="show('home')">Inicio</button>
<button onclick="show('patients')">Pacientes</button>
<button onclick="show('agenda')">Agenda</button>
<button class="secondary" onclick="logout()">Cerrar sesión</button>
</div>
</div>
</div>
<div id="home" class="card">
<h2>Inicio</h2>
<p class="muted">El odontograma está dentro del expediente de cada paciente.</p>
<div class="grid">
<div><h3>Pacientes</h3><p class="muted">Registro y expedientes clínicos.</p></div>
<div><h3>Agenda</h3><p class="muted">Citas de la clínica.</p></div>
<div><h3>Usuarios</h3><p class="muted">Roles y permisos.</p></div>
</div>
</div>
<div id="patients" class="card hidden">
<h2>Pacientes</h2>
<button onclick="toggleForm()">+ Nuevo paciente</button>
<button class="secondary" onclick="loadPatients()">Actualizar</button>
<div id="newPatient" class="patient hidden">
<h3>Nuevo paciente</h3>
<div class="formgrid">
<div><label>Nombre completo *</label><input id="pName"></div>
<div><label>Fecha de nacimiento</label><input id="pBirth" type="date"></div>
<div><label>Teléfono</label><input id="pPhone" type="tel"></div>
<div><label>Correo</label><input id="pEmail" type="email"></div>
</div>
<button onclick="createPatient()">Guardar paciente</button>
<button class="secondary" onclick="toggleForm()">Cancelar</button>
<p id="patientMsg"></p>
</div>
<div id="patientsList" style="margin-top:16px" class="muted">Cargando...</div>
</div>
<div id="detail" class="card hidden">
<button class="secondary" onclick="show('patients')">← Volver</button>
<h2 id="dName"></h2>
<p id="dInfo" class="muted"></p>
<div class="odontogram-box">
<div class="topbar">
<div><h3>■ Odontograma</h3><p id="odontogramInfo" class="muted">Selecciona un diente.</p></div>
<button class="secondary" onclick="loadOdontogram()">Actualizar</button>
</div>
<div class="teeth-row" id="upperTeeth"></div>
<div class="teeth-row" id="lowerTeeth"></div>
<div id="odontogramEditor" class="hidden">
<h3 id="selectedToothTitle"></h3>
<div class="status-options" id="statusOptions"></div>
<label>Notas</label>
<textarea id="toothNotes" placeholder="Notas del diente..."></textarea>
<button onclick="saveTooth()">Guardar diente</button>
<p id="toothMsg"></p>
</div>
</div>
</div>
<div id="agenda" class="card hidden">
<h2>Agenda</h2>
<button onclick="loadAgenda()">Actualizar</button>
<div id="agendaList" class="muted">Cargando...</div>
</div>
</section>
</main>
<script>
var me = null;
var currentPatientId = null;
var currentTooth = null;
var odontogramData = {};
var TOOTH_STATUSES = [
{value:"sano",label:"Sano"},
{value:"caries",label:"Caries"},
{value:"restauracion",label:"Restauración"},
{value:"ausente",label:"Ausente"},
{value:"extraccion",label:"Extracción"},
{value:"endodoncia",label:"Endodoncia"},
{value:"corona",label:"Corona"},
{value:"implante",label:"Implante"},
{value:"fractura",label:"Fractura"},
{value:"otro",label:"Otro"}
];
function el(id){ return document.getElementById(id); }
async function api(path, options){
try{
var r = await fetch(path, options || {});
var d = await r.json().catch(function(){ return {}; });
return {r:r,d:d};
}catch(e){
return {r:{ok:false,status:0},d:{error:"No se pudo conectar con el servidor."}};
}
}
async function init(){
try{
var x = await api("/api/me");
if(x.d && x.d.authenticated){
me = x.d.user;
openApp();
}else{
el("login").classList.remove("hidden");
el("setup").classList.add("hidden");
el("app").classList.add("hidden");
}
}catch(e){
el("login").classList.remove("hidden");
el("loginMsg").className = "error";
el("loginMsg").textContent = "No se pudo cargar la sesión.";
}
}
function openApp(){
el("setup").classList.add("hidden");
el("login").classList.add("hidden");
el("app").classList.remove("hidden");
el("welcome").textContent = (me.name || "") + " · " + (me.role || "");
show("home");
}
async function setupAdmin(){
var x = await api("/api/setup-admin",{
method:"POST",
headers:{"content-type":"application/json"},
body:JSON.stringify({
name:el("setupName").value,
email:el("setupEmail").value,
password:el("setupPass").value
})
});
el("setupMsg").className = x.r.ok ? "ok" : "error";
el("setupMsg").textContent = x.r.ok ? "Administrador creado. Ya puedes iniciar sesión." : (x.d.error || "Error");
if(x.r.ok){
el("setup").classList.add("hidden");
el("login").classList.remove("hidden");
}
}
async function loginUser(){
el("loginMsg").textContent = "Entrando...";
var x = await api("/api/login",{
method:"POST",
headers:{"content-type":"application/json"},
body:JSON.stringify({
email:el("email").value,
password:el("password").value
})
});
if(!x.r.ok){
el("loginMsg").className = "error";
el("loginMsg").textContent = x.d.error || "Error al iniciar sesión.";
return;
}
me = x.d.user;
openApp();
}
async function logout(){
await api("/api/logout",{method:"POST"});
location.reload();
}
function show(id){
["home","patients","agenda","detail"].forEach(function(x){
el(x).classList.toggle("hidden",x !== id);
});
if(id === "patients") loadPatients();
if(id === "agenda") loadAgenda();
function toggleForm(){
el("newPatient").classList.toggle("hidden");
}
}
async function createPatient(){
var name = el("pName").value.trim();
if(!name){
el("patientMsg").className = "error";
el("patientMsg").textContent = "El nombre completo es obligatorio.";
return;
}
var x = await api("/api/patients",{
method:"POST",
headers:{"content-type":"application/json"},
body:JSON.stringify({
full_name:name,
birth_date:el("pBirth").value,
phone:el("pPhone").value,
email:el("pEmail").value
})
});
if(!x.r.ok){
el("patientMsg").className = "error";
el("patientMsg").textContent = x.d.error || "No se pudo guardar.";
return;
}
el("patientMsg").className = "ok";
el("patientMsg").textContent = "Paciente guardado correctamente.";
["pName","pBirth","pPhone","pEmail"].forEach(function(id){el(id).value="";});
setTimeout(function(){
el("newPatient").classList.add("hidden");
el("patientMsg").textContent = "";
loadPatients();
},500);
}
async function loadPatients(){
var x = await api("/api/patients");
if(!x.r.ok){
el("patientsList").innerHTML = '<p class="error">'+esc(x.d.error || "No se pudieron cargar los pacientes.")+"</p>"
;
return;
}
if(!Array.isArray(x.d) || !x.d.length){
el("patientsList").textContent = "Aún no hay pacientes.";
return;
}
el("patientsList").innerHTML = x.d.map(function(p){
return '<div class="patient"><b>'+esc(p.full_name)+'</b><div class="muted">'+
esc(p.phone || "Sin teléfono")+" · "+esc(p.email || "Sin correo")+
'</div><button onclick="openPatient(\''+escAttr(p.id)+'\')">Abrir expediente</button></div>';
}).join("");
}
async function openPatient(id){
var x = await api("/api/patients/"+encodeURIComponent(id));
if(!x.r.ok){
alert(x.d.error || "Error");
return;
}
currentPatientId = x.d.id;
currentTooth = null;
odontogramData = {};
el("dName").textContent = x.d.full_name;
el("dInfo").textContent = (x.d.phone || "Sin teléfono")+" · "+(x.d.email || "Sin correo")+" · "+(x.d.birth_date || "
Sin fecha");
show("detail");
renderTeeth();
await loadOdontogram();
}
async function loadOdontogram(){
if(!currentPatientId) return;
var x = await api("/api/odontogram?patient_id="+encodeURIComponent(currentPatientId));
if(!x.r.ok){
el("odontogramInfo").textContent = x.d.error || "No se pudo cargar el odontograma.";
return;
}
odontogramData = {};
(Array.isArray(x.d) ? x.d : []).forEach(function(row){
odontogramData[String(row.tooth)] = row;
});
renderTeeth();
refreshToothButtons();
}
function renderTeeth(){
var upper = [];
var lower = [];
for(var i=1;i<=16;i++) upper.push(i);
for(var j=32;j>=17;j--) lower.push(j);
el("upperTeeth").innerHTML = upper.map(toothButton).join("");
el("lowerTeeth").innerHTML = lower.map(toothButton).join("");
}
function toothButton(tooth){
var row = odontogramData[String(tooth)] || {status:"sano",notes:""};
var label = getStatusLabel(row.status);
return '<button type="button" class="tooth '+escAttr(row.status || "sano")+
'" data-tooth="'+tooth+'" onclick="selectTooth('+tooth+')">'+
'<span class="tooth-number">'+tooth+'</span>'+
'<span class="tooth-status">'+esc(label)+'</span></button>';
}
function selectTooth(tooth){
currentTooth = String(tooth);
var row = odontogramData[currentTooth] || {status:"sano",notes:""};
el("selectedToothTitle").textContent = "Diente "+currentTooth;
el("toothNotes").value = row.notes || "";
el("odontogramEditor").classList.remove("hidden");
el("toothMsg").textContent = "";
chooseStatus(row.status || "sano");
el("odontogramInfo").textContent = "Editando diente "+currentTooth+".";
refreshToothButtons();
}
function chooseStatus(status){
document.querySelectorAll("#statusOptions .status-button").forEach(function(btn){
btn.classList.toggle("active",btn.getAttribute("data-status")===status);
});
}
function getSelectedStatus(){
var active = document.querySelector("#statusOptions .status-button.active");
return active ? active.getAttribute("data-status") : "sano";
}
}
}
function refreshToothButtons(){
document.querySelectorAll(".tooth").forEach(function(btn){
btn.classList.toggle("selected",currentTooth === btn.getAttribute("data-tooth"));
});
function renderStatusButtons(){
el("statusOptions").innerHTML = TOOTH_STATUSES.map(function(s){
return '<button type="button" class="status-button" data-status="'+s.value+
'" onclick="chooseStatus(\''+s.value+'\')">'+esc(s.label)+"</button>";
}).join("");
async function saveTooth(){
if(!currentPatientId || !currentTooth) return;
if(!me || (me.role !== "admin" && me.role !== "doctor")){
el("toothMsg").className = "error";
el("toothMsg").textContent = "Tu usuario no tiene permiso para modificar el odontograma.";
return;
}
var status = getSelectedStatus();
var notes = el("toothNotes").value;
var x = await api("/api/odontogram",{
method:"POST",
headers:{"content-type":"application/json"},
body:JSON.stringify({
patient_id:currentPatientId,
tooth:currentTooth,
status:status,
notes:notes
})
});
if(!x.r.ok){
el("toothMsg").className = "error";
el("toothMsg").textContent = x.d.error || "No se pudo guardar.";
return;
}
odontogramData[currentTooth] = {
patient_id:currentPatientId,
tooth:currentTooth,
status:status,
notes:notes
};
el("toothMsg").className = "ok";
el("toothMsg").textContent = "Diente guardado.";
renderTeeth();
refreshToothButtons();
}
async function loadAgenda(){
var x = await api("/api/appointments");
if(!x.r.ok){
return;
el("agendaList").innerHTML = '<p class="error">'+esc(x.d.error || "No se pudo cargar la agenda.")+"</p>";
}
if(!Array.isArray(x.d) || !x.d.length){
el("agendaList").textContent = "Aún no hay citas.";
return;
}
el("agendaList").innerHTML = x.d.map(function(a){
return "<p><b>"+esc(a.full_name || a.patient_id)+"</b> · "+esc(a.starts_at || "")+"</p>";
}).join("");
}
function getStatusLabel(value){
var found = TOOTH_STATUSES.find(function(s){return s.value===value;});
return found ? found.label : "Sano";
}
function esc(value){
return String(value == null ? "" : value).replace(/[&<>"']/g,function(c){
return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];
});
}
}
renderStatusButtons();
init();
</script>
</body>
</html>`;
function escAttr(value){
return String(value == null ? "" : value).replace(/[^a-zA-Z0-9_:.\\-]/g,"");
