export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      return Response.json({ ok: true, app: "DentalSM" });
    }

    return new Response(HTML, {
      headers: { "content-type": "text/html; charset=UTF-8" }
    });
  }
};

const HTML = `<!doctype html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>DentalSM</title>
  <style>
    *{box-sizing:border-box}
    body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f5f7fb;color:#172033}
    header{background:#fff;border-bottom:1px solid #e5e9f0;padding:18px 20px;position:sticky;top:0}
    .brand{font-size:24px;font-weight:800;color:#1769e0}
    main{max-width:900px;margin:0 auto;padding:24px 18px}
    .hero{background:#fff;border-radius:18px;padding:28px;box-shadow:0 4px 18px #0000000b}
    h1{margin:0 0 8px;font-size:30px}
    p{color:#667085;line-height:1.5}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;margin-top:22px}
    .card{background:#fff;border:1px solid #e7ebf2;border-radius:14px;padding:20px}
    .card strong{display:block;font-size:18px;margin-bottom:6px}
    .status{color:#0a9f68;font-weight:700}
    button{border:0;border-radius:10px;background:#1769e0;color:white;padding:12px 18px;font-weight:700;font-size:15px}
  </style>
</head>
<body>
<header><div class="brand">DentalSM</div></header>
<main>
  <section class="hero">
    <h1>Sistema DentalSM</h1>
    <p>La aplicación está desplegada correctamente en Cloudflare Workers.</p>
    <p class="status">● Sistema en línea</p>
    <button onclick="check()">Comprobar conexión</button>
    <p id="result"></p>
  </section>
  <section class="grid">
    <div class="card"><strong>Pacientes</strong><span>Gestión de pacientes</span></div>
    <div class="card"><strong>Citas</strong><span>Agenda y seguimiento</span></div>
    <div class="card"><strong>Expedientes</strong><span>Información clínica</span></div>
  </section>
</main>
<script>
async function check(){
  const r = await fetch('/api/health');
  const data = await r.json();
  document.querySelector('#result').textContent =
    data.ok ? 'Conexión correcta ✓' : 'No se pudo comprobar la conexión';
}
</script>
</body>
</html>`;
