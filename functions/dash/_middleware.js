// Porteiro de /dash: nada em /dash (página ou dados) sai sem login.
// Login = senha da equipe (DASH_SENHA). Sessão = cookie assinado com HMAC (DASH_SEGREDO), 30 dias.
// Segredos ficam nas variáveis de ambiente do projeto Pages, nunca neste repositório (que é público).

const COOKIE = 'sg_dash';
const DIAS = 30;
const SEM_INDICE = { 'x-robots-tag': 'noindex, nofollow', 'cache-control': 'no-store' };

const enc = new TextEncoder();

async function assinar(texto, segredo) {
  const chave = await crypto.subtle.importKey('raw', enc.encode(segredo), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', chave, enc.encode(texto));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Comparação em tempo constante (não vaza, pelo tempo de resposta, quantos caracteres batem).
function iguais(a, b) {
  const x = enc.encode(String(a)), y = enc.encode(String(b));
  let dif = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) dif |= (x[i] || 0) ^ (y[i] || 0);
  return dif === 0;
}

async function sessaoValida(request, env) {
  const m = (request.headers.get('cookie') || '').match(new RegExp('(?:^|; )' + COOKIE + '=([^;]+)'));
  if (!m) return false;
  const [expira, sig] = m[1].split('.');
  if (!expira || !sig || Number(expira) < Date.now()) return false;
  return iguais(sig, await assinar(expira, env.DASH_SEGREDO));
}

function paginaLogin(erro) {
  const html = `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Painel SG</title>
<style>
  :root{--fundo:#0b1220;--cartao:rgba(255,255,255,.05);--borda:rgba(255,255,255,.1);--texto:#e8edf7;--suave:#94a3b8;--acento:#5b8cff;--erro:#f87171}
  *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(1200px 600px at 20% -10%,#1d2b55,transparent),var(--fundo);color:var(--texto);font:15px/1.5 Inter,system-ui,-apple-system,sans-serif;padding:16px}
  form{width:100%;max-width:360px;background:var(--cartao);border:1px solid var(--borda);border-radius:16px;padding:28px;backdrop-filter:blur(12px)}
  h1{font-size:18px;margin:0 0 4px}p{color:var(--suave);margin:0 0 20px;font-size:13px}
  input{width:100%;padding:12px 14px;border-radius:10px;border:1px solid var(--borda);background:rgba(0,0,0,.25);color:var(--texto);font:inherit;margin-bottom:12px}
  button{width:100%;padding:12px;border:0;border-radius:10px;background:var(--acento);color:#fff;font:600 15px Inter,system-ui,sans-serif;cursor:pointer}
  .erro{color:var(--erro);font-size:13px;margin:-4px 0 12px}
</style></head><body>
<form method="post" action="/dash/entrar">
  <h1>Painel SG</h1><p>Acesso restrito à equipe.</p>
  ${erro ? '<div class="erro">Senha incorreta.</div>' : ''}
  <input type="password" name="senha" placeholder="Senha da equipe" autocomplete="current-password" autofocus required>
  <button type="submit">Entrar</button>
</form></body></html>`;
  return new Response(html, { status: erro ? 401 : 200, headers: { 'content-type': 'text/html; charset=utf-8', ...SEM_INDICE } });
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  if (!env.DASH_SENHA || !env.DASH_SEGREDO) return new Response('Painel não configurado.', { status: 503, headers: SEM_INDICE });

  if (url.pathname === '/dash/entrar' && request.method === 'POST') {
    const form = await request.formData().catch(() => null);
    if (!form || !iguais(form.get('senha') || '', env.DASH_SENHA)) return paginaLogin(true);
    const expira = String(Date.now() + DIAS * 86400000);
    const valor = expira + '.' + (await assinar(expira, env.DASH_SEGREDO));
    return new Response(null, {
      status: 303,
      headers: {
        location: '/dash',
        'set-cookie': `${COOKIE}=${valor}; Path=/dash; Max-Age=${DIAS * 86400}; HttpOnly; Secure; SameSite=Lax`,
        ...SEM_INDICE,
      },
    });
  }

  if (url.pathname === '/dash/sair') {
    return new Response(null, {
      status: 303,
      headers: { location: '/dash', 'set-cookie': `${COOKIE}=; Path=/dash; Max-Age=0; HttpOnly; Secure; SameSite=Lax`, ...SEM_INDICE },
    });
  }

  if (!(await sessaoValida(request, env))) {
    if (url.pathname.startsWith('/dash/api')) {
      return new Response(JSON.stringify({ erro: 'não autenticado' }), { status: 401, headers: { 'content-type': 'application/json', ...SEM_INDICE } });
    }
    return paginaLogin(false);
  }

  const resposta = await next();
  const r = new Response(resposta.body, resposta);
  Object.entries(SEM_INDICE).forEach(([k, v]) => r.headers.set(k, v));
  return r;
}
