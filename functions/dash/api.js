// GET /dash/api — números agregados do painel (só passa daqui com sessão válida: ver _middleware.js).
// Chama public.dash_reativacao no Supabase com o token do painel (DASH_TOKEN). Só agregados: nenhum dado pessoal.

export async function onRequestGet({ env }) {
  const r = await fetch(`${env.SUPABASE_URL}/rest/v1/rpc/dash_reativacao`, {
    method: 'POST',
    headers: {
      apikey: env.SUPABASE_ANON_KEY,
      authorization: `Bearer ${env.SUPABASE_ANON_KEY}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ p_token: env.DASH_TOKEN }),
  });
  if (!r.ok) {
    console.log('falha dash_reativacao', r.status, (await r.text()).slice(0, 300));
    return new Response(JSON.stringify({ erro: 'falha ao consultar o banco' }), { status: 502, headers: { 'content-type': 'application/json' } });
  }
  return new Response(await r.text(), { headers: { 'content-type': 'application/json; charset=utf-8' } });
}
