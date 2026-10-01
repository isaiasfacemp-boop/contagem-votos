// Contagem de Votos — Worker (API + arquivos estáticos)
// Alteração: config "mostrarPct" (mostrar ou não a porcentagem nos cards)

const SESSAO_DIAS = 7;
const ITER = 100000;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
  });
}
const erro = (msg, status = 400) => json({ erro: msg }, status);

function hex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function fromHex(h) {
  return new Uint8Array(h.match(/.{2}/g).map((x) => parseInt(x, 16)));
}
async function hashSenha(senha, saltHex) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(senha), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: fromHex(saltHex), iterations: ITER },
    key,
    256
  );
  return hex(bits);
}
function novoSalt() {
  return hex(crypto.getRandomValues(new Uint8Array(16)));
}
function novoToken() {
  return hex(crypto.getRandomValues(new Uint8Array(32)));
}

const SQL_VERSAO = `INSERT INTO config (k, v) VALUES ('versao', '1')
  ON CONFLICT(k) DO UPDATE SET v = CAST(v AS INTEGER) + 1`;

const ZONAS_PADRAO = ["56", "202"];
function normZona(v) {
  return String(v || "").replace(/[ªº°]/g, "").replace(/ZONA/gi, "").trim().toUpperCase().slice(0, 10);
}
async function lerZonas(db) {
  const r = await db.prepare("SELECT v FROM config WHERE k = 'zonas'").first();
  if (!r) return [...ZONAS_PADRAO];
  try { return JSON.parse(r.v); } catch { return [...ZONAS_PADRAO]; }
}
async function salvarZonas(db, lista, extras = []) {
  const ordenada = [...lista].sort((a, b) => (parseInt(a, 10) || 0) - (parseInt(b, 10) || 0) || a.localeCompare(b));
  await db.batch([
    db.prepare("INSERT OR REPLACE INTO config (k, v) VALUES ('zonas', ?)").bind(JSON.stringify(ordenada)),
    ...extras,
    db.prepare(SQL_VERSAO)
  ]);
}

// toda exclusão exige a senha do admin que está conectado (cabeçalho X-Senha)
async function senhaAdminOk(req, db, me) {
  let senha = req.headers.get("X-Senha") || "";
  try { senha = decodeURIComponent(senha); } catch {}
  if (!senha) return false;
  const u = await db.prepare("SELECT salt, hash FROM users WHERE id = ?").bind(me.id).first();
  return !!u && await hashSenha(senha, u.salt) === u.hash;
}
const SENHA_ERRADA = "Senha incorreta. Nada foi excluído.";

function publicUser(u) {
  return { id: u.id, user: u.user, role: u.role, acessos: JSON.parse(u.acessos) };
}

async function usuarioDaSessao(req, db) {
  const auth = req.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return null;
  const row = await db.prepare(
    `SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expira > ?`
  ).bind(token, Date.now()).first();
  return row ? { ...publicUser(row), token } : null;
}

function validarAcessos(role, acessos) {
  const ok = ["resumo", "registro", "secoes"];
  const lista = (Array.isArray(acessos) ? acessos : []).filter((a) => ok.includes(a));
  if (role === "admin") return ["resumo", "registro", "secoes", "admin"];
  return lista;
}

async function onRequest(ctx) {
  const { request, env, params } = ctx;
  const db = env.DB;
  if (!db) return erro("Banco D1 não configurado (binding DB).", 500);
  const partes = Array.isArray(params.path) ? params.path : params.path ? [params.path] : [];
  const rota = partes[0] || "";
  const id = partes[1];
  const metodo = request.method;
  let body = {};
  if (metodo === "POST" || metodo === "PUT") {
    try {
      body = await request.json();
    } catch {
      body = {};
    }
  }
  try {
    if (rota === "login" && metodo === "POST") {
      const user = String(body.user || "").trim().toUpperCase();
      const pass = String(body.pass || "");
      const u = await db.prepare("SELECT * FROM users WHERE user = ?").bind(user).first();
      if (!u || await hashSenha(pass, u.salt) !== u.hash) return erro("Usuário ou senha incorretos.", 401);
      const token = novoToken();
      await db.batch([
        db.prepare("DELETE FROM sessions WHERE expira < ?").bind(Date.now()),
        db.prepare("INSERT INTO sessions (token, user_id, expira) VALUES (?, ?, ?)").bind(token, u.id, Date.now() + SESSAO_DIAS * 864e5)
      ]);
      return json({ token, user: publicUser(u) });
    }

    const me = await usuarioDaSessao(request, db);
    if (!me) return erro("Sessão expirada. Entre novamente.", 401);
    const isAdmin = me.role === "admin";

    if (rota === "logout" && metodo === "POST") {
      await db.prepare("DELETE FROM sessions WHERE token = ?").bind(me.token).run();
      return json({ ok: true });
    }
    if (rota === "me" && metodo === "GET") {
      const { token, ...u } = me;
      return json({ user: u });
    }
    if (rota === "versao" && metodo === "GET") {
      const v = await db.prepare("SELECT v FROM config WHERE k = 'versao'").first();
      return json({ v: v ? Number(v.v) : 0 });
    }
    if (rota === "state" && metodo === "GET") {
      // lista de usuários só é buscada para o admin (economiza leituras no banco)
      const consultas = [
        db.prepare("SELECT k, v FROM config"),
        db.prepare(`SELECT r.id, r.zona, r.sec, r.d, r.p, r.r, r.por, r.criado,
                    (SELECT COUNT(*) FROM fotos f WHERE f.reg_id = r.id) AS nfotos
                    FROM regs r ORDER BY r.id`)
      ];
      if (isAdmin) consultas.push(db.prepare("SELECT id, user, role, acessos FROM users ORDER BY id"));
      const [cfg, regs, users] = await db.batch(consultas);
      const config = {};
      let zonas = ZONAS_PADRAO;
      cfg.results.forEach((x) => {
        if (x.k === "zonas") {
          try { zonas = JSON.parse(x.v); } catch {}
        } else config[x.k] = Number(x.v);
      });
      return json({
        totalSec: config.totalSec || 0,
        totalEleitores: config.totalEleitores || 0,
        mostrarPct: config.mostrarPct ? 1 : 0,
        zonas,
        versao: config.versao || 0,
        regs: regs.results,
        users: isAdmin && users ? users.results.map(publicUser) : []
      });
    }
    if (rota === "config" && metodo === "PUT") {
      if (!isAdmin) return erro("Sem permissão.", 403);
      const sec = parseInt(body.totalSec, 10);
      const ele = parseInt(body.totalEleitores, 10) || 0;
      const mostrarPct = Number(body.mostrarPct) === 1 ? 1 : 0;
      if (!(sec > 0)) return erro("Informe o número de seções.");
      if (ele < 0) return erro("Quantidade de eleitores inválida.");
      await db.batch([
        db.prepare("INSERT OR REPLACE INTO config (k, v) VALUES (?, ?)").bind("totalSec", String(sec)),
        db.prepare("INSERT OR REPLACE INTO config (k, v) VALUES (?, ?)").bind("totalEleitores", String(ele)),
        db.prepare("INSERT OR REPLACE INTO config (k, v) VALUES (?, ?)").bind("mostrarPct", String(mostrarPct)),
        db.prepare(SQL_VERSAO)
      ]);
      return json({ ok: true });
    }
    // ---------- ZONAS (lista guardada na tabela config, chave "zonas") ----------
    if (rota === "zonas") {
      if (!isAdmin) return erro("Sem permissão.", 403);
      const zonas = await lerZonas(db);
      const alvo = id ? normZona(decodeURIComponent(id)) : "";
      if (metodo === "POST" && !id) {
        const z = normZona(body.zona);
        if (!z) return erro("Digite o número da zona.");
        if (zonas.includes(z)) return erro("Essa zona já existe.", 409);
        await salvarZonas(db, [...zonas, z]);
        return json({ ok: true });
      }
      if (metodo === "PUT" && id) {
        const z = normZona(body.zona);
        if (!z) return erro("Digite o número da zona.");
        if (!zonas.includes(alvo)) return erro("Zona não encontrada.", 404);
        if (z !== alvo && zonas.includes(z)) return erro("Essa zona já existe.", 409);
        // renomeia também nas seções já digitadas
        await salvarZonas(db, zonas.map((x) => (x === alvo ? z : x)), [
          db.prepare("UPDATE regs SET zona = ? WHERE zona = ?").bind(z, alvo)
        ]);
        return json({ ok: true });
      }
      if (metodo === "DELETE" && id) {
        if (!await senhaAdminOk(request, db, me)) return erro(SENHA_ERRADA, 403);
        const usadas = await db.prepare("SELECT COUNT(*) AS n FROM regs WHERE zona = ?").bind(alvo).first();
        if (usadas && usadas.n > 0) return erro(`A zona ${alvo} tem ${usadas.n} seção(ões) digitada(s). Exclua as seções antes.`, 409);
        const resto = zonas.filter((x) => x !== alvo);
        if (!resto.length) return erro("Precisa ter pelo menos uma zona.");
        await salvarZonas(db, resto);
        return json({ ok: true });
      }
    }
    if (rota === "regs" && metodo === "POST" && !id) {
      if (!me.acessos.includes("registro")) return erro("Sem permissão para registrar.", 403);
      const zona = String(body.zona || "").trim().toUpperCase();
      const sec = String(body.sec || "").trim().toUpperCase();
      const n = (v) => Math.max(0, parseInt(v, 10) || 0);
      if (!zona || !sec) return erro("Informe a zona e a seção.");
      // seção é número único: 100, 0100 e 00100 são a mesma seção
      const existe = await db.prepare("SELECT id, zona, sec FROM regs WHERE LTRIM(sec, '0') = LTRIM(?, '0')").bind(sec).first();
      if (existe) return erro(`Seção ${existe.sec} já foi digitada (zona ${existe.zona}). Não pode repetir.`, 409);
      const fotos = Array.isArray(body.fotos) ? body.fotos.filter((f) => typeof f === "string" && f.startsWith("data:image/")) : [];
      if (!fotos.length) return erro("Anexe pelo menos uma foto do comprovante.");
      if (fotos.some((f) => f.length > 18e5)) return erro("Foto muito grande.", 413);
      const ins = await db.prepare(
        "INSERT INTO regs (zona, sec, d, p, r, por, criado) VALUES (?, ?, ?, ?, ?, ?, ?)"
      ).bind(zona, sec, n(body.d), n(body.p), n(body.r), me.user, Date.now()).run();
      const regId = ins.meta.last_row_id;
      await db.batch([
        ...fotos.map((src) => db.prepare("INSERT INTO fotos (reg_id, src) VALUES (?, ?)").bind(regId, src)),
        db.prepare(SQL_VERSAO)
      ]);
      return json({ ok: true, id: regId });
    }
    if (rota === "regs" && metodo === "DELETE" && id) {
      if (!isAdmin) return erro("Sem permissão.", 403);
      if (!await senhaAdminOk(request, db, me)) return erro(SENHA_ERRADA, 403);
      await db.batch([
        db.prepare("DELETE FROM fotos WHERE reg_id = ?").bind(id),
        db.prepare("DELETE FROM regs WHERE id = ?").bind(id),
        db.prepare(SQL_VERSAO)
      ]);
      return json({ ok: true });
    }
    if (rota === "fotos" && metodo === "GET" && id) {
      const r = await db.prepare("SELECT id, src FROM fotos WHERE reg_id = ? ORDER BY id").bind(id).all();
      return json({ fotos: r.results });
    }
    if (rota === "users") {
      if (!isAdmin) return erro("Sem permissão.", 403);
      if (metodo === "POST" && !id) {
        const user = String(body.user || "").trim().toUpperCase();
        const pass = String(body.pass || "");
        const role = ["admin", "digitador", "visualizador"].includes(body.role) ? body.role : "digitador";
        if (!user || !pass) return erro("Preencha usuário e senha.");
        if (pass.length < 4) return erro("Senha mínima de 4 caracteres.");
        const existe = await db.prepare("SELECT id FROM users WHERE user = ?").bind(user).first();
        if (existe) return erro("Usuário já existe.", 409);
        const salt = novoSalt();
        await db.prepare("INSERT INTO users (user, salt, hash, role, acessos) VALUES (?, ?, ?, ?, ?)").bind(user, salt, await hashSenha(pass, salt), role, JSON.stringify(validarAcessos(role, body.acessos))).run();
        await db.prepare(SQL_VERSAO).run();
        return json({ ok: true });
      }
      if (metodo === "PUT" && id) {
        const user = String(body.user || "").trim().toUpperCase();
        const pass = String(body.pass || "");
        const role = Number(id) === 1 ? "admin" : ["admin", "digitador", "visualizador"].includes(body.role) ? body.role : "digitador";
        if (!user) return erro("Preencha o usuário.");
        if (pass && pass.length < 4) return erro("Senha mínima de 4 caracteres.");
        const outro = await db.prepare("SELECT id FROM users WHERE user = ? AND id <> ?").bind(user, id).first();
        if (outro) return erro("Usuário já existe.", 409);
        const acessos = JSON.stringify(validarAcessos(role, body.acessos));
        if (pass) {
          const salt = novoSalt();
          await db.batch([
            db.prepare("UPDATE users SET user = ?, salt = ?, hash = ?, role = ?, acessos = ? WHERE id = ?").bind(user, salt, await hashSenha(pass, salt), role, acessos, id),
            db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(id),
            db.prepare(SQL_VERSAO)
          ]);
        } else {
          await db.batch([
            db.prepare("UPDATE users SET user = ?, role = ?, acessos = ? WHERE id = ?").bind(user, role, acessos, id),
            db.prepare(SQL_VERSAO)
          ]);
        }
        return json({ ok: true });
      }
      if (metodo === "DELETE" && id) {
        if (!await senhaAdminOk(request, db, me)) return erro(SENHA_ERRADA, 403);
        if (Number(id) === 1) return erro("O administrador principal não pode ser excluído.", 403);
        await db.batch([
          db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(id),
          db.prepare("DELETE FROM users WHERE id = ?").bind(id),
          db.prepare(SQL_VERSAO)
        ]);
        return json({ ok: true });
      }
    }
    return erro("Rota não encontrada.", 404);
  } catch (e) {
    return erro("Erro no servidor: " + (e && e.message ? e.message : e), 500);
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/api" || url.pathname.startsWith("/api/")) {
      const path = url.pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean);
      return onRequest({ request, env, params: { path } });
    }
    return env.ASSETS.fetch(request);
  }
};
