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
const MSG_ENCERRADO = "Apuração encerrada. Acesso desativado.";
const SENHA_ERRADA = "Senha incorreta. Nada foi excluído.";

function publicUser(u) {
  return { id: u.id, user: u.user, role: u.role, acessos: JSON.parse(u.acessos) };
}

async function usuarioDaSessao(req, db) {
  const auth = req.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return null;
  const row = await db.prepare(
    `SELECT u.*, (SELECT v FROM config WHERE k = 'encerrado') AS encerrado
     FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expira > ?`
  ).bind(token, Date.now()).first();
  if (!row) return null;
  // apuração encerrada: só admin continua com acesso
  if (row.encerrado === "1" && row.role !== "admin") return { bloqueado: true };
  return { ...publicUser(row), token };
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
      if (u.role !== "admin") {
        const enc = await db.prepare("SELECT v FROM config WHERE k = 'encerrado'").first();
        if (enc && enc.v === "1") return json({ erro: MSG_ENCERRADO, encerrado: true }, 403);
      }
      const token = novoToken();
      await db.batch([
        db.prepare("DELETE FROM sessions WHERE expira < ?").bind(Date.now()),
        db.prepare("INSERT INTO sessions (token, user_id, expira) VALUES (?, ?, ?)").bind(token, u.id, Date.now() + SESSAO_DIAS * 864e5)
      ]);
      return json({ token, user: publicUser(u) });
    }

    // foto do candidato: pública e guardada em cache pelo navegador (o ?v= muda quando a foto muda)
    if (rota === "cand-foto" && metodo === "GET" && id) {
      const c = await db.prepare("SELECT foto FROM candidatos WHERE id = ?").bind(id).first();
      const m = c && c.foto && /^data:(image\/[a-z+]+);base64,(.*)$/s.exec(c.foto);
      if (!m) return new Response("sem foto", { status: 404 });
      const bin = Uint8Array.from(atob(m[2]), (ch) => ch.charCodeAt(0));
      return new Response(bin, { headers: { "Content-Type": m[1], "Cache-Control": "public, max-age=31536000, immutable" } });
    }

    const me = await usuarioDaSessao(request, db);
    if (!me) return erro("Sessão expirada. Entre novamente.", 401);
    if (me.bloqueado) return json({ erro: MSG_ENCERRADO, encerrado: true }, 401);
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
        db.prepare(`SELECT r.id, r.zona, r.sec, r.d, r.p, r.r, r.votos, r.por, r.criado,
                    (SELECT COUNT(*) FROM fotos f WHERE f.reg_id = r.id) AS nfotos
                    FROM regs r ORDER BY r.id`),
        db.prepare("SELECT id, nome, cargo, cor, fv, ordem FROM candidatos ORDER BY ordem, rowid")
      ];
      if (isAdmin) consultas.push(db.prepare("SELECT id, user, role, acessos FROM users ORDER BY id"));
      const [cfg, regs, cands, users] = await db.batch(consultas);
      // votos de cada seção por candidato (seções antigas: colunas d e p)
      const regsOut = regs.results.map((r) => {
        let votos = null;
        try { votos = r.votos ? JSON.parse(r.votos) : null; } catch {}
        if (!votos) votos = { d: r.d || 0, p: r.p || 0 };
        return { id: r.id, zona: r.zona, sec: r.sec, votos, por: r.por, criado: r.criado, nfotos: r.nfotos };
      });
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
        mostrarPctVotos: config.mostrarPctVotos ? 1 : 0,
        encerrado: config.encerrado ? 1 : 0,
        zonas,
        versao: config.versao || 0,
        candidatos: cands.results,
        regs: regsOut,
        users: isAdmin && users ? users.results.map(publicUser) : []
      });
    }
    if (rota === "config" && metodo === "PUT") {
      if (!isAdmin) return erro("Sem permissão.", 403);
      const sec = parseInt(body.totalSec, 10);
      const ele = parseInt(body.totalEleitores, 10) || 0;
      const mostrarPct = Number(body.mostrarPct) === 1 ? 1 : 0;
      const mostrarPctVotos = Number(body.mostrarPctVotos) === 1 ? 1 : 0;
      if (!(sec > 0)) return erro("Informe o número de seções.");
      if (ele < 0) return erro("Quantidade de eleitores inválida.");
      await db.batch([
        db.prepare("INSERT OR REPLACE INTO config (k, v) VALUES (?, ?)").bind("totalSec", String(sec)),
        db.prepare("INSERT OR REPLACE INTO config (k, v) VALUES (?, ?)").bind("totalEleitores", String(ele)),
        db.prepare("INSERT OR REPLACE INTO config (k, v) VALUES (?, ?)").bind("mostrarPct", String(mostrarPct)),
        db.prepare("INSERT OR REPLACE INTO config (k, v) VALUES (?, ?)").bind("mostrarPctVotos", String(mostrarPctVotos)),
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
    // ---------- ENCERRAR / REABRIR ACESSO (só admin) ----------
    if (rota === "encerrar" && metodo === "PUT") {
      if (!isAdmin) return erro("Sem permissão.", 403);
      const v = Number(body.encerrado) === 1 ? "1" : "0";
      const lote = [
        db.prepare("INSERT OR REPLACE INTO config (k, v) VALUES ('encerrado', ?)").bind(v),
        db.prepare(SQL_VERSAO)
      ];
      // quem não é admin é desconectado na próxima atualização (em até 5 s) com o aviso de encerrado
      await db.batch(lote);
      return json({ ok: true });
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
      // votos por candidato: { idDoCandidato: quantidade }
      const ids = (await db.prepare("SELECT id FROM candidatos").all()).results.map((c) => c.id);
      const entrada = body.votos && typeof body.votos === "object" ? body.votos : { d: body.d, p: body.p };
      const votos = {};
      (ids.length ? ids : Object.keys(entrada)).forEach((k) => { votos[k] = n(entrada[k]); });
      const ins = await db.prepare(
        "INSERT INTO regs (zona, sec, d, p, r, votos, por, criado) VALUES (?, ?, ?, ?, 0, ?, ?, ?)"
      ).bind(zona, sec, votos.d || 0, votos.p || 0, JSON.stringify(votos), me.user, Date.now()).run();
      const regId = ins.meta.last_row_id;
      await db.batch([
        ...fotos.map((src) => db.prepare("INSERT INTO fotos (reg_id, src) VALUES (?, ?)").bind(regId, src)),
        db.prepare(SQL_VERSAO)
      ]);
      return json({ ok: true, id: regId });
    }
    // ---------- ZERAR APURAÇÃO (apaga todas as seções e fotos) ----------
    if (rota === "regs" && metodo === "DELETE" && !id) {
      if (!isAdmin) return erro("Sem permissão.", 403);
      if (!await senhaAdminOk(request, db, me)) return erro(SENHA_ERRADA, 403);
      await db.batch([
        db.prepare("DELETE FROM fotos"),
        db.prepare("DELETE FROM regs"),
        db.prepare("DELETE FROM sqlite_sequence WHERE name IN ('regs', 'fotos')"),
        db.prepare(SQL_VERSAO)
      ]);
      return json({ ok: true });
    }
    // ---------- CANDIDATOS ----------
    if (rota === "candidatos") {
      if (!isAdmin) return erro("Sem permissão.", 403);
      const txt = (v, max) => String(v || "").trim().toUpperCase().slice(0, max);
      const cor = (v) => (/^#[0-9a-f]{6}$/i.test(String(v || "")) ? String(v) : "#1565c0");
      const fotoOk = (f) => typeof f === "string" && f.startsWith("data:image/") && f.length <= 15e5;
      if (metodo === "POST" && !id) {
        const nome = txt(body.nome, 40);
        if (!nome) return erro("Digite o nome do candidato.");
        const total = await db.prepare("SELECT COUNT(*) AS n, COALESCE(MAX(ordem), 0) AS m FROM candidatos").first();
        if (total.n >= 6) return erro("Máximo de 6 candidatos.");
        let novoId = /^[a-z0-9]{1,12}$/.test(String(body.id || "")) ? String(body.id) : "c" + hex(crypto.getRandomValues(new Uint8Array(4)));
        if (await db.prepare("SELECT id FROM candidatos WHERE id = ?").bind(novoId).first()) novoId = "c" + hex(crypto.getRandomValues(new Uint8Array(4)));
        const foto = fotoOk(body.foto) ? body.foto : null;
        await db.batch([
          db.prepare("INSERT INTO candidatos (id, nome, cargo, cor, foto, fv, ordem) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(novoId, nome, txt(body.cargo, 60), cor(body.cor), foto, foto ? Date.now() : 0, total.m + 1),
          db.prepare(SQL_VERSAO)
        ]);
        return json({ ok: true, id: novoId });
      }
      if (metodo === "PUT" && id === "ordem") {
        const lista = Array.isArray(body.ids) ? body.ids : [];
        await db.batch([
          ...lista.map((cid, i) => db.prepare("UPDATE candidatos SET ordem = ? WHERE id = ?").bind(i + 1, String(cid))),
          db.prepare(SQL_VERSAO)
        ]);
        return json({ ok: true });
      }
      if (metodo === "PUT" && id) {
        const nome = txt(body.nome, 40);
        if (!nome) return erro("Digite o nome do candidato.");
        if (!await db.prepare("SELECT id FROM candidatos WHERE id = ?").bind(id).first()) return erro("Candidato não encontrado.", 404);
        const lote = [db.prepare("UPDATE candidatos SET nome = ?, cargo = ?, cor = ? WHERE id = ?").bind(nome, txt(body.cargo, 60), cor(body.cor), id)];
        if (body.foto === "") lote.push(db.prepare("UPDATE candidatos SET foto = NULL, fv = 0 WHERE id = ?").bind(id));
        else if (fotoOk(body.foto)) lote.push(db.prepare("UPDATE candidatos SET foto = ?, fv = ? WHERE id = ?").bind(body.foto, Date.now(), id));
        lote.push(db.prepare(SQL_VERSAO));
        await db.batch(lote);
        return json({ ok: true });
      }
      if (metodo === "DELETE" && id) {
        if (!await senhaAdminOk(request, db, me)) return erro(SENHA_ERRADA, 403);
        // não deixa sumir voto: candidato com votos só sai depois de zerar a apuração
        const regsV = (await db.prepare("SELECT votos, d, p FROM regs").all()).results;
        const temVoto = regsV.some((r) => {
          let v = null; try { v = r.votos ? JSON.parse(r.votos) : null; } catch {}
          if (!v) v = { d: r.d, p: r.p };
          return (v[id] || 0) > 0;
        });
        if (temVoto) return erro("Esse candidato tem votos nas seções digitadas. Zere a apuração antes de excluir.", 409);
        await db.batch([db.prepare("DELETE FROM candidatos WHERE id = ?").bind(id), db.prepare(SQL_VERSAO)]);
        return json({ ok: true });
      }
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
