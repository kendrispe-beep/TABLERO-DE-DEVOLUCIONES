"""Actualiza el tablero de devoluciones (index.html cifrado) con datos de Snowflake.

Lee las credenciales de variables de entorno (GitHub Secrets):
  SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER, SNOWFLAKE_PRIVATE_KEY o SNOWFLAKE_PASSWORD,
  SNOWFLAKE_ROLE (opcional), SNOWFLAKE_WAREHOUSE (opcional),
  TABLERO_USUARIO, TABLERO_CLAVE.
Actualización incremental: conserva el histórico del index.html actual y solo
consulta lo nuevo (notas de cambio desde la última fecha, devoluciones efectivas
desde el inicio del último mes, y la venta mensual completa, que es liviana).
"""
import base64, datetime, gzip, json, os, re, sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

RAIZ = Path(__file__).resolve().parent.parent
INDEX = RAIZ / "index.html"
SQL = Path(__file__).resolve().parent
IT = 250000


def env(n, req=True):
    v = os.environ.get(n, "").strip()
    if req and not v:
        sys.exit(f"Falta el secreto {n}")
    return v


def clave(usuario, pw, salt):
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, IT).derive(
        (usuario.strip().lower() + ":" + pw).encode())


def descifrar(html, usuario, pw):
    g = lambda k: base64.b64decode(re.search(rf'const S="([^"]+)",V="([^"]+)",C="([^"]+)"', html).group(k))
    salt, iv, ct = g(1), g(2), g(3)
    return gzip.decompress(AESGCM(clave(usuario, pw, salt)).decrypt(iv, ct, None)).decode("utf-8")


def cifrar(plano, login_html, usuario, pw):
    salt, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(clave(usuario, pw, salt)).encrypt(iv, gzip.compress(plano.encode("utf-8")), None)
    b = lambda x: base64.b64encode(x).decode()
    return re.sub(r'const S="[^"]+",V="[^"]+",C="[^"]+"',
                  lambda _: f'const S="{b(salt)}",V="{b(iv)}",C="{b(ct)}"', login_html, count=1)


def bloque(html, id_):
    m = re.search(rf'<script type="application/json" id="{id_}">(.*?)</script>', html, re.S)
    return m, json.loads(m.group(1).replace("<\\/", "</"))


def poner(html, id_, obj):
    m, _ = bloque(html, id_)
    t = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    return html[:m.start(1)] + t + html[m.end(1):]


def conectar():
    import snowflake.connector
    acc = env("SNOWFLAKE_ACCOUNT")
    acc = re.sub(r"^https?://", "", acc).split(".snowflakecomputing.com")[0]
    m = re.search(r"app\.snowflake\.com/([^/]+)/([^/#]+)", acc)
    if m:
        acc = f"{m.group(1)}-{m.group(2)}"
    p = dict(account=acc, user=env("SNOWFLAKE_USER"),
             role=env("SNOWFLAKE_ROLE", False) or None,
             warehouse=env("SNOWFLAKE_WAREHOUSE", False) or None,
             login_timeout=60, network_timeout=300)
    pk = env("SNOWFLAKE_PRIVATE_KEY", False)
    if pk:
        k = serialization.load_pem_private_key(pk.replace("\\n", "\n").encode(),
                                               password=(env("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE", False) or None) and env("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE").encode())
        p["private_key"] = k.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption())
    else:
        p["password"] = env("SNOWFLAKE_PASSWORD")
    print(f"Conectando a Snowflake: cuenta {acc}, usuario {p['user']}")
    return snowflake.connector.connect(**{k: v for k, v in p.items() if v is not None})


def consultar(cx, archivo, params=None):
    cur = cx.cursor()
    cur.execute((SQL / archivo).read_text(), params or {})
    filas = cur.fetchall()
    cur.close()
    return filas


def fila(x):
    return json.loads(x) if isinstance(x, str) else list(x)


def config_github(html):
    """Deja dentro del tablero cifrado la configuración del botón "Actualizar datos"."""
    html = re.sub(r'<script id="ghcfg">.*?</script>', "", html, flags=re.S)
    tok = env("TABLERO_GH_TOKEN", False)
    repo = os.environ.get("GITHUB_REPOSITORY", "kendrispe-beep/TABLERO-DE-DEVOLUCIONES")
    if not tok:
        print("Aviso: sin TABLERO_GH_TOKEN; el botón Actualizar datos no podrá lanzar la tarea.")
        return html
    cfg = json.dumps({"repo": repo, "token": tok, "workflow": "actualizar.yml", "ref": "main"})
    return html.replace("<body>", f'<body><script id="ghcfg">window.GH_CFG={cfg};</script>', 1)


def main():
    usuario, pw = env("TABLERO_USUARIO"), env("TABLERO_CLAVE")
    login = INDEX.read_text(encoding="utf-8")
    html = descifrar(login, usuario, pw)
    _, nc = bloque(html, "devdata")
    _, ef = bloque(html, "efdata")
    _, vt = bloque(html, "ventasdata")

    nc_desde = max(r[2] for r in nc["rows"])                      # último día con notas de cambio
    ef_desde = max(r[2] for r in ef["rows"])[:7] + "-01"          # inicio del último mes de Oracle
    print(f"Notas de cambio en el tablero hasta {nc_desde}; devoluciones efectivas hasta {max(r[2] for r in ef['rows'])}")

    cx = conectar()
    try:
        nc_new = [fila(r[0]) for r in consultar(cx, "sql_nc.sql", {"desde": nc_desde})]
        ef_new = [fila(r[0]) for r in consultar(cx, "sql_ef.sql", {"desde": ef_desde})]
        vt_new = [[r[0], int(r[1]), int(r[2]), int(r[3])] for r in consultar(cx, "sql_ventas.sql")]
    finally:
        cx.close()

    for r in nc_new:
        r[10] = float(r[10]); r[11] = int(float(r[11] or 0))
    for r in ef_new:
        r[10] = int(float(r[10])); r[11] = int(float(r[11] or 0))
    ids = {r[0] for r in nc_new}
    nc["rows"] = [r for r in nc["rows"] if r[0] not in ids] + nc_new
    ef["rows"] = [r for r in ef["rows"] if r[2] < ef_desde] + ef_new

    # Controles: sin duplicados y devoluciones efectivas = devoluciones de Oracle en cada mes
    assert len({r[0] for r in nc["rows"]}) == len(nc["rows"]), "Casos duplicados en notas de cambio"
    assert len({(r[0], r[2][:7]) for r in ef["rows"]}) == len(ef["rows"]), "Duplicados en devoluciones efectivas"
    devol = {m: d for m, _, d, _ in vt_new}
    for m in sorted({r[2][:7] for r in ef["rows"]}):
        tot = sum(r[10] for r in ef["rows"] if r[2][:7] == m)
        if m in devol and abs(tot - devol[m]) > 1:
            sys.exit(f"Descuadre en {m}: devoluciones efectivas {tot:,} vs Oracle {devol[m]:,}. No se publica.")

    ahora = (datetime.datetime.utcnow() - datetime.timedelta(hours=5)).strftime("%Y-%m-%d %H:%M")
    nc["updated"] = ef["updated"] = ahora
    vt = {"updated": ahora[:10], "rows": vt_new}
    html = poner(poner(poner(html, "devdata", nc), "efdata", ef), "ventasdata", vt)
    html = config_github(html)
    INDEX.write_text(cifrar(html, login, usuario, pw), encoding="utf-8")
    print(f"Listo: +{len(nc_new)} notas de cambio desde {nc_desde}, {len(ef_new)} devoluciones efectivas desde {ef_desde}. "
          f"Total {len(nc['rows'])} casos / {len(ef['rows'])} devoluciones. Actualizado {ahora}.")


if __name__ == "__main__":
    main()
