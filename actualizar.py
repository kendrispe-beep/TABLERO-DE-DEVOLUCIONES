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

RAIZ = Path(__file__).resolve().parent
INDEX = RAIZ / "index.html"
SQL = Path(__file__).resolve().parent
IT = 250000

SQLS = {
    "sql_nc.sql": r"""WITH hist AS (
 SELECT NRO_RECLAMO nro, 'RECLAMO' tipo_pqr, FECHA_HORA_CAMBIO fh FROM JM_SILVER_PRD_DB.JM_PQRS.FACT_RECLAMO_HISTORIAL WHERE CAMPO_MODIFICADO='Tipo_de_Devolucion__c' AND FECHA_CAMBIO >= '2026-01-01'
 UNION ALL SELECT NRO_PETICION, 'PETICION', FECHA_HORA_CAMBIO FROM JM_SILVER_PRD_DB.JM_PQRS.FACT_PETICION_HISTORIAL WHERE CAMPO_MODIFICADO='Tipo_de_Devolucion__c' AND FECHA_CAMBIO >= '2026-01-01'
 UNION ALL SELECT NRO_QUEJA, 'QUEJA', FECHA_HORA_CAMBIO FROM JM_SILVER_PRD_DB.JM_PQRS.FACT_QUEJA_HISTORIAL WHERE CAMPO_MODIFICADO='Tipo_de_Devolucion__c' AND FECHA_CAMBIO >= '2026-01-01'
 UNION ALL SELECT NRO_CASO, NULL, FECHA_HORA_CAMBIO FROM JM_SILVER_PRD_DB.JM_PQRS.STG_SF_CASEHISTORY WHERE CAMPO_MODIFICADO='Tipo_de_Devolucion__c' AND FECHA_CAMBIO >= '2026-01-01'),
stg AS (SELECT NRO_CASO nro, TIPO_DEVOLUCION td, ESTADO_DEVOLUCION ed FROM JM_SILVER_PRD_DB.JM_PQRS.STG_SF_CASE_RECLAMO UNION ALL SELECT NRO_CASO, TIPO_DEVOLUCION, ESTADO_DEVOLUCION FROM JM_SILVER_PRD_DB.JM_PQRS.STG_SF_CASE_QUEJA UNION ALL SELECT NRO_CASO, TIPO_DEVOLUCION, ESTADO_DEVOLUCION FROM JM_SILVER_PRD_DB.JM_PQRS.STG_SF_CASE_PETICION),
casos AS (SELECT nro, MAX(tipo_pqr) tipo_pqr, MAX(fh) fecha FROM hist GROUP BY 1),
tsol AS (SELECT NRO_RECLAMO nro, COALESCE(NULLIF(VALOR_ANTERIOR,''), VALOR_NUEVO) ts FROM JM_SILVER_PRD_DB.JM_PQRS.FACT_RECLAMO_HISTORIAL WHERE CAMPO_MODIFICADO='TIPO_SOLUCION' QUALIFY ROW_NUMBER() OVER (PARTITION BY NRO_RECLAMO ORDER BY FECHA_HORA_CAMBIO, NK_HISTORY_ID)=1),
fact AS (
 SELECT f.NRO_RECLAMO nro, f.SK_RESPONSABLE_CREADOR sk, IFF(s.NRO_CASO IS NULL, f.COMENTARIO_DEVOLUCION, s.COMENTARIO_DEVOLUCION) com, REPLACE(IFF(s.NRO_CASO IS NULL, f.IMAGEN_DANO, s.IMAGEN_DANO),'https://portal-cliente-garantia-fotos-prd.s3.amazonaws.com/','') img FROM JM_SILVER_PRD_DB.JM_PQRS.FACT_RECLAMO f LEFT JOIN JM_SILVER_PRD_DB.JM_PQRS.STG_SF_CASE_RECLAMO s ON s.NRO_CASO=f.NRO_RECLAMO
 UNION ALL SELECT f.NRO_PETICION, f.SK_RESPONSABLE_CREADOR, IFF(s.NRO_CASO IS NULL, f.COMENTARIO_DEVOLUCION, s.COMENTARIO_DEVOLUCION), '' FROM JM_SILVER_PRD_DB.JM_PQRS.FACT_PETICION f LEFT JOIN JM_SILVER_PRD_DB.JM_PQRS.STG_SF_CASE_PETICION s ON s.NRO_CASO=f.NRO_PETICION
 UNION ALL SELECT f.NRO_QUEJA, f.SK_RESPONSABLE_CREADOR, IFF(s.NRO_CASO IS NULL, f.COMENTARIO_DEVOLUCION, s.COMENTARIO_DEVOLUCION), '' FROM JM_SILVER_PRD_DB.JM_PQRS.FACT_QUEJA f LEFT JOIN JM_SILVER_PRD_DB.JM_PQRS.STG_SF_CASE_QUEJA s ON s.NRO_CASO=f.NRO_QUEJA),
p AS (SELECT p.*, COUNT(DISTINCT CODIGO_PRODUCTO) OVER (PARTITION BY NUM_SERVICIO) unidades FROM JM_GOLD_PRD_DB.JM_SAC.PQRS p JOIN casos c ON p.NUM_SERVICIO=c.nro
 QUALIFY ROW_NUMBER() OVER (PARTITION BY NUM_SERVICIO ORDER BY PRECIO_PRODUCTO DESC NULLS LAST, CODIGO_PRODUCTO)=1)
SELECT ARRAY_CONSTRUCT(c.nro, COALESCE(c.tipo_pqr, p.TIPO_PQR), TO_CHAR(c.fecha,'YYYY-MM-DD'), COALESCE(NULLIF(st.td,''), p.TIPO_DEVOLUCION, ''), COALESCE(p.CAUSAL_PRINCIPAL,''), COALESCE(p.FUENTE_DANO,''), COALESCE(p.CAUSAL_DANO,''), COALESCE(p.SUBCAUSAL_DANO,''),
 COALESCE(t.ts,''), COALESCE(r.NOMBRE,''), COALESCE(ROUND(p.PRECIO_PRODUCTO,0),0), COALESCE(p.unidades,0), COALESCE(NULLIF(st.ed,''), p.ESTADO_DEVOLUCION, ''), COALESCE(LEFT(fa.com,400),''), COALESCE(p.CODIGO_PRODUCTO,''), COALESCE(p.DESCRIPCION_PRODUCTO,''), COALESCE(p.CATEGORIA,''), COALESCE(p.LINEA,''), COALESCE(p.SUBLINEA,''), COALESCE(p.PROVEEDOR_DEL_PRODUCTO,''), COALESCE(fa.img,'')) AS fila
FROM casos c JOIN p ON p.NUM_SERVICIO=c.nro
LEFT JOIN tsol t ON t.nro=c.nro
LEFT JOIN stg st ON st.nro=c.nro
LEFT JOIN fact fa ON fa.nro=c.nro
LEFT JOIN JM_SILVER_PRD_DB.JM_PQRS.DIM_RESPONSABLE r ON r.SK_RESPONSABLE=fa.sk
WHERE COALESCE(NULLIF(st.td,''), p.TIPO_DEVOLUCION, '') NOT IN ('SIN DATO','')
 AND COALESCE(p.CAUSAL_PRINCIPAL,'') NOT ILIKE 'REDENCI%%N DE NOTA DE CAMBIO'
 AND c.fecha >= %(desde)s""",
    "sql_ef.sql": r"""WITH d AS (SELECT * FROM JM_GOLD_PRD_DB.JM_SAC.JM_DEVOLUCIONES WHERE UNIDAD_FECHA >= '2026-01-01'),
ox AS (SELECT f.REM s, DATE_FROM_PARTS(t.ANO,t.MES,t.NUM_DIA_MES) fe, f.VALOR_VENTA_OFERTA v, f.UNIDADES_VENDIDAS u FROM JM_SILVER_PRD_DB.JM_VENTAS_LEGACY.FACT_FACTURACION f JOIN JM_SILVER_PRD_DB.JM_CORE_LEGACY.DIM_UNIDAD_TIEMPO t ON f.UNIDAD_TIEMPO_ID=t.ID WHERE t.ANO>=2026 AND f.VALOR_VENTA_OFERTA<0),
g AS (SELECT s, DATE_TRUNC('month',fe) m, MAX(fe) f, -SUM(v) v, -SUM(u) u FROM ox GROUP BY 1,2),
tp AS (SELECT SERVICIO s, DATE_TRUNC('month',UNIDAD_FECHA) m, TIPO_SOLICITUD t, TIPO_DEVOLUCION td, CAUSAL_PRINCIPAL cp, FUENTE fd, CAUSAL_DANO cd, SUBCAUSAL_DANO sd, ESTADO_DEVOLUCION ed, COMENTARIO_DEVOLUCION co, PROD_CODIGO pc, PROD_DESCRIPCION pd, CATEGORIA cat, LINEA lin, SUBLINEA sub, PROVEEDOR prov FROM d QUALIFY ROW_NUMBER() OVER (PARTITION BY SERVICIO, DATE_TRUNC('month',UNIDAD_FECHA) ORDER BY VALOR DESC, PROD_CODIGO)=1),
tsol AS (SELECT NRO_RECLAMO nro, COALESCE(NULLIF(VALOR_ANTERIOR,''), VALOR_NUEVO) ts FROM JM_SILVER_PRD_DB.JM_PQRS.FACT_RECLAMO_HISTORIAL WHERE CAMPO_MODIFICADO='TIPO_SOLUCION' QUALIFY ROW_NUMBER() OVER (PARTITION BY NRO_RECLAMO ORDER BY FECHA_HORA_CAMBIO, NK_HISTORY_ID)=1),
fact0 AS (
 SELECT f.NRO_RECLAMO nro, f.SK_RESPONSABLE_CREADOR sk, IFF(s.NRO_CASO IS NULL, f.COMENTARIO_DEVOLUCION, s.COMENTARIO_DEVOLUCION) com, REPLACE(IFF(s.NRO_CASO IS NULL, f.IMAGEN_DANO, s.IMAGEN_DANO),'https://portal-cliente-garantia-fotos-prd.s3.amazonaws.com/','') img FROM JM_SILVER_PRD_DB.JM_PQRS.FACT_RECLAMO f LEFT JOIN JM_SILVER_PRD_DB.JM_PQRS.STG_SF_CASE_RECLAMO s ON s.NRO_CASO=f.NRO_RECLAMO
 UNION ALL SELECT f.NRO_PETICION, f.SK_RESPONSABLE_CREADOR, IFF(s.NRO_CASO IS NULL, f.COMENTARIO_DEVOLUCION, s.COMENTARIO_DEVOLUCION), '' FROM JM_SILVER_PRD_DB.JM_PQRS.FACT_PETICION f LEFT JOIN JM_SILVER_PRD_DB.JM_PQRS.STG_SF_CASE_PETICION s ON s.NRO_CASO=f.NRO_PETICION
 UNION ALL SELECT f.NRO_QUEJA, f.SK_RESPONSABLE_CREADOR, IFF(s.NRO_CASO IS NULL, f.COMENTARIO_DEVOLUCION, s.COMENTARIO_DEVOLUCION), '' FROM JM_SILVER_PRD_DB.JM_PQRS.FACT_QUEJA f LEFT JOIN JM_SILVER_PRD_DB.JM_PQRS.STG_SF_CASE_QUEJA s ON s.NRO_CASO=f.NRO_QUEJA),
fact AS (SELECT * FROM fact0 QUALIFY ROW_NUMBER() OVER (PARTITION BY nro ORDER BY sk NULLS LAST)=1)
SELECT ARRAY_CONSTRUCT(g.s, COALESCE(tp.t,'SIN PQR'), TO_CHAR(g.f,'YYYY-MM-DD'), COALESCE(tp.td,''), COALESCE(tp.cp,''), COALESCE(tp.fd,''), COALESCE(tp.cd,''), COALESCE(tp.sd,''), COALESCE(t.ts,''), COALESCE(r.NOMBRE,''), ROUND(g.v,0), g.u, COALESCE(tp.ed,''), COALESCE(LEFT(COALESCE(NULLIF(tp.co,''),fa.com),400),''), COALESCE(tp.pc,''), COALESCE(tp.pd,''), COALESCE(tp.cat,''), COALESCE(tp.lin,''), COALESCE(tp.sub,''), COALESCE(tp.prov,''), COALESCE(fa.img,'')) AS fila
FROM g LEFT JOIN tp ON tp.s=g.s AND tp.m=g.m
LEFT JOIN tsol t ON t.nro=g.s
LEFT JOIN fact fa ON fa.nro=g.s
LEFT JOIN JM_SILVER_PRD_DB.JM_PQRS.DIM_RESPONSABLE r ON r.SK_RESPONSABLE=fa.sk
WHERE g.m >= DATE_TRUNC('month', TO_DATE(%(desde)s))""",
    "sql_ventas.sql": r"""SELECT TO_CHAR(DATE_FROM_PARTS(t.ANO,t.MES,1),'YYYY-MM') mes, ROUND(SUM(IFF(f.VALOR_VENTA_OFERTA>0,f.VALOR_VENTA_OFERTA,0))) bruta, ROUND(-SUM(IFF(f.VALOR_VENTA_OFERTA<0,f.VALOR_VENTA_OFERTA,0))) devol, MAX(t.NUM_DIA_MES) ult_dia FROM JM_SILVER_PRD_DB.JM_VENTAS_LEGACY.FACT_FACTURACION f JOIN JM_SILVER_PRD_DB.JM_CORE_LEGACY.DIM_UNIDAD_TIEMPO t ON f.UNIDAD_TIEMPO_ID=t.ID WHERE t.ANO>=2025 GROUP BY 1 ORDER BY 1""",
}


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
    cur.execute(SQLS[archivo], params or {})
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
