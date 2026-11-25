"""Microservicio centralizado de licencias POS (FastAPI + PostgreSQL + RSA)."""

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import base64
import hmac
import json
import os
import threading
from typing import Any, Dict, Generator, List, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.responses import HTMLResponse
import psycopg2
from psycopg2 import errors as pg_errors
from psycopg2.extensions import connection as PgConnection
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel, Field


CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS licencias (
    id SERIAL PRIMARY KEY,
    clave_licencia VARCHAR UNIQUE NOT NULL,
    cliente_nombre VARCHAR NOT NULL,
    sistema VARCHAR NOT NULL,
    hwid_vinculado VARCHAR NULL,
    estado VARCHAR NOT NULL DEFAULT 'ACTIVA',
    estado_pago VARCHAR NOT NULL DEFAULT 'PAGADO',
    fecha_vencimiento TIMESTAMP NOT NULL,
    ultimo_pago TIMESTAMP NULL,
    ultimo_ping TIMESTAMP NULL
);
ALTER TABLE licencias ADD COLUMN IF NOT EXISTS estado_pago VARCHAR NOT NULL DEFAULT 'PAGADO';
ALTER TABLE licencias ADD COLUMN IF NOT EXISTS ultimo_pago TIMESTAMP NULL;
CREATE TABLE IF NOT EXISTS versiones_app (
    sistema VARCHAR PRIMARY KEY,
    version VARCHAR NOT NULL,
    download_url TEXT NOT NULL,
    sha256 VARCHAR NOT NULL DEFAULT '',
    notas TEXT NOT NULL DEFAULT '',
    actualizado_en TIMESTAMP NOT NULL
);
"""

LICENCIA_COLUMNS = """
    id, clave_licencia, cliente_nombre, sistema,
    hwid_vinculado, estado, estado_pago,
    fecha_vencimiento, ultimo_pago, ultimo_ping
"""

_schema_lock = threading.Lock()
_schema_initialized = False


def _utc_now_naive() -> datetime:
    """Devuelve la fecha/hora actual en UTC sin tzinfo para columnas TIMESTAMP."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _format_utc_iso(dt: datetime) -> str:
    """Formatea un datetime (asumiendo UTC si es naive) a ISO 8601 con +00:00."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()


def _get_database_url() -> str:
    url = os.getenv("DATABASE_URL", "").strip()
    if not url:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="DATABASE_URL no está configurada en el entorno",
        )
    if url.lower().startswith("psql "):
        url = url[5:].strip()
    if (url.startswith('"') and url.endswith('"')) or (
        url.startswith("'") and url.endswith("'")
    ):
        url = url[1:-1].strip()
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    return url


def _open_connection() -> PgConnection:
    return psycopg2.connect(
        _get_database_url(),
        cursor_factory=RealDictCursor,
        connect_timeout=8,
    )


def ensure_schema(conn: Optional[PgConnection] = None) -> None:
    """Crea o actualiza la tabla `licencias` si no existe (idempotente por instancia)."""
    global _schema_initialized
    if _schema_initialized:
        return

    with _schema_lock:
        if _schema_initialized:
            return
        own_conn = conn is None
        active_conn = _open_connection() if own_conn else conn
        try:
            with active_conn.cursor() as cur:
                cur.execute(CREATE_TABLE_SQL)
            active_conn.commit()
            _schema_initialized = True
        finally:
            if own_conn:
                active_conn.close()


def get_db() -> Generator[PgConnection, None, None]:
    """Dependencia FastAPI que entrega una conexión PostgreSQL lista y la cierra al finalizar."""
    try:
        conn = _open_connection()
    except HTTPException:
        raise
    except Exception as exc:
        err_line = str(exc).strip().splitlines()[0] if str(exc).strip() else "Fallo de conexión"
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error de conexión a PostgreSQL ({type(exc).__name__}): {err_line}",
        ) from exc
    try:
        ensure_schema(conn)
        yield conn
    except HTTPException:
        raise
    except Exception as exc:
        err_line = str(exc).strip().splitlines()[0] if str(exc).strip() else "Fallo de esquema"
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error en base de datos ({type(exc).__name__}): {err_line}",
        ) from exc
    finally:
        conn.close()


def _load_private_key() -> RSAPrivateKey:
    raw_pem = os.getenv("PRIVATE_KEY_PEM", "").strip()
    if not raw_pem:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="PRIVATE_KEY_PEM no está configurada en el entorno",
        )

    # Normaliza saltos de línea escapados cuando la llave se pega en variables de entorno
    if (raw_pem.startswith('"') and raw_pem.endswith('"')) or (
        raw_pem.startswith("'") and raw_pem.endswith("'")
    ):
        raw_pem = raw_pem[1:-1]
    normalized_pem = raw_pem.replace("\\n", "\n").encode("utf-8")

    try:
        key = serialization.load_pem_private_key(normalized_pem, password=None)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="PRIVATE_KEY_PEM inválida",
        ) from exc

    if not isinstance(key, RSAPrivateKey):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="La llave configurada no es de tipo RSA",
        )
    return key


def _sign_payload(payload: Dict[str, Any], private_key: RSAPrivateKey) -> str:
    """Serializa el payload de forma determinista y lo firma con RSA SHA-256 (PKCS1v15)."""
    canonical_bytes = json.dumps(
        payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    signature = private_key.sign(
        canonical_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("ascii")


def require_admin(
    x_admin_secret: Optional[str] = Header(default=None, alias="X-Admin-Secret"),
) -> None:
    """Valida el header X-Admin-Secret contra ADMIN_SECRET en tiempo constante."""
    expected_secret = os.getenv("ADMIN_SECRET", "")
    if not expected_secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="ADMIN_SECRET no está configurado en el entorno",
        )
    if not x_admin_secret or not hmac.compare_digest(x_admin_secret, expected_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No autorizado",
        )


def _normalize_required_text(value: str, field_name: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"El campo '{field_name}' no puede estar vacío",
        )
    return cleaned


def _serialize_licencia(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "clave_licencia": row["clave_licencia"],
        "cliente_nombre": row["cliente_nombre"],
        "sistema": row["sistema"],
        "hwid_vinculado": row["hwid_vinculado"],
        "estado": row["estado"],
        "estado_pago": row["estado_pago"],
        "fecha_vencimiento": _format_utc_iso(row["fecha_vencimiento"]),
        "ultimo_pago": _format_utc_iso(row["ultimo_pago"]) if row["ultimo_pago"] else None,
        "ultimo_ping": _format_utc_iso(row["ultimo_ping"]) if row["ultimo_ping"] else None,
    }


class VerificarRequest(BaseModel):
    clave_licencia: str = Field(..., min_length=1)
    hwid: str = Field(..., min_length=1)
    sistema: Optional[str] = Field(
        default=None,
        description="Opcional: valida que la licencia pertenezca a CAFE_POS o PLAYZONE_POS",
    )


class VerificarResponse(BaseModel):
    payload: Dict[str, Any]
    firma: str


class CrearLicenciaRequest(BaseModel):
    clave_licencia: str = Field(..., min_length=1)
    cliente_nombre: str = Field(..., min_length=1)
    sistema: str = Field(..., min_length=1)
    dias: int = Field(..., gt=0, description="Días de vigencia inicial")
    pagado: bool = Field(default=True, description="Si el cliente ya realizó el pago inicial")


class RenovarLicenciaRequest(BaseModel):
    clave_licencia: str = Field(..., min_length=1)
    dias: int = Field(default=30, gt=0, description="Días a sumar a fecha_vencimiento")


class PagoLicenciaRequest(BaseModel):
    clave_licencia: str = Field(..., min_length=1)
    dias: int = Field(
        default=30,
        ge=0,
        description="Días a extender desde hoy o el vencimiento actual (0 solo marca pagado)",
    )


class ImpagoLicenciaRequest(BaseModel):
    clave_licencia: str = Field(..., min_length=1)
    suspender: bool = Field(
        default=True,
        description="Si es True, también cambia estado a SUSPENDIDA inmediatamente",
    )


class SuspenderLicenciaRequest(BaseModel):
    clave_licencia: str = Field(..., min_length=1)


class VersionReleaseRequest(BaseModel):
    sistema: str = Field(..., min_length=1)
    version: str = Field(..., min_length=1)
    download_url: str = Field(..., min_length=1)
    sha256: str = Field(default="")
    notas: str = Field(default="")


class LicenciaOut(BaseModel):
    id: int
    clave_licencia: str
    cliente_nombre: str
    sistema: str
    hwid_vinculado: Optional[str]
    estado: str
    estado_pago: str
    fecha_vencimiento: str
    ultimo_pago: Optional[str]
    ultimo_ping: Optional[str]


@asynccontextmanager
async def lifespan(_: FastAPI):
    if os.getenv("DATABASE_URL"):
        try:
            ensure_schema()
        except Exception:
            # Si falla durante arranque en frío transitorio, get_db() reintentará en la petición.
            pass
    yield


app = FastAPI(
    title="Servidor Centralizado de Licencias POS",
    version="1.1.0",
    lifespan=lifespan,
)


@app.get("/")
def healthcheck() -> Dict[str, str]:
    return {"status": "ok", "servicio": "licencias-pos"}


@app.post("/api/v1/licencia/verificar", response_model=VerificarResponse)
def verificar_licencia(
    body: VerificarRequest,
    conn: PgConnection = Depends(get_db),
) -> VerificarResponse:
    clave = _normalize_required_text(body.clave_licencia, "clave_licencia")
    hwid = _normalize_required_text(body.hwid, "hwid")
    sistema_solicitado = body.sistema.strip() if body.sistema and body.sistema.strip() else None

    private_key = _load_private_key()
    ahora_utc = _utc_now_naive()

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT clave_licencia, sistema, hwid_vinculado, estado, estado_pago, fecha_vencimiento
                FROM licencias
                WHERE clave_licencia = %s
                FOR UPDATE
                """,
                (clave,),
            )
            row = cur.fetchone()

            if row is None:
                conn.rollback()
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Licencia no encontrada",
                )

            if sistema_solicitado is not None and row["sistema"] != sistema_solicitado:
                conn.rollback()
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Licencia no corresponde a este sistema",
                )

            if row["estado"] == "SUSPENDIDA":
                conn.rollback()
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Licencia suspendida por administración",
                )

            hwid_vinculado = row["hwid_vinculado"]
            if hwid_vinculado is not None and hwid_vinculado != hwid:
                conn.rollback()
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Hardware no autorizado",
                )

            cur.execute(
                """
                UPDATE licencias
                SET hwid_vinculado = %s,
                    ultimo_ping = %s
                WHERE clave_licencia = %s
                """,
                (hwid, ahora_utc, clave),
            )
        conn.commit()
    except HTTPException:
        raise
    except Exception as exc:
        conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al verificar la licencia",
        ) from exc

    payload = {
        "clave": row["clave_licencia"],
        "sistema": row["sistema"],
        "hwid": hwid,
        "estado": row["estado"],
        "estado_pago": row["estado_pago"],
        "expira": _format_utc_iso(row["fecha_vencimiento"]),
        "emitido": _format_utc_iso(ahora_utc),
    }
    firma_base64 = _sign_payload(payload, private_key)
    return VerificarResponse(payload=payload, firma=firma_base64)


@app.post(
    "/api/v1/admin/crear",
    response_model=LicenciaOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin)],
)
def crear_licencia(
    body: CrearLicenciaRequest,
    conn: PgConnection = Depends(get_db),
) -> Dict[str, Any]:
    clave = _normalize_required_text(body.clave_licencia, "clave_licencia")
    cliente = _normalize_required_text(body.cliente_nombre, "cliente_nombre")
    sistema = _normalize_required_text(body.sistema, "sistema")
    ahora_utc = _utc_now_naive()
    fecha_vencimiento = ahora_utc + timedelta(days=body.dias)
    estado_pago = "PAGADO" if body.pagado else "IMPAGO"
    ultimo_pago = ahora_utc if body.pagado else None

    try:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                INSERT INTO licencias (
                    clave_licencia,
                    cliente_nombre,
                    sistema,
                    estado,
                    estado_pago,
                    fecha_vencimiento,
                    ultimo_pago
                )
                VALUES (%s, %s, %s, 'ACTIVA', %s, %s, %s)
                RETURNING {LICENCIA_COLUMNS}
                """,
                (clave, cliente, sistema, estado_pago, fecha_vencimiento, ultimo_pago),
            )
            created = cur.fetchone()
        conn.commit()
    except pg_errors.UniqueViolation as exc:
        conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Ya existe una licencia con esa clave",
        ) from exc
    except Exception as exc:
        conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al crear la licencia",
        ) from exc

    return _serialize_licencia(created)


@app.post(
    "/api/v1/admin/renovar",
    response_model=LicenciaOut,
    dependencies=[Depends(require_admin)],
)
def renovar_licencia(
    body: RenovarLicenciaRequest,
    conn: PgConnection = Depends(get_db),
) -> Dict[str, Any]:
    clave = _normalize_required_text(body.clave_licencia, "clave_licencia")
    ahora_utc = _utc_now_naive()

    try:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE licencias
                SET fecha_vencimiento = fecha_vencimiento + make_interval(days => %s),
                    estado = 'ACTIVA',
                    estado_pago = 'PAGADO',
                    ultimo_pago = %s
                WHERE clave_licencia = %s
                RETURNING {LICENCIA_COLUMNS}
                """,
                (body.dias, ahora_utc, clave),
            )
            updated = cur.fetchone()
        conn.commit()
    except Exception as exc:
        conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al renovar la licencia",
        ) from exc

    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Licencia no encontrada",
        )

    return _serialize_licencia(updated)


@app.post(
    "/api/v1/admin/pago",
    response_model=LicenciaOut,
    dependencies=[Depends(require_admin)],
)
def registrar_pago(
    body: PagoLicenciaRequest,
    conn: PgConnection = Depends(get_db),
) -> Dict[str, Any]:
    """Marca la licencia como PAGADO, la activa y opcionalmente suma días desde hoy o su vencimiento."""
    clave = _normalize_required_text(body.clave_licencia, "clave_licencia")
    ahora_utc = _utc_now_naive()

    try:
        with conn.cursor() as cur:
            if body.dias > 0:
                cur.execute(
                    f"""
                    UPDATE licencias
                    SET fecha_vencimiento = GREATEST(fecha_vencimiento, %s) + make_interval(days => %s),
                        estado = 'ACTIVA',
                        estado_pago = 'PAGADO',
                        ultimo_pago = %s
                    WHERE clave_licencia = %s
                    RETURNING {LICENCIA_COLUMNS}
                    """,
                    (ahora_utc, body.dias, ahora_utc, clave),
                )
            else:
                cur.execute(
                    f"""
                    UPDATE licencias
                    SET estado = 'ACTIVA',
                        estado_pago = 'PAGADO',
                        ultimo_pago = %s
                    WHERE clave_licencia = %s
                    RETURNING {LICENCIA_COLUMNS}
                    """,
                    (ahora_utc, clave),
                )
            updated = cur.fetchone()
        conn.commit()
    except Exception as exc:
        conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al registrar el pago",
        ) from exc

    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Licencia no encontrada",
        )

    return _serialize_licencia(updated)


@app.post(
    "/api/v1/admin/impago",
    response_model=LicenciaOut,
    dependencies=[Depends(require_admin)],
)
def marcar_impago(
    body: ImpagoLicenciaRequest,
    conn: PgConnection = Depends(get_db),
) -> Dict[str, Any]:
    """Marca la licencia como IMPAGO y opcionalmente la suspende de inmediato."""
    clave = _normalize_required_text(body.clave_licencia, "clave_licencia")

    try:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE licencias
                SET estado_pago = 'IMPAGO',
                    estado = CASE WHEN %s THEN 'SUSPENDIDA' ELSE estado END
                WHERE clave_licencia = %s
                RETURNING {LICENCIA_COLUMNS}
                """,
                (body.suspender, clave),
            )
            updated = cur.fetchone()
        conn.commit()
    except Exception as exc:
        conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al marcar impago",
        ) from exc

    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Licencia no encontrada",
        )

    return _serialize_licencia(updated)


@app.post(
    "/api/v1/admin/suspender",
    response_model=LicenciaOut,
    dependencies=[Depends(require_admin)],
)
def suspender_licencia(
    body: SuspenderLicenciaRequest,
    conn: PgConnection = Depends(get_db),
) -> Dict[str, Any]:
    clave = _normalize_required_text(body.clave_licencia, "clave_licencia")

    try:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE licencias
                SET estado = 'SUSPENDIDA'
                WHERE clave_licencia = %s
                RETURNING {LICENCIA_COLUMNS}
                """,
                (clave,),
            )
            updated = cur.fetchone()
        conn.commit()
    except Exception as exc:
        conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al suspender la licencia",
        ) from exc

    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Licencia no encontrada",
        )

    return _serialize_licencia(updated)


@app.get(
    "/api/v1/admin/listar",
    response_model=List[LicenciaOut],
    dependencies=[Depends(require_admin)],
)
def listar_licencias(
    sistema: Optional[str] = Query(default=None, description="Filtrar por sistema (ej. CAFE_POS, PLAYZONE_POS)"),
    conn: PgConnection = Depends(get_db),
) -> List[Dict[str, Any]]:
    filtro = sistema.strip() if sistema and sistema.strip() else None
    try:
        with conn.cursor() as cur:
            if filtro:
                cur.execute(
                    f"""
                    SELECT {LICENCIA_COLUMNS}
                    FROM licencias
                    WHERE sistema = %s
                    ORDER BY id DESC
                    """,
                    (filtro,),
                )
            else:
                cur.execute(
                    f"""
                    SELECT {LICENCIA_COLUMNS}
                    FROM licencias
                    ORDER BY id DESC
                    """
                )
            rows = cur.fetchall()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al listar las licencias",
        ) from exc

    return [_serialize_licencia(row) for row in rows]


@app.get("/api/v1/version")
def obtener_version_publicada(
    sistema: str = Query(..., min_length=1),
    conn: PgConnection = Depends(get_db),
) -> Dict[str, Any]:
    sys_clean = sistema.strip()
    with conn.cursor() as cur:
        cur.execute(
            "SELECT sistema, version, download_url, sha256, notas, actualizado_en FROM versiones_app WHERE sistema = %s",
            (sys_clean,),
        )
        row = cur.fetchone()
    if not row:
        return {
            "sistema": sys_clean,
            "version": "0.0.0",
            "download_url": "",
            "sha256": "",
            "notas": "",
            "actualizado_en": None,
        }
    return {
        "sistema": row["sistema"],
        "version": row["version"],
        "download_url": row["download_url"],
        "sha256": row["sha256"],
        "notas": row["notas"],
        "actualizado_en": _format_utc_iso(row["actualizado_en"]),
    }


@app.get(
    "/api/v1/admin/versiones",
    dependencies=[Depends(require_admin)],
)
def listar_versiones(conn: PgConnection = Depends(get_db)) -> List[Dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT sistema, version, download_url, sha256, notas, actualizado_en FROM versiones_app ORDER BY sistema"
        )
        rows = cur.fetchall()
    return [
        {
            "sistema": r["sistema"],
            "version": r["version"],
            "download_url": r["download_url"],
            "sha256": r["sha256"],
            "notas": r["notas"],
            "actualizado_en": _format_utc_iso(r["actualizado_en"]),
        }
        for r in rows
    ]


@app.post(
    "/api/v1/admin/version",
    dependencies=[Depends(require_admin)],
)
def publicar_version(
    body: VersionReleaseRequest,
    conn: PgConnection = Depends(get_db),
) -> Dict[str, Any]:
    sistema = _normalize_required_text(body.sistema, "sistema")
    version = _normalize_required_text(body.version, "version")
    download_url = _normalize_required_text(body.download_url, "download_url")
    ahora_utc = _utc_now_naive()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO versiones_app (sistema, version, download_url, sha256, notas, actualizado_en)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (sistema) DO UPDATE
            SET version = EXCLUDED.version,
                download_url = EXCLUDED.download_url,
                sha256 = EXCLUDED.sha256,
                notas = EXCLUDED.notas,
                actualizado_en = EXCLUDED.actualizado_en
            RETURNING sistema, version, download_url, sha256, notas, actualizado_en
            """,
            (sistema, version, download_url, body.sha256.strip(), body.notas.strip(), ahora_utc),
        )
        row = cur.fetchone()
    conn.commit()
    return {
        "sistema": row["sistema"],
        "version": row["version"],
        "download_url": row["download_url"],
        "sha256": row["sha256"],
        "notas": row["notas"],
        "actualizado_en": _format_utc_iso(row["actualizado_en"]),
    }


ADMIN_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Panel de Licencias POS</title>
  <style>
    :root { font-family: system-ui, -apple-system, sans-serif; color-scheme: dark; }
    body { margin: 0; background: #0f172a; color: #e2e8f0; padding: 24px; }
    .wrap { max-width: 1100px; margin: 0 auto; }
    h1 { margin: 0 0 16px; font-size: 1.5rem; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 16px; margin-bottom: 16px; }
    .row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
    input, select, button { padding: 8px 12px; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; font-size: 0.9rem; }
    button { cursor: pointer; font-weight: 600; border: none; }
    .btn-primary { background: #2563eb; }
    .btn-ok { background: #16a34a; }
    .btn-warn { background: #dc2626; }
    .btn-muted { background: #334155; }
    table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
    th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid #334155; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 0.75rem; font-weight: 700; }
    .ok { background: #14532d; color: #86efac; }
    .bad { background: #7f1d1d; color: #fca5a5; }
    .sys { background: #1e3a8a; color: #93c5fd; }
    #msg { margin-top: 8px; font-size: 0.88rem; color: #93c5fd; }
  </style>
</head>
<body>
<div class="wrap">
  <h1>Control de Licencias, Pagos y Actualizaciones OTA (Kafi POS / PlayZone POS)</h1>
  <div class="card">
    <div class="row">
      <input id="secret" type="password" placeholder="ADMIN_SECRET" style="min-width:240px" />
      <select id="filtro">
        <option value="">Todos los sistemas</option>
        <option value="CAFE_POS">Kafi POS (CAFE_POS)</option>
        <option value="PLAYZONE_POS">PlayZone POS (PLAYZONE_POS)</option>
      </select>
      <button class="btn-primary" onclick="cargar()">Conectar / Actualizar</button>
    </div>
    <div id="msg"></div>
  </div>

  <div class="card">
    <div class="row">
      <input id="n_clave" placeholder="Clave (ej. CAFE-2026-001)" />
      <input id="n_cliente" placeholder="Nombre del cliente" />
      <select id="n_sistema">
        <option value="CAFE_POS">Kafi POS (CAFE_POS)</option>
        <option value="PLAYZONE_POS">PlayZone POS (PLAYZONE_POS)</option>
      </select>
      <input id="n_dias" type="number" value="30" min="1" style="width:90px" />
      <button class="btn-ok" onclick="crear()">Crear licencia</button>
    </div>
  </div>

  <div class="card">
    <div class="row">
      <select id="v_sistema">
        <option value="CAFE_POS">Kafi POS (CAFE_POS)</option>
        <option value="PLAYZONE_POS">PlayZone POS (PLAYZONE_POS)</option>
      </select>
      <input id="v_version" placeholder="Versión (ej. 1.0.1)" style="width:140px" />
      <input id="v_url" placeholder="URL del .zip (GitHub Release / ZIP)" style="min-width:280px;flex:1" />
      <input id="v_sha" placeholder="SHA-256 (opcional)" style="width:180px" />
      <button class="btn-primary" onclick="publicarVersion()">Publicar Actualización</button>
    </div>
    <div id="v_list" style="margin-top:8px;font-size:0.8rem;color:#94a3b8;"></div>
  </div>

  <div class="card" style="overflow-x:auto">
    <table>
      <thead>
        <tr>
          <th>Clave</th><th>Cliente</th><th>Sistema</th><th>Estado</th><th>Pago</th><th>Vence (UTC)</th><th>Último ping</th><th>Acciones</th>
        </tr>
      </thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>
</div>
<script>
const el = id => document.getElementById(id);
el('secret').value = sessionStorage.getItem('adm_sec') || '';
function msg(t) { el('msg').textContent = t; }
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
async function api(path, method='GET', body=null) {
  const sec = el('secret').value.trim();
  sessionStorage.setItem('adm_sec', sec);
  const res = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-Admin-Secret': sec },
    body: body ? JSON.stringify(body) : null
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || ('HTTP ' + res.status));
  return data;
}
async function cargar() {
  try {
    const f = el('filtro').value;
    const rows = await api('/api/v1/admin/listar' + (f ? '?sistema=' + encodeURIComponent(f) : ''));
    el('tbody').innerHTML = rows.map(r => `
      <tr>
        <td><code>${esc(r.clave_licencia)}</code></td>
        <td>${esc(r.cliente_nombre)}</td>
        <td><span class="badge sys">${esc(r.sistema)}</span></td>
        <td><span class="badge ${r.estado === 'ACTIVA' ? 'ok' : 'bad'}">${esc(r.estado)}</span></td>
        <td><span class="badge ${r.estado_pago === 'PAGADO' ? 'ok' : 'bad'}">${esc(r.estado_pago)}</span></td>
        <td>${esc(r.fecha_vencimiento.slice(0,10))}</td>
        <td>${r.ultimo_ping ? esc(r.ultimo_ping.slice(0,16).replace('T',' ')) : '-'}</td>
        <td class="row">
          <button class="btn-ok" data-act="pago" data-clave="${esc(r.clave_licencia)}">Pagó (+30d)</button>
          <button class="btn-warn" data-act="impago" data-clave="${esc(r.clave_licencia)}">No pagó</button>
        </td>
      </tr>`).join('');
    msg('Licencias cargadas: ' + rows.length);
    const vers = await api('/api/v1/admin/versiones');
    el('v_list').innerHTML = vers.length
      ? 'Versiones activas: ' + vers.map(v => `<strong>${esc(v.sistema)}</strong> v${esc(v.version)}`).join(' | ')
      : 'Sin actualizaciones OTA publicadas todavía.';
  } catch (e) { msg('Error: ' + e.message); }
}
async function publicarVersion() {
  try {
    const res = await api('/api/v1/admin/version', 'POST', {
      sistema: el('v_sistema').value,
      version: el('v_version').value,
      download_url: el('v_url').value,
      sha256: el('v_sha').value
    });
    msg('Actualización publicada: ' + res.sistema + ' v' + res.version);
    await cargar();
  } catch (e) { msg('Error: ' + e.message); }
}
el('tbody').addEventListener('click', ev => {
  const btn = ev.target.closest('button[data-act]');
  if (!btn) return;
  const clave = btn.dataset.clave;
  if (btn.dataset.act === 'pago') pago(clave, 30);
  if (btn.dataset.act === 'impago') impago(clave);
});
async function crear() {
  try {
    await api('/api/v1/admin/crear', 'POST', {
      clave_licencia: el('n_clave').value,
      cliente_nombre: el('n_cliente').value,
      sistema: el('n_sistema').value,
      dias: Number(el('n_dias').value || 30),
      pagado: true
    });
    el('n_clave').value = ''; el('n_cliente').value = '';
    await cargar();
  } catch (e) { msg('Error: ' + e.message); }
}
async function pago(clave, dias) {
  try { await api('/api/v1/admin/pago', 'POST', { clave_licencia: clave, dias }); await cargar(); }
  catch (e) { msg('Error: ' + e.message); }
}
async function impago(clave) {
  try { await api('/api/v1/admin/impago', 'POST', { clave_licencia: clave, suspender: true }); await cargar(); }
  catch (e) { msg('Error: ' + e.message); }
}
</script>
</body>
</html>
"""


@app.get("/admin", response_class=HTMLResponse)
def admin_panel() -> str:
    return ADMIN_HTML
