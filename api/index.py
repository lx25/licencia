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
from fastapi import Depends, FastAPI, Header, HTTPException, status
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
    fecha_vencimiento TIMESTAMP NOT NULL,
    ultimo_ping TIMESTAMP NULL
);
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
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    return url


def _open_connection() -> PgConnection:
    return psycopg2.connect(_get_database_url(), cursor_factory=RealDictCursor)


def ensure_schema(conn: Optional[PgConnection] = None) -> None:
    """Crea la tabla `licencias` si no existe (idempotente por instancia)."""
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
    conn = _open_connection()
    try:
        ensure_schema(conn)
        yield conn
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
        "fecha_vencimiento": _format_utc_iso(row["fecha_vencimiento"]),
        "ultimo_ping": _format_utc_iso(row["ultimo_ping"]) if row["ultimo_ping"] else None,
    }


class VerificarRequest(BaseModel):
    clave_licencia: str = Field(..., min_length=1)
    hwid: str = Field(..., min_length=1)


class VerificarResponse(BaseModel):
    payload: Dict[str, Any]
    firma: str


class CrearLicenciaRequest(BaseModel):
    clave_licencia: str = Field(..., min_length=1)
    cliente_nombre: str = Field(..., min_length=1)
    sistema: str = Field(..., min_length=1)
    dias: int = Field(..., gt=0, description="Días de vigencia inicial")


class RenovarLicenciaRequest(BaseModel):
    clave_licencia: str = Field(..., min_length=1)
    dias: int = Field(default=30, gt=0, description="Días a sumar a fecha_vencimiento")


class SuspenderLicenciaRequest(BaseModel):
    clave_licencia: str = Field(..., min_length=1)


class LicenciaOut(BaseModel):
    id: int
    clave_licencia: str
    cliente_nombre: str
    sistema: str
    hwid_vinculado: Optional[str]
    estado: str
    fecha_vencimiento: str
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
    version="1.0.0",
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

    private_key = _load_private_key()
    ahora_utc = _utc_now_naive()

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT clave_licencia, hwid_vinculado, estado, fecha_vencimiento
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
        "hwid": hwid,
        "estado": row["estado"],
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
    fecha_vencimiento = _utc_now_naive() + timedelta(days=body.dias)

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO licencias (
                    clave_licencia,
                    cliente_nombre,
                    sistema,
                    estado,
                    fecha_vencimiento
                )
                VALUES (%s, %s, %s, 'ACTIVA', %s)
                RETURNING id, clave_licencia, cliente_nombre, sistema,
                          hwid_vinculado, estado, fecha_vencimiento, ultimo_ping
                """,
                (clave, cliente, sistema, fecha_vencimiento),
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

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE licencias
                SET fecha_vencimiento = fecha_vencimiento + make_interval(days => %s),
                    estado = 'ACTIVA'
                WHERE clave_licencia = %s
                RETURNING id, clave_licencia, cliente_nombre, sistema,
                          hwid_vinculado, estado, fecha_vencimiento, ultimo_ping
                """,
                (body.dias, clave),
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
                """
                UPDATE licencias
                SET estado = 'SUSPENDIDA'
                WHERE clave_licencia = %s
                RETURNING id, clave_licencia, cliente_nombre, sistema,
                          hwid_vinculado, estado, fecha_vencimiento, ultimo_ping
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
def listar_licencias(conn: PgConnection = Depends(get_db)) -> List[Dict[str, Any]]:
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, clave_licencia, cliente_nombre, sistema,
                       hwid_vinculado, estado, fecha_vencimiento, ultimo_ping
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
