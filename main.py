# from fastapi import FastAPI, HTTPException
# from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel
# from passlib.context import CryptContext
# import jwt

# app = FastAPI()

# origins = ["*"]
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=origins,
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# SECRET_KEY = "secret123"
# ALGORITHM = "HS256"

# # Create hashed password for psdas
# stored_user = {
#     "username": "psdas",
#     "hashed_password": pwd_context.hash("psdas")
# }

# class Login(BaseModel):
#     username: str
#     password: str

# @app.post("/login")
# def login_user(data: Login):
#     if data.username != stored_user["username"]:
#         raise HTTPException(status_code=400, detail="Invalid username")

#     if not pwd_context.verify(data.password, stored_user["hashed_password"]):
#         raise HTTPException(status_code=400, detail="Invalid password")

#     token = jwt.encode({"user": data.username}, SECRET_KEY, algorithm=ALGORITHM)

#     return {
#         "username": data.username,
#         "access_token": token
#     }
# from fastapi import FastAPI, HTTPException
# from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel
# from passlib.context import CryptContext
# import jwt

# app = FastAPI()

# # -------------------------------------
# # CORS
# # -------------------------------------
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# SECRET_KEY = "secret123"
# ALGORITHM = "HS256"


# # =====================================
# # USERS + PASSWORDS (PLAIN → HASHED)
# # =====================================
# # REAL PASSWORDS YOU MUST USE:
# # psdas  → psdas
# # john   → 1234
# # admin  → admin123

# users_db = {
#     "psdas": pwd_context.hash("psdas"),
#     "john": pwd_context.hash("1234"),
#     "admin": pwd_context.hash("admin123"),
# }


# # =====================================
# # CONTROLLERS PER USER
# # =====================================
# controller_map = {
#     "psdas": [
#         {"id": 862360073810546, "name": "PS Controller 1", "status": "Active"},
#         {"id": 862360073810165, "name": "PS Controller 2", "status": "Offline"},
#         {"id": 862360073810166, "name": "PS Controller 3", "status": "Online"}
#     ],
#     "john": [
#         {"id": 21, "name": "John Farm Main", "status": "Active"},
#         {"id": 22, "name": "John Pump Node", "status": "Maintenance"},
#     ],
#     "admin": [
#         {"id": 101, "name": "Master Node A", "status": "Active"},
#         {"id": 102, "name": "Master Node B", "status": "Offline"},
#         {"id": 103, "name": "Backup Node", "status": "Active"},
#     ],
# }


# # =====================================
# # REQUEST MODEL
# # =====================================
# class Login(BaseModel):
#     username: str
#     password: str


# # =====================================
# # LOGIN API
# # =====================================
# @app.post("/login")
# def login_user(data: Login):

#     # check user exists
#     if data.username not in users_db:
#         raise HTTPException(status_code=400, detail="Invalid username")

#     # check password
#     hashed_pw = users_db[data.username]
#     if not pwd_context.verify(data.password, hashed_pw):
#         raise HTTPException(status_code=400, detail="Invalid password")

#     # create JWT
#     token = jwt.encode({"user": data.username}, SECRET_KEY, algorithm=ALGORITHM)

#     # get controllers of this user
#     user_controllers = controller_map.get(data.username, [])

#     return {
#         "username": data.username,
#         "access_token": token,
#         "controllers": user_controllers
#     }
# main.py

import time
import threading
from typing import Optional, Dict, Any
from datetime import datetime

import jwt
import paho.mqtt.client as mqtt
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
from sqlalchemy import (
    create_engine, MetaData, Table, Column, Integer, BigInteger, String, ForeignKey,
    Text, Float, select, insert, desc
)
from sqlalchemy.exc import SQLAlchemyError

# -----------------------------
# DATABASE CONFIG (Render PostgreSQL)
# -----------------------------
DATABASE_URL = (
    "postgresql+psycopg2://"
    "sudharshan_g7lp_user:"
    "AIpEl9ea020DCNHYKC6sPW1RH3hSlMmW"
    "@dpg-d4l8pa49c44c73fca56g-a.virginia-postgres.render.com:5432/"
    "sudharshan_g7lp?sslmode=require"
)

engine = create_engine(DATABASE_URL, future=True)
metadata = MetaData()

# -----------------------------
# TABLES
# -----------------------------
users = Table(
    "users", metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String, unique=True, nullable=False),
    Column("password_hash", String, nullable=False),
)

controllers = Table(
    "controllers", metadata,
    Column("id", Integer, primary_key=True),
    Column("controller_id", BigInteger, nullable=False, unique=False),
    Column("name", String, nullable=False),
    Column("status", String, nullable=False, default="Unknown"),
    Column("user_id", Integer, ForeignKey("users.id"), nullable=False),
)

# persist ACKs / status (for command responses)
controller_status = Table(
    "controller_status", metadata,
    Column("id", Integer, primary_key=True),
    Column("controller_id", BigInteger, nullable=False, index=True),
    Column("payload", Text, nullable=False),
    Column("timestamp", Float, nullable=False),  # epoch seconds
)

# store ALL MQTT telemetry messages (history)
controller_telemetry = Table(
    "controller_telemetry", metadata,
    Column("id", Integer, primary_key=True),
    Column("topic", String, nullable=False),
    Column("controller_id", BigInteger, nullable=True, index=True),
    Column("raw_payload", Text, nullable=False),
    Column("d0", String, nullable=True),
    Column("c0", String, nullable=True),
    Column("a3", String, nullable=True),
    Column("a4", String, nullable=True),
    Column("received_at", Float, nullable=False),  # epoch seconds
)

# last setting apply time per controller (c0 = 512)
controller_last_setting = Table(
    "controller_last_setting", metadata,
    Column("controller_id", BigInteger, primary_key=True),
    Column("set_time_raw", String, nullable=True),    # raw a3 like '051225163324'
    Column("set_time_epoch", Float, nullable=True),   # parsed epoch seconds
    Column("last_c0", String, nullable=True),         # should be '512'
    Column("last_payload", Text, nullable=False),     # full ACK payload from device
    Column("set_payload", Text, nullable=True),       # command we sent to controller
)

# Create tables if they do not exist (won't add new columns to existing tables)
metadata.create_all(engine)

# ✅ Ensure schema matches what we expect
def ensure_controller_last_setting_schema():
    with engine.begin() as conn:
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS controller_last_setting (
                controller_id   BIGINT PRIMARY KEY,
                set_time_raw    TEXT,
                set_time_epoch  DOUBLE PRECISION,
                last_c0         TEXT,
                last_payload    TEXT NOT NULL,
                set_payload     TEXT
            );
            """
        )
        conn.exec_driver_sql(
            """
            ALTER TABLE controller_last_setting
            ADD COLUMN IF NOT EXISTS set_payload TEXT;
            """
        )

ensure_controller_last_setting_schema()

# -----------------------------
# FASTAPI + AUTH SETUP
# -----------------------------
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # adjust for prod if needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "Authorization"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "secret123"
ALGORITHM = "HS256"

# -----------------------------
# Pydantic models
# -----------------------------
class Login(BaseModel):
    username: str
    password: str


class CommandPayload(BaseModel):
    payload: str = "c0=201"


# -----------------------------
# MQTT and ACK / TELEMETRY handling
# -----------------------------
mqtt_client = mqtt.Client()
MQTT_BROKER = "broker.emqx.io"
MQTT_PORT = 1883
MQTT_RESPONSE_TOPIC = "psdasaqs"  # device -> server topic from controller


def on_connect(client, userdata, flags, rc):
    print("MQTT connected:", rc)
    client.subscribe(MQTT_RESPONSE_TOPIC)


def on_message(client, userdata, msg):
    # strip() to remove trailing newlines
    payload = msg.payload.decode(errors="ignore").strip()
    print("MQTT RECEIVED on", msg.topic, ":", payload)

    # Parse fields from payload string: d0, c0, a3, a4
    parts = payload.split("&")
    d0 = None
    c0_val = None
    a3_val = None
    a4_val = None

    for p in parts:
        if p.startswith("d0="):
            d0 = p.replace("d0=", "")
        elif p.startswith("c0="):
            c0_val = p.replace("c0=", "")
        elif p.startswith("a3="):
            a3_val = p.replace("a3=", "").strip()
        elif p.startswith("a4="):
            a4_val = p.replace("a4=", "")

    if not d0:
        print("MQTT message missing d0, skipping DB insert.")
        return

    try:
        ts = time.time()
        with engine.begin() as conn:
            # 1) Insert into controller_status for ACK logic
            conn.execute(
                insert(controller_status).values(
                    controller_id=int(d0),
                    payload=payload,
                    timestamp=ts,
                )
            )

            # 2) Update controller row status -> Online
            conn.execute(
                controllers.update()
                .where(controllers.c.controller_id == int(d0))
                .values(status="Online")
            )

            # 3) Insert into telemetry history
            conn.execute(
                insert(controller_telemetry).values(
                    topic=msg.topic,
                    controller_id=int(d0),
                    raw_payload=payload,
                    d0=d0,
                    c0=c0_val,
                    a3=a3_val,
                    a4=a4_val,
                    received_at=ts,
                )
            )

        print(
            f"Inserted controller_status + telemetry for {d0} at {ts} "
            f"(c0={c0_val}, a3={a3_val}, a4={a4_val})"
        )
    except Exception as e:
        print("Failed to write ACK/telemetry to DB:", e)


mqtt_client.on_connect = on_connect
mqtt_client.on_message = on_message
mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
# Run MQTT in background so FastAPI can serve HTTP
threading.Thread(target=mqtt_client.loop_forever, daemon=True).start()


# -----------------------------
# Helpers: auth dependency
# -----------------------------
def create_token(username: str) -> str:
    return jwt.encode({"user": username}, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        return None


def get_current_username(authorization: Optional[str] = Header(None)):
    """
    Expects Authorization header with 'Bearer <token>' or token directly.
    Returns username or raises HTTPException.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    token = authorization
    if authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()

    payload = decode_token(token)
    if not payload or "user" not in payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    return payload["user"]


# -----------------------------
# LOGIN endpoint (DB-backed)
# -----------------------------
@app.post("/login")
def login_user(data: Login):
    try:
        with engine.connect() as conn:
            query = select(users).where(users.c.username == data.username)
            user_row = conn.execute(query).fetchone()

            if not user_row:
                raise HTTPException(status_code=400, detail="Invalid username")

            pw_hash = user_row._mapping.get("password_hash") or getattr(user_row, "password_hash", None)
            if not pw_hash or not pwd_context.verify(data.password, pw_hash):
                raise HTTPException(status_code=400, detail="Invalid password")

            ctrl_q = select(controllers).where(controllers.c.user_id == user_row._mapping["id"])
            rows = conn.execute(ctrl_q).fetchall()
            controllers_list = [
                {"id": r._mapping["controller_id"], "name": r._mapping["name"], "status": r._mapping["status"]}
                for r in rows
            ]

            token = create_token(data.username)

            return {"username": data.username, "access_token": token, "controllers": controllers_list}

    except SQLAlchemyError as e:
        raise HTTPException(status_code=500, detail=str(e))


# -----------------------------
# Get controllers for current user
# -----------------------------
@app.get("/controllers")
def get_controllers(current_user: str = Depends(get_current_username)):
    try:
        with engine.connect() as conn:
            user_q = select(users).where(users.c.username == current_user)
            user_row = conn.execute(user_q).fetchone()
            if not user_row:
                raise HTTPException(status_code=401, detail="User not found")

            ctrl_q = select(controllers).where(controllers.c.user_id == user_row._mapping["id"])
            rows = conn.execute(ctrl_q).fetchall()
            controllers_list = [
                {"id": r._mapping["controller_id"], "name": r._mapping["name"], "status": r._mapping["status"]}
                for r in rows
            ]
            return {"username": current_user, "controllers": controllers_list}
    except SQLAlchemyError as e:
        raise HTTPException(status_code=500, detail=str(e))


# -----------------------------
# Publish command -> wait for ACK (poll DB)
# -----------------------------
@app.post("/controller/{controller_id}/command")
def send_command(controller_id: int, command: CommandPayload, current_user: str = Depends(get_current_username)):
    """
    Validates that controller belongs to the current user, publishes MQTT command,
    then waits (polling DB) for an ACK entry with timestamp > start (within timeout).
    On a successful settings ACK (c0=512), we also store the sent setting payload
    into controller_last_setting.
    """
    start_ts = time.time()

    try:
        # ✅ use engine.begin so writes are committed
        with engine.begin() as conn:
            # Validate controller ownership
            ctrl_q = select(controllers).where(
                (controllers.c.controller_id == controller_id)
            )
            ctrl_row = conn.execute(ctrl_q).fetchone()
            if not ctrl_row:
                raise HTTPException(status_code=404, detail="Controller not found")

            owner_id = ctrl_row._mapping["user_id"]
            user_q = select(users).where(users.c.username == current_user)
            user_row = conn.execute(user_q).fetchone()
            if not user_row:
                raise HTTPException(status_code=401, detail="User not found")

            if owner_id != user_row._mapping["id"]:
                raise HTTPException(status_code=403, detail="Not authorized to command this controller")

            # Publish command to controller-specific topic
            topic = f"psdasaqp/{controller_id}"
            mqtt_client.publish(topic, command.payload)
            print(f"Published to {topic}: {command.payload}")

            # Poll DB for new ack with timestamp > start_ts
            timeout = 6.0
            poll_interval = 0.1
            deadline = start_ts + timeout

            while time.time() < deadline:
                ack_q = (
                    select(controller_status)
                    .where(controller_status.c.controller_id == controller_id)
                    .order_by(desc(controller_status.c.timestamp))
                )
                ack_row = conn.execute(ack_q).fetchone()
                if ack_row and ack_row._mapping["timestamp"] > start_ts:
                    ack_payload = (ack_row._mapping["payload"] or "").strip()
                    ack_ts = ack_row._mapping["timestamp"]

                    # Parse ACK payload to get c0 and a3
                    parts = ack_payload.split("&")
                    c0_val = None
                    a3_val = None
                    for p in parts:
                        if p.startswith("c0="):
                            c0_val = p[3:]
                        elif p.startswith("a3="):
                            a3_val = p[3:].strip()

                    # Only if this is a successful settings ACK (c0=512)
                    if c0_val == "512":
                        # Parse a3 "ddmmyyHHMMSS" -> epoch seconds
                        set_epoch = None
                        if a3_val and len(a3_val) == 12 and a3_val.isdigit():
                            day = int(a3_val[0:2])
                            month = int(a3_val[2:4])
                            year = 2000 + int(a3_val[4:6])
                            hour = int(a3_val[6:8])
                            minute = int(a3_val[8:10])
                            second = int(a3_val[10:12])
                            try:
                                dt = datetime(year, month, day, hour, minute, second)
                                set_epoch = dt.timestamp()
                            except ValueError:
                                set_epoch = None

                        # UPSERT into controller_last_setting: include set_payload
                        upd = (
                            controller_last_setting.update()
                            .where(controller_last_setting.c.controller_id == controller_id)
                            .values(
                                set_time_raw=a3_val,
                                set_time_epoch=set_epoch,
                                last_c0=c0_val,
                                last_payload=ack_payload,
                                set_payload=command.payload,  # what we sent
                            )
                        )
                        result = conn.execute(upd)
                        if result.rowcount == 0:
                            conn.execute(
                                insert(controller_last_setting).values(
                                    controller_id=controller_id,
                                    set_time_raw=a3_val,
                                    set_time_epoch=set_epoch,
                                    last_c0=c0_val,
                                    last_payload=ack_payload,
                                    set_payload=command.payload,
                                )
                            )

                    print("RAW MQTT ACK PAYLOAD:", ack_payload)
                    return {
                        "status": "success",
                        "controller_id": controller_id,
                        "payload": command.payload,
                        "ack": "received",
                        "ack_payload": ack_payload,
                        "ack_timestamp": ack_ts,
                    }
                time.sleep(poll_interval)

            # timeout
            return {
                "status": "success",
                "controller_id": controller_id,
                "payload": command.payload,
                "ack": "not_received",
            }

    except SQLAlchemyError as e:
        raise HTTPException(status_code=500, detail=str(e))


# -----------------------------
# Get latest status/ACK for a controller
# -----------------------------
@app.get("/controller/{controller_id}/status")
def controller_status_endpoint(controller_id: int, current_user: str = Depends(get_current_username)):
    try:
        with engine.connect() as conn:
            # validate controller exists and ownership
            ctrl_q = select(controllers).where(controllers.c.controller_id == controller_id)
            ctrl_row = conn.execute(ctrl_q).fetchone()
            if not ctrl_row:
                raise HTTPException(status_code=404, detail="Controller not found")

            user_q = select(users).where(users.c.username == current_user)
            user_row = conn.execute(user_q).fetchone()
            if not user_row or user_row._mapping["id"] != ctrl_row._mapping["user_id"]:
                raise HTTPException(status_code=403, detail="Not authorized")

            ack_q = (
                select(controller_status)
                .where(controller_status.c.controller_id == controller_id)
                .order_by(desc(controller_status.c.timestamp))
            )
            ack_row = conn.execute(ack_q).fetchone()
            if not ack_row:
                return {"controller_id": controller_id, "status": "no_ack_found"}

            return {
                "controller_id": controller_id,
                "payload": ack_row._mapping["payload"],
                "timestamp": ack_row._mapping["timestamp"],
            }

    except SQLAlchemyError as e:
        raise HTTPException(status_code=500, detail=str(e))


# -----------------------------
# Get recent telemetry messages for a controller
# -----------------------------
@app.get("/controller/{controller_id}/telemetry")
def controller_telemetry_endpoint(
    controller_id: int,
    limit: int = 50,
    current_user: str = Depends(get_current_username),
):
    """
    Returns the most recent telemetry messages for a controller
    from controller_telemetry table.
    """
    if limit <= 0:
        limit = 1
    if limit > 200:
        limit = 200  # safety cap

    try:
        with engine.connect() as conn:
            # validate controller exists and ownership
            ctrl_q = select(controllers).where(controllers.c.controller_id == controller_id)
            ctrl_row = conn.execute(ctrl_q).fetchone()
            if not ctrl_row:
                raise HTTPException(status_code=404, detail="Controller not found")

            user_q = select(users).where(users.c.username == current_user)
            user_row = conn.execute(user_q).fetchone()
            if not user_row or user_row._mapping["id"] != ctrl_row._mapping["user_id"]:
                raise HTTPException(status_code=403, detail="Not authorized")

            telem_q = (
                select(controller_telemetry)
                .where(controller_telemetry.c.controller_id == controller_id)
                .order_by(desc(controller_telemetry.c.received_at))
                .limit(limit)
            )
            rows = conn.execute(telem_q).fetchall()

            data = [
                {
                    "id": r._mapping["id"],
                    "topic": r._mapping["topic"],
                    "controller_id": r._mapping["controller_id"],
                    "raw_payload": r._mapping["raw_payload"],
                    "d0": r._mapping["d0"],
                    "c0": r._mapping["c0"],
                    "a3": r._mapping["a3"],
                    "a4": r._mapping["a4"],
                    "received_at": r._mapping["received_at"],
                }
                for r in rows
            ]

            return {
                "controller_id": controller_id,
                "count": len(data),
                "items": data,
            }

    except SQLAlchemyError as e:
        raise HTTPException(status_code=500, detail=str(e))
    

import logging

logger = logging.getLogger(__name__)

@app.get("/controller/{controller_id}/last-setting")
def get_last_setting(controller_id: int, current_user: str = Depends(get_current_username)):
    """
    Returns the last successful settings apply info (c0=512) for this controller,
    including the sent setting payload and device ACK payload.
    """
    try:
        with engine.connect() as conn:
            # Validate controller exists & ownership
            ctrl = conn.execute(
                select(controllers).where(controllers.c.controller_id == controller_id)
            ).mappings().first()

            if not ctrl:
                raise HTTPException(status_code=404, detail="Controller not found")

            user = conn.execute(
                select(users).where(users.c.username == current_user)
            ).mappings().first()

            if not user or user.get("id") != ctrl.get("user_id"):
                raise HTTPException(status_code=403, detail="Not authorized")

            # Fetch the most recent stored last setting -- ensure ORDER BY for "last"
            q = (
                select(controller_last_setting)
                .where(controller_last_setting.c.controller_id == controller_id)
                .order_by(desc(controller_last_setting.c.set_time_epoch))
                .limit(1)
            )
            last = conn.execute(q).mappings().first()

            if not last:
                return {"controller_id": controller_id, "status": "no_setting_found"}

            # Normalize types
            set_time_epoch = last.get("set_time_epoch")
            if set_time_epoch is not None:
                try:
                    set_time_epoch = int(set_time_epoch)
                except (TypeError, ValueError):
                    # leave as-is or set to None if conversion fails
                    set_time_epoch = None

            return {
                "controller_id": controller_id,
                "status": "ok",
                "sent_settings": last.get("set_payload"),
                "device_ack": last.get("last_payload"),
                "set_time_raw": last.get("set_time_raw"),
                "set_time_epoch": set_time_epoch,
            }

    except SQLAlchemyError:
        logger.exception("DB error while fetching last setting for controller %s", controller_id)
        # Generic error detail to avoid leaking internals
        raise HTTPException(status_code=500, detail="Internal server error")


