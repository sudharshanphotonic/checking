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
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt
import paho.mqtt.client as mqtt
import time
import threading

app = FastAPI()

# ------------------------------------------------------------
# CORS

#captain (DB entry passsword)
# ------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "secret123"
ALGORITHM = "HS256"

users_db = {
    "psdas": pwd_context.hash("psdas"),
    "john": pwd_context.hash("1234"),
    "admin": pwd_context.hash("admin123"),
}

controller_map = {
    "psdas": [
        {"id": 862360073810546, "name": "PS Controller 1", "status": "Active"},
        {"id": 862360073810165, "name": "PS Controller 2", "status": "Offline"},
        {"id": 862360073810166, "name": "PS Controller 3", "status": "Online"}
    ]
}

class Login(BaseModel):
    username: str
    password: str

class CommandPayload(BaseModel):
    payload: str = "c0=201"


# -------------------------------------------------------------------------
# MQTT LIVE ACK STORAGE (device → server)
# -------------------------------------------------------------------------
last_ack = {}        # example: {"862360073810165": 1728828282.22}
last_ack_payload = {}  # example: {"862360073810165": "d0=...&c0=100&..."}


# -------------------------------------------------------------------------
# MQTT CALLBACKS
# -------------------------------------------------------------------------
def on_message(client, userdata, msg):
    global last_ack, last_ack_payload

    payload = msg.payload.decode()
    print("MQTT RECEIVED:", payload)

    # data is coming from topic: psdasaqs
    if msg.topic == "psdasaqs":
        # Extract controller ID from string
        parts = payload.split("&")
        d0 = None
        for p in parts:
            if p.startswith("d0="):
                d0 = p.replace("d0=", "")
        
        if d0:
            last_ack[d0] = time.time()
            last_ack_payload[d0] = payload


def on_connect(client, userdata, flags, rc):
    print("MQTT connected:", rc)
    client.subscribe("psdasaqs")  # device response topic


# -------------------------------------------------------------------------
# START BACKGROUND MQTT SUBSCRIBER THREAD
# -------------------------------------------------------------------------
mqtt_client = mqtt.Client()
mqtt_client.on_connect = on_connect
mqtt_client.on_message = on_message
mqtt_client.connect("broker.emqx.io", 1883)
threading.Thread(target=mqtt_client.loop_forever, daemon=True).start()


# -------------------------------------------------------------------------
# LOGIN API
# -------------------------------------------------------------------------
@app.post("/login")
def login_user(data: Login):
    if data.username not in users_db:
        raise HTTPException(status_code=400, detail="Invalid username")

    if not pwd_context.verify(data.password, users_db[data.username]):
        raise HTTPException(status_code=400, detail="Invalid password")

    token = jwt.encode({"user": data.username}, SECRET_KEY, algorithm=ALGORITHM)

    return {
        "username": data.username,
        "access_token": token,
        "controllers": controller_map.get(data.username, [])
    }


# -------------------------------------------------------------------------
# PUBLISH COMMAND AND CHECK ACK
# -------------------------------------------------------------------------
@app.post("/controller/{controller_id}/command")
def send_command(controller_id: str, command: CommandPayload):

    # Before sending command → clear previous ACK
    last_ack[controller_id] = 0

    topic = f"psdasaqp/{controller_id}"
    result = mqtt_client.publish(topic, command.payload)

    print("Command Sent:", command.payload)

    # Wait up to 3 seconds for ACK
    timeout = 3
    start = time.time()

    while time.time() - start < timeout:
        if controller_id in last_ack and last_ack[controller_id] > start:
            return {
                "status": "success",
                "controller_id": controller_id,
                "payload": command.payload,
                "ack": "received",
                "ack_payload": last_ack_payload.get(controller_id)
            }
        time.sleep(0.1)

    return {
        "status": "success",
        "controller_id": controller_id,
        "payload": command.payload,
        "ack": "not_received"
    }
