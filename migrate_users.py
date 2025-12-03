from sqlalchemy import create_engine, MetaData, Table, Column, Integer, BigInteger, String, ForeignKey
from passlib.context import CryptContext

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

engine = create_engine(DATABASE_URL)
metadata = MetaData()

# -----------------------------
# TABLE DEFINITIONS
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
    Column("controller_id", BigInteger, nullable=False),
    Column("name", String, nullable=False),
    Column("status", String, nullable=False, default="Unknown"),
    Column("user_id", Integer, ForeignKey("users.id"), nullable=False),
)

metadata.create_all(engine)

# -----------------------------
# PASSWORD HASHING
# -----------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# -----------------------------
# USERS & CONTROLLERS TO MIGRATE
# -----------------------------
old_users = {
    "psdas": "psdas",
    "sam": "sam"
}

controller_map = {
    "psdas": [
        {"id": 862360073810546, "name": "PS Controller 1", "status": "Active"},
        {"id": 862360073810165, "name": "PS Controller 2", "status": "Offline"},
        {"id": 862360073810166, "name": "PS Controller 3", "status": "Online"},
        {"id": 862360073810167, "name": "PS Controller 4", "status": "Active"},  # new controller
    ],
    "sam": [
        {"id": 862360073810546, "name": "PS Controller 1", "status": "Active"},
        {"id": 862360073810168, "name": "PS Controller 2", "status": "Online"}  # new controller for sam
    ]
}

# -----------------------------
# MIGRATION LOGIC
# -----------------------------
updated_users = []
updated_controllers = []

with engine.begin() as conn:  # begin transaction ensures commits
    for username, password in old_users.items():
        # Check if user exists
        existing_user = conn.execute(
            users.select().where(users.c.username == username)
        ).fetchone()

        if existing_user:
            user_id = existing_user.id
            updated_users.append(f"User '{username}' already exists → ID {user_id}")
        else:
            # Insert new user
            pw_hash = pwd_context.hash(password)
            inserted = conn.execute(
                users.insert().values(username=username, password_hash=pw_hash)
            )
            user_id = inserted.inserted_primary_key[0]
            updated_users.append(f"Inserted new user '{username}' → ID {user_id}")

        # Insert new controllers for user
        if username in controller_map:
            for ctrl in controller_map[username]:
                # Only insert if controller for this user does not exist
                existing_ctrl = conn.execute(
                    controllers.select().where(
                        (controllers.c.controller_id == ctrl["id"]) &
                        (controllers.c.user_id == user_id)
                    )
                ).fetchone()

                if existing_ctrl:
                    updated_controllers.append(
                        f"Controller {ctrl['id']} already exists for user '{username}' → SKIP"
                    )
                else:
                    conn.execute(
                        controllers.insert().values(
                            controller_id=ctrl["id"],
                            name=ctrl["name"],
                            status=ctrl["status"],
                            user_id=user_id
                        )
                    )
                    updated_controllers.append(
                        f"Inserted controller {ctrl['id']} → '{ctrl['name']}' for user '{username}'"
                    )

# -----------------------------
# PRINT REPORT
# -----------------------------
print("\n=== MIGRATION REPORT ===")

if updated_users:
    print("\nUsers Updated/Inserted:")
    for u in updated_users:
        print("-", u)

if updated_controllers:
    print("\nControllers Inserted/Skipped:")
    for c in updated_controllers:
        print("-", c)

if not updated_users and not updated_controllers:
    print("\nNo new users or controllers inserted. Database is up-to-date.")

# -----------------------------
# PRINT ALL DATA
# -----------------------------
with engine.connect() as conn:
    print("\n=== ALL USERS IN DB ===")
    for u in conn.execute(users.select()).fetchall():
        print(dict(u._mapping))

    print("\n=== ALL CONTROLLERS IN DB ===")
    for c in conn.execute(controllers.select()).fetchall():
        print(dict(c._mapping))
