import streamlit as st
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from bson.objectid import ObjectId
import bcrypt
from datetime import datetime, timezone
import pandas as pd
import re

st.set_page_config(page_title="Streamlit + MongoDB | KinderJoy", layout="wide")

# ---------- Helpers ----------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def valid_username(u: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9_.-]{3,30}$", (u or "").strip()))

def now_utc():
    return datetime.now(timezone.utc)

# ---------- Connect to MongoDB ----------
@st.cache_resource
def get_db():
    try:
        uri = st.secrets["mongodb"]["uri"]
        dbname = st.secrets["mongodb"]["db"]
        client = MongoClient(uri)
        return client[dbname]
    except Exception as e:
        st.error(f"MongoDB connection failed: {e}")
        st.stop()

db = get_db()
users_col = db["users"]
results_col = db["results"]

# ---------- Ensure unique usernames ----------
try:
    users_col.create_index("username", unique=True)
except Exception:
    pass

# ---------- Ensure admin exists ----------
def ensure_admin():
    admin = users_col.find_one({"role": "Admin"})
    if admin:
        return
    init_admin = st.secrets.get("initial_admin", {})
    username = init_admin.get("username", "admin")
    password = init_admin.get("password", "admin")
    hashed = hash_password(password)
    users_col.insert_one({
        "username": username,
        "name": "Administrator",
        "password": hashed,
        "role": "Admin",
        "created_at": now_utc(),
    })
    st.info(f"Admin user '{username}' created with password '{password}' (demo only — please change).")

ensure_admin()

# ---------- Session state ----------
if "user" not in st.session_state:
    st.session_state.user = None

def login_user(username, password):
    u = users_col.find_one({"username": username})
    if not u:
        return False, "User not found"
    if verify_password(password, u["password"]):
        st.session_state.user = {
            "id": str(u["_id"]),
            "username": u["username"],
            "name": u.get("name", ""),
            "role": u.get("role", "User")
        }
        return True, "Login successful!"
    return False, "Invalid password"

def logout_user():
    st.session_state.user = None
    st.experimental_rerun()

# ---------- Sidebar login/logout ----------
st.sidebar.title("Authentication")
if st.session_state.user:
    st.sidebar.success(f"Logged in as **{st.session_state.user['username']}** ({st.session_state.user['role']})")
    if st.sidebar.button("Logout"):
        logout_user()
else:
    with st.sidebar.form("login_form"):
        uname = st.text_input("Username")
        pwd = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
        if submit:
            ok, msg = login_user(uname.strip(), pwd)
            if ok:
                st.experimental_rerun()
            else:
                st.sidebar.error(msg)

# ---------- Main ----------
st.title("KinderJoy — Streamlit + MongoDB App")

if not st.session_state.user:
    st.write("Please sign in using the sidebar.")
    st.stop()

user = st.session_state.user

# ---------- Admin page ----------
if user["role"] == "Admin":
    st.header("Admin Dashboard 👩‍💼")

    with st.expander("Create new user"):
        with st.form("create_user"):
            name = st.text_input("Full Name")
            username = st.text_input("Username (letters/numbers only)")
            password = st.text_input("Password", type="password")
            role = st.selectbox("Role", ["User", "Admin"])
            submit = st.form_submit_button("Create User")
            if submit:
                if not (name and username and password):
                    st.error("All fields are required.")
                elif not valid_username(username):
                    st.error("Invalid username (3–30 chars, letters/numbers only).")
                elif len(password) < 6:
                    st.error("Password too short (min 6 characters).")
                else:
                    try:
                        users_col.insert_one({
                            "name": name,
                            "username": username,
                            "password": hash_password(password),
                            "role": role,
                            "created_at": now_utc()
                        })
                        st.success(f"User '{username}' created successfully!")
                    except DuplicateKeyError:
                        st.error("Username already exists.")

    st.markdown("### Existing users")
    users = list(users_col.find({}, {"password": 0}))
    if users:
        df = pd.DataFrame([
            {
                "Name": u.get("name"),
                "Username": u.get("username"),
                "Role": u.get("role"),
                "Created": u.get("created_at")
            } for u in users
        ])
        st.dataframe(df)
    else:
        st.info("No users found yet.")

# ---------- User Page ----------
st.header("User Page ✨")
st.write(f"Welcome, **{user['name'] or user['username']}**!")

with st.form("input_form"):
    text = st.text_input("Enter text:")
    submitted = st.form_submit_button("Submit")
    if submitted and text.strip():
        results_col.insert_one({
            "user_id": user["id"],
            "username": user["username"],
            "input": text,
            "output": text[::-1],  # simple "processing"
            "timestamp": now_utc()
        })
        st.success("Saved successfully!")

st.markdown("### Your Recent Entries")
recent = list(results_col.find({"username": user["username"]}).sort([("_id", -1)]).limit(10))
if recent:
    for r in recent:
        st.write(f"- **Input:** {r.get('input')} → **Output:** {r.get('output')}")
else:
    st.info("No entries yet.")

st.markdown("---")
st.caption("Secure Streamlit + MongoDB Demo — Admin: chetna / chetna01")
