# app.py
import streamlit as st
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError, PyMongoError
from bson.objectid import ObjectId
import bcrypt
from datetime import datetime, timezone
import pandas as pd
import re

st.set_page_config(page_title="KinderJoy — Streamlit + MongoDB", layout="wide")

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

# ---------- DB connection (from Streamlit secrets) ----------
@st.cache_resource
def get_db():
    try:
        uri = st.secrets["mongodb"]["uri"]
        dbname = st.secrets["mongodb"]["db"]
    except Exception:
        st.error("Missing MongoDB secrets. Add mongodb.uri and mongodb.db to Streamlit secrets.")
        st.stop()

    try:
        client = MongoClient(uri)
        return client[dbname]
    except PyMongoError as e:
        st.error(f"Could not connect to MongoDB: {e}")
        st.stop()

db = get_db()
users_col = db["users"]
results_col = db["results"]
auth_events_col = db["auth_events"]

# Ensure unique username index
try:
    users_col.create_index("username", unique=True)
except Exception:
    # if index creation fails (permissions etc.), app will continue but uniqueness not enforced at DB level
    pass

# ---------- Ensure admin exists using secrets ----------
def ensure_admin_from_secrets():
    # If any admin exists, do nothing
    if users_col.find_one({"role": "Admin"}):
        return

    init = st.secrets.get("initial_admin", {})
    username = init.get("username")
    password = init.get("password")

    if not username or not password:
        # No auto-create if secrets don't have both username & password
        return

    # create admin (hashed password)
    try:
        users_col.insert_one({
            "username": username,
            "name": "Administrator",
            "password": hash_password(password),
            "role": "Admin",
            "created_at": now_utc(),
            "meta": {"must_change_password": True}
        })
        st.info(f"Admin user '{username}' created from secrets. Please change the password after first login.")
    except DuplicateKeyError:
        # someone created it concurrently
        pass
    except Exception as e:
        st.warning(f"Could not auto-create admin: {e}")

ensure_admin_from_secrets()

# ---------- Session state ----------
if "user" not in st.session_state:
    st.session_state.user = None

def login_user(username: str, password: str):
    username = (username or "").strip()
    u = users_col.find_one({"username": username})
    # record basic auth event
    auth_event = {"username": username, "time": now_utc(), "success": False}
    if not u:
        auth_event["note"] = "not_found"
        auth_events_col.insert_one(auth_event)
        return False, "User not found"
    if verify_password(password, u.get("password", "")):
        st.session_state.user = {
            "id": str(u.get("_id")),
            "username": u.get("username"),
            "name": u.get("name", ""),
            "role": u.get("role", "User")
        }
        auth_event["success"] = True
        auth_events_col.insert_one(auth_event)
        if u.get("meta", {}).get("must_change_password"):
            return True, "Logged in — please change your temporary password."
        return True, "Login successful"
    else:
        auth_event["note"] = "invalid_password"
        auth_events_col.insert_one(auth_event)
        return False, "Invalid password"

def logout_user():
    st.session_state.user = None
    # use stable rerun API
    st.rerun()

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
        submitted = st.form_submit_button("Login")
        if submitted:
            ok, msg = login_user(uname, pwd)
            if ok:
                st.sidebar.success(msg)
                st.rerun()
            else:
                st.sidebar.error(msg)

# ---------- Main ----------
st.title("KinderJoy — Streamlit + MongoDB App")

if not st.session_state.user:
    st.write("Please sign in using the sidebar.")
    st.stop()

user = st.session_state.user

# ---------- Admin dashboard ----------
if user["role"] == "Admin":
    st.header("Admin Dashboard")

    with st.expander("Create new user"):
        with st.form("create_user"):
            name = st.text_input("Full Name")
            username = st.text_input("Username (3-30 chars)")
            password = st.text_input("Password", type="password")
            role = st.selectbox("Role", ["User", "Admin"])
            create = st.form_submit_button("Create")
            if create:
                if not (name and username and password):
                    st.error("All fields required.")
                elif not valid_username(username):
                    st.error("Invalid username (3-30 chars, letters/numbers/._-).")
                elif len(password) < 6:
                    st.error("Password too short (min 6 chars).")
                else:
                    try:
                        users_col.insert_one({
                            "name": name,
                            "username": username,
                            "password": hash_password(password),
                            "role": role,
                            "created_at": now_utc()
                        })
                        st.success(f"User '{username}' created.")
                    except DuplicateKeyError:
                        st.error("Username already exists.")
                    except Exception as e:
                        st.error(f"Error creating user: {e}")

    st.markdown("---")
    st.subheader("Existing users")
    try:
        users = list(users_col.find({}, {"password": 0}))
        if users:
            df = pd.DataFrame([{
                "Name": u.get("name"),
                "Username": u.get("username"),
                "Role": u.get("role"),
                "Created": u.get("created_at")
            } for u in users])
            st.dataframe(df)
        else:
            st.info("No users found.")
    except Exception as e:
        st.error(f"Could not fetch users: {e}")

# ---------- User page ----------
st.header("User Page")
st.write(f"Welcome, **{user['name'] or user['username']}**!")

with st.form("input_form"):
    text = st.text_input("Enter some text")
    submit = st.form_submit_button("Submit")
    if submit:
        if not text.strip():
            st.error("Please enter some text.")
        else:
            try:
                uid = user["id"]
                uid_obj = ObjectId(uid) if ObjectId.is_valid(uid) else uid
                results_col.insert_one({
                    "user_id": uid_obj,
                    "username": user["username"],
                    "input": text,
                    "output": text[::-1],
                    "created_at": now_utc()
                })
                st.success("Saved.")
            except Exception as e:
                st.error(f"Save failed: {e}")

st.markdown("### Your recent outputs")
try:
    recent = list(results_col.find({"username": user["username"]}).sort([("_id", -1)]).limit(10))
    if recent:
        for r in recent:
            st.write(f"- **Input:** {r.get('input')} → **Output:** {r.get('output')}")
    else:
        st.info("No results yet.")
except Exception as e:
    st.error(f"Could not fetch results: {e}")

st.markdown("---")
st.caption("Demo app — change the admin password after first login.")
