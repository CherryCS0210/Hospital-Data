# app.py
import streamlit as st
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError, PyMongoError
from bson.objectid import ObjectId
import bcrypt
from datetime import datetime, timezone
import pandas as pd
import re
import random
import string
import io
import os

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

def normalize_text(s: str) -> str:
    if s is None:
        return ""
    s = str(s).strip()
    s = re.sub(r"\s+", " ", s)
    return s.lower()

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

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
    pass  # continue if we can't create the index

# ---------- Ensure admin exists using secrets ----------
def ensure_admin_from_secrets():
    if users_col.find_one({"role": "Admin"}):
        return

    init = st.secrets.get("initial_admin", {}) or {}
    username = init.get("username")
    password = init.get("password")

    if not username or not password:
        return

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
    auth_event = {"username": username, "time": now_utc(), "success": False}
    if not u:
        auth_event["note"] = "not_found"
        try:
            auth_events_col.insert_one(auth_event)
        except Exception:
            pass
        return False, "User not found"
    if verify_password(password, u.get("password", "")):
        st.session_state.user = {
            "id": str(u.get("_id")),
            "username": u.get("username"),
            "name": u.get("name", ""),
            "role": u.get("role", "User")
        }
        auth_event["success"] = True
        try:
            auth_events_col.insert_one(auth_event)
        except Exception:
            pass
        if u.get("meta", {}).get("must_change_password"):
            return True, "Logged in — please change your temporary password."
        return True, "Login successful"
    else:
        auth_event["note"] = "invalid_password"
        try:
            auth_events_col.insert_one(auth_event)
        except Exception:
            pass
        return False, "Invalid password"

def logout_user():
    st.session_state.user = None
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
    st.subheader("Existing users (no passwords shown)")
    try:
        users = list(users_col.find({}, {"password": 0}))
        if users:
            df_users = pd.DataFrame([{
                "Name": u.get("name"),
                "Username": u.get("username"),
                "Role": u.get("role"),
                "Created": u.get("created_at")
            } for u in users])
            st.dataframe(df_users)
        else:
            st.info("No users found.")
    except Exception as e:
        st.error(f"Could not fetch users: {e}")

    st.markdown("---")
    st.subheader("Sample Data Tools (Admin)")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Insert 20 Sample Data Rows"):
            samples = []
            for i in range(20):
                txt = ''.join(random.choice(string.ascii_letters + " ") for _ in range(8)).strip() or "sample"
                samples.append({
                    "user_id": "sample_user_id",
                    "username": "sample_user",
                    "input": txt,
                    "output": txt[::-1],
                    "created_at": now_utc()
                })
            try:
                results_col.insert_many(samples)
                st.success("20 sample rows inserted!")
            except Exception as e:
                st.error(f"Could not insert sample data: {e}")

    with col2:
        if st.button("Clear All Sample Results (username=sample_user)"):
            try:
                res = results_col.delete_many({"username": "sample_user"})
                st.success(f"Deleted {res.deleted_count} sample rows.")
            except Exception as e:
                st.error(f"Delete failed: {e}")

# ---------- User page ----------
st.header("User Page")
st.write(f"Welcome, **{user['name'] or user['username']}**!")

# ---------- File upload: convert to CSV (backend), insert into DB, save CSV to disk ----------
st.markdown("### Upload file to convert to CSV (backend only)")

uploaded = st.file_uploader("Upload a CSV or plain text file (each row will become an input). Transforms and visualizations are NOT shown in the app.", type=["csv", "txt"], accept_multiple_files=False)

if uploaded is not None:
    # read bytes
    try:
        file_name = uploaded.name
        content = uploaded.read()
        # try to parse as CSV first
        df_inputs = None
        try:
            # attempt to read as CSV - this will work for many text-based inputs
            df_tmp = pd.read_csv(io.BytesIO(content))
            # prefer a column named 'input' (case-insensitive)
            cols = {c.lower(): c for c in df_tmp.columns}
            if "input" in cols:
                df_inputs = pd.DataFrame({"input": df_tmp[cols["input"]]})
            else:
                # take first column
                first_col = df_tmp.columns[0]
                df_inputs = pd.DataFrame({"input": df_tmp[first_col]})
        except Exception:
            # fallback: treat as plain text, split lines
            try:
                text = content.decode("utf-8", errors="replace")
            except Exception:
                text = str(content)
            lines = [ln for ln in text.splitlines() if ln.strip() != ""]
            df_inputs = pd.DataFrame({"input": lines})

        # normalize and create outputs
        df_inputs["input"] = df_inputs["input"].astype(str).apply(normalize_text)
        df_inputs["output"] = df_inputs["input"].apply(lambda s: s[::-1])
        df_inputs["username"] = user["username"]
        # choose user_id as ObjectId or string
        uid = user["id"]
        try:
            uid_obj = ObjectId(uid) if ObjectId.is_valid(uid) else uid
        except Exception:
            uid_obj = uid
        df_inputs["user_id"] = uid_obj
        df_inputs["created_at"] = now_utc()

        # Insert into MongoDB (bulk)
        try:
            docs = df_inputs.to_dict(orient="records")
            # convert any pandas.Timestamp to Python datetimes
            for d in docs:
                if isinstance(d.get("created_at"), pd.Timestamp):
                    d["created_at"] = d["created_at"].to_pydatetime()
            if docs:
                results_col.insert_many(docs)
        except Exception as e:
            st.error(f"Failed to insert to DB: {e}")
            # continue to still write CSV to disk

        # Save CSV to disk under /mnt/data (common writeable path in this environment)
        out_dir = "/mnt/data"
        ensure_dir(out_dir)
        timestamp = now_utc().strftime("%Y%m%dT%H%M%SZ")
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", user["username"])
        out_path = os.path.join(out_dir, f"converted_{safe_name}_{timestamp}.csv")
        try:
            # write CSV without modifying index
            df_inputs.to_csv(out_path, index=False)
        except Exception as e:
            st.error(f"Failed to write CSV to disk: {e}")
            out_path = None

        # Provide minimal UI feedback (no data display, no transforms shown)
        st.success("File uploaded and converted to CSV on the server. Transforms are not displayed in the app.")
        if out_path:
            # Streamlit download button will stream file contents to the user.
            try:
                with open(out_path, "rb") as f:
                    st.download_button(
                        label="⬇️ Download converted CSV",
                        data=f,
                        file_name=os.path.basename(out_path),
                        mime="text/csv"
                    )
            except Exception as e:
                st.info(f"CSV saved at: {out_path} (download unavailable via web UI).")
    except Exception as e:
        st.error(f"Could not process uploaded file: {e}")

st.markdown("---")
st.caption("Uploads convert to CSV and are saved to disk and to the DB. No transforms or visualizations are shown in the app.")
