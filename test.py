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
import altair as alt

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
    s = s.strip()
    # basic normalization: lowercase and collapse whitespace
    s = re.sub(r"\s+", " ", s)
    return s.lower()

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

    init = st.secrets.get("initial_admin", {}) or {}
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
    # ---------- Sample Data Population (Admin) ----------
    st.subheader("Sample Data Tools (Admin)")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Insert 20 Sample Data Rows"):
            samples = []
            for i in range(20):
                txt = ''.join(random.choice(string.ascii_letters + " ") for _ in range(8)).strip()
                txt = txt or "sample"
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

    st.markdown("---")
    # ---------- Admin: View & Analyze All Results ----------
    st.subheader("All Results (Admin view & analysis)")
    try:
        all_results = list(results_col.find({}).sort([("_id", -1)]).limit(1000))
        if not all_results:
            st.info("No results in DB yet.")
        else:
            df_all = pd.DataFrame(all_results)
            # drop large columns if present
            if "_id" in df_all.columns:
                df_all["_id_str"] = df_all["_id"].astype(str)
            # Normalize and clean
            df_all["input"] = df_all.get("input", "").apply(lambda x: normalize_text(x) if pd.notna(x) else "")
            df_all["output"] = df_all.get("output", "").apply(lambda x: normalize_text(x) if pd.notna(x) else "")
            df_all["created_at"] = pd.to_datetime(df_all["created_at"], errors="coerce")
            df_all["input_length"] = df_all["input"].apply(lambda x: len(x) if pd.notna(x) else 0)

            st.write("Preview of recent results")
            st.dataframe(df_all.head(50))

            # Aggregate stats
            st.markdown("### Aggregate stats")
            col_a, col_b, col_c = st.columns(3)
            with col_a:
                st.metric("Total results", len(df_all))
            with col_b:
                unique_users = df_all["username"].nunique() if "username" in df_all.columns else 0
                st.metric("Unique users", unique_users)
            with col_c:
                avg_len = df_all["input_length"].mean() if not df_all["input_length"].empty else 0
                st.metric("Avg input length", f"{avg_len:.1f}")

            # Chart: input length distribution
            st.markdown("### Input length distribution")
            hist = alt.Chart(df_all).mark_bar().encode(
                alt.X("input_length:Q", bin=alt.Bin(maxbins=30)),
                y="count()",
                tooltip=["count()"]
            ).properties(width=700, height=300)
            st.altair_chart(hist)

            # Chart: inputs over time
            st.markdown("### Inputs over time (last 90 days)")
            df_time = df_all.dropna(subset=["created_at"])
            if not df_time.empty:
                df_time_recent = df_time[df_time["created_at"] >= (pd.Timestamp.now(tz='UTC') - pd.Timedelta(days=90))]
                line = alt.Chart(df_time_recent).mark_line(point=True).encode(
                    x=alt.X("created_at:T", title="Created at"),
                    y=alt.Y("count():Q", title="Count"),
                    color="username:N",
                    tooltip=["username", "count()"]
                ).properties(width=800, height=350)
                st.altair_chart(line)
            else:
                st.info("Not enough timestamped data to show time chart.")

            # Export all results (Admin)
            to_export = df_all.copy()
            # remove raw object ids
            if "_id" in to_export.columns:
                to_export = to_export.drop(columns=["_id"])
            csv_all = to_export.to_csv(index=False).encode("utf-8")
            st.download_button("⬇️ Download ALL results as CSV (Admin)", csv_all, "all_results.csv", "text/csv")
    except Exception as e:
        st.error(f"Admin analysis failed: {e}")

# ---------- User page ----------
st.header("User Page")
st.write(f"Welcome, **{user['name'] or user['username']}**!")

with st.form("input_form"):
    text = st.text_input("Enter some text")
    submit = st.form_submit_button("Submit")
    if submit:
        if not (text and text.strip()):
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
    recent = list(results_col.find({"username": user["username"]}).sort([("_id", -1)]).limit(100))
    if recent:
        for r in recent:
            st.write(f"- **Input:** {r.get('input')} → **Output:** {r.get('output')}  *(at {r.get('created_at')})*")
    else:
        st.info("No results yet.")
except Exception as e:
    st.error(f"Could not fetch results: {e}")

st.markdown("---")

# ---------- Per-user cleaning, transform, download & visualize ----------
st.subheader("My Data — Clean, Transform, Export & Visualize")
try:
    my_results = list(results_col.find({"username": user["username"]}).sort([("_id", -1)]))
    if not my_results:
        st.info("You have no saved results yet.")
    else:
        df_me = pd.DataFrame(my_results)
        # Clean & transform
        if "_id" in df_me.columns:
            df_me["_id_str"] = df_me["_id"].astype(str)
        df_me["input"] = df_me.get("input", "").apply(lambda x: normalize_text(x) if pd.notna(x) else "")
        df_me["output"] = df_me.get("output", "").apply(lambda x: normalize_text(x) if pd.notna(x) else "")
        df_me["created_at"] = pd.to_datetime(df_me["created_at"], errors="coerce")
        df_me["input_length"] = df_me["input"].apply(lambda x: len(x) if pd.notna(x) else 0)
        # Additional transforms (example): reversed normalized input saved as column
        df_me["input_reversed_norm"] = df_me["input"].apply(lambda x: x[::-1] if pd.notna(x) else "")

        st.write("Cleaned preview")
        st.dataframe(df_me[["input", "output", "created_at", "input_length"]].head(50))

        # CSV download (user)
        export_df = df_me.drop(columns=[c for c in df_me.columns if c == "_id"], errors='ignore')
        csv = export_df.to_csv(index=False).encode("utf-8")
        st.download_button("⬇️ Download My Data as CSV", csv, f"{user['username']}_results.csv", "text/csv")

        # Visualization: input length over time
        st.markdown("#### Input length over time")
        df_time = df_me.dropna(subset=["created_at"])
        if not df_time.empty and len(df_time) >= 1:
            chart = (
                alt.Chart(df_time)
                .mark_line(point=True)
                .encode(
                    x=alt.X("created_at:T", title="Created at"),
                    y=alt.Y("input_length:Q", title="Input length"),
                    tooltip=["input", "output", "created_at"]
                )
                .properties(width=700, height=300)
            )
            st.altair_chart(chart)
        else:
            st.info("Not enough data points to visualize input length over time.")

        # Visualization: input length histogram
        st.markdown("#### Input length histogram")
        hist = alt.Chart(df_me).mark_bar().encode(
            alt.X("input_length:Q", bin=alt.Bin(maxbins=20)),
            y="count()",
            tooltip=["count()"]
        ).properties(width=700, height=300)
        st.altair_chart(hist)

        # Simple textual analysis: most common words in inputs (basic)
        st.markdown("#### Top tokens (basic)")
        all_input_text = " ".join(df_me["input"].astype(str).tolist())
        tokens = re.findall(r"\w+", all_input_text)
        tokens = [t for t in tokens if len(t) > 1]  # filter single-char tokens
        if tokens:
            top_tokens = pd.Series(tokens).value_counts().head(10).rename_axis("token").reset_index(name="count")
            st.table(top_tokens)
        else:
            st.info("No tokens to analyze.")
except Exception as e:
    st.error(f"My data analysis failed: {e}")

st.markdown("---")
st.caption("Demo app — change the admin password after first login.")
