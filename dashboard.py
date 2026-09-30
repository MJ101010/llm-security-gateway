"""Streamlit SOC-style dashboard over the JSONL event log."""
import json, os
import pandas as pd
import streamlit as st

LOG = os.environ.get("GATEWAY_LOG", "logs/security_events.jsonl")
st.set_page_config(page_title="LLM Gateway SOC", layout="wide")
st.title("LLM Security Gateway - Event Dashboard")

if not os.path.exists(LOG):
    st.info("No events yet. Send requests to the gateway first.")
    st.stop()

df = pd.DataFrame([json.loads(l) for l in open(LOG) if l.strip()])
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total requests", len(df))
c2.metric("Blocked", int((df.action == "block").sum()))
c3.metric("Redacted", int((df.action == "redact").sum()))
c4.metric("Allowed", int((df.action == "allow").sum()))

st.subheader("Latest events")
st.dataframe(df.sort_values("timestamp", ascending=False).head(50), use_container_width=True)

l, r = st.columns(2)
with l:
    st.subheader("Injection rules triggered")
    rules = pd.Series([x for row in df.injection_rules for x in row], dtype="object").value_counts()
    if len(rules): st.bar_chart(rules)
    else: st.write("None")
with r:
    st.subheader("Sensitive data types found")
    types = pd.Series([x for row in (df.secret_types + df.pii_types) for x in row], dtype="object").value_counts()
    if len(types): st.bar_chart(types)
    else: st.write("None")
