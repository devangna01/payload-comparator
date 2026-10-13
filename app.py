import json
import re
import csv
import io
from typing import Any

import streamlit as st

st.set_page_config(page_title="Axis Precheck RCA | Payload Comparator", page_icon="🔎", layout="wide")

st.markdown("""
<style>
:root { --rupeek-magenta: #ff00ff; --rupeek-red: #ff0000; --rupeek-blue: #0000ff; }
.block-container { padding-top: 1.7rem; padding-bottom: 2rem; max-width: 1500px; }
.hero { padding: 1.35rem 1.55rem; border-radius: 18px; color: white;
        background: linear-gradient(115deg, #ff00ff 0%, #ff0000 48%, #0000ff 100%);
        box-shadow: 0 8px 28px rgba(75, 0, 130, .18); margin-bottom: 1rem; }
.hero h1 { color: white; font-size: 2rem; margin: 0 0 .35rem 0; }
.hero p { color: white; opacity: .96; margin: 0; font-size: 1rem; }
div.stButton > button[kind="primary"] { background: linear-gradient(100deg, #ff00ff, #ff0000, #0000ff);
    color: white; border: 0; border-radius: 10px; font-weight: 700; }
div[data-testid="stMetric"] { border: 1px solid rgba(128,128,128,.22); padding: 12px 14px; border-radius: 12px; }
.status-pill { display: inline-block; border-radius: 999px; padding: 5px 11px; margin: 3px 5px 5px 0;
    font-size: .88rem; font-weight: 700; }
.status-fail { background: #ffe5e5; color: #b00020; border: 1px solid #ffb3b3; }
.status-pass { background: #e4f8eb; color: #126b35; border: 1px solid #a6e3bb; }
.status-unknown { background: #eeeeff; color: #292980; border: 1px solid #c8c8ff; }
.section-note { border-left: 4px solid #ff00ff; padding: .65rem .9rem; background: rgba(255,0,255,.055); border-radius: 0 8px 8px 0; }
</style>
<div class="hero"><h1>Axis Precheck · Payload RCA</h1>
<p>Compare the original request with the lender-side request, pinpoint field mismatches, and review the failing precheck checks.</p></div>
""", unsafe_allow_html=True)

SENSITIVE_KEYS = re.compile(
    r"pan|aadhaar|aadhar|mobile|phone|email|token|password|secret|api.?key|authorization",
    re.I,
)


def normalize_key(key: str) -> str:
    """Normalize camelCase/snake_case so common naming variants can be matched."""
    key = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(key))
    return re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")


def split_top_level(text: str, separator: str = ",") -> list[str]:
    parts, start, depth = [], 0, 0
    quote, escaped = None, False
    for i, char in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ('"', "'"):
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == separator and depth == 0:
            parts.append(text[start:i].strip())
            start = i + 1
    parts.append(text[start:].strip())
    return [part for part in parts if part]


def find_balanced_end(text: str, start: int, opening: str = "(", closing: str = ")") -> int:
    depth, quote, escaped = 0, None, False
    for i in range(start, len(text)):
        char = text[i]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ('"', "'"):
            quote = char
        elif char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return i
    return -1


def parse_java_value(raw: str) -> Any:
    """Parse common Java/Kotlin object toString forms, e.g. Address(city=DELHI, pin=110037)."""
    raw = raw.strip()
    if raw == "null":
        return None
    if raw == "true":
        return True
    if raw == "false":
        return False
    if re.fullmatch(r"[-+]?\d+(?:\.\d+)?", raw):
        return float(raw) if "." in raw else int(raw)
    if raw.startswith('"') and raw.endswith('"'):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw[1:-1]
    if raw.startswith("'") and raw.endswith("'"):
        return raw[1:-1]
    if raw.startswith("[") and raw.endswith("]"):
        return [parse_java_value(item) for item in split_top_level(raw[1:-1])]
    if raw.startswith("{") and raw.endswith("}"):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass

    match = re.match(r"^([\w.$]+)\s*\(", raw)
    if match:
        type_name = match.group(1)
        open_pos = raw.find("(", match.start())
        end_pos = find_balanced_end(raw, open_pos)
        if end_pos == len(raw) - 1:
            result = {"_object_type": type_name}
            for item in split_top_level(raw[open_pos + 1:end_pos]):
                # Find first equals sign outside nested structures and quotes.
                depth, quote, eq_pos = 0, None, -1
                for i, char in enumerate(item):
                    if quote:
                        if char == quote and (i == 0 or item[i - 1] != "\\"):
                            quote = None
                        continue
                    if char in ('"', "'"):
                        quote = char
                    elif char in "([{":
                        depth += 1
                    elif char in ")]}":
                        depth -= 1
                    elif char == "=" and depth == 0:
                        eq_pos = i
                        break
                if eq_pos > 0:
                    key = item[:eq_pos].strip()
                    result[key] = parse_java_value(item[eq_pos + 1:])
            return result
    return raw


def extract_json_value(text: str) -> Any:
    """Parse JSON or extract a JSON/Java object embedded in a log or labelled paste."""
    text = text.strip()

    # A pasted log wrapper may itself be valid JSON, but the object we need to
    # compare is the AxisPrecheckRequest inside rpk.log.message.
    try:
        parsed = json.loads(text)
        message = (parsed.get("rpk", {}).get("log", {}).get("message")
                   if isinstance(parsed, dict) else None)
        if isinstance(message, str) and "AxisPrecheckRequest(" in message:
            match = re.search(r"\bAxisPrecheckRequest\s*\(", message)
            if match:
                open_pos = message.find("(", match.start())
                end_pos = find_balanced_end(message, open_pos)
                if end_pos >= 0:
                    return parse_java_value(message[match.start():end_pos + 1])
        # If the input is a plain JSON payload, return it as-is.
        if isinstance(parsed, (dict, list)):
            return parsed
    except json.JSONDecodeError:
        pass

    # Logs may contain multiple concatenated JSON records. If an Axis request
    # object appears anywhere in the pasted text, extract that request before
    # falling back to the first JSON wrapper/record.
    axis_match = re.search(r"\bAxisPrecheckRequest\s*\(", text)
    if axis_match:
        open_pos = text.find("(", axis_match.start())
        end_pos = find_balanced_end(text, open_pos)
        if end_pos >= 0:
            return parse_java_value(text[axis_match.start():end_pos + 1])

    # Inputs such as "Payload: {...} Response: {...}" are not valid JSON as a
    # whole. Prefer the first JSON object (the request) rather than the response.
    decoder = json.JSONDecoder()
    # Find embedded JSON objects/arrays, e.g. log prefix followed by {"field": ...}.
    for i, char in enumerate(text):
        if char in "{[":
            try:
                value, _ = decoder.raw_decode(text[i:])
                if isinstance(value, (dict, list)):
                    return value
            except json.JSONDecodeError:
                continue

    # Common Java-style request/response object strings in application logs.
    known_types = (
        "AxisPrecheckRequest", "LenderPrecheckResponse", "ResponseMapStatus",
        "ResponseMap", "Address", "DedupeId",
    )
    for type_name in known_types:
        match = re.search(r"\b" + re.escape(type_name) + r"\s*\(", text)
        if match:
            open_pos = text.find("(", match.start())
            end_pos = find_balanced_end(text, open_pos)
            if end_pos >= 0:
                return parse_java_value(text[match.start():end_pos + 1])

    # Last attempt: any Java-style object string.
    match = re.search(r"\b[\w.$]+\s*\(", text)
    if match:
        open_pos = text.find("(", match.start())
        end_pos = find_balanced_end(text, open_pos)
        if end_pos >= 0:
            return parse_java_value(text[match.start():end_pos + 1])

    raise ValueError(
        "Could not parse this input. Paste valid JSON, a log containing JSON, "
        "or a Java-style object such as AxisPrecheckRequest(field=value, ...)."
    )


def flatten(value: Any, path: str = "$") -> dict[str, Any]:
    output = {}
    if isinstance(value, dict):
        if not value:
            output[path] = {}
        else:
            for key, child in value.items():
                child_path = f"{path}.{key}" if path != "$" else str(key)
                output.update(flatten(child, child_path))
    elif isinstance(value, list):
        if not value:
            output[path] = []
        else:
            for index, child in enumerate(value):
                output.update(flatten(child, f"{path}[{index}]"))
    else:
        output[path] = value
    return output


def canonical_path(path: str) -> str:
    # Keep array indices distinct while normalizing each field name.
    parts = re.split(r"(\[\d+\])", path)
    return "".join(
        part if re.fullmatch(r"\[\d+\]", part) else
        ".".join(normalize_key(segment) for segment in part.split("."))
        for part in parts
    )


def display_value(value: Any) -> str:
    if value is MISSING:
        return "<missing>"
    return json.dumps(value, ensure_ascii=False, default=str)


class _Missing:
    pass


MISSING = _Missing()


def flatten_for_compare(value: Any, path: str = "$", parent_key: str = "") -> dict[str, Any]:
    """Flatten objects; align address/dedupe arrays by semantic keys instead of list position."""
    output = {}
    if isinstance(value, dict):
        if not value:
            output[path] = {}
        else:
            for key, child in value.items():
                child_path = f"{path}.{key}" if path != "$" else str(key)
                output.update(flatten_for_compare(child, child_path, str(key)))
    elif isinstance(value, list):
        if not value:
            output[path] = []
        else:
            for index, child in enumerate(value):
                label = str(index)
                if isinstance(child, dict):
                    if "id_type" in child or "idType" in child:
                        id_type = child.get("id_type", child.get("idType", ""))
                        label = f"id_type={str(id_type).strip().upper() or 'BLANK_ENTRY'}"
                    elif "address_type" in child or "addressType" in child:
                        address_type = child.get("address_type", child.get("addressType", ""))
                        label = f"address_type={str(address_type).strip().upper() or 'UNKNOWN'}"
                output.update(flatten_for_compare(child, f"{path}[{label}]", parent_key))
    else:
        output[path] = value
    return output


def extract_lender_statuses(raw_text: str) -> dict[str, dict[str, str]]:
    """Read status signals from the Axis response JSON embedded inside a log message."""
    statuses = {}
    for name, status, message in re.findall(
        r'"(dedupe|pan|ramp|hunter|timble)"\s*:\s*\{\s*"status"\s*:\s*"(SUCCESS|FAILURE)"\s*,\s*"statusMessage"\s*:\s*"([^"]*)"',
        raw_text, flags=re.I
    ):
        statuses[name.lower()] = {"status": status.upper(), "message": message}
    # Fallback for Java-style response objects
    for name, status, message in re.findall(
        r'\b(dedupe|pan|ramp|hunter|timble)=ResponseMapStatus\(status=(SUCCESS|FAILURE),\s*statusMessage=([^)]*)\)',
        raw_text, flags=re.I
    ):
        statuses.setdefault(name.lower(), {"status": status.upper(), "message": message.strip()})
    return statuses


def compare_payloads(payload_a: Any, payload_b: Any, normalize_names: bool = True) -> list[dict[str, str]]:
    flat_a, flat_b = flatten_for_compare(payload_a), flatten_for_compare(payload_b)
    key_a = {canonical_path(k) if normalize_names else k: k for k in flat_a}
    key_b = {canonical_path(k) if normalize_names else k: k for k in flat_b}
    differences = []

    for canonical in sorted(set(key_a) | set(key_b)):
        path_a, path_b = key_a.get(canonical), key_b.get(canonical)
        value_a = flat_a[path_a] if path_a is not None else MISSING
        value_b = flat_b[path_b] if path_b is not None else MISSING
        shown_path = path_a if path_a == path_b or path_b is None else (
            path_b if path_a is None else f"{path_a} ↔ {path_b}"
        )

        if path_a is None:
            kind, label = "Missing field", "Missing in Payload A"
        elif path_b is None:
            kind, label = "Missing field", "Missing in Payload B"
        elif type(value_a) is not type(value_b):
            kind, label = "Type mismatch", "Different data types"
        elif value_a != value_b:
            kind, label = "Value mismatch", "Different values"
        else:
            continue

        differences.append({
            "Category": kind,
            "Finding": label,
            "Field path": shown_path,
            "Payload A": display_value(value_a),
            "Payload B": display_value(value_b),
            "_sensitive": bool(SENSITIVE_KEYS.search(shown_path)),
        })
    return differences


def field_review_summary(differences: list[dict[str, str]]) -> list[dict[str, str]]:
    """Turn raw differences into a practical checklist for reviewing Payload A."""
    summary = []
    seen = set()
    for row in differences:
        path = row["Field path"]
        path_norm = normalize_key(path)
        # Classify common lender precheck fields so the user can quickly focus RCA.
        if re.search(r"(^|[._])(?:first_name|middle_name|last_name|name_as_per_pan|name)(?:[._\[]|$)", path_norm):
            group = "Name"
            action = "Check spelling, order, and consistency with the source document. If Payload B is the correct expected value, update the corresponding name field in Payload A."
        elif re.search(r"address|(^|[._])(?:city|state|pincode|pin_code|postal_code)(?:[._\[]|$)", path_norm):
            group = "Address / location"
            action = "Verify address type, full address, city, state, and pincode separately. Correct Payload A only after confirming the customer’s verified address; formatting differences alone may be harmless."
        elif re.search(r"mobile|phone|contact_number", path_norm):
            group = "Phone number"
            action = "Verify the phone number against the customer record and check country-code/format requirements. Do not change it just to make the payloads match unless Payload B is verified as correct."
        elif re.search(r"gender", path_norm):
            group = "Gender format"
            action = "Check the lender’s accepted values (for example, M/F versus male/female) and use the documented enum format in Payload A."
        elif re.search(r"customer_id|client_loan_id|agreement_id|application_id|applicant_id", path_norm):
            group = "Customer / loan identifier"
            action = "Confirm the ID mapping with the source system and lender contract. Different IDs or formats can be intentional; do not replace them without verification."
        elif re.search(r"dedupe|aadhar|aadhaar|pan", path_norm):
            group = "Identity / dedupe"
            action = "Check identifier type, masking/format, and whether blank or omitted dedupe entries are allowed by the lender schema."
        else:
            group = "Other field"
            action = "Check the field against the lender API schema and the actual error response before changing Payload A."

        key = (group, path)
        if key in seen:
            continue
        seen.add(key)
        # Avoid exposing full values for sensitive fields in the summary.
        if row.get("_sensitive"):
            value_a = "[REDACTED]"
            value_b = "[REDACTED]"
        else:
            value_a = row["Payload A"]
            value_b = row["Payload B"]
        summary.append({
            "Priority area": group,
            "Field to review": path,
            "Payload A (current)": value_a,
            "Payload B (comparison)": value_b,
            "Suggested action": action,
        })
    return summary


def report_csv(differences: list[dict[str, str]]) -> str:
    stream = io.StringIO()
    fields = ["Category", "Finding", "Field path", "Payload A", "Payload B"]
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()
    for row in differences:
        safe_row = {field: row[field] for field in fields}
        if row["_sensitive"]:
            safe_row["Payload A"] = "[REDACTED]"
            safe_row["Payload B"] = "[REDACTED]"
        writer.writerow(safe_row)
    return stream.getvalue()


st.caption("RCA workspace · Field-level comparison · Sensitive values are redacted in the summary and CSV export.")
with st.expander("How to use", expanded=False):
    st.markdown(
        "1. Paste the first request or log into **Payload A**.\\n"
        "2. Paste the second payload into **Payload B**.\\n"
        "3. Click **Compare payloads**.\\n"
        "4. Filter results or download a CSV report.\\n\\n"
        "Accepts JSON and common Java-style log strings such as `AxisPrecheckRequest(...)`. For RCA, include the Axis response/log text in Payload B so reported SUCCESS/FAILURE statuses can be detected."
    )

with st.sidebar:
    st.header("Comparison settings")
    normalize_names = st.checkbox(
        "Match camelCase and snake_case", value=True,
        help="For example, customerId and customer_id will be treated as the same field."
    )
    st.info("The app compares payload content locally. It does not send pasted data to an external API.")

col_a, col_b = st.columns(2)
with col_a:
    st.subheader("Payload A")
    st.caption("Original precheck request (Payload A)")
    input_a = st.text_area("Payload A input", height=330, key="payload_a",
                           placeholder='Paste JSON or AxisClient log here…', label_visibility="collapsed")
with col_b:
    st.subheader("Payload B")
    st.caption("Lender-side Axis precheck request extracted from the log (Payload B)")
    input_b = st.text_area("Payload B input", height=330, key="payload_b",
                           placeholder="Paste the second payload here…", label_visibility="collapsed")

compare_clicked = st.button("Compare payloads", type="primary", use_container_width=False)

if compare_clicked:
    try:
        if not input_a.strip() or not input_b.strip():
            raise ValueError("Please paste both Payload A and Payload B.")
        parsed_a = extract_json_value(input_a)
        parsed_b = extract_json_value(input_b)
        st.session_state["payload_diff_rows"] = compare_payloads(parsed_a, parsed_b, normalize_names)
        st.session_state["payload_diff_error"] = None
    except Exception as exc:
        st.session_state["payload_diff_error"] = str(exc)
        st.session_state.pop("payload_diff_rows", None)

if st.session_state.get("payload_diff_error"):
    st.error(st.session_state["payload_diff_error"])

if "payload_diff_rows" in st.session_state:
    differences = st.session_state["payload_diff_rows"]
    missing_count = sum(r["Category"] == "Missing field" for r in differences)
    value_count = sum(r["Category"] == "Value mismatch" for r in differences)
    type_count = sum(r["Category"] == "Type mismatch" for r in differences)

    st.divider()
    st.subheader("Precheck result from Payload B")
    statuses = extract_lender_statuses(st.session_state.get("payload_b", ""))
    if statuses:
        pills = []
        for name in ["dedupe", "pan", "ramp", "hunter", "timble"]:
            if name in statuses:
                item = statuses[name]
                css = "status-fail" if item["status"] == "FAILURE" else "status-pass"
                label = f"{name.upper()}: {item['status']}"
                pills.append(f'<span class="status-pill {css}">{label}</span>')
        st.markdown(" ".join(pills), unsafe_allow_html=True)
        failed = [name.upper() for name, item in statuses.items() if item["status"] == "FAILURE"]
        passed = [name.upper() for name, item in statuses.items() if item["status"] == "SUCCESS"]
        if failed:
            st.error("Reported failures: " + ", ".join(failed) + ". These are confirmed response statuses; the field differences below are investigation leads, not proof of causation.")
        if passed:
            st.success("Reported successes: " + ", ".join(passed))
    else:
        st.info("No structured lender status was detected in Payload B. Paste the full response/log if you want status extraction.")

    st.subheader("Field comparison report")
    metric_cols = st.columns(4)
    metric_cols[0].metric("Total differences", len(differences))
    metric_cols[1].metric("Missing fields", missing_count)
    metric_cols[2].metric("Value mismatches", value_count)
    metric_cols[3].metric("Type mismatches", type_count)

    st.subheader("RCA checklist · What to verify in Payload A")
    if differences:
        st.markdown('<div class="section-note"><b>How to read this:</b> mismatches are highlighted for investigation. Do not change customer data solely to make payloads identical; confirm the verified source record and Axis API contract first.</div>', unsafe_allow_html=True)
        st.dataframe(field_review_summary(differences), use_container_width=True, hide_index=True)
    else:
        st.success("No differences found, so there are no fields to review in Payload A.")

    if not differences:
        st.success("No differences found. The parsed payloads match.")
    else:
        filter_cols = st.columns([1, 2])
        category_filter = filter_cols[0].selectbox(
            "Filter category", ["All", "Missing field", "Value mismatch", "Type mismatch"]
        )
        search = filter_cols[1].text_input("Search field or value")
        visible = differences
        if category_filter != "All":
            visible = [r for r in visible if r["Category"] == category_filter]
        if search:
            needle = search.casefold()
            visible = [
                r for r in visible
                if needle in " ".join(str(r[k]) for k in
                                      ["Category", "Finding", "Field path", "Payload A", "Payload B"]).casefold()
            ]

        safe_display = []
        for row in visible:
            safe_display.append({k: row[k] for k in
                                 ["Category", "Finding", "Field path", "Payload A", "Payload B"]})
        st.dataframe(safe_display, use_container_width=True, hide_index=True)
        st.download_button(
            "Download CSV report (sensitive values redacted)",
            data=report_csv(differences),
            file_name="payload_comparison_report.csv",
            mime="text/csv",
        )

st.caption(
    "Note: a difference does not by itself prove the root cause of an API failure. "
    "Confirm against the lender schema, validation rules, and matching trace/request ID. "
    "Exported CSV redacts values for fields with names suggesting personal or secret data."
)
