
import argparse
import json
import re
import sys
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET


# ------------------------------
# Utility / XML helpers
# ------------------------------

LINE_RE = re.compile(r'^\[(?P<ts>[\d\-:\. ]+)\];(?P<dir>SEND|RECV);(?P<size>\d+)bytes\s*$', re.MULTILINE)
NOKIA_LINE_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+\w+:\s+\[[^\]]+\]\s+Session\s+(?P<session>\d+):\s+(?P<dir>Sending|Received)\s+message:\s*(?P<tail>.*)$',
    re.MULTILINE
)
NOKIA_INLINE_HEADER_RE = re.compile(
    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\s+\w+:\s+\[[^\]]+\]\s+Session\s+\d+:\s+(?:Sending|Received)\s+message:\s*'
)


def parse_log_timestamp(ts: str) -> Optional[str]:
    """Return ISO-like string; keep original if parsing fails."""
    ts = (ts or "").strip()
    if not ts:
        return None
    # Nokia style: 2024-07-05T17:16:40.272Z
    if ts.endswith("Z") and "T" in ts:
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).isoformat()
        except Exception:
            pass
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt).isoformat()
        except Exception:
            continue
    return ts or None


def clean_xml_fragment(xml_string: str) -> str:
    """Remove namespaces/prefixes to simplify ET parsing (including prefixed attrs like nc:operation)."""
    # Drop XML declaration if present inside fragments
    xml_string = re.sub(r'<\?xml[^>]*\?>', '', xml_string, flags=re.IGNORECASE)
    # Remove namespace declarations
    xml_string = re.sub(r'\s+xmlns(:[^=\s]+)?="[^"]*"', '', xml_string)
    # Remove prefixes from element tags: <nc:foo> -> <foo>
    xml_string = re.sub(r'(</?)[a-zA-Z0-9_\-]+:([a-zA-Z0-9_\-]+)', r'\1\2', xml_string)
    # Remove prefixed attributes that become unbound after xmlns stripping, e.g. nc:operation="create"
    xml_string = re.sub(r'\s+[A-Za-z_][\w\-\.]*:[A-Za-z_][\w\-\.]*\s*=\s*"[^"]*"', '', xml_string)
    return xml_string.strip()


def xml_to_dict(element: ET.Element) -> Any:
    """Recursive XML -> dict/list/scalar preserving repeated tags as list."""
    data: Dict[str, Any] = {}
    text = (element.text or "").strip()
    if text:
        data["text"] = text

    for child in list(element):
        tag = child.tag.split('}')[-1]
        val = xml_to_dict(child)
        if isinstance(val, dict) and list(val.keys()) == ["text"]:
            val = val["text"]

        if tag in data:
            if not isinstance(data[tag], list):
                data[tag] = [data[tag]]
            data[tag].append(val)
        else:
            data[tag] = val

    return data if data else text


def as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def deep_merge_dict(dst: Dict[str, Any], src: Dict[str, Any]) -> Dict[str, Any]:
    """Recursive merge for partial edit-config updates."""
    out = deepcopy(dst)
    for k, v in src.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = deep_merge_dict(out[k], v)
        else:
            out[k] = deepcopy(v)
    return out


def short_fragment(s: str, n: int = 160) -> str:
    s = re.sub(r'\s+', ' ', s.strip())
    return s[:n] + ("..." if len(s) > n else "")


# ------------------------------
# Data models
# ------------------------------

@dataclass
class WarningItem:
    phase: str
    tag: Optional[str]
    message: str
    fragment: Optional[str] = None
    message_id: Optional[str] = None
    ts: Optional[str] = None

@dataclass
class ObjectVersion:
    ts: Optional[str]
    direction: Optional[str]
    message_id: Optional[str]
    rpc_type: Optional[str]
    source: str  # "user-plane-configuration" / "processing-elements" / ...
    raw: Dict[str, Any]

@dataclass
class StateStore:
    carriers_tx: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    carriers_rx: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    endpoints_tx: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    endpoints_rx: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    links_tx: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    links_rx: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    prach_configs: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    processing_elements: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    history: Dict[str, List[ObjectVersion]] = field(default_factory=lambda: {})
    warnings: List[WarningItem] = field(default_factory=list)
    validations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ------------------------------
# NETCONF log extraction
# ------------------------------

def _normalize_nokia_payload_line(line: str) -> Optional[str]:
    """
    Remove Nokia NETCONF trace prefixes from payload continuation lines.
    Returns payload text or None for empty/non-payload-only lines.
    """
    s = line.rstrip("\n")
    if not s.strip():
        return None
    m = NOKIA_LINE_RE.match(s.strip())
    if m:
        tail = (m.group("tail") or "")
        tail = NOKIA_INLINE_HEADER_RE.sub("", tail)
        return tail if tail != "" else None
    # continuation lines often start with timestamp + 'Dbg:' but no Session header
    s2 = re.sub(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\s+\w+:\s*', '', s.strip())
    s2 = NOKIA_INLINE_HEADER_RE.sub("", s2)
    return s2


def _strip_nokia_inline_headers(text: str) -> str:
    """Remove Nokia NETCONF headers accidentally embedded inside XML fragments."""
    return NOKIA_INLINE_HEADER_RE.sub("", text or "")


def _looks_like_fresh_xml_message(text: str) -> bool:
    s = (text or "").lstrip()
    return s.startswith(("<rpc", "<notification", "<hello", "<rpc-reply"))


def _xml_fragment_incomplete(text: str) -> bool:
    s = (text or "").strip()
    if not s:
        return False
    if s.endswith(("=", "=\"", "'", "\"", "<")):
        return True
    if re.search(r'<[^>]*$', s):
        return True
    stack: List[str] = []
    for m in re.finditer(r'<(/?)([A-Za-z_][\w:\-\.]*)([^>]*)>', s):
        is_end = m.group(1) == "/"
        tag = m.group(2)
        suffix = m.group(3) or ""
        self_closing = suffix.strip().endswith("/")
        if not is_end and not self_closing:
            stack.append(tag)
        elif is_end:
            if stack and stack[-1] == tag:
                stack.pop()
            else:
                return True
    if stack:
        return True
    return False


def _is_same_rpc_continuation(current: Optional[Dict[str, Any]], tail: str) -> bool:
    """
    Decide whether a repeated Nokia Session header is a continuation of the same XML
    message rather than the start of a brand-new NETCONF message.
    """
    if current is None:
        return False
    payload_lines = current.get("_payload_lines", []) or []
    recent_window = payload_lines[-12:]
    current_text = _reconstruct_xmlish_text("\n".join(recent_window)).strip()
    if not current_text:
        return not _looks_like_fresh_xml_message(tail)
    if _xml_fragment_incomplete(current_text):
        return True
    if tail and not _looks_like_fresh_xml_message(tail):
        return True
    return False


def _reconstruct_xmlish_text(text: str) -> str:
    """
    Best-effort repair for Nokia traces where XML tokens are split across log headers,
    e.g. '<config' on one line and '>' on the next line.
    """
    text = _strip_nokia_inline_headers(text)
    if not text:
        return text
    lines = [ln for ln in text.splitlines() if ln is not None]
    out: List[str] = []
    for ln in lines:
        cur = _strip_nokia_inline_headers(ln).strip()
        if cur == "":
            continue
        if out:
            prev = out[-1]
            # join dangling tag opener
            if (prev.lstrip().startswith("<") and not prev.rstrip().endswith(">")) and cur in (">", "/>"):
                out[-1] = prev + cur
                continue
            # join split close/open angle fragments (rare)
            if prev.endswith("<") and cur.startswith("/"):
                out[-1] = prev + cur
                continue
            # join scalar text split from its closing tag after inline header removal
            if cur.startswith("</") and not prev.rstrip().endswith(">"):
                out[-1] = prev + cur
                continue
        out.append(cur)
    return "\n".join(out)


def extract_log_segments(content: str) -> List[Dict[str, Any]]:
    """
    Split log into segments. Supports:
      1) legacy [timestamp];SEND/RECV;Nbytes
      2) Nokia NETCONF trace '... Session N: Sending/Received message:'
    """
    # Format 1: semicolon header
    matches = list(LINE_RE.finditer(content))
    if matches:
        segments: List[Dict[str, Any]] = []
        for i, m in enumerate(matches):
            start = m.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
            body = content[start:end].strip()
            seg = {
                "raw_ts": m.group("ts"),
                "ts": parse_log_timestamp(m.group("ts")),
                "direction": m.group("dir"),
                "size_bytes": int(m.group("size")),
                "body": body,
                "log_format": "semicolon",
            }
            segments.append(seg)
        return segments

    # Format 2: Nokia Session trace
    n_matches = list(NOKIA_LINE_RE.finditer(content))
    if not n_matches:
        return []

    lines = content.splitlines()
    segments = []
    current = None

    for raw_line in lines:
        m = NOKIA_LINE_RE.match(raw_line.strip())
        if m:
            tail = m.group("tail") or ""
            new_direction = "SEND" if m.group("dir") == "Sending" else "RECV"
            new_raw_ts = m.group("ts")
            new_session = m.group("session")

            # Nokia traces may split one XML message over multiple repeated
            # "Sending message:" / "Received message:" headers (same ts+session+dir).
            # Merge those fragments instead of starting a new segment.
            if (
                current is not None
                and current.get("log_format") == "nokia_dbg_session"
                and current.get("session_id") == new_session
                and current.get("direction") == new_direction
                and (
                    current.get("raw_ts") == new_raw_ts
                    or _is_same_rpc_continuation(current, tail)
                )
            ):
                if tail:
                    current.setdefault("_payload_lines", []).append(tail)
                continue

            if current is not None:
                current["body"] = _reconstruct_xmlish_text("\n".join(current.get("_payload_lines", []))).strip()
                current.pop("_payload_lines", None)
                segments.append(current)

            current = {
                "raw_ts": new_raw_ts,
                "ts": parse_log_timestamp(new_raw_ts),
                "direction": new_direction,
                "size_bytes": None,
                "session_id": new_session,
                "_payload_lines": [tail] if tail else [],
                "log_format": "nokia_dbg_session",
            }
            continue

        if current is None:
            continue
        payload = _normalize_nokia_payload_line(raw_line)
        if payload is not None:
            current["_payload_lines"].append(payload)

    if current is not None:
        current["body"] = _reconstruct_xmlish_text("\n".join(current.get("_payload_lines", []))).strip()
        current.pop("_payload_lines", None)
        segments.append(current)

    return segments


def extract_rpc_context(body: str) -> Dict[str, Optional[str]]:
    """
    Best-effort extraction of message-id and rpc type (edit-config/get/get-config/notification/rpc-reply).
    """
    msg_id = None
    m = re.search(r'<(?:[\w\-]+:)?(?:rpc|rpc-reply)\b[^>]*\bmessage-id="([^"]+)"', body, re.IGNORECASE)
    if m:
        msg_id = m.group(1)

    rpc_type = None
    if re.search(r'<(?:[\w\-]+:)?notification\b', body):
        rpc_type = "notification"
    elif re.search(r'<(?:[\w\-]+:)?edit-config\b', body):
        rpc_type = "edit-config"
    elif re.search(r'<(?:[\w\-]+:)?get-config\b', body):
        rpc_type = "get-config"
    elif re.search(r'<(?:[\w\-]+:)?get\b', body):
        rpc_type = "get"
    elif re.search(r'<(?:[\w\-]+:)?rpc-reply\b', body):
        rpc_type = "rpc-reply"
    return {"message_id": msg_id, "rpc_type": rpc_type}


def find_xml_blocks(tag: str, text: str) -> List[str]:
    """
    Namespace-prefix tolerant extraction of a specific XML element block.
    """
    pattern = rf"<(?:[\w\-]+:)?{re.escape(tag)}(?:\s[^>]*>|>).*?</(?:[\w\-]+:)?{re.escape(tag)}>"
    return re.findall(pattern, text, flags=re.DOTALL | re.IGNORECASE)


def parse_xml_block(xml_str: str, phase: str, tag: str, state: StateStore, ctx: Dict[str, Any]) -> Optional[ET.Element]:
    try:
        cleaned = clean_xml_fragment(xml_str)
        return ET.fromstring(cleaned)
    except Exception as e:
        state.warnings.append(WarningItem(
            phase=phase, tag=tag, message=f"{type(e).__name__}: {e}",
            fragment=short_fragment(xml_str), message_id=ctx.get("message_id"), ts=ctx.get("ts")
        ))
        return None


# ------------------------------
# Normalization helpers
# ------------------------------

KEY_FIELDS_COMMON = {"name", "active", "type", "gain", "endpoint-type", "array"}

def add_meta(d: Dict[str, Any], ctx: Dict[str, Any], source: str) -> Dict[str, Any]:
    dd = deepcopy(d)
    dd.setdefault("_meta", {})
    dd["_meta"].update({
        "last_ts": ctx.get("ts"),
        "direction": ctx.get("direction"),
        "message_id": ctx.get("message_id"),
        "rpc_type": ctx.get("rpc_type"),
        "source": source,
    })
    return dd


def record_history(state: StateStore, category: str, name: str, data: Dict[str, Any], ctx: Dict[str, Any], source: str):
    key = f"{category}:{name}"
    state.history.setdefault(key, []).append(ObjectVersion(
        ts=ctx.get("ts"),
        direction=ctx.get("direction"),
        message_id=ctx.get("message_id"),
        rpc_type=ctx.get("rpc_type"),
        source=source,
        raw=deepcopy(data),
    ))


def upsert_named(target: Dict[str, Dict[str, Any]], category: str, item: Dict[str, Any], state: StateStore, ctx: Dict[str, Any], source: str):
    name = item.get("name")
    if not name:
        state.warnings.append(WarningItem(
            phase="upsert", tag=category, message="Missing name field", fragment=short_fragment(json.dumps(item, ensure_ascii=False)),
            message_id=ctx.get("message_id"), ts=ctx.get("ts")
        ))
        return
    existing = target.get(name, {})
    merged = deep_merge_dict(existing, item)
    merged = add_meta(merged, ctx, source)
    target[name] = merged
    record_history(state, category, name, merged, ctx, source)


def normalize_leaflist(value: Any) -> Any:
    # optional pretty normalization for leaf-lists with dict wrappers
    if isinstance(value, list):
        return [normalize_leaflist(v) for v in value]
    if isinstance(value, dict):
        return {k: normalize_leaflist(v) for k, v in value.items()}
    return value


# ------------------------------
# Parsing specific modules
# ------------------------------

def parse_user_plane_configuration(block: str, state: StateStore, ctx: Dict[str, Any]):
    root = parse_xml_block(block, "parse_upc", "user-plane-configuration", state, ctx)
    if root is None:
        return

    # carriers
    for tag, store_name, cat in [
        ("tx-array-carriers", state.carriers_tx, "carrier_tx"),
        ("rx-array-carriers", state.carriers_rx, "carrier_rx"),
    ]:
        for node in root.findall(tag):
            d = normalize_leaflist(xml_to_dict(node))
            if isinstance(d, dict):
                upsert_named(store_name, cat, d, state, ctx, "user-plane-configuration")

    # endpoints (support both static/non-static)
    endpoint_tags = [
        ("low-level-tx-endpoints", state.endpoints_tx, "endpoint_tx"),
        ("low-level-rx-endpoints", state.endpoints_rx, "endpoint_rx"),
        ("static-low-level-tx-endpoints", state.endpoints_tx, "endpoint_tx"),
        ("static-low-level-rx-endpoints", state.endpoints_rx, "endpoint_rx"),
    ]
    for tag, store, cat in endpoint_tags:
        for node in root.findall(tag):
            d = normalize_leaflist(xml_to_dict(node))
            if isinstance(d, dict):
                d["_endpoint_tag"] = tag
                upsert_named(store, cat, d, state, ctx, "user-plane-configuration")

    # links
    for tag, store, ltype, cat in [
        ("low-level-tx-links", state.links_tx, "TX", "link_tx"),
        ("low-level-rx-links", state.links_rx, "RX", "link_rx"),
    ]:
        for node in root.findall(tag):
            d = normalize_leaflist(xml_to_dict(node))
            if isinstance(d, dict):
                d["_type"] = ltype
                upsert_named(store, cat, d, state, ctx, "user-plane-configuration")

    # PRACH configs
    for node in root.findall("static-prach-configurations"):
        d = normalize_leaflist(xml_to_dict(node))
        if not isinstance(d, dict):
            continue
        key = str(d.get("static-prach-config-id", ""))
        if not key:
            state.warnings.append(WarningItem(
                phase="parse_upc", tag="static-prach-configurations",
                message="Missing static-prach-config-id",
                fragment=short_fragment(json.dumps(d, ensure_ascii=False)),
                message_id=ctx.get("message_id"), ts=ctx.get("ts")
            ))
            continue
        existing = state.prach_configs.get(key, {})
        merged = deep_merge_dict(existing, d)
        merged = add_meta(merged, ctx, "user-plane-configuration")
        state.prach_configs[key] = merged
        record_history(state, "prach", key, merged, ctx, "user-plane-configuration")


def parse_processing_elements(block: str, state: StateStore, ctx: Dict[str, Any]):
    root = parse_xml_block(block, "parse_pe", "processing-elements", state, ctx)
    if root is None:
        return

    # Common structure: <ru-elements><name>...</name><transport-flow>...</transport-flow></ru-elements>
    ru_elements = root.findall("ru-elements")
    for node in ru_elements:
        d = normalize_leaflist(xml_to_dict(node))
        if isinstance(d, dict):
            upsert_named(state.processing_elements, "processing_element", d, state, ctx, "processing-elements")


def parse_notifications(body: str, state: StateStore, ctx: Dict[str, Any]):
    # Optional lightweight extraction for user-plane related notifications
    # Keep generic; store only warning-like notes instead of complex state machine.
    if "<notification" not in body:
        return
    if "rx-array-carriers-state-change" in body or "tx-array-carriers-state-change" in body:
        state.warnings.append(WarningItem(
            phase="notification", tag="user-plane-state-change",
            message="User-plane state-change notification observed (not fully merged into config state)",
            fragment=short_fragment(body), message_id=ctx.get("message_id"), ts=ctx.get("ts")
        ))


def parse_mplane_log(file_path: str) -> StateStore:
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    state = StateStore()
    state.metadata["input_file"] = file_path
    state.metadata["file_size_bytes"] = len(content.encode("utf-8", errors="ignore"))

    segments = extract_log_segments(content)
    state.metadata["segment_count"] = len(segments)
    state.metadata["detected_log_format"] = segments[0].get("log_format") if segments else "unknown"

    # Parse per-segment (preferred path)
    for seg in segments:
        ctx = {**seg, **extract_rpc_context(seg.get("body", ""))}

        up_blocks = find_xml_blocks("user-plane-configuration", seg.get("body", ""))
        for blk in up_blocks:
            parse_user_plane_configuration(blk, state, ctx)

        pe_blocks = find_xml_blocks("processing-elements", seg.get("body", ""))
        for blk in pe_blocks:
            parse_processing_elements(blk, state, ctx)

        parse_notifications(seg.get("body", ""), state, ctx)

    # Fallback: raw-file XML scan if segment parsing failed or extracted nothing meaningful
    total_objects = (
        len(state.carriers_tx) + len(state.carriers_rx) +
        len(state.endpoints_tx) + len(state.endpoints_rx) +
        len(state.links_tx) + len(state.links_rx) +
        len(state.prach_configs) + len(state.processing_elements)
    )

    raw_up_count = len(find_xml_blocks("user-plane-configuration", content))
    raw_pe_count = len(find_xml_blocks("processing-elements", content))
    state.metadata["raw_user_plane_block_count"] = raw_up_count
    state.metadata["raw_processing_elements_block_count"] = raw_pe_count

    if (len(segments) == 0 and (raw_up_count or raw_pe_count)) or (total_objects == 0 and (raw_up_count or raw_pe_count)):
        state.warnings.append(WarningItem(
            phase="parser", tag="segment-extraction",
            message="No/insufficient objects parsed from segments while XML blocks exist in raw file. Applying raw-file fallback scan (likely unsupported log header format or split XML).",
            fragment=None, message_id=None, ts=None
        ))

        fallback_ctx = {
            "raw_ts": None, "ts": None, "direction": None, "size_bytes": None,
            "message_id": None, "rpc_type": "raw-fallback", "log_format": "raw_fallback"
        }
        for blk in find_xml_blocks("user-plane-configuration", content):
            parse_user_plane_configuration(blk, state, fallback_ctx)
        for blk in find_xml_blocks("processing-elements", content):
            parse_processing_elements(blk, state, fallback_ctx)

        if re.search(r'<config\s*$[\s\S]{0,120}^\d{4}-\d{2}-\d{2}T.*?>', content, flags=re.MULTILINE):
            state.warnings.append(WarningItem(
                phase="parser", tag="xml-reconstruction",
                message="Detected likely split XML tokens across Nokia log headers (e.g., '<config' and '>' on separate lines). Fallback parsing may miss context metadata but should recover objects.",
                fragment=None, message_id=None, ts=None
            ))

    validate_state(state)
    return state


# ------------------------------
# Validation
# ------------------------------

def _ep_ref_keys(link_type: str) -> Tuple[str, str]:
    if link_type == "TX":
        return "low-level-tx-endpoint", "tx-array-carrier"
    return "low-level-rx-endpoint", "rx-array-carrier"


def validate_state(state: StateStore):
    vals: List[str] = []

    # Parser quality checks
    seg_cnt = int(state.metadata.get("segment_count", 0) or 0)
    raw_up = int(state.metadata.get("raw_user_plane_block_count", 0) or 0)
    fmt = state.metadata.get("detected_log_format", "unknown")
    if seg_cnt == 0 and raw_up > 0:
        vals.append("[ERROR] No NETCONF segments parsed, but raw file contains user-plane-configuration XML. Unsupported log header format likely.")
    if fmt == "nokia_dbg_session":
        vals.append("[INFO] Detected Nokia NETCONF trace format; Nokia segment parser enabled.")

    # Link reference checks
    seen_eaxc: Dict[Tuple[str, str, str, str], List[str]] = {}  # scope -> endpoint names

    for link_name, link in sorted({**state.links_tx, **state.links_rx}.items()):
        ltype = link.get("_type") or ("TX" if link_name in state.links_tx else "RX")
        ep_key, car_key = _ep_ref_keys(ltype)
        ep_name = link.get(ep_key)
        car_name = link.get(car_key)

        ep_store = state.endpoints_tx if ltype == "TX" else state.endpoints_rx
        car_store = state.carriers_tx if ltype == "TX" else state.carriers_rx

        if not ep_name:
            vals.append(f"[ERROR] Link '{link_name}' ({ltype}) missing endpoint reference key '{ep_key}'.")
        elif ep_name not in ep_store:
            vals.append(f"[ERROR] Link '{link_name}' ({ltype}) references missing endpoint '{ep_name}'.")
        if not car_name:
            vals.append(f"[ERROR] Link '{link_name}' ({ltype}) missing carrier reference key '{car_key}'.")
        elif car_name not in car_store:
            vals.append(f"[ERROR] Link '{link_name}' ({ltype}) references missing carrier '{car_name}'.")

        if ep_name and ep_name in ep_store:
            ep = ep_store[ep_name]
            # PRACH validations for RX
            if ltype == "RX":
                scs = ep.get("static-config-supported")
                spc = ep.get("static-prach-configuration")
                if str(scs).upper() == "PRACH" and spc in (None, "", []):
                    vals.append(f"[WARN] RX endpoint '{ep_name}' static-config-supported=PRACH but no static-prach-configuration.")
                if spc not in (None, "", []) and str(spc) not in state.prach_configs:
                    vals.append(f"[WARN] RX endpoint '{ep_name}' references missing static PRACH config '{spc}'.")

            # Compression checks
            comp = ep.get("compression")
            if comp and isinstance(comp, dict):
                if comp.get("fs-offset") is not None and not comp.get("compression-method"):
                    vals.append(f"[WARN] Endpoint '{ep_name}' has fs-offset but missing compression-method.")
            elif "compression" not in ep:
                vals.append(f"[WARN] Endpoint '{ep_name}' missing compression block.")

            # eAxC duplication checks
            eaxc = ep.get("e-axcid")
            if isinstance(eaxc, dict):
                scope = (
                    str(eaxc.get("o-du-port-bitmask", "")),
                    str(eaxc.get("band-sector-bitmask", "")),
                    str(eaxc.get("ccid-bitmask", "")),
                    str(eaxc.get("ru-port-bitmask", "")),
                )
                eid = str(eaxc.get("eaxc-id", ""))
                if any(scope) and eid:
                    seen_eaxc.setdefault(scope + (eid,), []).append(ep_name)

    for key, eps in seen_eaxc.items():
        if len(eps) > 1:
            vals.append(f"[WARN] Duplicate eAxC scope+eaxc-id {key}: endpoints={', '.join(sorted(eps))}")

    # Orphan objects
    referenced_eps = set()
    referenced_cars_tx = set()
    referenced_cars_rx = set()
    for l in state.links_tx.values():
        if l.get("low-level-tx-endpoint"): referenced_eps.add(l["low-level-tx-endpoint"])
        if l.get("tx-array-carrier"): referenced_cars_tx.add(l["tx-array-carrier"])
    for l in state.links_rx.values():
        if l.get("low-level-rx-endpoint"): referenced_eps.add(l["low-level-rx-endpoint"])
        if l.get("rx-array-carrier"): referenced_cars_rx.add(l["rx-array-carrier"])

    for ep in sorted(set(state.endpoints_tx.keys()) | set(state.endpoints_rx.keys())):
        if ep not in referenced_eps:
            vals.append(f"[INFO] Endpoint '{ep}' is not referenced by any low-level link.")
    for c in sorted(state.carriers_tx.keys()):
        if c not in referenced_cars_tx:
            vals.append(f"[INFO] TX carrier '{c}' is not referenced by any TX link.")
    for c in sorted(state.carriers_rx.keys()):
        if c not in referenced_cars_rx:
            vals.append(f"[INFO] RX carrier '{c}' is not referenced by any RX link.")

    state.validations = vals


# ------------------------------
# Report formatting
# ------------------------------

def fmt(v: Any) -> str:
    if v is None or v == "":
        return "-"
    if isinstance(v, list):
        return ", ".join(fmt(x) for x in v)
    if isinstance(v, dict):
        return json.dumps(v, ensure_ascii=False)
    return str(v)

def extract_endpoint_summary(ep: Dict[str, Any]) -> Dict[str, Any]:
    comp = ep.get("compression", {}) if isinstance(ep.get("compression"), dict) else {}
    eaxc = ep.get("e-axcid", {}) if isinstance(ep.get("e-axcid"), dict) else {}
    nprb = ep.get("number-of-prb-per-scs", {})
    if isinstance(nprb, list):
        nprb_s = "; ".join(
            f"{x.get('scs','?')}:{x.get('number-of-prb','?')}" if isinstance(x, dict) else str(x)
            for x in nprb
        )
    elif isinstance(nprb, dict):
        nprb_s = f"{nprb.get('scs','?')}:{nprb.get('number-of-prb','?')}"
    else:
        nprb_s = fmt(nprb)

    return {
        "endpoint-type": ep.get("endpoint-type"),
        "array": ep.get("array"),
        "frame-structure": ep.get("frame-structure"),
        "cp-type": ep.get("cp-type"),
        "cp-length": ep.get("cp-length"),
        "cp-length-other": ep.get("cp-length-other"),
        "offset-to-absolute-frequency-center": ep.get("offset-to-absolute-frequency-center"),
        "number-of-prb-per-scs": nprb_s,
        "non-time-managed-delay-enabled": ep.get("non-time-managed-delay-enabled"),
        "compression.iq-bitwidth": comp.get("iq-bitwidth"),
        "compression.type": comp.get("compression-type"),
        "compression.method": comp.get("compression-method"),
        "compression.exponent": comp.get("exponent"),
        "compression.fs-offset": comp.get("fs-offset"),
        "eaxc.o-du-port-bitmask": eaxc.get("o-du-port-bitmask"),
        "eaxc.band-sector-bitmask": eaxc.get("band-sector-bitmask"),
        "eaxc.ccid-bitmask": eaxc.get("ccid-bitmask"),
        "eaxc.ru-port-bitmask": eaxc.get("ru-port-bitmask"),
        "eaxc.eaxc-id": eaxc.get("eaxc-id"),
        "eaxc-gain-correction": ep.get("eaxc-gain-correction"),
        "static-config-supported": ep.get("static-config-supported"),
        "static-prach-configuration": ep.get("static-prach-configuration"),
        "prach-group": ep.get("prach-group"),
        "_meta": ep.get("_meta", {}),
    }

def extract_carrier_summary(car: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "active": car.get("active"),
        "type": car.get("type"),
        "center-of-channel-bandwidth": car.get("center-of-channel-bandwidth"),
        "channel-bandwidth": car.get("channel-bandwidth"),
        "gain": car.get("gain"),
        "reference-level": car.get("reference-level"),
        "downlink-radio-frame-offset": car.get("downlink-radio-frame-offset"),
        "downlink-sfn-offset": car.get("downlink-sfn-offset"),
        "uplink-radio-frame-offset": car.get("uplink-radio-frame-offset"),
        "uplink-sfn-offset": car.get("uplink-sfn-offset"),
        "_meta": car.get("_meta", {}),
    }

def prach_lookup_for_endpoint(ep: Dict[str, Any], prach_configs: Dict[str, Dict[str, Any]]) -> Optional[Tuple[str, Dict[str, Any]]]:
    # Priority: static-prach-configuration -> prach-group
    for keyname in ("static-prach-configuration", "prach-group"):
        key = ep.get(keyname)
        if key not in (None, "", []):
            k = str(key)
            if k in prach_configs:
                return k, prach_configs[k]
            return k, {}
    return None

def build_chain_records(state: StateStore) -> List[Dict[str, Any]]:
    recs = []
    for ltype, links, eps, cars in [
        ("TX", state.links_tx, state.endpoints_tx, state.carriers_tx),
        ("RX", state.links_rx, state.endpoints_rx, state.carriers_rx),
    ]:
        ep_key, car_key = _ep_ref_keys(ltype)
        for name, link in sorted(links.items()):
            ep_name = link.get(ep_key, "N/A")
            car_name = link.get(car_key, "N/A")
            recs.append({
                "type": ltype,
                "link_name": name,
                "link": link,
                "ep_name": ep_name,
                "carrier_name": car_name,
                "endpoint": eps.get(ep_name),
                "carrier": cars.get(car_name),
                "processing_element_name": link.get("processing-element"),
                "processing_element": state.processing_elements.get(link.get("processing-element", "")),
            })
    return recs

def render_report(state: StateStore, show: str = "all") -> str:
    lines: List[str] = []
    w = lines.append

    w("=" * 120)
    w("M-PLANE USER-PLANE CONFIGURATION ANALYSIS (Enhanced)")
    w("=" * 120)
    w(f"Input file       : {state.metadata.get('input_file')}")
    w(f"Segments parsed  : {state.metadata.get('segment_count')}")
    w(f"Objects          : TX carriers={len(state.carriers_tx)}, RX carriers={len(state.carriers_rx)}, "
      f"TX endpoints={len(state.endpoints_tx)}, RX endpoints={len(state.endpoints_rx)}, "
      f"TX links={len(state.links_tx)}, RX links={len(state.links_rx)}, "
      f"PRACH configs={len(state.prach_configs)}, Processing elements={len(state.processing_elements)}")

    # CHAIN VIEW
    if show in ("all", "chain"):
        w("\n" + "=" * 120)
        w("CHAIN VIEW  (Link -> Endpoint -> Carrier -> Processing Element/Transport)")
        w("=" * 120)
        chains = build_chain_records(state)
        if not chains:
            w("(No low-level link chains found)")
        for c in chains:
            ltype = c["type"]
            link = c["link"]
            ep = c["endpoint"] or {}
            car = c["carrier"] or {}
            pe = c["processing_element"] or {}

            w(f"\n🔗 Chain: {c['link_name']} ({ltype})")
            w("-" * 100)

            # Endpoint
            w(f"  [Endpoint] {c['ep_name']}")
            if ep:
                es = extract_endpoint_summary(ep)
                for k in [
                    "array","endpoint-type","frame-structure","cp-type","cp-length","cp-length-other",
                    "offset-to-absolute-frequency-center","number-of-prb-per-scs",
                    "non-time-managed-delay-enabled",
                    "compression.iq-bitwidth","compression.type","compression.method","compression.exponent","compression.fs-offset",
                    "eaxc.o-du-port-bitmask","eaxc.band-sector-bitmask","eaxc.ccid-bitmask","eaxc.ru-port-bitmask","eaxc.eaxc-id",
                    "eaxc-gain-correction",
                    "static-config-supported","static-prach-configuration","prach-group",
                ]:
                    v = es.get(k)
                    if v not in (None, "", "-", "?:?"):
                        w(f"      ├── {k}: {fmt(v)}")
                ri = ep.get("restricted-interfaces")
                if ri:
                    w(f"      ├── restricted-interfaces: {fmt(ri)}")

                pl = prach_lookup_for_endpoint(ep, state.prach_configs) if ltype == "RX" else None
                if pl:
                    pk, pc = pl
                    if pc:
                        w(f"      ├── PRACH config matched: {pk}")
                        w(f"      │   ├── pattern-period: {fmt(pc.get('pattern-period'))}")
                        w(f"      │   ├── sequence-duration: {fmt(pc.get('sequence-duration'))}")
                        w(f"      │   ├── num-prach-re: {fmt(pc.get('num-prach-re'))}")
                        w(f"      │   ├── guard-tone-low-re: {fmt(pc.get('guard-tone-low-re'))}")
                        w(f"      │   └── guard-tone-high-re: {fmt(pc.get('guard-tone-high-re'))}")
                    else:
                        w(f"      ├── PRACH ref present but config not found: {pk}")

                meta = ep.get("_meta", {})
                w(f"      └── [meta] msg-id={fmt(meta.get('message_id'))}, ts={fmt(meta.get('last_ts'))}, rpc={fmt(meta.get('rpc_type'))}")
            else:
                w("      (No Endpoint Details)")

            # Link
            w("      │")
            w(f"      ▼ (Link PE: {fmt(link.get('processing-element'))})")
            w("      │")
            if link:
                for lk in ("name", "low-level-tx-endpoint", "low-level-rx-endpoint", "tx-array-carrier", "rx-array-carrier"):
                    if lk in link:
                        w(f"      ├── link.{lk}: {fmt(link.get(lk))}")
                lmeta = link.get("_meta", {})
                w(f"      └── [meta] msg-id={fmt(lmeta.get('message_id'))}, ts={fmt(lmeta.get('last_ts'))}, rpc={fmt(lmeta.get('rpc_type'))}")

            # Carrier
            w(f"  [Carrier] {c['carrier_name']}")
            if car:
                cs = extract_carrier_summary(car)
                for k in [
                    "active","type","center-of-channel-bandwidth","channel-bandwidth","gain",
                    "reference-level","downlink-radio-frame-offset","downlink-sfn-offset",
                    "uplink-radio-frame-offset","uplink-sfn-offset"
                ]:
                    v = cs.get(k)
                    if v not in (None, "", "-"):
                        suffix = " Hz" if k in ("center-of-channel-bandwidth","channel-bandwidth") else ""
                        w(f"      ├── {k}: {fmt(v)}{suffix}")
                meta = car.get("_meta", {})
                w(f"      └── [meta] msg-id={fmt(meta.get('message_id'))}, ts={fmt(meta.get('last_ts'))}, rpc={fmt(meta.get('rpc_type'))}")
            else:
                w("      (No Carrier Details)")

            # Processing-element / transport flow
            pe_name = c.get("processing_element_name")
            w(f"  [Processing Element] {fmt(pe_name)}")
            if pe:
                tf = pe.get("transport-flow", {})
                if isinstance(tf, list):
                    tf_list = tf
                elif isinstance(tf, dict):
                    tf_list = [tf]
                else:
                    tf_list = []
                w(f"      ├── name: {fmt(pe.get('name'))}")
                for i, flow in enumerate(tf_list, 1):
                    w(f"      ├── transport-flow[{i}]")
                    if isinstance(flow, dict):
                        w(f"      │   ├── interface-name: {fmt(flow.get('interface-name'))}")
                        eth = flow.get("eth-flow", {})
                        if isinstance(eth, dict):
                            w(f"      │   ├── eth.ru-mac-address: {fmt(eth.get('ru-mac-address'))}")
                            w(f"      │   ├── eth.o-du-mac-address: {fmt(eth.get('o-du-mac-address'))}")
                            w(f"      │   └── eth.vlan-id: {fmt(eth.get('vlan-id'))}")
                meta = pe.get("_meta", {})
                w(f"      └── [meta] msg-id={fmt(meta.get('message_id'))}, ts={fmt(meta.get('last_ts'))}, rpc={fmt(meta.get('rpc_type'))}")
            else:
                w("      (No Processing Element Details)")

    # Endpoint summary table (text)
    if show in ("all", "endpoint"):
        w("\n" + "=" * 120)
        w("ENDPOINT SUMMARY")
        w("=" * 120)
        rows = []
        for direction, eps in [("TX", state.endpoints_tx), ("RX", state.endpoints_rx)]:
            for name, ep in sorted(eps.items()):
                es = extract_endpoint_summary(ep)
                rows.append({
                    "dir": direction,
                    "name": name,
                    "eaxc": es.get("eaxc.eaxc-id"),
                    "ru-port-mask": es.get("eaxc.ru-port-bitmask"),
                    "fs-offset": es.get("compression.fs-offset"),
                    "iq-bw": es.get("compression.iq-bitwidth"),
                    "method": es.get("compression.method"),
                    "frame-structure": es.get("frame-structure"),
                    "freq-offset": es.get("offset-to-absolute-frequency-center"),
                    "prach-ref": es.get("static-prach-configuration") or es.get("prach-group"),
                })
        if rows:
            header = ["DIR", "ENDPOINT", "EAXC", "RU_MASK", "FS_OFFSET", "IQ_BW", "METHOD", "FRAME", "FREQ_OFFSET", "PRACH_REF"]
            w(" | ".join(header))
            w("-" * 120)
            for r in rows:
                w(" | ".join([
                    fmt(r["dir"]), fmt(r["name"]), fmt(r["eaxc"]), fmt(r["ru-port-mask"]), fmt(r["fs-offset"]),
                    fmt(r["iq-bw"]), fmt(r["method"]), fmt(r["frame-structure"]), fmt(r["freq-offset"]), fmt(r["prach-ref"])
                ]))
        else:
            w("(No endpoints)")

    return "\n".join(lines)


# ------------------------------
# JSON export
# ------------------------------

def dataclass_to_jsonable_state(state: StateStore) -> Dict[str, Any]:
    def warning_to_dict(w: WarningItem) -> Dict[str, Any]:
        return {
            "phase": w.phase, "tag": w.tag, "message": w.message, "fragment": w.fragment,
            "message_id": w.message_id, "ts": w.ts
        }
    def hist_to_dict(h: ObjectVersion) -> Dict[str, Any]:
        return {
            "ts": h.ts, "direction": h.direction, "message_id": h.message_id,
            "rpc_type": h.rpc_type, "source": h.source, "raw": h.raw
        }

    return {
        "metadata": state.metadata,
        "carriers_tx": state.carriers_tx,
        "carriers_rx": state.carriers_rx,
        "endpoints_tx": state.endpoints_tx,
        "endpoints_rx": state.endpoints_rx,
        "links_tx": state.links_tx,
        "links_rx": state.links_rx,
        "prach_configs": state.prach_configs,
        "processing_elements": state.processing_elements,
        "validations": state.validations,
        "warnings": [warning_to_dict(w) for w in state.warnings],
        "history": {k: [hist_to_dict(v) for v in vv] for k, vv in state.history.items()},
    }


# ------------------------------
# CLI
# ------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Enhanced M-Plane user-plane configuration analyzer (NETCONF log parser)"
    )
    p.add_argument("input_file", nargs="?", default="20260218_fs-offset_0_M-Plane.txt",
                   help="NETCONF M-Plane log file")
    p.add_argument("-o", "--output", default="mplane_analysis_result_enhanced.txt",
                   help="Text report output file")
    p.add_argument("--json-out", default="mplane_analysis_result_enhanced.json",
                   help="JSON output file")
    p.add_argument("--show", default="all",
                   choices=["all", "chain", "endpoint", "validate", "warnings", "history"],
                   help="Which report section to render")
    p.add_argument("--no-json", action="store_true", help="Do not write JSON output")
    p.add_argument("--filter", choices=["all", "tx", "rx"], default="all",
                   help="Reserved for future (currently report includes all)")
    p.add_argument("--grep", default=None, help="Reserved for future object-name substring filter")
    return p.parse_args()


def main():
    args = parse_args()
    print(f"Analyzing {args.input_file} ...")
    state = parse_mplane_log(args.input_file)

    report = render_report(state, show=args.show)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report)
    print(report)
    print(f"\n[OK] Text report saved: {args.output}")

    if not args.no_json:
        payload = dataclass_to_jsonable_state(state)
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"[OK] JSON report saved: {args.json_out}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
