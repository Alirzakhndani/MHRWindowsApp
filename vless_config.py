import hashlib
import uuid
from urllib.parse import quote, urlencode

DEFAULT_VLESS_PORT = 443
VLESS_NAMESPACE = uuid.UUID("8d4a41d8-5d51-4d9f-b0d0-4b4f3a6d1b6d")


def stable_uuid(seed: str) -> str:
    """Return a VLESS-safe UUID, deriving one when the seed is not already a UUID."""
    value = (seed or "").strip()
    if value:
        try:
            return str(uuid.UUID(value))
        except ValueError:
            pass
    if not value:
        value = uuid.uuid4().hex
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return str(uuid.uuid5(VLESS_NAMESPACE, digest))


def _clean(value):
    if value is None:
        return ""
    return str(value).strip()


def build_vless_uri(
    *,
    user_id: str,
    address: str,
    port: int = DEFAULT_VLESS_PORT,
    name: str = "MasterVPN VLESS",
    security: str = "tls",
    transport: str = "ws",
    host: str = "",
    path: str = "/",
    sni: str = "",
    flow: str = "",
    fingerprint: str = "chrome",
    alpn: str = "",
    allow_insecure: bool = False,
) -> str:
    """Build a VLESS share URI accepted by clients such as V2BOX."""
    clean_id = stable_uuid(user_id)
    clean_address = _clean(address)
    if not clean_address:
        raise ValueError("Server address is required")
    try:
        clean_port = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError("Port must be a number") from exc
    if clean_port < 1 or clean_port > 65535:
        raise ValueError("Port must be between 1 and 65535")

    query = {
        "encryption": "none",
        "security": _clean(security) or "tls",
        "type": _clean(transport) or "ws",
    }
    clean_flow = _clean(flow)
    if clean_flow:
        query["flow"] = clean_flow
    clean_sni = _clean(sni)
    if clean_sni:
        query["sni"] = clean_sni
    clean_fingerprint = _clean(fingerprint)
    if clean_fingerprint and query["security"] in {"tls", "reality"}:
        query["fp"] = clean_fingerprint
    clean_alpn = _clean(alpn)
    if clean_alpn:
        query["alpn"] = clean_alpn
    if allow_insecure:
        query["allowInsecure"] = "1"

    if query["type"] == "ws":
        clean_host = _clean(host)
        if clean_host:
            query["host"] = clean_host
        clean_path = _clean(path) or "/"
        if not clean_path.startswith("/"):
            clean_path = "/" + clean_path
        query["path"] = clean_path

    encoded_query = urlencode(query, safe="/:,.-")
    return f"vless://{clean_id}@{clean_address}:{clean_port}?{encoded_query}#{quote(_clean(name) or 'MasterVPN VLESS')}"


def config_to_vless_defaults(config: dict) -> dict:
    """Convert the app's current tunnel settings into editable VLESS defaults."""
    mode = config.get("mode", "apps_script")
    script = config.get("script_ids") or config.get("script_id") or ""
    if isinstance(script, list):
        script = script[0] if script else ""

    if mode == "custom_domain":
        address = config.get("custom_domain", "")
        host = address
        sni = address
        path = config.get("worker_path", "/") or "/"
        name = "MasterVPN Custom Domain"
    elif mode == "google_fronting":
        address = config.get("front_domain", "www.google.com")
        host = config.get("worker_host", "")
        sni = config.get("front_domain", "www.google.com")
        path = config.get("worker_path", "/") or "/"
        name = "MasterVPN Google Fronting"
    elif mode == "domain_fronting":
        address = config.get("front_domain", "")
        host = config.get("worker_host", "")
        sni = config.get("front_domain", "")
        path = config.get("worker_path", "/") or "/"
        name = "MasterVPN Domain Fronting"
    else:
        address = config.get("front_domain", "www.google.com")
        host = "script.google.com"
        sni = config.get("front_domain", "www.google.com")
        path = f"/macros/s/{script}/exec" if script else "/macros/s/YOUR_SCRIPT_ID/exec"
        name = "MasterVPN Apps Script"

    return {
        "user_id": stable_uuid(config.get("auth_key") or script),
        "address": address,
        "port": DEFAULT_VLESS_PORT,
        "name": name,
        "security": "tls",
        "transport": "ws",
        "host": host,
        "path": path,
        "sni": sni,
        "fingerprint": "chrome",
        "alpn": "h2,http/1.1",
        "flow": "",
        "allow_insecure": not config.get("verify_ssl", True),
    }
