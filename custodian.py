#!/usr/bin/env python3
"""Safe local operator layer for personal v3 onion services.

The default workflow only stages local state and prints redacted output.
Deployment is intentionally a separate, explicit command.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

MODES = ("onion-only", "onion+clearnet", "clearnet-redirect")
STATE_ENV = "ONION_CUSTODIAN_STATE"


def state_dir() -> Path:
    value = os.environ.get(STATE_ENV)
    path = Path(value).expanduser() if value else Path.home() / ".local" / "share" / "onion-custodian"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def state_file() -> Path:
    return state_dir() / "services.json"


def load_state() -> dict[str, Any]:
    path = state_file()
    if not path.exists():
        return {"version": 1, "services": []}
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict) or not isinstance(value.get("services"), list):
        raise ValueError(f"invalid state file: {path}")
    return value


def save_state(value: dict[str, Any]) -> None:
    path = state_file()
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    os.chmod(path, 0o600)


def validate_service(name: str, mode: str, backend: str | None, redirect: str | None) -> None:
    if not name or "/" in name or name in {".", ".."}:
        raise ValueError("service name must be a simple non-empty path component")
    if mode not in MODES:
        raise ValueError(f"mode must be one of: {', '.join(MODES)}")
    if mode == "clearnet-redirect":
        if backend:
            raise ValueError("clearnet-redirect has no backend; it points to an onion address")
        if not redirect or not redirect.endswith(".onion"):
            raise ValueError("clearnet-redirect requires an .onion redirect target")
    elif not backend:
        raise ValueError(f"{mode} requires a loopback backend")
    if backend and not (backend.startswith("127.0.0.1:") or backend.startswith("localhost:")):
        raise ValueError("backend must be loopback (127.0.0.1 or localhost)")


def find_service(value: dict[str, Any], name: str) -> dict[str, Any]:
    for service in value["services"]:
        if service.get("name") == name:
            return service
    raise ValueError(f"unknown service: {name}")


def tor_generate_identity(directory: Path, backend: str) -> tuple[str, str]:
    """Ask Tor to create an actual v3 identity without enabling networking."""
    tor = shutil.which("tor")
    if not tor:
        raise RuntimeError("tor executable not found")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    tor_data = directory / "tor-data"
    hidden = directory / "hidden-service"
    tor_data.mkdir(mode=0o700, exist_ok=True)
    hidden.mkdir(mode=0o700, exist_ok=True)
    config = directory / "generate.torrc"
    config.write_text(
        "\n".join(
            [
                f"DataDirectory {tor_data}",
                f"HiddenServiceDir {hidden}",
                f"HiddenServicePort 80 {backend}",
                "SocksPort 0",
                "ControlPort 0",
                "DisableNetwork 1",
                "Log notice stdout",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    os.chmod(config, 0o600)
    process = subprocess.Popen([tor, "-f", str(config), "--hush"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        hostname = hidden / "hostname"
        secret = hidden / "hs_ed25519_secret_key"
        public = hidden / "hs_ed25519_public_key"
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not (hostname.exists() and secret.exists() and public.exists()):
            if process.poll() is not None:
                error = (process.stderr.read() if process.stderr else "").strip()
                raise RuntimeError(f"tor could not create identity: {error[-400:]}")
            time.sleep(0.1)
        if not hostname.exists() or not secret.exists() or not public.exists():
            raise TimeoutError("timed out waiting for Tor to create the v3 identity")
        address = hostname.read_text(encoding="utf-8").strip()
        import hashlib
        fingerprint = hashlib.sha256(public.read_bytes()).hexdigest()[:16].upper()
        os.chmod(secret, 0o600)
        return address, fingerprint
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()


def cmd_add(args: argparse.Namespace) -> int:
    validate_service(args.name, args.mode, args.backend, args.redirect)
    state = load_state()
    if any(item.get("name") == args.name for item in state["services"]):
        raise ValueError(f"service already exists: {args.name}")
    record: dict[str, Any] = {"name": args.name, "mode": args.mode, "backend": args.backend, "redirect": args.redirect, "version": 3, "key": None, "address": None, "fingerprint": None}
    if args.generate:
        target = state_dir() / "identities" / args.name
        address, fingerprint = tor_generate_identity(target, args.backend or "127.0.0.1:8080")
        record.update(address=address, fingerprint=fingerprint, key=str(target / "hidden-service" / "hs_ed25519_secret_key"))
    state["services"].append(record)
    save_state(state)
    print(f"staged {args.name} · mode={args.mode} · key={'generated' if record['key'] else 'not generated'}")
    if record["address"]:
        print(f"address {record['address']} · fingerprint {record['fingerprint']}")
    return 0


def auth_dir(service: dict[str, Any]) -> Path:
    key = service.get("key")
    path = Path(key).parent / "authorized_clients" if key else state_dir() / "authorizations" / service["name"]
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def cmd_auth_add(args: argparse.Namespace) -> int:
    state = load_state()
    service = find_service(state, args.service)
    source = Path(args.file).expanduser()
    if not source.is_file() or source.is_symlink():
        raise ValueError("descriptor must be a regular local file")
    payload = source.read_bytes()
    if not payload or len(payload) > 65536:
        raise ValueError("descriptor must be between 1 byte and 64 KiB")
    if not args.client or "/" in args.client or args.client in {".", ".."}:
        raise ValueError("client name must be a simple path component")
    target = auth_dir(service) / f"{args.client}.auth"
    if target.exists() and not args.replace:
        raise ValueError(f"authorization exists; use --replace explicitly: {args.client}")
    target.write_bytes(payload)
    os.chmod(target, 0o600)
    clients = service.setdefault("clients", [])
    clients[:] = [client for client in clients if client.get("name") != args.client]
    clients.append({"name": args.client, "file": str(target), "stale": False})
    save_state(state)
    print(f"authorization stored locally · service={service['name']} client={args.client}")
    return 0


def cmd_auth_list(args: argparse.Namespace) -> int:
    service = find_service(load_state(), args.service)
    for client in service.get("clients", []):
        status = "STALE" if client.get("stale") else "AUTHORIZED"
        print(f"{client.get('name', 'unnamed'):<24} {status}")
    return 0


def cmd_auth_revoke(args: argparse.Namespace) -> int:
    if not args.confirm:
        raise ValueError("revocation changes access; repeat with --confirm")
    state = load_state()
    service = find_service(state, args.service)
    clients = service.get("clients", [])
    match = next((client for client in clients if client.get("name") == args.client), None)
    if not match:
        raise ValueError(f"unknown client: {args.client}")
    target = Path(match["file"])
    if target.exists():
        target.unlink()
    service["clients"] = [client for client in clients if client.get("name") != args.client]
    save_state(state)
    print(f"authorization revoked · service={service['name']} client={args.client}")
    return 0


def cmd_rotate(args: argparse.Namespace) -> int:
    if not args.confirm:
        raise ValueError("identity rotation changes the onion address; repeat with --confirm")
    state = load_state()
    service = find_service(state, args.service)
    if service.get("mode") == "clearnet-redirect":
        raise ValueError("clearnet redirects do not own service identities")
    if not service.get("backend") or not service.get("key"):
        raise ValueError("service must have a generated identity and backend before rotation")
    old_dir = Path(service["key"]).parent.parent
    archive = state_dir() / "rotated" / f"{service['name']}-{int(time.time())}"
    archive.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.move(str(old_dir), str(archive))
    new_dir = state_dir() / "identities" / service["name"]
    try:
        address, fingerprint = tor_generate_identity(new_dir, service["backend"])
    except Exception:
        shutil.move(str(archive), str(old_dir))
        raise
    service.setdefault("previous_identities", []).append({"address": service.get("address"), "fingerprint": service.get("fingerprint"), "archived": str(archive)})
    service.update(address=address, fingerprint=fingerprint, key=str(new_dir / "hidden-service" / "hs_ed25519_secret_key"), authorization_stale=True)
    for client in service.get("clients", []):
        client["stale"] = True
    save_state(state)
    print(f"rotated {service['name']} · new address {address} · fingerprint {fingerprint}")
    print("existing client authorizations marked stale; archived identity retained locally")
    return 0


def audit_records(records: list[dict[str, Any]]) -> list[str]:
    warnings: list[str] = []
    backends: dict[str, list[dict[str, Any]]] = {}
    for service in records:
        backend = service.get("backend")
        if backend:
            backends.setdefault(backend, []).append(service)
        if service.get("mode") == "onion+clearnet":
            warnings.append(f"{service['name']}: onion + clearnet is an explicit dual route")
    for backend, services in backends.items():
        routes = {item.get("mode") for item in services}
        if len(services) > 1 and "onion-only" in routes and "onion+clearnet" in routes:
            names = ", ".join(item["name"] for item in services)
            warnings.append(f"shared backend {backend}: {names} expose mixed route modes")
    return warnings


def listener_exposure_warnings(records: list[dict[str, Any]], ss_output: str) -> list[str]:
    """Find service backends listening beyond loopback from `ss -ltn` output."""
    backend_ports = {str(service.get("backend", "")).rsplit(":", 1)[-1]: service.get("name") for service in records if service.get("backend")}
    warnings: list[str] = []
    for line in ss_output.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        local = fields[3]
        port = local.rsplit(":", 1)[-1].rstrip("]")
        if port not in backend_ports:
            continue
        host = local[: -(len(port) + 1)].strip("[]")
        if host in {"127.0.0.1", "::1", "localhost"} or host.startswith("127."):
            continue
        warnings.append(f"{backend_ports[port]}: backend listener {local} is not loopback-only")
    return warnings


def minimal_config(state: dict[str, Any]) -> str:
    lines = ["# generated by onion-custodian; secret values intentionally omitted", "version = 1", ""]
    for service in state["services"]:
        lines += [f"[service.{service['name']}]"]
        lines += [f"mode = {json.dumps(service['mode'])}", f"version = {service.get('version', 3)}"]
        if service.get("backend"):
            lines.append(f"backend = {json.dumps(service['backend'])}")
        if service.get("redirect"):
            lines.append(f"redirect = {json.dumps(service['redirect'])}")
        if service.get("key"):
            lines.append(f"key_ref = {json.dumps('vault://' + service['name'])}")
        clients = [client.get("name") for client in service.get("clients", []) if client.get("name") and not client.get("stale")]
        if clients:
            lines.append(f"authorize_clients = {json.dumps(clients)}")
        lines.append("")
    return "\n".join(lines)


def cmd_audit(args: argparse.Namespace) -> int:
    records = load_state()["services"]
    warnings = audit_records(records)
    if args.live:
        ss = shutil.which("ss")
        if not ss:
            raise RuntimeError("--live requires the ss command")
        listeners = subprocess.run([ss, "-ltnH"], capture_output=True, text=True, check=False)
        warnings.extend(listener_exposure_warnings(records, listeners.stdout))
    if not warnings:
        print("PASS · no mixed-backend route exposure found")
        return 0
    print("REVIEW REQUIRED")
    for warning in warnings:
        print(f"! {warning}")
    return 2


def cmd_config(args: argparse.Namespace) -> int:
    output = minimal_config(load_state())
    if args.output:
        target = Path(args.output).expanduser()
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_text(output, encoding="utf-8")
        os.chmod(target, 0o600)
        print(f"wrote redacted config: {target}")
    else:
        print(output, end="")
    return 0


def control_request(host: str, port: int, command: str, cookie_file: str | None = None) -> str:
    """Send one authenticated control-port request and return its bounded response."""
    with socket.create_connection((host, port), timeout=3) as connection:
        connection.settimeout(3)
        greeting = connection.recv(4096).decode("utf-8", "replace")
        if not greeting.startswith("250"):
            raise RuntimeError(f"unexpected Tor control greeting: {greeting[:120].strip()}")
        if cookie_file:
            cookie = Path(cookie_file).expanduser()
            if not cookie.is_file() or cookie.is_symlink():
                raise ValueError("control cookie must be a regular local file")
            raw_cookie = cookie.read_bytes()
            if not raw_cookie or len(raw_cookie) > 128:
                raise ValueError("control cookie has an invalid size")
            connection.sendall(f"AUTHENTICATE {raw_cookie.hex()}\r\n".encode("ascii"))
            auth_response = connection.recv(4096).decode("utf-8", "replace")
            if not auth_response.startswith("250"):
                raise RuntimeError("Tor control cookie authentication failed")
        connection.sendall((command + "\r\nQUIT\r\n").encode("ascii"))
        chunks: list[bytes] = []
        total = 0
        while total < 262144:
            chunk = connection.recv(min(8192, 262144 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            payload = b"".join(chunks)
            if b"\r\n250 OK\r\n" in payload or b"\r\n250 closing\r\n" in payload:
                break
    payload_text = b"".join(chunks).decode("utf-8", "replace")
    if not payload_text.startswith("250"):
        raise RuntimeError(f"Tor control port rejected query: {payload_text[:120].strip()}")
    return payload_text


def control_query(host: str, port: int, command: str, cookie_file: str | None = None) -> list[str]:
    payload = control_request(host, port, command, cookie_file)
    return [line for line in payload.splitlines() if line and not line.startswith("250 OK") and not line.startswith("250 closing")]


def control_query_block(host: str, port: int, command: str, cookie_file: str | None = None) -> str:
    """Read a bounded GETINFO block; callers must redact before displaying it."""
    return control_request(host, port, command, cookie_file)


def cmd_probe(args: argparse.Namespace) -> int:
    lines = control_query(args.host, args.port, "GETINFO status/bootstrap-phase", args.cookie_file)
    print("TOR CONTROL PORT REACHABLE")
    for line in lines:
        print(line)
    print("destination history: not requested")
    return 0


def cmd_intro_health(args: argparse.Namespace) -> int:
    service = find_service(load_state(), args.service)
    address = service.get("address")
    if not address or not address.endswith(".onion"):
        raise ValueError("service has no generated v3 onion address")
    payload = control_query_block(args.host, args.port, f"GETINFO hs/service/desc/id/{address}", args.cookie_file)
    points = sum(1 for line in payload.splitlines() if "introduction-point" in line)
    if "250 OK" not in payload:
        raise RuntimeError("Tor returned no complete service descriptor")
    print(f"{service['name']} · descriptor available · introduction points observed: {points}")
    print("descriptor contents: withheld · destination history: not requested")
    return 0


def cmd_monitor(args: argparse.Namespace) -> int:
    """Poll aggregate Tor bootstrap status; never records destinations."""
    while True:
        lines = control_query(args.host, args.port, "GETINFO status/bootstrap-phase", args.cookie_file)
        summary = next((line.split("=", 1)[1] for line in lines if "bootstrap-phase=" in line), "status unavailable")
        print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} · bootstrap · {summary}", flush=True)
        if not args.follow:
            return 0
        time.sleep(max(1, args.interval))


def recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    while sum(len(chunk) for chunk in chunks) < size:
        chunk = connection.recv(size - sum(len(part) for part in chunks))
        if not chunk:
            raise RuntimeError("SOCKS5 peer closed during handshake")
        chunks.append(chunk)
    return b"".join(chunks)


def socks5_connect(socks_host: str, socks_port: int, target_host: str, target_port: int) -> None:
    encoded_host = target_host.encode("idna")
    if len(encoded_host) > 255:
        raise ValueError("target hostname is too long")
    with socket.create_connection((socks_host, socks_port), timeout=10) as connection:
        connection.sendall(b"\x05\x01\x00")
        if recv_exact(connection, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 proxy requires unsupported authentication")
        connection.sendall(b"\x05\x01\x00\x03" + bytes([len(encoded_host)]) + encoded_host + target_port.to_bytes(2, "big"))
        response = recv_exact(connection, 4)
        if response[0] != 5 or response[1] != 0:
            raise RuntimeError(f"SOCKS5 CONNECT failed with code {response[1]}")
        address_type = response[3]
        sizes = {1: 4, 4: 16}
        if address_type in sizes:
            recv_exact(connection, sizes[address_type] + 2)
        elif address_type == 3:
            length = recv_exact(connection, 1)[0]
            recv_exact(connection, length + 2)
        else:
            raise RuntimeError("SOCKS5 proxy returned an unknown address type")


def cmd_reach(args: argparse.Namespace) -> int:
    service = find_service(load_state(), args.service)
    address = service.get("address")
    if not address or not address.endswith(".onion"):
        raise ValueError("service has no generated v3 onion address")
    started = time.monotonic()
    socks5_connect(args.socks_host, args.socks_port, address, args.port)
    elapsed = (time.monotonic() - started) * 1000
    print(f"REACHABLE · {service['name']} · TCP connect via SOCKS5 · {elapsed:.0f}ms")
    print("application content: not requested · destination history: not stored")
    return 0


def torrc_fragment(state: dict[str, Any]) -> str:
    lines = ["# onion-custodian generated fragment; review before applying to torrc", ""]
    for service in state["services"]:
        if service.get("mode") == "clearnet-redirect":
            continue
        key = service.get("key")
        backend = service.get("backend")
        if not key or not backend:
            lines.append(f"# {service['name']}: skipped until an identity and backend are staged")
            continue
        hidden_dir = str(Path(key).parent)
        lines += [f"HiddenServiceDir {hidden_dir}", "HiddenServiceVersion 3"]
        clients = [client.get("name") for client in service.get("clients", []) if client.get("name") and not client.get("stale")]
        if clients:
            lines.append(f"HiddenServiceAuthorizeClient stealth {' '.join(clients)}")
        lines += [f"HiddenServicePort 80 {backend}", ""]
    return "\n".join(lines)


def cmd_torrc(args: argparse.Namespace) -> int:
    output = torrc_fragment(load_state())
    if not args.output:
        print(output, end="")
        return 0
    target = Path(args.output).expanduser()
    if target.exists() and not args.replace:
        raise ValueError(f"refusing to overwrite existing file without --replace: {target}")
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if target.exists():
        backup = target.with_suffix(target.suffix + ".bak")
        shutil.copy2(target, backup)
        os.chmod(backup, 0o600)
    target.write_text(output, encoding="utf-8")
    os.chmod(target, 0o600)
    print(f"wrote reviewed torrc fragment: {target}")
    return 0


def cmd_deploy(args: argparse.Namespace) -> int:
    if not args.confirm:
        raise ValueError("deployment changes live network state; repeat with --confirm")
    state = load_state()
    warnings = audit_records(state["services"])
    if warnings and not args.allow_shared_backend:
        raise ValueError("route audit requires review before deployment; use --allow-shared-backend only after review")
    fragment = torrc_fragment(state)
    if "skipped until" in fragment:
        raise ValueError("every non-redirect service needs a generated identity and backend before deployment")
    runtime = state_dir() / "runtime"
    runtime.mkdir(mode=0o700, exist_ok=True)
    torrc = runtime / "deployed.torrc"
    cookie_file = runtime / "tor-data" / "control_auth_cookie"
    cookie_file.parent.mkdir(mode=0o700, exist_ok=True)
    torrc.write_text("\n".join([fragment.rstrip(), f"SocksPort {args.socks_port}", f"ControlPort {args.control_port}", "CookieAuthentication 1", f"CookieAuthFile {cookie_file}", "Log notice stdout", ""]) , encoding="utf-8")
    os.chmod(torrc, 0o600)
    tor = shutil.which("tor")
    if not tor:
        raise RuntimeError("tor executable not found")
    verified = subprocess.run([tor, "--verify-config", "-f", str(torrc)], capture_output=True, text=True, check=False)
    if verified.returncode != 0:
        raise RuntimeError(f"Tor rejected generated config: {verified.stderr[-400:]}")
    print(f"verified deployment config: {torrc}")
    print(f"control port: 127.0.0.1:{args.control_port} · socks: 127.0.0.1:{args.socks_port} · cookie: {cookie_file}")
    if not args.foreground:
        print("staged only · pass --foreground to start Tor")
        return 0
    print("starting Tor in foreground; Ctrl-C stops the service")
    return subprocess.run([tor, "-f", str(torrc)]).returncode


def cmd_list(_: argparse.Namespace) -> int:
    for service in load_state()["services"]:
        print(f"{service['name']:<18} {service['mode']:<18} {service.get('address') or 'identity not generated'}")
    return 0


def cmd_tui(_: argparse.Namespace) -> int:
    """Run a read-only curses operator view; mutations remain explicit CLI actions."""
    import curses

    state = load_state()
    tabs = ["OVERVIEW", "SERVICES", "REACHABILITY", "AUTHORIZATION", "EXPOSURE AUDIT"]
    selected = 0

    def draw(screen: Any) -> None:
        nonlocal selected
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        screen.keypad(True)
        while True:
            screen.erase()
            height, width = screen.getmaxyx()
            if height < 18 or width < 72:
                screen.addnstr(1, 2, "ONION SERVICE CUSTODIAN needs a larger terminal", max(1, width - 4))
                screen.addnstr(3, 2, "resize · q quits", max(1, width - 4))
                screen.refresh()
                if screen.getch() in (ord("q"), 27):
                    return
                continue
            screen.addnstr(0, 0, " ONION SERVICE CUSTODIAN ".center(width, "─"), width - 1, curses.A_BOLD)
            screen.addnstr(2, 2, "CUSTODY", width - 4, curses.A_DIM)
            for index, tab in enumerate(tabs):
                attr = curses.A_REVERSE if index == selected else curses.A_NORMAL
                screen.addnstr(4 + index, 2, f" {index + 1}. {tab:<20}", 25, attr)
            screen.vline(2, 28, curses.ACS_VLINE, max(1, height - 5))
            title = tabs[selected]
            screen.addnstr(2, 32, title, width - 35, curses.A_BOLD)
            if selected == 0:
                lines = [
                    "LOCAL ONLY · VAULT STATE REDACTED",
                    "",
                    f"services              {len(state['services'])}",
                    "introduction points   current snapshot only",
                    "route audit           run: onion-custodian audit",
                    "config                run: onion-custodian config",
                    "",
                    "SAFE MODE: no network sync · no secret display",
                ]
            elif selected == 1:
                lines = [f"{item['name']:<18} {item['mode']:<20} {item.get('address') or 'identity not generated'}" for item in state["services"]] or ["no services staged"]
            elif selected == 2:
                lines = ["INTRODUCTION-POINT HEALTH", "", "Run: onion-custodian intro-health SERVICE", "Run: onion-custodian reach SERVICE", "No destination history is retained."]
            elif selected == 3:
                lines = ["CLIENT AUTHORIZATION", "", "Run: onion-custodian auth list SERVICE", "Run: onion-custodian auth revoke SERVICE CLIENT --confirm", "Descriptors remain local and redacted."]
            else:
                warnings = audit_records(state["services"])
                lines = ["ROUTE CLASSIFICATION", ""] + (warnings or ["PASS · no mixed-backend route exposure found"])
            for row, line in enumerate(lines, start=4):
                screen.addnstr(row, 32, line, max(1, width - 35))
            screen.addnstr(height - 2, 2, "↑↓/1-5 select · d stage deploy · q quit", width - 4, curses.A_DIM)
            screen.refresh()
            key = screen.getch()
            if key in (ord("q"), 27):
                return
            if key == ord("d"):
                curses.echo()
                screen.addnstr(height - 3, 2, "type DEPLOY to verify and stage: ", width - 4, curses.A_BOLD)
                answer = screen.getstr(height - 3, min(width - 1, 34), 6).decode("utf-8", "replace")
                curses.noecho()
                if answer == "DEPLOY":
                    try:
                        with contextlib.redirect_stdout(io.StringIO()):
                            cmd_deploy(argparse.Namespace(confirm=True, foreground=False, control_port=9051, socks_port=9050, allow_shared_backend=False))
                        screen.addnstr(height - 3, 2, "deployment verified and staged; Tor was not started", width - 4)
                    except (OSError, RuntimeError, ValueError) as error:
                        screen.addnstr(height - 3, 2, f"deployment refused: {error}", width - 4)
                else:
                    screen.addnstr(height - 3, 2, "deployment cancelled", width - 4)
                screen.refresh()
                screen.getch()
                continue
            if key in (curses.KEY_UP, ord("k")):
                selected = (selected - 1) % len(tabs)
            elif key in (curses.KEY_DOWN, ord("j")):
                selected = (selected + 1) % len(tabs)
            elif ord("1") <= key <= ord("5"):
                selected = key - ord("1")

    curses.wrapper(draw)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="onion-custodian", description="safe local onion-service operator")
    sub = parser.add_subparsers(dest="command", required=True)
    add = sub.add_parser("add", help="stage a service definition")
    add.add_argument("name"); add.add_argument("--mode", choices=MODES, required=True); add.add_argument("--backend"); add.add_argument("--redirect"); add.add_argument("--generate", action="store_true", help="ask Tor to generate a v3 identity locally")
    add.set_defaults(func=cmd_add)
    sub.add_parser("list", help="list redacted service state").set_defaults(func=cmd_list)
    audit = sub.add_parser("audit", help="audit mixed route exposure"); audit.add_argument("--live", action="store_true", help="also inspect local TCP listener binds"); audit.set_defaults(func=cmd_audit)
    config = sub.add_parser("config", help="print or write a minimal redacted config"); config.add_argument("--output"); config.set_defaults(func=cmd_config)
    probe = sub.add_parser("probe", help="read Tor bootstrap status without requesting destinations"); probe.add_argument("--host", default="127.0.0.1"); probe.add_argument("--port", type=int, default=9051); probe.add_argument("--cookie-file"); probe.set_defaults(func=cmd_probe)
    intro = sub.add_parser("intro-health", help="inspect one service descriptor through the control port"); intro.add_argument("service"); intro.add_argument("--host", default="127.0.0.1"); intro.add_argument("--port", type=int, default=9051); intro.add_argument("--cookie-file"); intro.set_defaults(func=cmd_intro_health)
    monitor = sub.add_parser("monitor", help="poll aggregate Tor health without destination history"); monitor.add_argument("--host", default="127.0.0.1"); monitor.add_argument("--port", type=int, default=9051); monitor.add_argument("--cookie-file"); monitor.add_argument("--follow", action="store_true"); monitor.add_argument("--interval", type=int, default=10); monitor.set_defaults(func=cmd_monitor)
    reach = sub.add_parser("reach", help="TCP-probe one staged onion address through SOCKS5"); reach.add_argument("service"); reach.add_argument("--socks-host", default="127.0.0.1"); reach.add_argument("--socks-port", type=int, default=9050); reach.add_argument("--port", type=int, default=80); reach.set_defaults(func=cmd_reach)
    torrc = sub.add_parser("torrc", help="render a reviewed v3 torrc fragment"); torrc.add_argument("--output"); torrc.add_argument("--replace", action="store_true", help="allow replacing an existing explicit output path"); torrc.set_defaults(func=cmd_torrc)
    deploy = sub.add_parser("deploy", help="verify and optionally start a staged service set"); deploy.add_argument("--confirm", action="store_true"); deploy.add_argument("--foreground", action="store_true"); deploy.add_argument("--control-port", type=int, default=9051); deploy.add_argument("--socks-port", type=int, default=9050); deploy.add_argument("--allow-shared-backend", action="store_true", help="acknowledge an audited mixed-route backend"); deploy.set_defaults(func=cmd_deploy)
    auth = sub.add_parser("auth", help="manage local client authorization files")
    auth_sub = auth.add_subparsers(dest="auth_command", required=True)
    auth_add = auth_sub.add_parser("add", help="copy one descriptor into the local vault"); auth_add.add_argument("service"); auth_add.add_argument("client"); auth_add.add_argument("--file", required=True); auth_add.add_argument("--replace", action="store_true"); auth_add.set_defaults(func=cmd_auth_add)
    auth_list = auth_sub.add_parser("list", help="list redacted authorization names"); auth_list.add_argument("service"); auth_list.set_defaults(func=cmd_auth_list)
    auth_revoke = auth_sub.add_parser("revoke", help="revoke one client authorization"); auth_revoke.add_argument("service"); auth_revoke.add_argument("client"); auth_revoke.add_argument("--confirm", action="store_true"); auth_revoke.set_defaults(func=cmd_auth_revoke)
    rotate = sub.add_parser("rotate", help="rotate one v3 identity with explicit confirmation"); rotate.add_argument("service"); rotate.add_argument("--confirm", action="store_true"); rotate.set_defaults(func=cmd_rotate)
    sub.add_parser("tui", help="open the read-only terminal interface").set_defaults(func=cmd_tui)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        os.umask(0o077)
        args = build_parser().parse_args(argv)
        return int(args.func(args))
    except (OSError, RuntimeError, TimeoutError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
