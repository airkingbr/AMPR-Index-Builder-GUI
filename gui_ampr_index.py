#!/usr/bin/env python3
"""
GUI para o build_ampr_index.py - gera o /app0/ampr_emu.index para o resolver
de arquivos APR do AMPR.

Empacotar em um unico .exe com:
    pyinstaller --onefile --noconsole --name AmprIndexBuilder gui_ampr_index.py
"""

from __future__ import annotations

import ftplib
import hashlib
import os
import queue
import shutil
import struct
import sys
import threading
import tkinter as tk
from dataclasses import dataclass, field
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from urllib.parse import unquote, urlparse


# ---------------------------------------------------------------------------
# Versoes conhecidas de /fakelib/libSceAmpr.sprx por hash SHA-256
# ---------------------------------------------------------------------------

AMPR_SPRX_RELATIVE_PATH = Path("fakelib") / "libSceAmpr.sprx"

AMPR_SPRX_VERSIONS = {
    "6F13898045BFA1089CD9797355FCB5FF462DE9067223F392CE5C7D0CB556F277"[:64].upper(): "0.2.0",
    "042A53F6E98785B005AF2F9FB397C832C65D620BED917C26D1E280EDE9F12965"[:64].upper(): "0.2.1",
    "7A257448F9DF11EFC6B8F123AEE2FABA798B4580BBE3D97BDCC54E48B9ABD311"[:64].upper(): "0.2.4",
    "61FFA03FFB196F6E846F55F8702209A0325AE319501929E0FECA95BDCEC5C0A2"[:64].upper(): "0.2.4-debug",
    "85BAF50299D04FD549F09974D990ABEC4DCF68226011AEC34BC3B726E1AB7FB4"[:64].upper(): "0.2.5",
    "A21A87C3F6901A61BDF10704CAE7C1ABA8C16037A345147C12E59CAE973137F3"[:64].upper(): "0.2.5.3",
    "16CEE7263A7CBEC8F23C334B67AFE3F2E783CB575A17FE47F1C9D95AC0481FCB"[:64].upper(): "0.2.6",
    "0F57FFD092B220E41A3C0A0A8CFD6D8D9661CD410FD6238642A6820F0AD108C1"[:64].upper(): "0.2.7.1",
    "540163BDDBB8DC818FCF9C122ABEFBDB78567988AA4ACCB4CEDA6E5867CD9464"[:64].upper(): "0.2.7.2",
}


def sha256_of_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest().upper()


def detect_ampr_version(root_text: str) -> str:
    root = Path(root_text)
    sprx_path = root / AMPR_SPRX_RELATIVE_PATH
    if not sprx_path.is_file():
        return "arquivo nao encontrado"
    try:
        file_hash = sha256_of_file(sprx_path)
    except OSError as exc:
        return f"erro ao ler arquivo: {exc}"
    version = AMPR_SPRX_VERSIONS.get(file_hash)
    if version:
        return version
    return f"versao desconhecida (hash {file_hash})"


# ---------------------------------------------------------------------------
# Logica de indexacao (portada de build_ampr_index.py)
# ---------------------------------------------------------------------------

@dataclass
class HashCollisionStats:
    probe_steps: int = 0
    probed_entries: int = 0
    max_probe: int = 0
    duplicate_hash_groups: int = 0
    duplicate_hash_entries: int = 0
    duplicate_hash_samples: list[tuple[int, str, str]] = field(default_factory=list)


def key_for(path: str) -> str:
    return path.replace("\\", "/").lower()


def fnv1a64_path_hash(path: str) -> int:
    h = 1469598103934665603
    for ch in key_for(path):
        h ^= ord(ch)
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h or 1


def hash_slot_count(entry_count: int) -> int:
    if entry_count <= 0 or entry_count > 0xFFFFFFFE:
        raise ValueError("invalid index entry count")
    slots = 2
    target = entry_count * 2
    while slots < target:
        slots <<= 1
    return slots


def build_hash_slots(rows: list[tuple[int, int, str]]) -> tuple[list[tuple[int, int, int]], HashCollisionStats]:
    duplicate_flag = 1
    slots = [(0, 0, 0) for _ in range(hash_slot_count(len(rows)))]
    mask = len(slots) - 1
    stats = HashCollisionStats()
    duplicate_hashes: set[int] = set()
    for index, (_, _, path) in enumerate(rows):
        h = fnv1a64_path_hash(path)
        pos = h & mask
        duplicate = False
        probe = 0
        while slots[pos][1] != 0:
            if slots[pos][0] == h:
                old_hash, old_index_plus_one, old_flags = slots[pos]
                slots[pos] = (old_hash, old_index_plus_one, old_flags | duplicate_flag)
                if not duplicate:
                    if h not in duplicate_hashes:
                        duplicate_hashes.add(h)
                        stats.duplicate_hash_groups += 1
                        stats.duplicate_hash_entries += 2
                    else:
                        stats.duplicate_hash_entries += 1
                    if len(stats.duplicate_hash_samples) < 5:
                        stats.duplicate_hash_samples.append((h, rows[old_index_plus_one - 1][2], path))
                duplicate = True
            pos = (pos + 1) & mask
            probe += 1
        if probe:
            stats.probed_entries += 1
            stats.probe_steps += probe
            stats.max_probe = max(stats.max_probe, probe)
        slots[pos] = (h, index + 1, duplicate_flag if duplicate else 0)
    return slots, stats


def report_hash_collision_stats(stats: HashCollisionStats, slot_count: int, entry_count: int) -> None:
    if stats.probe_steps:
        print(
            "info: AMPRIDX3 hash table probe stats: "
            f"entries={entry_count} slots={slot_count} "
            f"probedEntries={stats.probed_entries} "
            f"probeSteps={stats.probe_steps} maxProbe={stats.max_probe}",
            file=sys.stderr,
        )
    if stats.duplicate_hash_groups:
        print(
            "warning: AMPRIDX3 duplicate 64-bit path hashes: "
            f"groups={stats.duplicate_hash_groups} entries={stats.duplicate_hash_entries}; "
            "duplicate slots will force full path compare at runtime",
            file=sys.stderr,
        )
        for h, first, second in stats.duplicate_hash_samples:
            print(
                f"warning: AMPRIDX3 duplicate hash sample hash=0x{h:016x}: {first} <-> {second}",
                file=sys.stderr,
            )


def app0_path(root: Path, path: Path) -> str:
    rel = path.relative_to(root).as_posix()
    return "/app0/" + rel


def report_progress(count: int) -> None:
    if count and count % 10000 == 0:
        print(f"indexed {count} files...", flush=True)


def validate_and_add_row(
    rows: list[tuple[int, int, str]],
    seen: dict[str, str],
    size: int,
    mtime: int,
    indexed_path: str,
    allow_case_collisions: bool,
) -> bool:
    if "\t" in indexed_path or "\n" in indexed_path or "\r" in indexed_path:
        print(f"warning: skipping path with unsupported whitespace: {indexed_path}", file=sys.stderr)
        return True

    key = key_for(indexed_path)
    existing = seen.get(key)
    if existing is not None:
        msg = f"case-insensitive path collision: {existing} <-> {indexed_path}"
        if not allow_case_collisions:
            print(f"error: {msg}", file=sys.stderr)
            return False
        print(f"warning: keeping first collision entry: {msg}", file=sys.stderr)
        return True

    seen[key] = indexed_path
    rows.append((size, mtime, indexed_path))
    report_progress(len(rows))
    return True


def write_index(rows: list[tuple[int, int, str]], output: Path) -> None:
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_suffix(output.suffix + ".tmp")
    rows = sorted(rows, key=lambda row: key_for(row[2]))

    record_struct = struct.Struct("<IIQq")
    hash_slot_struct = struct.Struct("<QII")
    header_struct = struct.Struct("<8sIIQQQII")
    if len(rows) > 0xFFFFFFFE:
        raise ValueError("index has too many records")
    path_blob = bytearray()
    records = bytearray()
    for size, mtime, path in rows:
        encoded = path.encode("utf-8") + b"\0"
        offset = len(path_blob)
        path_len = len(encoded) - 1
        if offset > 0xFFFFFFFF or path_len > 0xFFFFFFFF:
            raise ValueError("index path blob is too large")
        records += record_struct.pack(offset, path_len, size, mtime)
        path_blob += encoded

    hash_slots, hash_stats = build_hash_slots(rows)
    report_hash_collision_stats(hash_stats, len(hash_slots), len(rows))
    path_end = header_struct.size + len(records) + len(path_blob)
    hash_offset = (path_end + (hash_slot_struct.size - 1)) & ~(hash_slot_struct.size - 1)
    padding = b"\0" * (hash_offset - path_end)

    with tmp.open("wb") as f:
        f.write(
            header_struct.pack(
                b"AMPRIDX3",
                3,
                record_struct.size,
                len(rows),
                len(path_blob),
                hash_offset,
                hash_slot_struct.size,
                len(hash_slots),
            )
        )
        f.write(records)
        f.write(path_blob)
        f.write(padding)
        for h, index_plus_one, flags in hash_slots:
            f.write(hash_slot_struct.pack(h, index_plus_one, flags))
    tmp.replace(output)


def build_index_local(root: Path, output: Path, allow_case_collisions: bool) -> int:
    root = root.resolve()
    if not root.is_dir():
        print(f"error: root is not a directory: {root}", file=sys.stderr)
        return 2

    output = output.resolve()
    output_tmp = output.with_suffix(output.suffix + ".tmp")
    seen: dict[str, str] = {}
    rows: list[tuple[int, int, str]] = []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort(key=str.lower)
        filenames.sort(key=str.lower)
        for filename in filenames:
            path = Path(dirpath) / filename
            try:
                resolved = path.resolve()
            except OSError as exc:
                print(f"warning: skipping unresolved path {path}: {exc}", file=sys.stderr)
                continue
            if resolved == output or resolved == output_tmp:
                continue
            indexed_path = app0_path(root, path)
            try:
                st = path.stat()
            except OSError as exc:
                print(f"warning: skipping unreadable file {indexed_path}: {exc}", file=sys.stderr)
                continue
            if not path.is_file():
                continue
            if not validate_and_add_row(
                rows,
                seen,
                st.st_size,
                int(st.st_mtime),
                indexed_path,
                allow_case_collisions,
            ):
                return 3

    write_index(rows, output)
    print(f"indexed {len(rows)} files from {root}")
    print(f"wrote {output}")
    return 0


def is_ftp_url(root: str) -> bool:
    return urlparse(root).scheme.lower() == "ftp"


def ftp_join(parent: str, name: str) -> str:
    parent = parent.rstrip("/")
    return f"{parent}/{name}" if parent else f"/{name}"


def ftp_modify_to_int(value: str) -> int:
    if len(value) >= 14 and value[:14].isdigit():
        return int(value[:14])
    return 0


def ftp_is_dir(ftp: ftplib.FTP, path: str) -> bool:
    old = ftp.pwd()
    try:
        ftp.cwd(path)
        ftp.cwd(old)
        return True
    except ftplib.all_errors:
        try:
            ftp.cwd(old)
        except ftplib.all_errors:
            pass
        return False


def ftp_file_facts(ftp: ftplib.FTP, path: str) -> tuple[int, int]:
    size = 0
    mtime = 0
    try:
        got_size = ftp.size(path)
        if got_size is not None:
            size = int(got_size)
    except ftplib.all_errors:
        pass
    try:
        resp = ftp.sendcmd(f"MDTM {path}")
        parts = resp.split(maxsplit=1)
        if len(parts) == 2:
            mtime = ftp_modify_to_int(parts[1].strip())
    except ftplib.all_errors:
        pass
    return size, mtime


def ftp_list_entries(ftp: ftplib.FTP, current: str) -> list[tuple[str, dict[str, str]]]:
    try:
        return list(ftp.mlsd(current))
    except ftplib.all_errors:
        pass

    names = ftp.nlst(current)
    result: list[tuple[str, dict[str, str]]] = []
    prefix = current.rstrip("/") + "/"
    for item in names:
        name = item[len(prefix):] if item.startswith(prefix) else item.rsplit("/", 1)[-1]
        if name in ("", ".", ".."):
            continue
        remote_path = ftp_join(current, name)
        if ftp_is_dir(ftp, remote_path):
            result.append((name, {"type": "dir"}))
        else:
            size, mtime = ftp_file_facts(ftp, remote_path)
            result.append((name, {"type": "file", "size": str(size), "modify": str(mtime)}))
    return result


def parse_ftp_root(root_url: str) -> tuple[str, int, str, str, str]:
    parsed = urlparse(root_url)
    if not parsed.hostname:
        raise ValueError(f"FTP URL has no host: {root_url}")
    host = parsed.hostname
    port = parsed.port or 21
    user = unquote(parsed.username) if parsed.username else "anonymous"
    password = unquote(parsed.password) if parsed.password else "anonymous@"
    root = unquote(parsed.path or "/")
    if not root.startswith("/"):
        root = "/" + root
    root = root.rstrip("/") or "/"
    return host, port, user, password, root


def collect_ftp_rows(
    ftp: ftplib.FTP,
    root: str,
    allow_case_collisions: bool,
) -> tuple[int, list[tuple[int, int, str]]]:
    seen: dict[str, str] = {}
    rows: list[tuple[int, int, str]] = []
    dirs_seen = 0
    stack = [root]
    while stack:
        current = stack.pop()
        dirs_seen += 1
        try:
            entries = ftp_list_entries(ftp, current)
        except ftplib.error_perm as exc:
            print(f"warning: skipping unreadable FTP directory {current}: {exc}", file=sys.stderr)
            continue
        entries.sort(key=lambda item: item[0].lower())

        child_dirs: list[str] = []
        for name, facts in entries:
            if name in (".", ".."):
                continue
            typ = facts.get("type", "").lower()
            remote_path = ftp_join(current, name)
            if typ == "dir":
                child_dirs.append(remote_path)
                continue
            if typ not in ("file", ""):
                continue

            rel = remote_path[len(root):].lstrip("/") if root != "/" else remote_path.lstrip("/")
            indexed_path = "/app0/" + rel.replace("\\", "/")
            indexed_key = key_for(indexed_path)
            if indexed_key in ("/app0/ampr_emu.index", "/app0/ampr_emu.index.tmp"):
                continue

            size = int(facts.get("size", "0") or "0")
            mtime = ftp_modify_to_int(facts.get("modify", ""))
            if not validate_and_add_row(rows, seen, size, mtime, indexed_path, allow_case_collisions):
                raise ValueError("case-insensitive path collision")
        stack.extend(reversed(child_dirs))
    return dirs_seen, rows


def upload_index_to_ftp(ftp: ftplib.FTP, root: str, output: Path) -> None:
    remote_tmp = ftp_join(root, "ampr_emu.index.tmp")
    remote_dst = ftp_join(root, "ampr_emu.index")
    with output.open("rb") as f:
        ftp.storbinary(f"STOR {remote_tmp}", f)
    try:
        ftp.delete(remote_dst)
    except ftplib.all_errors:
        pass
    ftp.rename(remote_tmp, remote_dst)
    print(f"uploaded {remote_dst}")


def build_index_ftp(root_url: str, output: Path, allow_case_collisions: bool, upload: bool) -> int:
    ftp: ftplib.FTP | None = None
    try:
        host, port, user, password, root = parse_ftp_root(root_url)
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=30)
        ftp.login(user, password)

        dirs_seen, rows = collect_ftp_rows(ftp, root, allow_case_collisions)
        write_index(rows, output)
        print(f"indexed {len(rows)} files from {root_url} ({dirs_seen} directories)")
        print(f"wrote {output.resolve()}")
        if upload:
            upload_index_to_ftp(ftp, root, output.resolve())
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        if ftp is not None:
            try:
                ftp.quit()
            except ftplib.all_errors:
                ftp.close()


def run_build(root_text: str, allow_case_collisions: bool) -> int:
    if is_ftp_url(root_text):
        output = Path("ampr_emu.index")
        return build_index_ftp(root_text, output, allow_case_collisions, upload=False)

    root = Path(root_text)
    output = root / "ampr_emu.index"
    return build_index_local(root, output, allow_case_collisions)


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class QueueWriter:
    """Redireciona stdout/stderr para uma fila consumida pela GUI."""

    def __init__(self, q: "queue.Queue[str]") -> None:
        self._queue = q

    def write(self, text: str) -> int:
        if text:
            self._queue.put(text)
        return len(text)

    def flush(self) -> None:
        pass


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Gerador de Indice AMPR (ampr_emu.index)")
        self.geometry("720x520")
        self.minsize(640, 420)

        self._log_queue: "queue.Queue[str]" = queue.Queue()
        self._worker: threading.Thread | None = None

        self._build_widgets()
        self.after(100, self._poll_log_queue)

    def _build_widgets(self) -> None:
        pad = {"padx": 8, "pady": 4}

        frm = ttk.Frame(self)
        frm.pack(fill="x", **pad)

        # Pasta raiz / URL FTP
        ttk.Label(frm, text="Pasta do Jogo (Dump):").grid(row=0, column=0, sticky="w")
        self.root_var = tk.StringVar()
        self.root_var.trace_add("write", self._on_root_changed)
        ttk.Entry(frm, textvariable=self.root_var).grid(row=1, column=0, sticky="ew")
        ttk.Button(frm, text="Procurar...", command=self._browse_root).grid(row=1, column=1, padx=4)

        # Versao detectada do libSceAmpr.sprx
        self.version_var = tk.StringVar(value="Versao do libSceAmpr.sprx: -")
        ttk.Label(frm, textvariable=self.version_var).grid(row=2, column=0, sticky="w", pady=(4, 0))
        ttk.Button(frm, text="Atualizar libSceAmpr.sprx...", command=self._update_ampr_sprx).grid(
            row=2, column=1, padx=4, pady=(4, 0)
        )

        frm.columnconfigure(0, weight=1)

        # Opcoes
        opts = ttk.Frame(self)
        opts.pack(fill="x", **pad)

        self.allow_collisions_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            opts,
            text="Permitir colisoes de nomes (diferem so por maiusculas/minusculas)",
            variable=self.allow_collisions_var,
        ).pack(anchor="w")

        # Botoes de acao
        actions = ttk.Frame(self)
        actions.pack(fill="x", **pad)

        self.run_button = ttk.Button(actions, text="Gerar indice", command=self._on_run)
        self.run_button.pack(side="left")

        ttk.Button(actions, text="Limpar log", command=self._clear_log).pack(side="left", padx=8)

        # Log
        ttk.Label(self, text="Log:").pack(anchor="w", padx=8)
        self.log_text = scrolledtext.ScrolledText(self, state="disabled", wrap="word")
        self.log_text.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    # -- Acoes de UI ---------------------------------------------------

    def _browse_root(self) -> None:
        path = filedialog.askdirectory(title="Selecione a pasta raiz")
        if path:
            self.root_var.set(path)

    def _update_ampr_sprx(self) -> None:
        root_text = self.root_var.get().strip()
        if not root_text or is_ftp_url(root_text):
            messagebox.showerror("Erro", "Selecione uma pasta do jogo (Dump) local valida primeiro.")
            return

        root = Path(root_text)
        if not root.is_dir():
            messagebox.showerror("Erro", f"Pasta nao encontrada: {root}")
            return

        src = filedialog.askopenfilename(
            title="Selecione o novo arquivo libSceAmpr.sprx",
            filetypes=[("Todos os arquivos", "*.*")],
        )
        if not src:
            return

        dest_dir = root / "fakelib"
        dest = dest_dir / "libSceAmpr.sprx"
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
        except OSError as exc:
            messagebox.showerror("Erro", f"Falha ao copiar arquivo: {exc}")
            return

        messagebox.showinfo("Sucesso", f"Arquivo atualizado em:\n{dest}")
        self._on_root_changed()

    def _on_root_changed(self, *_args: object) -> None:
        root_text = self.root_var.get().strip()
        if not root_text or is_ftp_url(root_text):
            self.version_var.set("Versao do libSceAmpr.sprx: -")
            return
        version = detect_ampr_version(root_text)
        self.version_var.set(f"Versao do libSceAmpr.sprx: {version}")

    def _clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _append_log(self, text: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _poll_log_queue(self) -> None:
        try:
            while True:
                text = self._log_queue.get_nowait()
                self._append_log(text)
        except queue.Empty:
            pass
        self.after(100, self._poll_log_queue)

    def _on_run(self) -> None:
        root_text = self.root_var.get().strip()
        allow_case_collisions = self.allow_collisions_var.get()

        if not root_text:
            messagebox.showerror("Erro", "Informe a pasta raiz ou a URL FTP.")
            return

        if self._worker is not None and self._worker.is_alive():
            messagebox.showinfo("Aguarde", "Ja existe uma geracao de indice em andamento.")
            return

        self._clear_log()
        self.run_button.configure(state="disabled")

        self._worker = threading.Thread(
            target=self._run_build_thread,
            args=(root_text, allow_case_collisions),
            daemon=True,
        )
        self._worker.start()

    def _run_build_thread(self, root_text: str, allow_case_collisions: bool) -> None:
        writer = QueueWriter(self._log_queue)
        old_stdout, old_stderr = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = writer, writer
        try:
            code = run_build(root_text, allow_case_collisions)
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            code = 1
        finally:
            sys.stdout, sys.stderr = old_stdout, old_stderr

        if code == 0:
            self._log_queue.put("\nConcluido com sucesso.\n")
        else:
            self._log_queue.put(f"\nFinalizado com codigo de erro {code}.\n")

        self.after(0, lambda: self.run_button.configure(state="normal"))


def main() -> int:
    app = App()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
