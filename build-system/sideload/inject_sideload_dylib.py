#!/usr/bin/env python3
"""Inject sideloadFixerLol.dylib into an unsigned IPA for black-screen sideload fixes.

Copies the dylib into Payload/*.app/Frameworks, rewrites its install name to
@executable_path/Frameworks/..., and adds LC_LOAD_DYLIB to the main executable
when header padding allows. Intended for CI post-processing before artifact upload.
"""

from __future__ import annotations

import argparse
import os
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile


LC_REQ_DYLIB = 0x80000018  # LC_LOAD_WEAK_DYLIB
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE


def align(n: int, a: int) -> int:
    return (n + a - 1) & ~(a - 1)


def read_u32(data: bytes, off: int, le: bool) -> int:
    fmt = "<I" if le else ">I"
    return struct.unpack_from(fmt, data, off)[0]


def write_u32(buf: bytearray, off: int, value: int, le: bool) -> None:
    fmt = "<I" if le else ">I"
    struct.pack_into(fmt, buf, off, value)


def set_dylib_id(path: str, new_id: str) -> None:
    """Rewrite LC_ID_DYLIB path in-place when the new id fits the existing cmdsize."""
    data = bytearray(open(path, "rb").read())
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == MH_MAGIC_64:
        le = True
    elif magic == MH_CIGAM_64:
        le = False
    else:
        raise SystemExit(f"unsupported mach-o magic in {path}: {magic:#x}")

    ncmds = read_u32(data, 16, le)
    sizeofcmds = read_u32(data, 20, le)
    off = 32
    end = 32 + sizeofcmds
    while off + 8 <= end and ncmds > 0:
        cmd = read_u32(data, off, le)
        cmdsize = read_u32(data, off + 4, le)
        if cmdsize < 8:
            raise SystemExit(f"invalid cmdsize in {path}")
        if cmd == LC_ID_DYLIB:
            name_off = read_u32(data, off + 8, le)
            abs_name = off + name_off
            # space available until end of this command
            avail = cmdsize - name_off
            encoded = new_id.encode("utf-8") + b"\x00"
            if len(encoded) > avail:
                raise SystemExit(
                    f"new install name too long for existing LC_ID_DYLIB slot "
                    f"({len(encoded)} > {avail}): {new_id}"
                )
            data[abs_name : abs_name + avail] = encoded.ljust(avail, b"\x00")
            open(path, "wb").write(data)
            return
        off += cmdsize
        ncmds -= 1
    raise SystemExit(f"LC_ID_DYLIB not found in {path}")


def add_load_dylib(binary_path: str, dylib_path: str, weak: bool = True) -> None:
    data = bytearray(open(binary_path, "rb").read())
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == MH_MAGIC_64:
        le = True
    elif magic == MH_CIGAM_64:
        le = False
    else:
        raise SystemExit(f"unsupported mach-o magic in {binary_path}: {magic:#x}")

    ncmds = read_u32(data, 16, le)
    sizeofcmds = read_u32(data, 20, le)
    header_size = 32
    cmds_end = header_size + sizeofcmds

    # Skip if already present
    off = header_size
    remaining = ncmds
    while remaining > 0 and off + 8 <= cmds_end:
        cmd = read_u32(data, off, le)
        cmdsize = read_u32(data, off + 4, le)
        if cmd in (LC_LOAD_DYLIB, LC_REQ_DYLIB, LC_ID_DYLIB) and cmdsize >= 24:
            name_off = read_u32(data, off + 8, le)
            name = data[off + name_off : off + cmdsize].split(b"\x00", 1)[0].decode("utf-8", "replace")
            if name == dylib_path:
                print(f"load command already present: {dylib_path}")
                return
        off += cmdsize
        remaining -= 1

    encoded = dylib_path.encode("utf-8") + b"\x00"
    # dylib_command: cmd, cmdsize, name.offset, timestamp, current_version, compatibility_version + path
    cmd_payload_size = 24 + len(encoded)
    cmdsize = align(cmd_payload_size, 8)
    padding = cmdsize - cmd_payload_size

    # Find first non-zero byte after load commands = end of available header padding
    pad_start = cmds_end
    pad_end = pad_start
    while pad_end < len(data) and data[pad_end] == 0:
        pad_end += 1
    available = pad_end - pad_start
    if available < cmdsize:
        raise SystemExit(
            f"not enough mach-o header padding to insert load command "
            f"(need {cmdsize}, have {available}) in {binary_path}"
        )

    cmd = LC_REQ_DYLIB if weak else LC_LOAD_DYLIB
    fmt = "<" if le else ">"
    blob = struct.pack(
        fmt + "IIIIII",
        cmd,
        cmdsize,
        24,  # name offset from start of command
        0,   # timestamp
        0x10000,  # current_version 1.0.0
        0x10000,  # compatibility_version 1.0.0
    ) + encoded + (b"\x00" * padding)

    data[pad_start : pad_start + cmdsize] = blob
    write_u32(data, 16, ncmds + 1, le)
    write_u32(data, 20, sizeofcmds + cmdsize, le)
    open(binary_path, "wb").write(data)
    print(f"inserted {'weak ' if weak else ''}LC_LOAD_DYLIB {dylib_path}")


def app_executable(app_dir: str) -> str:
    info_path = os.path.join(app_dir, "Info.plist")
    with open(info_path, "rb") as f:
        info = plistlib.load(f)
    exe = info.get("CFBundleExecutable")
    if not exe:
        raise SystemExit(f"CFBundleExecutable missing in {info_path}")
    path = os.path.join(app_dir, exe)
    if not os.path.isfile(path):
        raise SystemExit(f"executable not found: {path}")
    return path


def inject_ipa(ipa_path: str, dylib_src: str) -> None:
    if not os.path.isfile(ipa_path):
        raise SystemExit(f"IPA not found: {ipa_path}")
    if not os.path.isfile(dylib_src):
        raise SystemExit(f"dylib not found: {dylib_src}")

    work = tempfile.mkdtemp(prefix="sideload-inject-")
    try:
        with zipfile.ZipFile(ipa_path, "r") as zf:
            zf.extractall(work)

        payload = os.path.join(work, "Payload")
        apps = [d for d in os.listdir(payload) if d.endswith(".app")]
        if len(apps) != 1:
            raise SystemExit(f"expected one .app in Payload, found {apps!r}")
        app_dir = os.path.join(payload, apps[0])
        frameworks = os.path.join(app_dir, "Frameworks")
        os.makedirs(frameworks, exist_ok=True)

        dylib_name = os.path.basename(dylib_src)
        dylib_dst = os.path.join(frameworks, dylib_name)
        shutil.copy2(dylib_src, dylib_dst)

        load_path = f"@executable_path/Frameworks/{dylib_name}"
        # Prefer install_name_tool when available (macOS CI); fall back to in-place rewrite.
        if shutil.which("install_name_tool"):
            subprocess.check_call(["install_name_tool", "-id", load_path, dylib_dst])
        else:
            set_dylib_id(dylib_dst, load_path)

        binary = app_executable(app_dir)
        add_load_dylib(binary, load_path, weak=True)

        tmp_ipa = ipa_path + ".tmp"
        if os.path.exists(tmp_ipa):
            os.remove(tmp_ipa)
        # Store zip like Xcode IPA (no compression required; deflated is fine)
        with zipfile.ZipFile(tmp_ipa, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(work):
                for name in files:
                    full = os.path.join(root, name)
                    rel = os.path.relpath(full, work)
                    zf.write(full, rel)
        os.replace(tmp_ipa, ipa_path)
        print(f"updated IPA: {ipa_path}")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ipa", required=True)
    parser.add_argument("--dylib", required=True)
    args = parser.parse_args()
    inject_ipa(os.path.abspath(args.ipa), os.path.abspath(args.dylib))


if __name__ == "__main__":
    main()
