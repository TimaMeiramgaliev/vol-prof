#!/usr/bin/env python3
import re
import subprocess
import sys
from pathlib import Path

ORACLE_OL7_DEBUGINFO = "https://oss.oracle.com/ol7/debuginfo"


def run(cmd, cwd=None, shell=False):
    """Run command, raise with stderr on failure."""
    result = subprocess.run(
        cmd,
        cwd=cwd,
        shell=shell,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if result.returncode != 0:
        err = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"Command failed: {cmd}\n{err}")
    return result.stdout


def need_tool(name: str, apt_pkg: str | None = None):
    """Fail fast if required tool missing."""
    from shutil import which
    if which(name) is None:
        msg = f"Missing required tool: {name}"
        if apt_pkg:
            msg += f"\nInstall: sudo apt update && sudo apt install {apt_pkg}"
        raise RuntimeError(msg)


def parse_banner(line: str) -> dict:
    # Works with: "0x... Linux version 3.10.0-... (...)"
    m = re.search(r"Linux version ([0-9A-Za-z.\-_]+)", line)
    if not m:
        raise ValueError("Cannot parse kernel version from input line")
    kernel = m.group(1)

    lower = line.lower()
    vendor = "oracle" if ("build-ol7" in lower or "oracle" in lower) else "unknown"
    distro = "el7" if "el7" in kernel else "unknown"

    return {"kernel": kernel, "vendor": vendor, "distro": distro}


def build_debuginfo_url(info: dict) -> str:
    kernel = info["kernel"]
    if info["vendor"] == "oracle" and info["distro"] == "el7":
        return f"{ORACLE_OL7_DEBUGINFO}/kernel-debuginfo-{kernel}.rpm"
    raise NotImplementedError(f"Unsupported vendor/distro for now: {info}")


def wget_spider(url: str):
    # Check URL exists
    run(["wget", "--spider", "-q", url])


def download(url: str, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if out_path.exists() and out_path.stat().st_size > 0:
        print(f"[+] RPM already exists: {out_path}")
        return out_path

    print(f"[+] Checking URL: {url}")
    wget_spider(url)

    print(f"[+] Downloading (this may take a while)...")
    subprocess.run(
        ["wget", "--progress=bar:force", "-O", str(out_path), url],
        check=True
    )

    return out_path


def extract_rpm(rpm_path: Path, extract_dir: Path):
    extract_dir.mkdir(parents=True, exist_ok=True)
    print("[+] Extracting RPM (rpm2cpio | cpio)")

    rpm_abs = rpm_path.resolve() 

    cmd = f"rpm2cpio '{rpm_abs}' | cpio -idmv"
    run(cmd, cwd=extract_dir, shell=True)

    


def find_vmlinux(extract_dir: Path) -> Path:
    print("[+] Searching for vmlinux")
    for p in extract_dir.rglob("vmlinux"):
        # prefer the standard debuginfo path
        if "usr/lib/debug/lib/modules" in str(p):
            print(f"[+] Found vmlinux: {p}")
            return p
    # fallback: any vmlinux
    for p in extract_dir.rglob("vmlinux"):
        print(f"[+] Found vmlinux: {p}")
        return p
    raise FileNotFoundError("vmlinux not found after RPM extraction")


def build_symbols(dwarf2json_path: Path, vmlinux: Path, kernel: str, vol_symbols_root: Path) -> Path:
    linux_dir = vol_symbols_root / "linux"
    linux_dir.mkdir(parents=True, exist_ok=True)

    out_json = linux_dir / f"{kernel}.json"
    print(f"[+] Building symbol JSON: {out_json} (this may take time)")

    # Write JSON to file
    with out_json.open("w") as f:
        proc = subprocess.run(
            [str(dwarf2json_path), "linux", "--elf", str(vmlinux)],
            stdout=f,
            stderr=subprocess.PIPE,
            text=True
        )
    if proc.returncode != 0:
        raise RuntimeError(f"dwarf2json failed:\n{proc.stderr}")

    if out_json.stat().st_size < 1024 * 1024:  # sanity check: usually many MB
        raise RuntimeError(f"Symbol JSON looks too small ({out_json.stat().st_size} bytes). Something went wrong.")

    return out_json


def main():
    # prerequisites
    need_tool("wget", "wget")
    need_tool("rpm2cpio", "rpm2cpio")
    need_tool("cpio", "cpio")

   
    dwarf2json_path = Path("./dwarf2json/dwarf2json")
    if not dwarf2json_path.exists():
        raise RuntimeError("Cannot find ./dwarf2json.\nBuild it:\n  git clone https://github.com/volatilityfoundation/dwarf2json.git\n  cd dwarf2json && go build -o dwarf2json .\n  cp dwarf2json <сюда>")

    print("[*] Paste ONE line from banners and press Enter:")
    banner_line = sys.stdin.readline().strip()
    if not banner_line:
        print("[-] Empty input")
        sys.exit(1)

    info = parse_banner(banner_line)
    print(f"[+] Parsed: {info}")

    url = build_debuginfo_url(info)

    workdir = Path("./symbol_work")
    workdir.mkdir(parents=True, exist_ok=True)  # FIX: create workdir early

    rpm_path = workdir / url.split("/")[-1]
    rpm_path = download(url, rpm_path)

    extract_dir = workdir / "extract"
    extract_rpm(rpm_path, extract_dir)

    vmlinux = find_vmlinux(extract_dir)

    # Volatility symbols directory: assume script run from volatility3 root
    vol_symbols_root = Path("./symbols")
    out_json = build_symbols(dwarf2json_path, vmlinux, info["kernel"], vol_symbols_root)

    print("\nDONE")
    print(f"[+] Installed: {out_json}")
   


if __name__ == "__main__":
    main()

