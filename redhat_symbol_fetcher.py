#!/usr/bin/env python3
import argparse
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


SUPPORTED_PROVIDERS: dict[str, dict[str, str]] = {
    "oracle-el7": {"debuginfo_base_url": ORACLE_OL7_DEBUGINFO},
}


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


def build_debuginfo_url(info: dict, provider: str | None = None, base_url: str | None = None) -> str:
    kernel = info["kernel"]

    if base_url:
        return f"{base_url.rstrip('/')}/kernel-debuginfo-{kernel}.rpm"

    if provider:
        if provider not in SUPPORTED_PROVIDERS:
            raise NotImplementedError(
                f"Unsupported provider: {provider}. Supported: {', '.join(sorted(SUPPORTED_PROVIDERS))}"
            )
        prov_base = SUPPORTED_PROVIDERS[provider]["debuginfo_base_url"]
        return f"{prov_base.rstrip('/')}/kernel-debuginfo-{kernel}.rpm"

    if info["vendor"] == "oracle" and info["distro"] == "el7":
        return f"{ORACLE_OL7_DEBUGINFO}/kernel-debuginfo-{kernel}.rpm"

    raise NotImplementedError(
        f"Cannot infer debuginfo provider from banner. Parsed: {info}\n"
        f"Use --provider one of: {', '.join(sorted(SUPPORTED_PROVIDERS))} or --debuginfo-base-url"
    )


def wget_spider(url: str):
    # Check URL exists
    try:
        run(["wget", "--spider", "-q", url])
    except RuntimeError as e:
        raise RuntimeError(f"URL check failed: {url}\n{e}")


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

    p1 = subprocess.Popen(
        ["rpm2cpio", str(rpm_abs)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )
    p2 = subprocess.Popen(
        ["cpio", "-idmv"],
        cwd=extract_dir,
        stdin=p1.stdout,
        stdout=None,
        stderr=subprocess.PIPE,
        text=True,
    )
    if p1.stdout is not None:
        p1.stdout.close()

    _, p2_err = p2.communicate()
    p1_err = p1.stderr.read().decode(errors="replace") if p1.stderr else ""
    p1_rc = p1.wait()

    if p1_rc != 0:
        raise RuntimeError(f"rpm2cpio failed for: {rpm_abs}\n{p1_err.strip()}")
    if p2.returncode != 0:
        raise RuntimeError(f"cpio failed while extracting: {rpm_abs}\n{(p2_err or '').strip()}")


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


def read_banner_from_args(args: argparse.Namespace) -> str:
    if args.banner:
        return args.banner.strip()
    if args.banner_file:
        p = Path(args.banner_file)
        text = p.read_text(encoding="utf-8", errors="replace")
        line = text.splitlines()[0].strip() if text.splitlines() else ""
        return line
    return ""


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Download debuginfo RPM and build Volatility 3 Linux symbols JSON via dwarf2json."
    )
    p.add_argument("--banner", help="One kernel banner line containing 'Linux version ...'")
    p.add_argument("--banner-file", help="Path to a text file whose first line is the banner")
    p.add_argument(
        "--provider",
        choices=sorted(SUPPORTED_PROVIDERS.keys()),
        help="Force a known debuginfo provider",
    )
    p.add_argument(
        "--debuginfo-base-url",
        help="Override debuginfo base URL (e.g. https://.../debuginfo)",
    )
    p.add_argument(
        "--dwarf2json",
        default=str(Path("./dwarf2json/dwarf2json")),
        help="Path to dwarf2json binary (default: ./dwarf2json/dwarf2json)",
    )
    p.add_argument(
        "--symbols-dir",
        default=str(Path("./symbols")),
        help="Volatility symbols directory root (default: ./symbols)",
    )
    p.add_argument(
        "--workdir",
        default=str(Path("./symbol_work")),
        help="Working directory for downloads/extraction (default: ./symbol_work)",
    )
    p.add_argument(
        "--list-providers",
        action="store_true",
        help="List supported providers and exit",
    )
    return p


def main():
    args = build_arg_parser().parse_args()

    if args.list_providers:
        for name in sorted(SUPPORTED_PROVIDERS):
            print(name)
        return

    # prerequisites
    need_tool("wget", "wget")
    need_tool("rpm2cpio", "rpm2cpio")
    need_tool("cpio", "cpio")

   
    dwarf2json_path = Path(args.dwarf2json)
    if not dwarf2json_path.exists():
        raise RuntimeError(
            "Cannot find dwarf2json binary at: "
            f"{dwarf2json_path}\nBuild it:\n  git clone https://github.com/volatilityfoundation/dwarf2json.git\n  cd dwarf2json && go build -o dwarf2json ."
        )

    banner_line = read_banner_from_args(args)
    if not banner_line:
        print("[*] Paste ONE line from banners and press Enter:")
        banner_line = sys.stdin.readline().strip()
    if not banner_line:
        print("[-] Empty input")
        sys.exit(1)

    info = parse_banner(banner_line)
    print(f"[+] Parsed: {info}")

    url = build_debuginfo_url(info, provider=args.provider, base_url=args.debuginfo_base_url)

    workdir = Path(args.workdir)
    kernel_workdir = workdir / info["kernel"]
    kernel_workdir.mkdir(parents=True, exist_ok=True)

    rpm_path = kernel_workdir / url.split("/")[-1]
    rpm_path = download(url, rpm_path)

    extract_dir = kernel_workdir / "extract"
    extract_rpm(rpm_path, extract_dir)

    vmlinux = find_vmlinux(extract_dir)

    # Volatility symbols directory: assume script run from volatility3 root
    vol_symbols_root = Path(args.symbols_dir)
    out_json = build_symbols(dwarf2json_path, vmlinux, info["kernel"], vol_symbols_root)

    print("\nDONE")
    print(f"[+] Installed: {out_json}")
   


if __name__ == "__main__":
    main()

