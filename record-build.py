"""Prepare build provenance before starting captures. Run from the quicly source checkout."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess


def cmake_abe_enabled(cmake_cache_text):
    """Whether QUICLY_USE_ABE is compiled in, read from CMAKE_C_FLAGS (last -D wins; header default is 1)."""
    flags = next((line.split("=", 1)[1] for line in cmake_cache_text.splitlines()
                  if line.startswith("CMAKE_C_FLAGS:")), "")
    value = "1"
    for token in flags.split():
        if token.startswith("-DQUICLY_USE_ABE="):
            value = token.rsplit("=", 1)[1]
    return value != "0"


def collect_build_info(build):
    """Collect (or reuse a cached copy of) the build's provenance: source diff, dependency versions, compiler/CMake
    configuration, and executable hashes. Cached in the build directory itself, keyed by the binaries' current hashes, so a
    rebuild is detected and recollected automatically instead of silently going stale."""
    binary_sha256 = {name: hashlib.sha256((build / name).read_bytes()).hexdigest()
                      for name in ["cli", "http09", "tunulator"]}
    cache_path = build / ".build-info-cache.json"
    if cache_path.exists():
        cached = json.loads(cache_path.read_text())
        if cached.get("binary_sha256") == binary_sha256:
            return cached
    cmake_cache = (build / "CMakeCache.txt").read_text() if (build / "CMakeCache.txt").exists() else ""
    info = dict(
        commit=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        source_diff=subprocess.check_output(["git", "diff", "HEAD", "--"], text=True),
        submodules=subprocess.check_output(["git", "submodule", "status", "--recursive"], text=True),
        kernel=platform.release(), machine=platform.machine(),
        compiler=subprocess.check_output(["cc", "--version"], text=True),
        cmake_cache=cmake_cache, abe_enabled=cmake_abe_enabled(cmake_cache),
        binary_sha256=binary_sha256)
    cache_path.write_text(json.dumps(info, indent=2) + "\n")
    return info


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', type=Path, required=True)
    args = p.parse_args()
    collect_build_info(args.build.resolve())


if __name__ == '__main__':
    main()
