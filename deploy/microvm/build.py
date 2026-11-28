import argparse
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("modules", type=Path, help="gzip newc initramfs for the selected ARM64 kernel")
parser.add_argument("model")
parser.add_argument("output", type=Path, help="new directory for the guest initramfs")
parser.add_argument("--rootfs-image", help="existing trusted ARM64 image with the locked Codex ACP runtime, Git, kmod and iproute2")
args = parser.parse_args()
if not re.fullmatch(r"[a-zA-Z0-9._-]{1,128}", args.model):
    parser.error("invalid model ID")
if args.output.exists():
    parser.error("choose a new output directory")
guest = Path(__file__).resolve().parent
crate = guest.parents[1] / "crates/howl"
adapter = crate / "tests/fixtures/codex-acp"
with tempfile.TemporaryDirectory() as scratch:
    context = Path(scratch)
    for path in (guest/"Dockerfile", guest/"init", guest/"worker.cjs", guest/"codex-guest.mjs",
                 adapter/"launch-codex.mjs", adapter/"package.json", adapter/"package-lock.json",
                 crate/"src/provider_bridge.cjs"):
        shutil.copyfile(path, context/path.name.replace("provider_bridge", "provider-bridge"))
    shutil.copyfile(args.modules, context/"modules.cpio.gz")
    (context/"howl-model").write_text(args.model + "\n")
    command = ["docker", "build", "--platform", "linux/arm64", "--output", "type=local,dest=" + str(args.output.resolve())]
    if args.rootfs_image:
        command.extend(["--build-arg", "CODEX_ROOTFS=" + args.rootfs_image])
    subprocess.run([*command, str(context)], check=True)
