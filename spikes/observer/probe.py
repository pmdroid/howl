import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()

    if not args.socket.is_absolute() or not args.socket.is_socket():
        parser.error("a local Linux Docker engine socket is required")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image):
        parser.error("a local image ID is required")
    docker = shutil.which("docker")
    if docker is None:
        parser.error("Docker CLI is required")

    with tempfile.TemporaryDirectory(prefix="howl-observer-") as directory:
        root = Path(directory).resolve()
        if "," in str(root):
            parser.error("the temporary directory path cannot contain commas")
        config = root / "docker-config"
        config.mkdir()
        docker = [docker, "--config", str(config), "--host", f"unix://{args.socket}"]
        env = {"PATH": os.defpath}
        info = subprocess.check_output(
            [*docker, "info", "--format", '{"os":{{json .OSType}},"security":{{json .SecurityOptions}}}'],
            env=env,
            timeout=10,
        )
        engine = json.loads(info)
        if engine["os"] != "linux" or "name=seccomp,profile=builtin" not in (engine["security"] or []):
            parser.error("the engine must run Linux with Docker's built-in seccomp profile")

        image_info = subprocess.check_output(
            [*docker, "image", "inspect", "--format", "{{json .Config.Volumes}}", args.image],
            env=env,
            timeout=10,
        )
        if json.loads(image_info):
            parser.error("the observer image must not declare volumes")

        snapshot = root / "snapshot"
        snapshot.mkdir()
        snapshot.chmod(0o777)
        tracked = snapshot / "tracked.txt"
        tracked.write_text("selected snapshot\n")
        tracked.chmod(0o666)
        sentinel = root / "host-credential"
        sentinel.write_text("synthetic credential\n")
        sentinel.chmod(0o644)
        name = f"howl-observer-probe-{uuid.uuid4().hex}"
        try:
            subprocess.run(
                [
                    *docker, "run", "--rm", "--name", name, "--pull=never",
                    "--init", "--read-only", "--network=none", "--cap-drop=ALL",
                    "--security-opt=no-new-privileges", "--user=65532:65532",
                    "--pids-limit=128", "--memory=768m", "--cpus=1",
                    "--tmpfs=/scratch:rw,noexec,nosuid,nodev,size=64m,mode=1777",
                    f"--mount=type=bind,src={snapshot},dst=/workspace,readonly,bind-recursive=disabled",
                    "--workdir=/workspace", "--env=HOME=/scratch", "--env=TMPDIR=/scratch",
                    f"--env=HOWL_PROBE_HOST_PATH={sentinel}",
                    "--entrypoint=/usr/local/bin/node", args.image, "/observer/probe.mjs",
                ],
                env=env,
                check=True,
                timeout=120,
            )
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            subprocess.run(
                [*docker, "rm", "-f", name], env=env, check=False,
                capture_output=True, timeout=10,
            )
            raise
        if tracked.read_text() != "selected snapshot\n":
            raise RuntimeError("observer changed the host snapshot")


if __name__ == "__main__":
    main()
