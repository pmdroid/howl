use std::{fs::Permissions, io, os::unix::fs::PermissionsExt, path::Path};

use serde_json::json;
use tokio::{net::UnixListener, process::Command};

use super::{BootedSandbox, Profile, SandboxProvider, process};
use crate::observer::Snapshot;

pub(super) struct Qemu<'a> {
    profile: &'a Profile,
    binary: &'a Path,
    accelerator: &'static str,
}

impl<'a> Qemu<'a> {
    pub(super) fn new(profile: &'a Profile, binary: &'a Path) -> io::Result<Self> {
        let accelerator = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("macos", "aarch64") => "hvf",
            ("linux", "aarch64") => {
                process::check_kvm(Path::new("/dev/kvm"))?;
                "kvm"
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "microVM workers require ARM64 with HVF or KVM",
                ));
            }
        };
        Ok(Self {
            profile,
            binary,
            accelerator,
        })
    }

    pub(super) fn accelerator(&self) -> &'static str {
        self.accelerator
    }
}

impl SandboxProvider for Qemu<'_> {
    async fn boot(&self, snapshot: Snapshot, inference: bool) -> io::Result<BootedSandbox> {
        let directory = tempfile::Builder::new()
            .prefix("howl-vm-")
            .permissions(Permissions::from_mode(0o700))
            .tempdir_in("/tmp")?;
        let archive = directory.path().join("repo.tar");
        snapshot.archive(&archive)?;
        drop(snapshot);
        let mut command = process::command(self.binary, directory.path());
        command
            .args([
                "-no-user-config",
                "-nodefaults",
                "-no-reboot",
                "-display",
                "none",
                "-monitor",
                "none",
                "-serial",
                "none",
                "-nic",
                "none",
            ])
            .args([
                "-machine",
                "virt",
                "-accel",
                self.accelerator,
                "-cpu",
                "host",
            ])
            .arg("-m")
            .arg(self.profile.memory_mib.to_string())
            .arg("-smp")
            .arg(self.profile.vcpus.to_string())
            .arg("-kernel")
            .arg(&self.profile.kernel)
            .arg("-initrd")
            .arg(&self.profile.initramfs)
            .args([
                "-append",
                "rdinit=/init quiet panic=1",
                "-device",
                "virtio-serial-device,id=howl",
            ])
            .arg("-blockdev")
            .arg(
                json!({ "driver": "raw", "node-name": "repository", "read-only": true,
                "file": { "driver": "file", "filename": archive } })
                .to_string(),
            )
            .args(["-device", "virtio-blk-device,drive=repository"]);
        let acp = port(&mut command, directory.path(), "acp", 1)?;
        let patch = port(&mut command, directory.path(), "patch", 2)?;
        let inference = inference
            .then(|| port(&mut command, directory.path(), "provider", 3))
            .transpose()?;
        let (process, (acp, patch, inference)) = process::boot(&mut command, |pid| async move {
            process::guest_ports(acp, patch, inference, pid).await
        })
        .await?;
        directory.close()?;
        Ok(BootedSandbox {
            acp,
            patch,
            inference,
            process,
        })
    }
}

fn port(
    command: &mut Command,
    directory: &Path,
    name: &str,
    number: u8,
) -> io::Result<UnixListener> {
    let socket = directory.join(name);
    let listener = UnixListener::bind(&socket)?;
    command
        .arg("-chardev")
        .arg(format!(
            "socket,id={name},path={},server=off",
            socket.display()
        ))
        .arg("-device")
        .arg(format!(
            "virtserialport,bus=howl.0,nr={number},chardev={name},name=howl.{name}"
        ));
    Ok(listener)
}
