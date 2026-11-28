use std::{fs::Permissions, io, os::unix::fs::PermissionsExt, path::Path};

use serde_json::json;
use tokio::net::UnixListener;

use super::{BootedSandbox, Profile, SandboxProvider, process};
use crate::observer::Snapshot;

pub(super) struct Firecracker<'a> {
    profile: &'a Profile,
    binary: &'a Path,
}

impl<'a> Firecracker<'a> {
    pub(super) fn new(profile: &'a Profile, binary: &'a Path) -> io::Result<Self> {
        if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Firecracker workers require x86-64 Linux with KVM",
            ));
        }
        process::check_kvm(Path::new("/dev/kvm"))?;
        Ok(Self { profile, binary })
    }
}

impl SandboxProvider for Firecracker<'_> {
    async fn boot(&self, snapshot: Snapshot, inference: bool) -> io::Result<BootedSandbox> {
        let directory = tempfile::Builder::new()
            .prefix("howl-vm-")
            .permissions(Permissions::from_mode(0o700))
            .tempdir_in("/tmp")?;
        let path = directory.path();
        let archive = path.join("repo.tar");
        snapshot.archive(&archive)?;
        drop(snapshot);
        let acp = UnixListener::bind(path.join("guest_7821"))?;
        let patch = UnixListener::bind(path.join("guest_7822"))?;
        let broker = inference
            .then(|| UnixListener::bind(path.join("guest_7823")))
            .transpose()?;
        let boot_args = format!(
            "console=ttyS0 reboot=k panic=1 pci=off rdinit=/init howl.transport=vsock howl.inference={}",
            u8::from(inference)
        );
        let config = json!({
            "boot-source": {
                "kernel_image_path": self.profile.kernel,
                "initrd_path": self.profile.initramfs,
                "boot_args": boot_args,
            },
            "drives": [{
                "drive_id": "repository",
                "path_on_host": archive,
                "is_root_device": false,
                "is_read_only": true,
            }],
            "machine-config": {
                "vcpu_count": self.profile.vcpus,
                "mem_size_mib": self.profile.memory_mib,
                "smt": false,
            },
            "entropy": {
                "rate_limiter": {
                    "bandwidth": { "size": 65536, "one_time_burst": 0, "refill_time": 1000 },
                },
            },
            "vsock": { "guest_cid": 3, "uds_path": path.join("guest") },
        });
        std::fs::write(path.join("config.json"), serde_json::to_vec(&config)?)?;
        let mut command = process::command(self.binary, path);
        command.args(["--no-api", "--config-file", "config.json"]);
        let (process, (acp, patch, inference)) = process::boot(&mut command, |pid| async move {
            process::guest_ports(acp, patch, broker, pid).await
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
