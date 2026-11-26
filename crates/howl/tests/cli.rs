use std::process::Command;

#[test]
fn help_describes_usage() {
    let output = Command::new(env!("CARGO_BIN_EXE_howl"))
        .arg("--help")
        .output()
        .expect("run howl --help");

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage: howl"));
}

#[test]
fn version_matches_package() {
    let output = Command::new(env!("CARGO_BIN_EXE_howl"))
        .arg("--version")
        .output()
        .expect("run howl --version");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        concat!("howl ", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn invalid_arguments_fail() {
    let output = Command::new(env!("CARGO_BIN_EXE_howl"))
        .arg("--invalid")
        .output()
        .expect("run howl with invalid argument");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid arguments"));
}
