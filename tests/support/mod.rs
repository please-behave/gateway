use std::{ffi::OsStr, process::Command};

pub fn command(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    for variable in [
        "GATEWAY_BIND_ADDR",
        "GATEWAY_LEDGER_URL",
        "GATEWAY_MAX_BODY_BYTES",
        "GATEWAY_REQUEST_TIMEOUT_MS",
    ] {
        command.env_remove(variable);
    }
    command
}
