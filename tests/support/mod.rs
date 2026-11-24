pub mod http;

use std::{ffi::OsStr, process::Command};

pub fn command(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    for variable in [
        "GATEWAY_API_KEYS",
        "GATEWAY_BIND_ADDR",
        "GATEWAY_GITHUB_OIDC_AUDIENCE",
        "GATEWAY_GITHUB_OIDC_REPOSITORIES",
        "GATEWAY_LEDGER_URL",
        "GATEWAY_MAX_BODY_BYTES",
        "GATEWAY_RATE_LIMIT_PER_MINUTE",
        "GATEWAY_REQUEST_TIMEOUT_MS",
    ] {
        command.env_remove(variable);
    }
    command
}
