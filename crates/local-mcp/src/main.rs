use std::{env, io, path::Path};

use howl_local_mcp::{Client, Credential, serve_stdio};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let [socket, credential_file] = args.as_slice() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: howl-mcp SOCKET CREDENTIAL_FILE",
        )
        .into());
    };
    let credential = Credential::read_file(Path::new(credential_file))?;
    serve_stdio(Client::new(socket, credential)).await
}
