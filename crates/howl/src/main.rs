use std::{env, process::ExitCode};

const HELP: &str = "Howl - agent collaboration\n\nUsage: howl [--help | --version]";

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);

    match (args.next(), args.next()) {
        (None, None) => println!("{HELP}"),
        (Some(arg), None) if arg == "--help" || arg == "-h" => println!("{HELP}"),
        (Some(arg), None) if arg == "--version" || arg == "-V" => {
            println!("howl {}", env!("CARGO_PKG_VERSION"));
        }
        _ => {
            eprintln!("Invalid arguments. Run howl --help.");
            return ExitCode::from(2);
        }
    }

    ExitCode::SUCCESS
}
