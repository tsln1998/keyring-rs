//! Foreground entrypoint for the agent service and its local control commands.

#![cfg(not(test))]

mod app;

fn main() -> std::process::ExitCode {
    app::run()
}
