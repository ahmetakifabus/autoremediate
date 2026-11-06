// Demo hedefi: kasıtlı olarak zafiyetli. Cargo tarafından DERLENMEZ.
use std::process::Command;

fn main() {
    let api_key = "sk-live-1234567890abcdef";
    let user = std::env::args().nth(1).unwrap_or_default();

    let query = format!("SELECT * FROM users WHERE name = '{user}'");
    let out = Command::new("sh").arg("-c").arg(format!("echo {user}")).output();

    let client_url = "http://api.example.com/v1";
    println!("{api_key} {query} {client_url} {out:?}");
}
