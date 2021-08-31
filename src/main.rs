use gatekeeper_members::{GateKeeperMemberListener, FetchError};
use libgatekeeper_sys::Nfc;

fn main() {
    let mut nfc = Nfc::new().unwrap();
    let mut listener = GateKeeperMemberListener::new(
        &mut nfc, "pn532_uart:/dev/ttyUSB0".to_string()
    ).unwrap();

    loop {
        if let Some(association) = listener.wait_for_user() {
            // Fetch user!
            println!("Read {}", association);
            match listener.fetch_user(association) {
                Ok(value) => {
                    println!("Got user with name {}", value["user"]["uid"]);
                }
                Err(FetchError::NotFound) => {
                    println!("User not found");
                }
                Err(_) => {
                    println!("Failed fetching...");
                }
            };
        }
    }
}
