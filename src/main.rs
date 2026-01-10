use age_recipient_pq::HybridRecipient;
use secrecy::ExposeSecret;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <recipient_file> <identity_file>", args[0]);
        std::process::exit(1);
    }
    let recipient_file = &args[1];
    let identity_file = &args[2];

    println!("Generating X-Wing keypair...");
    let (recipient, identity) = HybridRecipient::generate()?;

    println!("Writing recipient to {}", recipient_file);
    fs::write(recipient_file, recipient.to_string())?;

    println!("Writing identity to {}", identity_file);
    fs::write(identity_file, identity.to_string().expose_secret())?;

    println!("Keypair generated successfully.");
    Ok(())
}
