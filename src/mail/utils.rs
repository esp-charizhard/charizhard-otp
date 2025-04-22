use std::env;

use lettre::{message::SinglePart, transport::smtp::authentication::Credentials, Message};
use lettre::{SmtpTransport, Transport};

pub async fn send_email(dest: &str,otp_code : &str) -> Result<(), Box<dyn std::error::Error>> {
    let sender_email =std::env::var("EMAIL_LOGIN").unwrap(); 
    let sender_password = std::env::var("EMAIl_PASSWORD").unwrap(); 
    let subject = "YOUR OTP CODE"; 

    let email = Message::builder()
    .from(sender_email.parse()?)
    .to(sender_email.parse()?)//TODO MODIF POUR LE BON EMAIL (DEBUG)
    .subject(subject)
    .singlepart(SinglePart::plain(otp_code.to_string()))?;

    let credentials = Credentials::new(sender_email.to_string(), sender_password.to_string());
    
    let mailer = SmtpTransport::relay("smtp.gmail.com")?
        .credentials(credentials)
        .build();
    match mailer.send(&email) {
        Ok(_) => println!("E-mail envoyé avec succès !"),
        Err(e) => panic!("Impossible d'envoyer l'e-mail : {e:?}"),
    }
    Ok(())
}