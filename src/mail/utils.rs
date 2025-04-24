use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{message::SinglePart, transport::smtp::authentication::Credentials, Message};
use lettre::{SmtpTransport, Transport};

pub async fn send_email(_dest: &str,otp_code : &str) -> Result<(), Box<dyn std::error::Error>> {
    let sender_email =std::env::var("EMAIL_LOGIN").unwrap(); 
    let sender_password = std::env::var("EMAIL_PASSWORD").unwrap(); 
    let subject = "YOUR OTP CODE"; 

    let email = Message::builder()
    .from(sender_email.parse()?)
    .to(sender_email.parse()?)//TODO MODIF POUR LE BON EMAIL (DEBUG)
    .subject(subject)
    .singlepart(SinglePart::plain(otp_code.to_string()))?;

    let credentials = Credentials::new(sender_email.to_string(), sender_password.to_string());
    
    // let mailer = SmtpTransport::relay("smtp.gmail.com")?
    //     .credentials(credentials)
    //     .build();
    let tls_params = TlsParameters::builder("smtp.gmail.com".to_string())
    .dangerous_accept_invalid_certs(true) 
    .build()
    .unwrap();

let mailer = SmtpTransport::relay("smtp.gmail.com")
    .unwrap()
    .tls(Tls::Wrapper(tls_params))
    .credentials(credentials) 
    .build();

    match mailer.send(&email) {
        Ok(_) => println!("E-mail envoyé avec succès !"),
        Err(e) => panic!("Impossible d'envoyer l'e-mail : {e:?}"),
    }
    Ok(())
}