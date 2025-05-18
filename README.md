# charizhard-otp

**charizhard-otp** is a simple, server-side OTP (One-Time Password) generator and validator written in Rust. It allows you to manage the enrollment of CHARIZHARD keys in an infrastructure by verifying the authenticity of the user.

If the OTP is successfully validated, the server securely returns a WireGuard configuration file to the user over a TLS-encrypted connection. This configuration can then be used by the user to establish a VPN connection to the infrastructure, ensuring secure and authenticated access.

## 📦 Installation

> ⚠️ You need to have [Rust](https://www.rust-lang.org/tools/install) installed on your system.

### 🦀 1. Install Rust

Install Rust using [rustup](https://rustup.rs):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo --version
``` 


### ⚙️ 2. Set required environment variables

Before running the application, you need to define the following environment variables:

| Variable             | Description                                        |
|----------------------|--------------------------------------------------|
| `POSTGRES_USER`      | Username for the PostgreSQL database              |
| `POSTGRES_PASSWORD`  | Password for the PostgreSQL database              |
| `DATABASE_URL`       | Full database connection string                   |
| `ENDPOINT_WG`        | Public URL or IP where the WireGuard server is reachable |
| `EMAIL_LOGIN`        | Email address used to send configuration (SMTP)  |
| `EMAIL_PASSWORD`     | Password or app token for the SMTP email login   |


### 🛠 3. Build the project
```bash
git clone https://github.com/esp-charizhard/charizhard-otp
cd charizhard-otp
cargo build --release
```

### ▶️ 4. Run the server
```bash
./target/release/charizhard-otp
```

## 🛠 Usage

Once the server is running, you can interact with it to generate and validate OTPs as part of your authentication workflow.

### OTP Generation (`/gen_otp` endpoint):

- To generate an OTP, send a request to the `/gen_otp` endpoint.
- The communication must be done over **mTLS (mutual TLS)**, using certificates managed by the server's own CA or the company's private CA.
- You **must include the user’s email address in the request headers**.
- The email address must belong to the company domain (e.g., `@pm.me`).
- If the email is verified to belong to the company domain, the server will generate an OTP and send it to the user's email address securely (TLS).

### OTP Validation (`/otp` endpoint):

- When the user receives the OTP, they submit it to the `/otp` endpoint for validation.
- The request **must include the user’s email address and the OTP in the headers**.
- The email provided must correspond to the one associated with the OTP.
- Upon successful validation, the server will securely send a WireGuard VPN configuration file over the TLS-encrypted connection.
- The user can then use this configuration to connect to the company VPN infrastructure.

### Configuration Reset (`/reset` endpoint):

- The server provides a `/reset` endpoint to wipe the VPN configuration associated with a user.
- This operation requires that the client authenticates via mTLS.
- The server verifies that the client certificate used for the TLS connection matches the certificate tied to the user’s VPN configuration.
- If the certificates match, the server securely deletes the user’s VPN configuration, effectively revoking their VPN access.



## License

[GNU GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.fr.html#license-text)