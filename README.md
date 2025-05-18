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

## License

[GNU GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.fr.html#license-text)