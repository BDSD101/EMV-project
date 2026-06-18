# EMV-project

# EMV Payment System Simulation

A C++17 simulation of an EMV (Europay, Mastercard, Visa) chip card payment flow, demonstrating how real-world payment systems combine asymmetric and symmetric encryption to protect sensitive card data end-to-end.

---

## Overview

This project models three actors in an EMV transaction:

| Actor | Class | Role |
|---|---|---|
| Bank | `Bank` | Issues keys, holds the encrypted card database, authenticates cardholders |
| Terminal | `Terminal` | Point-of-sale device; logs transactions and delegates auth to the bank |
| Card | `Card` | Cardholder's chip card; exposes only RSA-encrypted field accessors |

The flow mirrors a real contactless/contact payment:

```
Card presented → Card detail check → Transaction type selected
    → PIN / Password authentication → Balance debited → Receipt printed
```

---

## Cryptography

| Purpose | Algorithm |
|---|---|
| Card field transmission | RSA-2048, OAEP-SHA256 padding |
| Card database at rest | AES-256-CBC with a random IV per session |
| PIN / Password hashing | SHA-384 |

All raw card data (PAN, CVV, expiry, balance, credentials) is AES-encrypted before being stored in the in-memory database. Card getters encrypt their return value with the bank's RSA public key before returning, so plaintext never crosses a class boundary.

---

## Card Validation

- **Luhn algorithm** — verifies the check digit of the Primary Account Number (PAN).
- **Card type detection** — classifies Visa (prefix `4`, length 13/16/19) and Mastercard/EuroCard (prefix 51–55 or 2221–2720, length 16).
- **CVV validation** — enforces the 3-digit range (100–999).
- **Expiry check** — rejects cards that have already passed their expiry month/year.

---

## Requirements

| Dependency | Version |
|---|---|
| C++ Standard | C++17 or later |
| [Crypto++](https://cryptopp.com/) | 8.x |

Install Crypto++ via Homebrew (macOS):
```bash
brew install cryptopp
```

Or on Ubuntu/Debian:
```bash
sudo apt-get install libcrypto++-dev
```

---

## Building

**macOS (Homebrew):**
```bash
g++ -std=c++17 EMV6.cpp -o emv \
    -lcryptopp \
    -I$(brew --prefix cryptopp)/include \
    -L$(brew --prefix cryptopp)/lib
```

**Linux:**
```bash
g++ -std=c++17 EMV6.cpp -o emv -lcryptopp
```

---

## Running

```bash
./emv
```

The program expects a `credit_card.csv` file in the working directory. The first row must be the header:

```
CardNumber,AccountNumber,CVV,ExpDate,Currency,AuthMeth,AuthPass,Balance
```

Example rows:
```
4716893064521783,12345679,234,11/26,EUR,PASS,password123,2345.67
4929176890231561,12345678,123,12/25,USD,PIN,1234,5467.23
```

> **Note:** `AuthMeth` must be `PIN` or `PASS`. `AuthPass` is the raw credential — hashing is handled internally.

---

## Project Structure

```
EMV6.cpp          — Full self-contained source
credit_card.csv   — Card database (not committed; create locally)
README.md         — This file
```

---

## Key Design Decisions

**Why RSA on every card getter?**  
Card objects expose no plaintext — every getter encrypts with the bank's public key. Only the bank's private key can recover the data, enforcing that sensitive fields can only be read by the issuing bank.

**Why AES-256-CBC for the database?**  
RSA cannot encrypt arbitrary-length data efficiently. AES-256 provides fast, authenticated bulk encryption for the card records stored in memory (and would do the same for a persistent database).

**Why SHA-384 for credentials?**  
SHA-384 is a strong one-way function with no known practical preimage attacks. Comparing hashes instead of plaintext avoids timing-observable string comparisons.

---

## Limitations & Future Work

This is a demonstration project. A production system would add:

- Persistent encrypted storage (e.g. SQLite with SQLCipher) instead of CSV.
- Proper key management (HSM or KMS) rather than session-ephemeral keys.
- HMAC-based message authentication to detect tampering.
- Secure PIN entry (no terminal echo).
- Full EMV kernel compliance (APDU command/response flow).

---

## License

MIT — see `LICENSE` for details.
