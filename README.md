# EMV Payment System Simulation

A C++17 simulation of an EMV (Europay, Mastercard, Visa) chip card payment flow, demonstrating how real-world payment systems combine asymmetric and symmetric encryption, multi-currency conversion, and adaptive authentication to protect sensitive card data end-to-end.

---

## Overview

This project models three actors in an EMV transaction:

| Actor | Class | Role |
|---|---|---|
| Bank | `Bank` | Issues RSA keys, holds the AES-encrypted card database, authenticates cardholders |
| Terminal | `Terminal` | Point-of-sale device; drives the full payment flow and logs transactions |
| Card | `Card` | Cardholder's chip card; exposes only RSA-encrypted field accessors |

A fourth component handles currency:

| Component | Class | Role |
|---|---|---|
| Currency Converter | `CurrencyConverter` | Converts merchant amounts to card currency via USD pivot rates |

The flow mirrors a real contactless/contact EMV payment:

```
Card number entered
    → Luhn + DB verification
    → Transaction type selected (Contactless / Contact)
    → Conditional authentication (see rules below)
    → Currency conversion (if merchant ≠ card currency)
    → Balance debited
    → RSA keys displayed (successful transactions only)
    → Receipt logged
```

---

## Authentication Rules

Authentication behaviour depends on transaction type and amount. The contactless limit is evaluated in **AUD** regardless of the merchant's billing currency, ensuring a consistent threshold across all currency pairs.

| Transaction Type | Amount (AUD equivalent) | Authentication |
|---|---|---|
| Contact | Any | ✅ Always required |
| Contactless | ≤ 100 AUD | ❌ Not required |
| Contactless | > 100 AUD | ✅ Required |

When authentication is required, the cardholder has **3 attempts** before the transaction is locked out and declined.

---

## Currency Conversion

The terminal operates in its own currency (AUD in the demo). If a card is denominated in a different currency, the charge is automatically converted before debiting.

Conversion uses **USD as a pivot currency** — only N rates are needed rather than N² direct pairs. The conversion breakdown is printed at payment time:

```
  CURRENCY CONVERSION
  Merchant amount : 150.00 AUD
  Exchange rate   : 1 AUD = 0.6536 USD  →  0.6013 EUR
  Charge to card  : 90.20 EUR
```

Supported currencies: USD, EUR, AUD, GBP, JPY, CAD, CHF, CNY, INR, SGD.

> **Production note:** The `CurrencyConverter` constructor contains a clearly marked hook for replacing the hardcoded rate table with a live API fetch (e.g. `exchangerate-api.com`).

---

## Cryptography

| Purpose | Algorithm |
|---|---|
| Card field transmission | RSA-2048, OAEP-SHA256 padding |
| Card database at rest | AES-256-CBC, random IV per session |
| PIN / Password hashing | SHA-384 |

All raw card data (PAN, CVV, expiry, balance, credentials) is AES-encrypted before being stored in the in-memory database. Every card getter encrypts its return value with the bank's RSA public key, so plaintext never crosses a class boundary. Credentials are compared by hash only — the plaintext credential is never held in a variable during comparison.

RSA keys are printed to the console **only** on successful payment completion. A declined payment, failed authentication, or invalid card suppresses key output entirely.

---

## Card Validation

- **Luhn algorithm** — verifies the check digit of the PAN, iterating right-to-left with correct alternating-digit doubling.
- **Card type detection** — classifies Visa (prefix `4`, length 13/16/19) and Mastercard/EuroCard (prefix 51–55 or 2221–2720, length 16).
- **CVV validation** — enforces the 3-digit range (100–999).
- **Expiry check** — rejects cards that have already passed their expiry month/year.
- **Format guard** — rejects non-digit characters and out-of-range lengths (< 13 or > 19 digits) before any DB lookup.

Invalid card detection is demonstrated in the demo with four distinct failure modes: too short, non-digit character, bad Luhn check digit, and valid format but unknown to the bank.

---

## Demo Walkthrough

The built-in demo runs five transactions covering every code path:

| Act | Type | Amount | Card currency | Auth triggered | Expected outcome |
|---|---|---|---|---|---|
| 1a | Contactless | 49.99 AUD | EUR | ❌ No (under limit) | Payment + FX conversion |
| 1b | Contactless | 150.00 AUD | USD | ✅ Yes (over limit) | PIN → payment + FX conversion |
| 1c | Contact | 25.00 AUD | USD | ✅ Yes (always) | PIN → payment + FX conversion |
| 2  | Contactless | 20.00 AUD | EUR | ❌ No (under limit) | 4 bad cards rejected, 5th succeeds |
| 3  | Contactless | 150.00 AUD | USD | ✅ Yes (over limit) | 3 wrong PINs → lockout |

Demo card reference:

| Card | Network | Auth | Credential | Balance | Currency |
|---|---|---|---|---|---|
| `4338908386379407` | Visa | PASS | `password123` | 2345.67 | EUR |
| `4104332181960018` | Visa | PIN | `1234` | 5467.23 | USD |
| `5300524278680116` | Mastercard | PIN | `1278` | 5420.00 | USD |

Invalid cards for demonstration:

| Number | Failure |
|---|---|
| `41043321819` | Too short (11 digits) |
| `4104332181960O18` | Contains non-digit character |
| `4104332181960011` | Bad Luhn check digit |
| `4012888888881881` | Valid format + Luhn, not in database |

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

The program expects a `credit_card.csv` in the working directory. The first row must be the header:

```
CardNumber,AccountNumber,CVV,ExpDate,Currency,AuthMeth,AuthPass,Balance
```

Example rows:
```
4338908386379407,12345679,234,11/28,EUR,PASS,password123,2345.67
4104332181960018,12345678,123,12/27,USD,PIN,1234,5467.23
```

`AuthMeth` must be `PIN` or `PASS`. `AuthPass` is the raw credential — SHA-384 hashing is handled internally. A sample `credit_card.csv` with 50 Luhn-valid cards (25 Visa, 25 Mastercard) is included in the repository.

---

## Project Structure

```
EMV6.cpp          — Full self-contained source (~1300 lines)
credit_card.csv   — 50-card demo database (25 Visa, 25 Mastercard)
README.md         — This file
```

---

## Key Design Decisions

**Why RSA on every card getter?**
Card objects expose no plaintext — every getter encrypts with the bank's public key before returning. Only the bank's private key can recover the data, enforcing that sensitive fields can only be read by the issuing bank, even within the same process.

**Why AES-256-CBC for the database?**
RSA cannot encrypt arbitrary-length data efficiently. AES-256 provides fast bulk encryption for the card records stored in memory. A random IV is generated per session, so the same plaintext produces different ciphertext each run.

**Why SHA-384 for credentials?**
SHA-384 is a strong one-way function with no known practical preimage attacks. Comparing hashes instead of plaintext eliminates timing-observable string comparisons and means the raw PIN or password is never stored in a local variable during authentication.

**Why USD as the conversion pivot?**
Storing one rate per currency (relative to USD) requires N entries instead of N² direct pairs. Any two supported currencies can be converted in two multiplications: source → USD → target.

**Why AUD as the contactless limit baseline?**
Evaluating the contactless threshold in a single fixed currency (AUD) means the limit is consistent regardless of what currency the merchant bills in. A €60 charge converts to ~91 AUD (under limit), a €70 charge to ~107 AUD (over limit) — the cardholder experiences the same effective ceiling whichever currency is on the receipt.

---

## Limitations & Future Work

This is a demonstration project. A production system would add:

- Persistent encrypted storage (e.g. SQLite with SQLCipher) instead of CSV.
- Proper key management (HSM or KMS) rather than session-ephemeral RSA keys.
- Live exchange rates fetched from a currency API (hook already present in `CurrencyConverter`).
- HMAC-based message authentication to detect in-memory tampering.
- Secure PIN entry (suppressed terminal echo).
- Full EMV kernel compliance (APDU command/response flow, cryptograms, scripts).

---

## License

MIT — see `LICENSE` for details.
