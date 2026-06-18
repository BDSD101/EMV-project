/**
 * @file    EMV6.cpp
 * @brief   EMV Payment System Simulation
 *
 * Simulates a simplified EMV (Europay, Mastercard, Visa) chip card payment
 * flow including card validation, RSA/AES encryption, PIN/password
 * authentication, and transaction management.
 *
 * The terminal prompts the operator to enter a card number at the start of
 * every transaction. The bank looks up the card in its encrypted database,
 * verifies all fields, then challenges the cardholder for their PIN or
 * password — regardless of whether the transaction is Contactless or Contact.
 *
 * Cryptography: Crypto++ 8.x (RSA-2048 OAEP-SHA256, AES-256-CBC, SHA-384)
 * Standard:     C++17
 *
 * Build (macOS / Homebrew):
 *   g++ -std=c++17 EMV6.cpp -o emv -lcryptopp \
 *       -I$(brew --prefix cryptopp)/include \
 *       -L$(brew --prefix cryptopp)/lib
 *
 * Build (Linux):
 *   g++ -std=c++17 EMV6.cpp -o emv -lcryptopp
 *
 * @note    This is a demonstration/educational project. Credentials and card
 *          data are stored in plain-text CSV files for simplicity; a production
 *          system would use a hardened database with proper key management.
 */

// ============================================================
//  Standard library headers
// ============================================================
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <list>
#include <random>
#include <ctime>
#include <chrono>
#include <thread>
#include <limits>
#include <stdexcept>
#include <algorithm>
#include <iomanip>
#include <filesystem>

// ============================================================
//  Crypto++ headers
// ============================================================
#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include "cryptopp/base64.h"
#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/secblock.h"
#include "cryptopp/pwdbased.h"
#include "cryptopp/sha.h"

namespace fs = std::filesystem;

// ============================================================
//  Global constants
// ============================================================

/// Maximum consecutive authentication attempts before lockout.
constexpr int MAX_ATTEMPTS = 3;

/// AES key sizes in bytes.
const int AES_128_KEY_SIZE = CryptoPP::AES::DEFAULT_KEYLENGTH; // 16
const int AES_192_KEY_SIZE = 24;
const int AES_256_KEY_SIZE = CryptoPP::AES::MAX_KEYLENGTH;     // 32

/// Visual separator for console output.
const std::string SEP = "======================================================";

/// Populated with the bank's RSA public key after Bank construction.
CryptoPP::RSA::PublicKey BANK_PUBLIC_KEY{};

// ============================================================
//  RSA helpers
// ============================================================

/**
 * @brief  Encrypts plaintext with RSA-OAEP-SHA256 and Base64-encodes the result.
 * @param  plaintext  Data to encrypt.
 * @param  publicKey  RSA public key.
 * @return Base64-encoded ciphertext string.
 */
std::string encryptRSA(const std::string& plaintext,
                       CryptoPP::RSA::PublicKey& publicKey)
{
    CryptoPP::AutoSeededRandomPool rng;
    std::string cipher, encoded;

    CryptoPP::RSAES_OAEP_SHA256_Encryptor enc(publicKey);
    CryptoPP::StringSource(plaintext, true,
        new CryptoPP::PK_EncryptorFilter(rng, enc,
            new CryptoPP::StringSink(cipher)));

    CryptoPP::StringSource(cipher, true,
        new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded)));

    return encoded;
}

/**
 * @brief  Decrypts a Base64-encoded RSA-OAEP-SHA256 ciphertext.
 * @param  encoded     Ciphertext produced by encryptRSA().
 * @param  privateKey  RSA private key.
 * @return Recovered plaintext.
 */
std::string decryptRSA(const std::string& encoded,
                       CryptoPP::RSA::PrivateKey& privateKey)
{
    CryptoPP::AutoSeededRandomPool rng;
    std::string cipher, recovered;

    CryptoPP::StringSource(encoded, true,
        new CryptoPP::Base64Decoder(new CryptoPP::StringSink(cipher)));

    CryptoPP::RSAES_OAEP_SHA256_Decryptor dec(privateKey);
    CryptoPP::StringSource(cipher, true,
        new CryptoPP::PK_DecryptorFilter(rng, dec,
            new CryptoPP::StringSink(recovered)));

    return recovered;
}

// ============================================================
//  AES helpers
// ============================================================

/**
 * @brief  Generates a random AES key of the requested byte length.
 * @param  keyLength  16, 24, or 32 bytes (128 / 192 / 256 bit).
 * @return SecByteBlock containing random key material.
 * @throws std::invalid_argument on unsupported key length.
 */
CryptoPP::SecByteBlock generateAESKey(int keyLength)
{
    if (keyLength != AES_128_KEY_SIZE &&
        keyLength != AES_192_KEY_SIZE &&
        keyLength != AES_256_KEY_SIZE)
    {
        throw std::invalid_argument(
            "Invalid AES key length. Choose 128, 192, or 256 bits.");
    }
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::SecByteBlock key(keyLength);
    rng.GenerateBlock(key, key.size());
    return key;
}

/**
 * @brief  Generates a random 16-byte AES initialisation vector.
 * @return SecByteBlock containing the IV.
 */
CryptoPP::SecByteBlock generateAESIV()
{
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    rng.GenerateBlock(iv, iv.size());
    return iv;
}

/**
 * @brief  Encrypts plaintext with AES-256-CBC.
 * @param  plaintext  Data to encrypt.
 * @param  key        AES key.
 * @param  iv         Initialisation vector.
 * @return Raw ciphertext as a std::string.
 */
std::string encryptAES(const std::string& plaintext,
                       const CryptoPP::SecByteBlock& key,
                       const CryptoPP::SecByteBlock& iv)
{
    std::string cipher;
    CryptoPP::AES::Encryption aesEnc(key, key.size());
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEnc(aesEnc, iv);
    CryptoPP::StringSource(plaintext, true,
        new CryptoPP::StreamTransformationFilter(cbcEnc,
            new CryptoPP::StringSink(cipher)));
    return cipher;
}

/**
 * @brief  Decrypts AES-256-CBC ciphertext.
 * @param  cipher  Raw ciphertext produced by encryptAES().
 * @param  key     AES key.
 * @param  iv      Initialisation vector.
 * @return Recovered plaintext.
 */
std::string decryptAES(const std::string& cipher,
                       const CryptoPP::SecByteBlock& key,
                       const CryptoPP::SecByteBlock& iv)
{
    std::string decrypted;
    CryptoPP::AES::Decryption aesDec(key, key.size());
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDec(aesDec, iv);
    CryptoPP::StringSource(cipher, true,
        new CryptoPP::StreamTransformationFilter(cbcDec,
            new CryptoPP::StringSink(decrypted)));
    return decrypted;
}

// ============================================================
//  Hashing
// ============================================================

/**
 * @brief  Computes a SHA-384 hex digest.
 * @param  input  Data to hash (PIN digits, password string, etc.).
 * @return 96-character uppercase hex string.
 */
std::string hashSHA384(const std::string& input)
{
    std::string digest;
    CryptoPP::SHA384 hash;
    CryptoPP::StringSource(input, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest), /*uppercase=*/true)));
    return digest;
}

// ============================================================
//  Console / input utilities
// ============================================================

/// Clears a failed or dirty std::cin state.
void clearInputBuffer()
{
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

/**
 * @brief  Returns local date-time as "HH:MM HRS - DD/MM/YY AEST".
 * @return Formatted date-time string.
 */
std::string getCurrentDateTime()
{
    std::time_t t   = std::time(nullptr);
    std::tm*    now = std::localtime(&t);

    std::ostringstream oss;
    oss << std::setw(2) << std::setfill('0') << now->tm_hour << ':'
        << std::setw(2) << std::setfill('0') << now->tm_min
        << " HRS - "
        << std::setw(2) << std::setfill('0') << now->tm_mday << '/'
        << std::setw(2) << std::setfill('0') << (now->tm_mon + 1)  << '/'
        << std::setw(2) << std::setfill('0') << (now->tm_year % 100)
        << " AEST";
    return oss.str();
}

// ============================================================
//  Class: UserData
// ============================================================

/**
 * @class UserData
 * @brief Stores a cardholder's personal details and manages account numbering.
 *
 * Account numbers are auto-incremented by reading the last row of
 * userdata.csv so each new user receives a unique sequential number.
 */
class UserData
{
public:
    UserData(const std::string& firstName,
             const std::string& lastName,
             const std::string& address)
        : firstName_(firstName), lastName_(lastName), address_(address)
    {
        accountNumber_ = readLastAccountNumber() + 1;
    }

    /// Prints cardholder information to stdout.
    void displayUserInfo() const
    {
        std::cout << SEP << '\n'
                  << "  Name:    " << firstName_ << ' ' << lastName_ << '\n'
                  << "  Address: " << address_   << '\n'
                  << "  Account: " << accountNumber_ << '\n'
                  << SEP << '\n';
    }

private:
    std::string firstName_;
    std::string lastName_;
    std::string address_;
    int         accountNumber_{0};
    const std::string CSV_FILE_ = "userdata.csv";

    /**
     * @brief  Reads the last account number from userdata.csv.
     * @return Last account number found, or 1000 if file is absent/empty.
     */
    int readLastAccountNumber() const
    {
        std::ifstream file(CSV_FILE_);
        if (!file.is_open()) return 1000;

        std::string line;
        int lastNum = 1000;

        while (std::getline(file, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            std::istringstream ss(line);
            std::string cell;
            std::vector<std::string> row;
            while (std::getline(ss, cell, ','))
                row.push_back(cell);
            if (!row.empty()) {
                try { lastNum = std::stoi(row[0]); }
                catch (...) {}
            }
        }
        return lastNum;
    }
};

// ============================================================
//  Class: Card
// ============================================================

/**
 * @class Card
 * @brief Represents an EMV payment card with encrypted field accessors.
 *
 * All sensitive getter methods RSA-encrypt their return value with the
 * bank's public key before returning — raw data never crosses a class
 * boundary in plaintext.
 *
 * Validated on construction:
 *  - CVV range (100–999)
 *  - Expiry date (not yet passed)
 *  - PAN length and character set
 *  - Luhn check digit
 *  - Card network (Visa / Mastercard-EuroCard)
 */
class Card
{
public:
    /**
     * @param cardNumber  PAN (13–19 digits).
     * @param cvv         3-digit CVV.
     * @param expDate     "MM/YY" expiry string.
     * @param currency    ISO 4217 currency code.
     * @param accountNb   Issuing bank account number.
     * @throws std::invalid_argument  on invalid CVV.
     * @throws std::runtime_error     if the card is expired.
     */
    Card(const std::string& cardNumber, int cvv,
         const std::string& expDate,
         const std::string& currency, int accountNb)
        : cardNumber_(cardNumber), cvv_(cvv), expDate_(expDate),
          currency_(currency), accountNb_(accountNb)
    {
        validateCVV(cvv);
        validateExpirationDate(expDate);
        validateAndPrintCardNumber();
        cardType_ = determineCardType();
    }

    // --------------------------------------------------------
    //  RSA-encrypted getters
    // --------------------------------------------------------
    std::string getCardNumber() const { return encryptRSA(cardNumber_, BANK_PUBLIC_KEY); }
    std::string getAccountNb()  const { return encryptRSA(std::to_string(accountNb_), BANK_PUBLIC_KEY); }
    std::string getCVV()        const { return encryptRSA(std::to_string(cvv_), BANK_PUBLIC_KEY); }
    std::string getExpDate()    const { return encryptRSA(expDate_, BANK_PUBLIC_KEY); }
    std::string getCurrency()   const { return encryptRSA(currency_, BANK_PUBLIC_KEY); }
    std::string getBalance()    const { return encryptRSA(std::to_string(balance_), BANK_PUBLIC_KEY); }

    /**
     * @brief  Validates the expiry date and throws if the card has expired.
     * @param  expDate  "MM/YY" string.
     * @throws std::runtime_error if expired.
     */
    void validateExpirationDate(const std::string& expDate) const
    {
        int month = 0, year = 0;
        char delim = '/';
        std::istringstream ss(expDate);
        ss >> month >> delim >> year;
        if (isCardExpired(month, year))
            throw std::runtime_error("Card is expired.");
    }

private:
    const std::string cardNumber_;
    const int         cvv_;
    const std::string expDate_;
    std::string       currency_;
    double            balance_{0.0};
    const int         accountNb_;
    std::string       cardType_;

    // --------------------------------------------------------
    //  Private helpers
    // --------------------------------------------------------

    /// Returns PAN with all but the last four digits masked.
    std::string getMaskedCardNumber() const
    {
        if (cardNumber_.size() < 4)
            return std::string(cardNumber_.size(), '*');
        return std::string(cardNumber_.size() - 4, '*') +
               cardNumber_.substr(cardNumber_.size() - 4);
    }

    void getCurrentMonthYear(int& month, int& year) const
    {
        std::time_t t   = std::time(nullptr);
        std::tm*    now = std::localtime(&t);
        month = now->tm_mon + 1;
        year  = now->tm_year % 100;
    }

    bool isCardExpired(int expMonth, int expYear) const
    {
        int curMonth = 0, curYear = 0;
        getCurrentMonthYear(curMonth, curYear);
        return (expYear < curYear) ||
               (expYear == curYear && expMonth <= curMonth);
    }

    void validateCVV(int cvv) const
    {
        if (cvv < 100 || cvv > 999)
            throw std::invalid_argument("CVV must be a 3-digit number.");
    }

    /**
     * @brief  Validates the PAN with the Luhn algorithm.
     *
     * Iterates right-to-left, doubling every second digit and subtracting 9
     * when the result exceeds 9. Valid if the total is divisible by 10.
     */
    bool validateLuhn() const
    {
        if (cardNumber_.empty() ||
            !std::all_of(cardNumber_.begin(), cardNumber_.end(), ::isdigit))
            return false;

        int  sum       = 0;
        bool alternate = false;

        for (int i = static_cast<int>(cardNumber_.size()) - 1; i >= 0; --i) {
            int n = cardNumber_[i] - '0';
            if (alternate) {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alternate = !alternate;
        }
        return (sum % 10 == 0);
    }

    /**
     * @brief  Identifies the card network from PAN prefix and length.
     * @return "Visa", "Mastercard / EuroCard", or "Unknown Card Type".
     */
    std::string determineCardType() const
    {
        if (cardNumber_.empty()) return "Unknown Card Type";

        // Visa: starts with 4, length 13 / 16 / 19
        if (cardNumber_[0] == '4' &&
            (cardNumber_.size() == 13 ||
             cardNumber_.size() == 16 ||
             cardNumber_.size() == 19))
            return "Visa";

        if (cardNumber_.size() == 16) {
            int first2 = std::stoi(cardNumber_.substr(0, 2));
            int first4 = std::stoi(cardNumber_.substr(0, 4));
            // Mastercard: prefix 51–55 or 2221–2720
            if ((first2 >= 51 && first2 <= 55) ||
                (first4 >= 2221 && first4 <= 2720))
                return "Mastercard / EuroCard";
        }

        return "Unknown Card Type";
    }

    /// Runs all structural checks and prints the result.
    void validateAndPrintCardNumber() const
    {
        if (cardNumber_.empty())          { std::cout << "Card number is empty.\n";                          return; }
        if (cardNumber_.size() < 13)      { std::cout << "Card number is too short.\n";                      return; }
        if (cardNumber_.size() > 19)      { std::cout << "Card number is too long.\n";                       return; }
        if (!std::all_of(cardNumber_.begin(), cardNumber_.end(), ::isdigit))
                                          { std::cout << "Card number contains non-digit characters.\n";     return; }

        if (validateLuhn()) {
            std::cout << "Card " << getMaskedCardNumber()
                      << " is VALID  [" << determineCardType() << "]\n";
        } else {
            std::cout << "Card number is INVALID (Luhn check failed).\n";
        }
    }
};

// ============================================================
//  Class: Bank
// ============================================================

/**
 * @class Bank
 * @brief Simulates the card-issuing bank's back-end.
 *
 * Responsibilities:
 *  - Holds a 2048-bit RSA key pair (private key never leaves the class).
 *  - Maintains an in-memory AES-256-CBC encrypted card database (encDB_).
 *  - Looks up cards by PAN, verifies all fields, and authenticates cardholders.
 *  - Supports card lookup directly by raw PAN string (used by the terminal
 *    when the operator enters a card number at the point of sale).
 *
 * @note CSV column order: CardNumber, AccountNumber, CVV, ExpDate, Currency,
 *       AuthMeth (PIN|PASS), AuthPass, Balance.
 *       The first row is treated as a header and skipped automatically.
 */
class Bank
{
public:
    // --------------------------------------------------------
    //  Encrypted card record (all fields AES-encrypted at rest)
    // --------------------------------------------------------
    struct CardRecord {
        std::string cardNo;
        std::string accNo;
        std::string cvv;
        std::string expDate;
        std::string currency;
        std::string authMethod;
        std::string authCredential;
        std::string balance;
    };

    // --------------------------------------------------------
    //  Constructor
    // --------------------------------------------------------

    /// Generates RSA keys, publishes the public key, and loads the card DB.
    Bank()
    {
        generateBankRSAKeys();
        BANK_PUBLIC_KEY = publicKey_;
        loadEncryptedCardDB("credit_card.csv");
    }

    // --------------------------------------------------------
    //  Public key accessor
    // --------------------------------------------------------
    CryptoPP::RSA::PublicKey getPublicKey() const { return publicKey_; }

    // --------------------------------------------------------
    //  Card lookup by raw PAN (used by Terminal::promptAndLoadCard)
    // --------------------------------------------------------

    /**
     * @brief  Looks up a card record by its plaintext PAN.
     *
     * Called by the Terminal after the operator types a card number.
     * Returns a fully-constructed Card object if the PAN exists in the DB,
     * throws otherwise.
     *
     * @param  pan  Plaintext card number entered by the operator.
     * @return Card object populated from the matched DB record.
     * @throws std::runtime_error if no matching record is found.
     */
    Card lookupCardByPAN(const std::string& pan)
    {
        for (const CardRecord& rec : encDB_) {
            if (decryptAES(rec.cardNo, secretKey_, iv_) == pan) {
                int         accNo    = std::stoi(decryptAES(rec.accNo,   secretKey_, iv_));
                int         cvv      = std::stoi(decryptAES(rec.cvv,     secretKey_, iv_));
                std::string expDate  = decryptAES(rec.expDate,  secretKey_, iv_);
                std::string currency = decryptAES(rec.currency, secretKey_, iv_);
                // Card constructor runs Luhn + expiry validation
                return Card(pan, cvv, expDate, currency, accNo);
            }
        }
        throw std::runtime_error("Card not found in database.");
    }

    // --------------------------------------------------------
    //  Card verification
    // --------------------------------------------------------

    /**
     * @brief  Verifies all card fields against the encrypted DB.
     * @param  card  Card whose encrypted getters will be queried.
     * @return true if a fully-matching, non-expired record is found.
     */
    bool checkCardDetail(const Card& card)
    {
        const std::string cardNum  = decryptRSA(card.getCardNumber(), privateKey_);
        const std::string accNum   = decryptRSA(card.getAccountNb(),  privateKey_);
        const std::string cardCVV  = decryptRSA(card.getCVV(),        privateKey_);
        const std::string expDate  = decryptRSA(card.getExpDate(),    privateKey_);
        const std::string currency = decryptRSA(card.getCurrency(),   privateKey_);

        card.validateExpirationDate(expDate);

        for (const CardRecord& rec : encDB_) {
            if (decryptAES(rec.cardNo,   secretKey_, iv_) == cardNum  &&
                decryptAES(rec.accNo,    secretKey_, iv_) == accNum   &&
                decryptAES(rec.cvv,      secretKey_, iv_) == cardCVV  &&
                decryptAES(rec.expDate,  secretKey_, iv_) == expDate  &&
                decryptAES(rec.currency, secretKey_, iv_) == currency)
            {
                return true;
            }
        }
        return false;
    }

    // --------------------------------------------------------
    //  Authentication
    // --------------------------------------------------------

    /**
     * @brief  Authenticates the cardholder for the given card.
     *
     * Locates the matching DB record, decrypts the auth method and stored
     * credential, then runs the interactive authenticate() loop.
     * Authentication is always required, regardless of transaction type
     * (Contactless or Contact).
     *
     * @param  card  The card being presented.
     * @return true on successful authentication within MAX_ATTEMPTS.
     */
    bool cardAuthentication(Card& card)
    {
        const std::string cardNo = decryptRSA(card.getCardNumber(), privateKey_);

        for (const CardRecord& rec : encDB_) {
            if (decryptAES(rec.cardNo, secretKey_, iv_) == cardNo) {
                const std::string method     = decryptAES(rec.authMethod,     secretKey_, iv_);
                const std::string credential = decryptAES(rec.authCredential, secretKey_, iv_);
                return authenticate(method, credential);
            }
        }
        std::cerr << "Error: card not found during authentication.\n";
        return false;
    }

    // --------------------------------------------------------
    //  Payment processing
    // --------------------------------------------------------

    /**
     * @brief  Deducts @p cost from the card's stored balance.
     *
     * Checks the current balance, deducts if funds are sufficient, and
     * updates the in-memory encrypted record.
     *
     * @param  card  Card to debit.
     * @param  cost  Amount to deduct (in the card's currency).
     */
    void processPayment(Card& card, double cost)
    {
        const std::string cardNo = decryptRSA(card.getCardNumber(), privateKey_);

        for (CardRecord& rec : encDB_) {
            if (decryptAES(rec.cardNo, secretKey_, iv_) == cardNo) {
                double      balance  = std::stod(decryptAES(rec.balance,  secretKey_, iv_));
                std::string currency = decryptAES(rec.currency, secretKey_, iv_);

                std::cout << "Current balance: "
                          << std::fixed << std::setprecision(2)
                          << balance << ' ' << currency << '\n';

                if (balance >= cost) {
                    balance    -= cost;
                    rec.balance = encryptAES(std::to_string(balance), secretKey_, iv_);

                    std::cout << "Payment successful. "
                              << std::fixed << std::setprecision(2)
                              << cost << ' ' << currency << " debited.\n"
                              << "New balance: "
                              << std::fixed << std::setprecision(2)
                              << balance << ' ' << currency << '\n';
                } else {
                    std::cout << "Payment declined: insufficient funds.\n";
                }
                return;
            }
        }
        std::cerr << "Error: card not found during payment.\n";
    }

    /**
     * @brief  Returns the ISO currency code for the given card.
     * @param  card  Card whose currency to look up.
     * @return Currency string (e.g. "EUR"), or "AUD" if not found.
     */
    std::string getCurrency(Card& card)
    {
        const std::string cardNo = decryptRSA(card.getCardNumber(), privateKey_);
        for (const CardRecord& rec : encDB_) {
            if (decryptAES(rec.cardNo, secretKey_, iv_) == cardNo)
                return decryptAES(rec.currency, secretKey_, iv_);
        }
        return "AUD";
    }

    /// Prints Base64-DER-encoded RSA public and private keys to stdout.
    void printKeys()
    {
        std::cout << "Public Key (Base64 DER):\n"
                  << encodeKeyToBase64(publicKey_)  << '\n'
                  << SEP << '\n'
                  << "Private Key (Base64 DER):\n"
                  << encodeKeyToBase64(privateKey_) << '\n';
    }

private:
    // --------------------------------------------------------
    //  Private members
    // --------------------------------------------------------
    CryptoPP::RSA::PublicKey  publicKey_;
    CryptoPP::RSA::PrivateKey privateKey_;
    CryptoPP::SecByteBlock    secretKey_{generateAESKey(AES_256_KEY_SIZE)};
    CryptoPP::SecByteBlock    iv_{generateAESIV()};
    std::vector<CardRecord>   encDB_;

    // --------------------------------------------------------
    //  Private helpers
    // --------------------------------------------------------

    /// Generates a fresh 2048-bit RSA key pair.
    void generateBankRSAKeys()
    {
        CryptoPP::AutoSeededRandomPool rng;
        privateKey_.GenerateRandomWithKeySize(rng, 2048);
        publicKey_.AssignFrom(privateKey_);
    }

    /**
     * @brief  Reads credit_card.csv, AES-encrypts every field, and stores
     *         records in encDB_.  The first row (header) is skipped.
     * @param  filename  Path to the plain-text card database CSV.
     */
    void loadEncryptedCardDB(const std::string& filename)
    {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Warning: could not open '" << filename
                      << "'. No card records loaded.\n";
            return;
        }

        std::string line;
        bool firstRow = true;

        while (std::getline(file, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;

            // Skip header — any row whose first character is not a digit
            if (firstRow) {
                firstRow = false;
                if (!::isdigit(static_cast<unsigned char>(line[0])))
                    continue;
            }

            std::istringstream ss(line);
            std::vector<std::string> cols;
            std::string cell;

            while (std::getline(ss, cell, ',')) {
                auto s = cell.find_first_not_of(" \t");
                auto e = cell.find_last_not_of(" \t");
                cols.push_back((s == std::string::npos) ? "" : cell.substr(s, e - s + 1));
            }

            if (cols.size() < 8) continue;

            CardRecord rec;
            rec.cardNo         = encryptAES(cols[0], secretKey_, iv_);
            rec.accNo          = encryptAES(cols[1], secretKey_, iv_);
            rec.cvv            = encryptAES(cols[2], secretKey_, iv_);
            rec.expDate        = encryptAES(cols[3], secretKey_, iv_);
            rec.currency       = encryptAES(cols[4], secretKey_, iv_);
            rec.authMethod     = encryptAES(cols[5], secretKey_, iv_);
            rec.authCredential = encryptAES(cols[6], secretKey_, iv_);
            rec.balance        = encryptAES(cols[7], secretKey_, iv_);
            encDB_.push_back(rec);
        }

        std::cout << "Bank: loaded " << encDB_.size()
                  << " card record(s) from '" << filename << "'.\n";
    }

    /**
     * @brief  Interactive authentication loop (up to MAX_ATTEMPTS tries).
     *
     * Compares SHA-384 hashes of the entered credential against the stored
     * hash to avoid timing-observable plaintext comparisons.
     *
     * @param  authMethod  "PIN" or "PASS".
     * @param  storedCred  Plaintext credential from the decrypted DB record.
     * @return true on success.
     */
    bool authenticate(const std::string& authMethod,
                      const std::string& storedCred)
    {
        const std::string storedHash = hashSHA384(storedCred);
        int  attempts = 0;
        bool success  = false;

        while (attempts < MAX_ATTEMPTS && !success) {
            ++attempts;

            std::string input;
            std::cout << ((authMethod == "PIN") ? "Enter your PIN: "
                                                : "Enter your Password: ");
            std::cin >> input;
            clearInputBuffer();
            std::cout << SEP << '\n';

            if (hashSHA384(input) == storedHash) {
                success = true;
            } else if (attempts < MAX_ATTEMPTS) {
                std::cout << "Incorrect. "
                          << (MAX_ATTEMPTS - attempts)
                          << " attempt(s) remaining.\n" << SEP << '\n';
            } else {
                std::cout << "Authentication failed after " << MAX_ATTEMPTS
                          << " attempts. Payment declined.\n";
            }
        }
        return success;
    }

    std::string encodeKeyToBase64(const CryptoPP::RSA::PublicKey& key) const
    {
        std::string encoded;
        CryptoPP::Base64Encoder enc(new CryptoPP::StringSink(encoded));
        key.DEREncode(enc);
        enc.MessageEnd();
        return encoded;
    }

    std::string encodeKeyToBase64(const CryptoPP::RSA::PrivateKey& key) const
    {
        std::string encoded;
        CryptoPP::Base64Encoder enc(new CryptoPP::StringSink(encoded));
        key.DEREncode(enc);
        enc.MessageEnd();
        return encoded;
    }
};

// ============================================================
//  Class: Terminal
// ============================================================

/**
 * @class Terminal
 * @brief Represents a point-of-sale (POS) terminal.
 *
 * The terminal drives the full payment flow:
 *  1. Prompts the operator to type the customer's card number.
 *  2. Asks the bank to look up and return a Card object.
 *  3. Verifies the card details with the bank.
 *  4. Lets the customer choose Contactless or Contact.
 *  5. Challenges the customer for their PIN / password (always required).
 *  6. Processes the payment through the bank.
 *  7. Logs the transaction to the internal list.
 */
class Terminal
{
public:
    Terminal() = default;

    /**
     * @brief  Runs a complete end-to-end payment transaction.
     *
     * Prompts for the card number, validates, selects transaction type,
     * authenticates (PIN/password always required), and processes payment.
     *
     * @param  bank     Bank that issued the card.
     * @param  amount   Amount to charge.
     * @param  merchant Description of the merchant / purchase location.
     */
    void runTransaction(Bank& bank, double amount, const std::string& merchant)
    {
        std::cout << '\n' << SEP << '\n'
                  << "  NEW TRANSACTION\n"
                  << SEP << '\n';

        // Step 1 — Card number entry
        Card card = promptAndLoadCard(bank);

        // Step 2 — Verify card against bank DB
        std::cout << SEP << '\n';
        if (!bank.checkCardDetail(card)) {
            std::cout << "Card details are invalid or not found. Transaction aborted.\n";
            return;
        }
        std::cout << "Card details verified.\n" << SEP << '\n';

        // Step 3 — Transaction type (Contactless / Contact)
        std::string txType = selectTransactionType();
        std::cout << SEP << '\n';

        // Step 4 — Authentication (PIN or password, always required)
        std::cout << "Authentication required for "
                  << txType << " transaction.\n" << SEP << '\n';
        if (!bank.cardAuthentication(card)) {
            std::cout << "Transaction aborted due to failed authentication.\n";
            return;
        }
        std::cout << "Authentication successful. Proceeding with payment.\n"
                  << SEP << '\n';

        // Step 5 — Payment
        bank.processPayment(card, amount);

        // Step 6 — Log (only reached on successful payment)
        std::string currency = bank.getCurrency(card);
        std::string txDate   = getCurrentDateTime();
        long long   tun      = generateTUN();
        transactions_.emplace_back(tun, currency, merchant, txType, txDate, amount);

        std::cout << SEP << '\n'
                  << "  Transaction complete.\n"
                  << "  TUN: " << tun << '\n'
                  << SEP << '\n';

        // Keys are shown only on successful payment completion.
        bank.printKeys();
    }

    /// Prints all recorded transactions to stdout.
    void displayTransactions() const
    {
        if (transactions_.empty()) {
            std::cout << "No transactions recorded.\n";
            return;
        }
        std::cout << '\n' << SEP << '\n'
                  << "  TRANSACTION LOG\n" << SEP << '\n';
        for (const Transaction& tx : transactions_) {
            std::cout << "  TUN:      " << tx.tun                              << '\n'
                      << "  Merchant: " << tx.merchant                         << '\n'
                      << "  Amount:   " << std::fixed << std::setprecision(2)
                                        << tx.amount << ' ' << tx.currency     << '\n'
                      << "  Type:     " << tx.type                             << '\n'
                      << "  Date:     " << tx.date                             << '\n'
                      << SEP << '\n';
        }
    }

private:
    // --------------------------------------------------------
    //  Transaction record
    // --------------------------------------------------------
    struct Transaction {
        long long   tun;
        std::string currency;
        std::string merchant;
        std::string type;
        std::string date;
        double      amount;

        Transaction(long long t, std::string c, std::string m,
                    std::string tp, std::string d, double a)
            : tun(t), currency(std::move(c)), merchant(std::move(m)),
              type(std::move(tp)), date(std::move(d)), amount(a) {}
    };

    std::list<Transaction> transactions_;

    // --------------------------------------------------------
    //  Private helpers
    // --------------------------------------------------------

    /**
     * @brief  Prompts the operator to enter a card number, validates its
     *         basic format (digits only, 13–19 chars), then asks the bank
     *         to look up the full card record.
     *
     * Retries indefinitely on invalid format; throws if the bank cannot
     * find the PAN in its database.
     *
     * @param  bank  Bank to query for the card record.
     * @return Fully-constructed and validated Card object.
     */
    Card promptAndLoadCard(Bank& bank) const
    {
        while (true) {
            std::string pan;
            std::cout << "Enter card number: ";
            std::cin >> pan;
            clearInputBuffer();

            // Basic format check before hitting the DB
            if (pan.size() < 13 || pan.size() > 19 ||
                !std::all_of(pan.begin(), pan.end(), ::isdigit))
            {
                std::cout << "Invalid card number format. "
                             "Must be 13–19 digits. Try again.\n";
                continue;
            }

            try {
                Card card = bank.lookupCardByPAN(pan);
                return card;
            } catch (const std::exception& ex) {
                std::cout << "Error: " << ex.what()
                          << " Please check the number and try again.\n";
            }
        }
    }

    /**
     * @brief  Prompts for transaction type selection.
     * @return "Contactless" or "Contact".
     */
    std::string selectTransactionType() const
    {
        int choice = 0;
        std::cout << "Transaction type: 1) Contactless  2) Contact: ";
        while (true) {
            std::cin >> choice;
            if (std::cin.fail() || (choice != 1 && choice != 2)) {
                clearInputBuffer();
                std::cout << "Invalid input. Enter 1 or 2: ";
            } else {
                break;
            }
        }
        clearInputBuffer();
        return (choice == 1) ? "Contactless" : "Contact";
    }

    /// Generates a cryptographically seeded random 16-digit TUN.
    long long generateTUN() const
    {
        std::random_device rd;
        std::mt19937_64    gen(rd());
        std::uniform_int_distribution<long long> dist(
            1'000'000'000'000'000LL,
            9'999'999'999'999'999LL);
        return dist(gen);
    }
};

// ============================================================
//  Entry point
// ============================================================

/**
 * @brief  Drives a structured EMV demonstration session.
 *
 * The demo is split into three acts:
 *
 *  ACT 1 — Valid transactions
 *    Two successful payments using different auth methods (PASS and PIN).
 *
 *  ACT 2 — Invalid card detection
 *    The terminal is fed four bad card numbers in sequence, each triggering
 *    a different validation error:
 *      a) Too short   (11 digits)
 *      b) Non-digit   (contains letter 'O')
 *      c) Bad Luhn    (valid-looking 16-digit number with wrong check digit)
 *      d) Not in DB   (correct format and Luhn, but unknown to the bank)
 *    After each bad card the terminal loops back and asks again, so
 *    ACT 2 feeds all four bad numbers then a valid one to exit cleanly.
 *
 *  ACT 3 — Wrong PIN lockout
 *    A valid card is presented but the cardholder enters the wrong PIN
 *    three times, triggering the MAX_ATTEMPTS lockout.
 */
int main()
{
    try {
        Terminal terminal;
        Bank     bank;
        UserData user("Bob", "Star", "11 Park Avenue, Switzerland");

        // ================================================================
        //  Reference sheet printed at startup
        // ================================================================
        std::cout << '\n' << SEP << '\n'
                  << "  EMV PAYMENT TERMINAL — DEMO\n"
                  << SEP << '\n'
                  << "  VALID CARDS\n"
                  << "    Card A  (PASS): 4338908386379407  pw: password123   bal: 2345.67 EUR\n"
                  << "    Card B  (PIN):  4104332181960018  PIN: 1234          bal: 5467.23 USD\n"
                  << "    Card C  (PIN):  5300524278680116  PIN: 1278          bal: 5420.00 USD\n"
                  << '\n'
                  << "  INVALID CARDS (for demonstration)\n"
                  << "    Too short:   41043321819\n"
                  << "    Non-digit:   4104332181960O18\n"
                  << "    Bad Luhn:    4104332181960011\n"
                  << "    Not in DB:   4012888888881881\n"
                  << SEP << '\n';

        // ================================================================
        //  ACT 1 — Two successful transactions
        // ================================================================
        std::cout << "\n>>> ACT 1: Valid transactions\n";

        // Transaction 1a — PASS auth
        std::cout << "\n[Enter card: 4338908386379407  then password: password123]\n";
        terminal.runTransaction(bank, 49.99, "Coffee Shop");

        // Transaction 1b — PIN auth
        std::cout << "\n[Enter card: 4104332181960018  then PIN: 1234]\n";
        terminal.runTransaction(bank, 120.00, "Supermarket");

        // ================================================================
        //  ACT 2 — Invalid card detection
        //  The terminal loops on bad input, so we feed four bad numbers
        //  followed by a valid one to let the transaction complete.
        // ================================================================
        std::cout << "\n>>> ACT 2: Invalid card detection\n"
                  << "[Enter in order: 41043321819 → 4104332181960O18 → "
                     "4104332181960011 → 4012888888881881 → 5300524278680116  PIN: 1278]\n";
        terminal.runTransaction(bank, 25.00, "Pharmacy");

        // ================================================================
        //  ACT 3 — Wrong PIN lockout (3 wrong attempts)
        // ================================================================
        std::cout << "\n>>> ACT 3: Wrong PIN lockout\n"
                  << "[Enter card: 4104332181960018  then PIN: 0000 three times]\n";
        terminal.runTransaction(bank, 50.00, "Electronics Store");

        // ================================================================
        //  Receipt — only shown if at least one transaction succeeded
        // ================================================================
        terminal.displayTransactions();


    } catch (const std::exception& ex) {
        std::cerr << "Fatal error: " << ex.what() << '\n';
        return 1;
    }

    return 0;
}
