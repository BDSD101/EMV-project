/**
 * @file    EMV6.cpp
 * @brief   EMV Payment System Simulation
 *
 * Simulates a simplified EMV (Europay, Mastercard, Visa) chip card payment
 * flow including card validation, RSA/AES encryption, PIN/password
 * authentication, and transaction management.
 *
 * Cryptography: Crypto++ 8.x (RSA-2048 OAEP-SHA256, AES-256-CBC, SHA-384)
 * Standard:     C++17
 *
 * Build:
 *   g++ -std=c++17 EMV6.cpp -o emv -lcryptopp \
 *       -I$(brew --prefix cryptopp)/include \
 *       -L$(brew --prefix cryptopp)/lib
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

/// Maximum number of consecutive authentication attempts before lockout.
constexpr int MAX_ATTEMPTS = 3;

/// AES key sizes in bytes (128 / 192 / 256 bit).
const int AES_128_KEY_SIZE = CryptoPP::AES::DEFAULT_KEYLENGTH; // 16
const int AES_192_KEY_SIZE = 24;
const int AES_256_KEY_SIZE = CryptoPP::AES::MAX_KEYLENGTH;     // 32

/// Separator line used throughout console output.
const std::string SEPARATOR = "======================================================";

/// Lazily populated with the bank's public key after the bank object is created.
CryptoPP::RSA::PublicKey BANK_PUBLIC_KEY{};

// ============================================================
//  RSA helpers
// ============================================================

/**
 * @brief Generates a 2048-bit RSA key pair.
 * @param[out] publicKey  Populated public key.
 * @param[out] privateKey Populated private key.
 */
void generateRSAKeys(CryptoPP::RSA::PublicKey& publicKey,
                     CryptoPP::RSA::PrivateKey& privateKey)
{
    CryptoPP::AutoSeededRandomPool rng;
    privateKey.GenerateRandomWithKeySize(rng, 2048);
    publicKey.AssignFrom(privateKey);
}

/**
 * @brief  Encrypts plaintext with RSA-OAEP-SHA256 and Base64-encodes the result.
 * @param  plaintext  Data to encrypt.
 * @param  publicKey  RSA public key used for encryption.
 * @return Base64-encoded ciphertext.
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
 * @param  encoded     Base64-encoded ciphertext produced by encryptRSA().
 * @param  privateKey  RSA private key used for decryption.
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
 * @brief  Generates a random AES key of the requested size.
 * @param  keyLength  Must be AES_128_KEY_SIZE, AES_192_KEY_SIZE, or
 *                    AES_256_KEY_SIZE.
 * @return SecByteBlock containing the key material.
 * @throws std::invalid_argument if keyLength is not a valid AES size.
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
 * @brief  Generates a random AES initialisation vector (16 bytes).
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
 * @param  key        AES key (SecByteBlock).
 * @param  iv         Initialisation vector (SecByteBlock).
 * @return Raw ciphertext bytes as a std::string.
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
 * @brief  Computes a SHA-384 hex digest of the input string.
 * @param  input  Data to hash (e.g. a PIN or password).
 * @return Uppercase hex string (96 characters).
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
 * @brief  Returns the local date-time formatted as "HH:MM HRS - DD/MM/YY AEST".
 * @return Formatted date-time string.
 */
std::string getCurrentDateTime()
{
    std::time_t t = std::time(nullptr);
    std::tm*    now = std::localtime(&t);

    std::ostringstream oss;
    oss << std::setw(2) << std::setfill('0') << now->tm_hour << ':'
        << std::setw(2) << std::setfill('0') << now->tm_min
        << " HRS - "
        << std::setw(2) << std::setfill('0') << now->tm_mday << '/'
        << std::setw(2) << std::setfill('0') << (now->tm_mon + 1) << '/'
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
 * Account numbers are auto-incremented by reading the last row of userdata.csv
 * so each new user receives a unique sequential number.
 */
class UserData
{
public:
    /**
     * @param firstName Cardholder first name.
     * @param lastName  Cardholder last name.
     * @param address   Cardholder billing address.
     */
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
        std::cout << SEPARATOR << '\n'
                  << "  Name:    " << firstName_ << ' ' << lastName_ << '\n'
                  << "  Address: " << address_   << '\n'
                  << "  Account: " << accountNumber_ << '\n'
                  << SEPARATOR << '\n';
    }

    /**
     * @brief  Prompts the user to pick PIN or Password authentication.
     * @return "PIN" or "Password".
     */
    std::string getAuthenticationChoice() const
    {
        int choice = 0;
        std::cout << "Choose authentication method: 1) PIN  2) Password: ";

        while (true) {
            std::cin >> choice;
            if (std::cin.fail() || (choice != 1 && choice != 2)) {
                clearInputBuffer();
                std::cout << "Invalid input. Enter 1 (PIN) or 2 (Password): ";
            } else {
                break;
            }
        }
        clearInputBuffer();
        return (choice == 1) ? "PIN" : "Password";
    }

private:
    std::string firstName_;
    std::string lastName_;
    std::string address_;
    int         accountNumber_{0};

    const std::string CSV_FILE_ = "userdata.csv";

    /**
     * @brief  Reads the last account number stored in the CSV.
     * @return Last account number found, or 1000 if the file is missing/empty.
     */
    int readLastAccountNumber() const
    {
        std::ifstream file(CSV_FILE_);
        if (!file.is_open()) return 1000;

        std::string line;
        int lastNum = 1000;

        while (std::getline(file, line)) {
            std::istringstream ss(line);
            std::string cell;
            std::vector<std::string> row;

            while (std::getline(ss, cell, ','))
                row.push_back(cell);

            if (!row.empty()) {
                try { lastNum = std::stoi(row[0]); }
                catch (...) { /* skip malformed rows */ }
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
 * All sensitive getter methods encrypt their return value with the bank's
 * RSA public key before returning, ensuring raw data never leaves the object
 * in plaintext over an insecure channel.
 *
 * Card numbers are validated against the Luhn algorithm and classified as
 * Visa or Mastercard/EuroCard on construction.
 */
class Card
{
public:
    /// Authentication methods supported by the card.
    enum class AuthMethod { PIN, PASSWORD };

    /**
     * @param cardNumber  16–19 digit PAN (Primary Account Number).
     * @param cvv         3-digit card verification value.
     * @param expDate     Expiry date string "MM/YY".
     * @param currency    ISO 4217 currency code (e.g. "EUR").
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
    //  Encrypted getters (RSA-encrypted with bank public key)
    // --------------------------------------------------------

    std::string getCardNumber() const { return encryptRSA(cardNumber_, BANK_PUBLIC_KEY); }
    std::string getAccountNb()  const { return encryptRSA(std::to_string(accountNb_), BANK_PUBLIC_KEY); }
    std::string getCVV()        const { return encryptRSA(std::to_string(cvv_), BANK_PUBLIC_KEY); }
    std::string getExpDate()    const { return encryptRSA(expDate_, BANK_PUBLIC_KEY); }
    std::string getCurrency()   const { return encryptRSA(currency_, BANK_PUBLIC_KEY); }
    std::string getBalance()    const { return encryptRSA(std::to_string(balance_), BANK_PUBLIC_KEY); }

    /**
     * @brief  Validates the expiry date string and throws if the card is expired.
     * @param  expDate  "MM/YY" formatted string.
     * @throws std::runtime_error if the card has expired.
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
    // --------------------------------------------------------
    //  Private data members
    // --------------------------------------------------------
    const std::string cardNumber_;
    const int         cvv_;
    const std::string expDate_;
    std::string       currency_;
    double            balance_{0.0};
    const int         accountNb_;
    std::string       authPass_;
    AuthMethod        authMethod_{AuthMethod::PIN};
    std::string       cardType_;

    // --------------------------------------------------------
    //  Private helpers
    // --------------------------------------------------------

    /**
     * @brief  Returns a masked PAN — all digits except the last four replaced
     *         with '*'. Example: "************1783".
     */
    std::string getMaskedCardNumber() const
    {
        if (cardNumber_.size() < 4)
            return std::string(cardNumber_.size(), '*');

        return std::string(cardNumber_.size() - 4, '*') +
               cardNumber_.substr(cardNumber_.size() - 4);
    }

    /// Populates @p month and @p year with the current local month/year (YY).
    void getCurrentMonthYear(int& month, int& year) const
    {
        std::time_t t = std::time(nullptr);
        std::tm*    now = std::localtime(&t);
        month = now->tm_mon + 1;
        year  = now->tm_year % 100;
    }

    /**
     * @brief  Returns true if the card's expiry is on or before today.
     * @param  expMonth  Expiry month (1–12).
     * @param  expYear   Expiry year (last two digits, e.g. 26 for 2026).
     */
    bool isCardExpired(int expMonth, int expYear) const
    {
        int curMonth = 0, curYear = 0;
        getCurrentMonthYear(curMonth, curYear);
        return (expYear < curYear) ||
               (expYear == curYear && expMonth <= curMonth);
    }

    /**
     * @brief  Throws if the CVV is outside the valid 3-digit range (100–999).
     * @throws std::invalid_argument on invalid CVV.
     */
    void validateCVV(int cvv) const
    {
        if (cvv < 100 || cvv > 999)
            throw std::invalid_argument("CVV must be a 3-digit number.");
    }

    /**
     * @brief  Validates the PAN using the Luhn algorithm.
     *
     * Iterates right-to-left, doubling every second digit and subtracting 9
     * when the doubled value exceeds 9, then checks the total mod 10.
     *
     * @return true if the check digit is correct.
     */
    bool validateLuhn() const
    {
        if (cardNumber_.empty() ||
            !std::all_of(cardNumber_.begin(), cardNumber_.end(), ::isdigit))
            return false;

        int  sum       = 0;
        bool alternate = false; // start from the rightmost digit

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
     * @brief  Identifies the card network from the PAN prefix.
     * @return Human-readable card type string, or "Invalid Card Type".
     */
    std::string determineCardType() const
    {
        if (cardNumber_.empty()) return "Invalid Card Type";

        // Visa: starts with 4, length 13, 16, or 19
        if (cardNumber_[0] == '4' &&
            (cardNumber_.size() == 13 ||
             cardNumber_.size() == 16 ||
             cardNumber_.size() == 19))
            return "Visa";

        if (cardNumber_.size() == 16) {
            int first2 = std::stoi(cardNumber_.substr(0, 2));
            int first4 = std::stoi(cardNumber_.substr(0, 4));

            // Mastercard: 51–55 or 2221–2720
            if ((first2 >= 51 && first2 <= 55) ||
                (first4 >= 2221 && first4 <= 2720))
                return "Mastercard / EuroCard";
        }

        return "Invalid Card Type";
    }

    /// Runs length/character/Luhn checks and prints the result.
    void validateAndPrintCardNumber() const
    {
        if (cardNumber_.empty()) {
            std::cout << "Card number is empty.\n";
            return;
        }
        if (cardNumber_.size() < 13) {
            std::cout << "Card number is too short.\n";
            return;
        }
        if (cardNumber_.size() > 19) {
            std::cout << "Card number is too long.\n";
            return;
        }
        if (!std::all_of(cardNumber_.begin(), cardNumber_.end(), ::isdigit)) {
            std::cout << "Card number contains non-digit characters.\n";
            return;
        }

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
 *  - Generates and holds the RSA-2048 key pair.
 *  - Maintains an in-memory AES-256-CBC encrypted card database (encDB_).
 *  - Validates card details, authenticates cardholders, and updates balances.
 *
 * @note encDB_ is populated from "credit_card.csv" on construction.
 *       CSV columns (in order): card_no, acc_no, cvv, exp_date, currency,
 *       auth_method, auth_credential, balance.
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
    //  Public key / IV accessors
    // --------------------------------------------------------

    CryptoPP::RSA::PublicKey   getPublicKey() const { return publicKey_; }
    CryptoPP::SecByteBlock     getIV()        const { return iv_; }

    // --------------------------------------------------------
    //  Card operations
    // --------------------------------------------------------

    /**
     * @brief  Checks whether all card fields match a record in the encrypted DB.
     * @param  card  Card object whose encrypted getters will be queried.
     * @return true if a matching, non-expired record is found.
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

    /**
     * @brief  Authenticates the cardholder against the stored credential.
     *
     * Locates the card record, determines whether the stored method is PIN or
     * PASS, then delegates to authenticate() for up to MAX_ATTEMPTS tries.
     *
     * @param  card  The card being authenticated.
     * @return true on successful authentication.
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
        return false;
    }

    /**
     * @brief  Deducts @p cost from the card's stored balance.
     *
     * Prints the current balance, deducts if funds are sufficient, and
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
        std::cerr << "Error: card not found in database.\n";
    }

    /**
     * @brief  Returns the ISO currency string for the given card.
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

    /// Prints Base64-DER-encoded public and private keys to stdout.
    void printKeys()
    {
        std::cout << "Public Key (Base64 DER):\n"
                  << encodeKeyToBase64(publicKey_)  << '\n'
                  << SEPARATOR << '\n'
                  << "Private Key (Base64 DER):\n"
                  << encodeKeyToBase64(privateKey_) << '\n';
    }

private:
    // --------------------------------------------------------
    //  Private data members
    // --------------------------------------------------------
    CryptoPP::RSA::PublicKey  publicKey_;
    CryptoPP::RSA::PrivateKey privateKey_;
    CryptoPP::SecByteBlock    secretKey_{generateAESKey(AES_256_KEY_SIZE)};
    CryptoPP::SecByteBlock    iv_{generateAESIV()};

    std::vector<CardRecord> encDB_;

    // --------------------------------------------------------
    //  Private helpers
    // --------------------------------------------------------

    /// Generates a fresh 2048-bit RSA key pair for this bank instance.
    void generateBankRSAKeys()
    {
        CryptoPP::AutoSeededRandomPool rng;
        privateKey_.GenerateRandomWithKeySize(rng, 2048);
        publicKey_.AssignFrom(privateKey_);
    }

    /**
     * @brief  Reads credit_card.csv, AES-encrypts every field, and stores the
     *         records in encDB_.
     *
     * Expected CSV column order:
     *   card_no, acc_no, cvv, exp_date, currency, auth_method, auth_credential, balance
     *
     * @param filename  Path to the plain-text card database CSV.
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
            // Strip Windows-style CR if present
            if (!line.empty() && line.back() == '\r')
                line.pop_back();

            if (line.empty()) continue;

            // Skip the header row (CardNumber,AccountNumber,...)
            if (firstRow) {
                firstRow = false;
                if (!line.empty() && !::isdigit(static_cast<unsigned char>(line[0])))
                    continue;
            }

            std::istringstream ss(line);
            std::vector<std::string> cols;
            std::string cell;

            while (std::getline(ss, cell, ',')) {
                // Trim leading/trailing whitespace from each cell
                auto start = cell.find_first_not_of(" \t");
                auto end   = cell.find_last_not_of(" \t");
                cols.push_back((start == std::string::npos) ? "" : cell.substr(start, end - start + 1));
            }

            if (cols.size() < 8) continue; // skip malformed rows

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
    }

    /**
     * @brief  Handles the interactive authentication loop (up to MAX_ATTEMPTS).
     *
     * Compares the SHA-384 hash of the user's input against the stored
     * credential hash to avoid any timing-observable plaintext comparison.
     *
     * @param  authMethod   "PIN" or "PASS".
     * @param  storedCred   Plaintext credential from the decrypted DB record.
     * @return true if the user authenticates within the allowed attempts.
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
            if (authMethod == "PIN") {
                std::cout << "Enter your PIN: ";
            } else {
                std::cout << "Enter your Password: ";
            }
            std::cin >> input;
            std::cout << SEPARATOR << '\n';

            if (hashSHA384(input) == storedHash) {
                success = true;
            } else if (attempts < MAX_ATTEMPTS) {
                std::cout << "Incorrect. "
                          << (MAX_ATTEMPTS - attempts)
                          << " attempt(s) remaining.\n"
                          << SEPARATOR << '\n';
            } else {
                std::cout << "Authentication failed after "
                          << MAX_ATTEMPTS << " attempts. Payment declined.\n";
            }
        }
        return success;
    }

    /**
     * @brief  DER-encodes an RSA public key and returns it as a Base64 string.
     * @param  key  RSA public key.
     */
    std::string encodeKeyToBase64(const CryptoPP::RSA::PublicKey& key) const
    {
        std::string encoded;
        CryptoPP::Base64Encoder enc(new CryptoPP::StringSink(encoded));
        key.DEREncode(enc);
        enc.MessageEnd();
        return encoded;
    }

    /**
     * @brief  DER-encodes an RSA private key and returns it as a Base64 string.
     * @param  key  RSA private key.
     */
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
 * Manages the transaction log, delegates card authentication to the bank,
 * and records the transaction type (Contactless / Contact).
 */
class Terminal
{
public:
    Terminal() = default;

    /**
     * @brief  Asks the bank to authenticate the cardholder.
     * @param  bank  Bank that issued the card.
     * @param  card  Card being presented at the terminal.
     */
    void validateAuthentication(Bank& bank, Card& card)
    {
        if (bank.cardAuthentication(card)) {
            std::cout << "Authentication successful. Proceeding with payment.\n";
        } else {
            std::cout << "Authentication failed.\n";
        }
    }

    /**
     * @brief  Records a new transaction with a freshly generated TUN.
     * @param  currency  ISO currency code.
     * @param  location  Merchant / transaction description.
     * @param  date      Formatted date-time string (from getCurrentDateTime()).
     */
    void addTransaction(const std::string& currency,
                        const std::string& location,
                        const std::string& date)
    {
        long long tun  = generateTUN();
        std::string type = selectTransactionType();
        transactions_.emplace_back(tun, currency, location, type, date);
    }

    /// Prints all recorded transactions to stdout.
    void displayTransactions() const
    {
        if (transactions_.empty()) {
            std::cout << "No transactions recorded.\n";
            return;
        }

        for (const Transaction& tx : transactions_) {
            std::cout << SEPARATOR << '\n'
                      << "  TUN:      " << tx.tun      << '\n'
                      << "  Currency: " << tx.currency  << '\n'
                      << "  Location: " << tx.location  << '\n'
                      << "  Type:     " << tx.type      << '\n'
                      << "  Date:     " << tx.date      << '\n';
        }
        std::cout << SEPARATOR << '\n';
    }

private:
    // --------------------------------------------------------
    //  Transaction record
    // --------------------------------------------------------
    struct Transaction {
        long long   tun;
        std::string currency;
        std::string location;
        std::string type;
        std::string date;

        Transaction(long long t, std::string c, std::string l,
                    std::string tp, std::string d)
            : tun(t), currency(std::move(c)), location(std::move(l)),
              type(std::move(tp)), date(std::move(d)) {}
    };

    std::list<Transaction> transactions_;

    // --------------------------------------------------------
    //  Private helpers
    // --------------------------------------------------------

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

    /**
     * @brief  Prompts the user to select Contactless or Contact payment.
     * @return "Contactless" or "Contact".
     */
    std::string selectTransactionType()
    {
        int choice = 0;
        std::cout << "Select transaction type: 1) Contactless  2) Contact: ";

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
};

// ============================================================
//  Entry point
// ============================================================

/**
 * @brief  Drives a single end-to-end EMV payment flow:
 *         card validation → transaction selection → authentication → payment.
 */
int main()
{
    try {
        // -- Instantiate the three core actors --------------------------------
        Terminal terminal;
        Bank     bank;
        UserData user("Bob", "Star", "11 Park Avenue, Switzerland");

        // -- Present a card at the terminal -----------------------------------
        //    Card(PAN, CVV, "MM/YY", currency, accountNumber)
        //    Matches CSV row 3: auth method PASS, credential "password123"
        Card validCard("4716893064521783", 234, "11/26", "EUR", 12345679);

        // -- Verify card details against the bank's encrypted DB --------------
        std::cout << SEPARATOR << '\n';
        if (!bank.checkCardDetail(validCard)) {
            std::cout << "Card details are invalid or not found. Aborting.\n";
            return 1;
        }
        std::cout << "Card details verified.\n" << SEPARATOR << '\n';

        // -- Log the transaction ----------------------------------------------
        std::string txDate = getCurrentDateTime();
        std::cout << "Select your payment method:\n" << SEPARATOR << '\n';
        terminal.addTransaction(bank.getCurrency(validCard), "Store Purchase", txDate);

        // -- Authenticate and process payment ---------------------------------
        std::cout << SEPARATOR << '\n';
        terminal.validateAuthentication(bank, validCard);
        bank.processPayment(validCard, 234.50);

        // -- Receipt ----------------------------------------------------------
        std::cout << SEPARATOR << '\n';
        terminal.displayTransactions();
        std::cout << SEPARATOR << '\n';

        // -- Bank key display (for demonstration only) ------------------------
        std::cout << "Bank RSA Keys (demonstration):\n" << SEPARATOR << '\n';
        bank.printKeys();
        std::cout << SEPARATOR << '\n';

    } catch (const std::exception& ex) {
        std::cerr << "Fatal error: " << ex.what() << '\n';
        return 1;
    }

    return 0;
}
