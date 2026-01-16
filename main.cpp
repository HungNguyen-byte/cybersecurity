// main.cpp
// Compile example (adjusted for split files):
// cl /EHsc /std:c++17 main.cpp encrypt.cpp decrypt.cpp ^
// /I D:\open\liboqs\include ^
// /I D:\open\openssl-msvc\include ^
// D:\open\liboqs\lib\Release\oqs.lib ^
// D:\open\openssl-msvc\lib\libcrypto.lib ^
// D:\open\openssl-msvc\lib\libssl.lib ^
// /link /OUT:hybrid.exe
// hybrid.exe genkey public.key secret.key
// hybrid.exe encrypt input.txt -o output.enc
// hybrid.exe encrypt demo
// hybrid.exe decrypt demo-data

// Hybrid ML-KEM-768 + AES-256-GCM encryption tool with interactive menu
// Output: encrypted/ and decrypted/ folders

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

#include <oqs/oqs.h>
#include "dump_alg_info.cpp"
#include "utils.h"

using bytes = std::vector<unsigned char>;

// ---------- External functions ----------
extern void encrypt_file_or_folder(const std::string &input_path,
                                   const bytes &pk,
                                   OQS_KEM *kem);

extern void decrypt_file_or_folder(const std::string &input_path,
                                   const bytes &sk,
                                   OQS_KEM *kem);

// ---------- Helper functions ----------
void log_openssl_errors(const char *context) {
    unsigned long err;
    while ((err = ERR_get_error()) != 0)
    {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        std::cerr << "[OpenSSL][" << context << "] " << buf << "\n";
    }
}

void secure_random_bytes(unsigned char *out, size_t len) {
    OQS_randombytes(out, len);
}

bytes sha256(const bytes &in) {
    bytes out(SHA256_DIGEST_LENGTH);
    SHA256(in.data(), in.size(), out.data());
    return out;
}

bytes hkdf_sha256_derive(const bytes &ikm, const bytes &salt, const bytes &info, size_t out_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) throw std::runtime_error("HKDF: cannot create context");

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), (int)ikm.size()) <= 0)
    {
        log_openssl_errors("HKDF setup");
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("HKDF setup failed");
    }

    if (!salt.empty())
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), (int)salt.size());
    if (!info.empty())
        EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), (int)info.size());

    bytes out(out_len);
    size_t derived_len = out_len;
    if (EVP_PKEY_derive(pctx, out.data(), &derived_len) <= 0 || derived_len != out_len) {
        log_openssl_errors("HKDF derive");
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("HKDF derivation failed");
    }

    EVP_PKEY_CTX_free(pctx);
    return out;
}

// ---------- UI Helpers ----------
void clear_screen()
{
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

void press_enter()
{
    std::cout << "\nPress Enter to continue...";
    std::cin.ignore(10000, '\n');
    std::cin.get();
}

void show_menu()
{
    clear_screen();
    std::cout << R"(
_________________________________________________________
|           Hybrid Post-Quantum Encryption Tool         |
|              ML-KEM-768 + AES-256-GCM                 |
|_______________________________________________________|

    1. Generate keypair (public.key + secret.key)
    2. Encrypt file or folder -> encrypted/
    3. Decrypt .enc file or encrypted/ -> decrypted/
    4. Show algorithm information
    0. Exit

)";
    std::cout << "Choose an option: ";
}

// ---------- Main ----------
int main() {
    try {
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();

        const char *kem_name = OQS_KEM_alg_ml_kem_768;
        if (!OQS_KEM_alg_is_enabled(kem_name)) {
            std::cerr << "Error: " << kem_name << " is not enabled in this liboqs build.\n";
            return 1;
        }

        OQS_KEM *kem = OQS_KEM_new(kem_name);
        if (!kem) {
            std::cerr << "Error: Cannot initialize " << kem_name << "\n";
            return 1;
        }

        std::cout << "Loaded KEM: " << kem_name << "\n\n";

        while (true) {
            show_menu();

            std::string input;
            std::getline(std::cin, input);
            int choice = -1;
            try { choice = std::stoi(input); } catch (...) {}

            if (choice == 0) {
                std::cout << "Goodbye!\n";
                break;
            }

            switch (choice) {
            // Generate keypair
            case 1: {
                std::cout << "Generating keypair...\n";
                bytes pk(kem->length_public_key);
                bytes sk(kem->length_secret_key);

                if (OQS_KEM_keypair(kem, pk.data(), sk.data()) != OQS_SUCCESS)
                    throw std::runtime_error("Keypair generation failed");

                write_file("public.key", pk);
                write_file("secret.key", sk);

                std::cout << "Keypair generated!\n";
                std::cout << "   Public key  : public.key  (" << pk.size() << " bytes)\n";
                std::cout << "   Secret key  : secret.key  (" << sk.size() << " bytes)\n";
                break;
            }

            // Encryption
            case 2: {
                std::cout << "Enter path to file or folder to encrypt: ";
                std::string path;
                std::getline(std::cin, path);
                if (path.empty()) { std::cout << "Cancelled.\n"; break; }

                if (!fs::exists("public.key")) {
                    std::cerr << "Error: public.key not found! Generate keys first.\n";
                    break;
                }

                bytes pk = read_file("public.key");
                if (pk.size() != kem->length_public_key) {
                    std::cerr << "Error: public.key is corrupted or wrong size.\n";
                    break;
                }

                std::cout << "Encrypting... ";
                std::cout.flush();
                encrypt_file_or_folder(path, pk, kem);
                break;
            }

            // Decryption
            case 3: {
                std::cout << "Enter path to .enc file or encrypted folder: ";
                std::string path;
                std::getline(std::cin, path);
                if (path.empty()) { std::cout << "Cancelled.\n"; break; }

                if (!fs::exists("secret.key")) {
                    std::cerr << "Error: secret.key not found!\n";
                    break;
                }

                bytes sk = read_file("secret.key");
                if (sk.size() != kem->length_secret_key) {
                    std::cerr << "Error: secret.key is corrupted.\n";
                    break;
                }

                std::cout << "Decrypting... ";
                std::cout.flush();
                decrypt_file_or_folder(path, sk, kem);
                break;
            }

            // Show algorithm info
            case 4:
                dump_hybrid_info_yaml(kem_name);
                break;

            // Invalid choice
            default:
                std::cout << "Invalid choice. Please try again.\n";
            }

            press_enter();
        }

        OQS_KEM_free(kem);
        EVP_cleanup();
        ERR_free_strings();
    } catch (const std::exception &e) {
        std::cerr << "\nError: " << e.what() << "\n";
        press_enter();
        return 1;
    }

    return 0;
}