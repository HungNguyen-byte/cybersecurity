// encrypt.cpp
#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>

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
#include "utils.h"

using bytes = std::vector<unsigned char>;

extern void log_openssl_errors(const char *context);
extern void secure_random_bytes(unsigned char *out, size_t len);
extern bytes sha256(const bytes &in);
extern bytes hkdf_sha256_derive(const bytes &ikm, const bytes &salt, const bytes &info, size_t out_len);

struct AESCipherResult {bytes ciphertext; bytes iv; bytes tag;};

AESCipherResult aes_256_gcm_encrypt_with_aad_stream(const bytes& plaintext, const bytes& key, const bytes& aad) {
    AESCipherResult result;
    result.iv.resize(12);
    result.tag.resize(16);

    secure_random_bytes(result.iv.data(), 12);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) ||
        1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) ||
        1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), result.iv.data()))
    {
        log_openssl_errors("encrypt_init");
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM encrypt setup failed");
    }

    int len = 0;
    if (!aad.empty()) {
        EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size());
    }

    result.ciphertext.reserve(plaintext.size() + 64);
    const size_t CHUNK = 4096;

    for (size_t i = 0; i < plaintext.size(); i += CHUNK) {
        size_t n = std::min(CHUNK, plaintext.size() - i);
        bytes outbuf(n + 64);
        if (1 != EVP_EncryptUpdate(ctx, outbuf.data(), &len, plaintext.data() + i, (int)n)) {
            log_openssl_errors("encrypt_update");
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encryption failed");
        }
        outbuf.resize(len);
        result.ciphertext.insert(result.ciphertext.end(), outbuf.begin(), outbuf.end());
    }

    EVP_EncryptFinal_ex(ctx, nullptr, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, result.tag.data());
    EVP_CIPHER_CTX_free(ctx);

    return result;
}

void encrypt_file_or_folder(const std::string& input_path, const bytes& pk, OQS_KEM* kem) {
    const std::string version_str = "HYBRID-MLKEM-v1";
    const std::string info_str = "aes256-gcm-key";
    bytes info(info_str.begin(), info_str.end());

    bytes kem_ct(kem->length_ciphertext);
    bytes shared_secret(kem->length_shared_secret);

    if (OQS_KEM_encaps(kem, kem_ct.data(), shared_secret.data(), pk.data()) != OQS_SUCCESS)
        throw std::runtime_error("OQS_KEM_encaps failed");

    bytes aes_key = hkdf_sha256_derive(shared_secret, {}, info, 32);
    bytes kem_ct_hash = sha256(kem_ct);

    bytes aad;
    aad.insert(aad.end(), version_str.begin(), version_str.end());
    aad.insert(aad.end(), kem_ct_hash.begin(), kem_ct_hash.end());

    // Output directory
    fs::path out_dir = "encrypted";
    fs::create_directory(out_dir);

    if (fs::is_directory(input_path)) {
        // Save KEM ciphertext once
        write_file((out_dir / "kem_ct.bin").string(), kem_ct);

        for (const auto& entry : fs::recursive_directory_iterator(input_path)) {
            if (!fs::is_regular_file(entry)) continue;

            std::string rel_path = fs::relative(entry.path(), input_path).string();
            if (ends_with(rel_path, ".enc")) continue;

            fs::path out_path = out_dir / rel_path;
            fs::create_directories(out_path.parent_path());

            bytes plaintext = read_file(entry.path().string());
            AESCipherResult enc = aes_256_gcm_encrypt_with_aad_stream(plaintext, aes_key, aad);

            bytes encrypted_data;
            encrypted_data.insert(encrypted_data.end(), enc.iv.begin(), enc.iv.end());
            encrypted_data.insert(encrypted_data.end(), enc.tag.begin(), enc.tag.end());
            encrypted_data.insert(encrypted_data.end(), enc.ciphertext.begin(), enc.ciphertext.end());

            write_file(out_path.string() + ".enc", encrypted_data);
        }
    } else if (fs::is_regular_file(input_path)) {
        bytes plaintext = read_file(input_path);
        AESCipherResult enc = aes_256_gcm_encrypt_with_aad_stream(plaintext, aes_key, aad);

        bytes encrypted_data;
        encrypted_data.insert(encrypted_data.end(), kem_ct.begin(), kem_ct.end());
        encrypted_data.insert(encrypted_data.end(), enc.iv.begin(), enc.iv.end());
        encrypted_data.insert(encrypted_data.end(), enc.tag.begin(), enc.tag.end());
        encrypted_data.insert(encrypted_data.end(), enc.ciphertext.begin(), enc.ciphertext.end());

        fs::path out_file = out_dir / (fs::path(input_path).filename().string() + ".enc");
        write_file(out_file.string(), encrypted_data);
    } else {
        throw std::runtime_error("Input must be a file or directory");
    }

    std::cout << "Encryption complete! All encrypted files are in: ./encrypted/\n";
}