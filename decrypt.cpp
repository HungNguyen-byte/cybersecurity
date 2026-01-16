// decrypt.cpp
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
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

#include <oqs/oqs.h>
#include "utils.h"

using bytes = std::vector<unsigned char>;

extern void log_openssl_errors(const char *context);
extern bytes sha256(const bytes &in);
extern bytes hkdf_sha256_derive(const bytes &ikm, const bytes &salt, const bytes &info, size_t out_len);

bytes aes_256_gcm_decrypt_with_aad_stream(const bytes& ciphertext, const bytes& tag, const bytes& key, const bytes& iv, const bytes& aad) {
    if (key.size() != 32 || iv.size() != 12 || tag.size() != 16)
        throw std::runtime_error("Invalid AES parameters");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    auto cleanup = [&]() { EVP_CIPHER_CTX_free(ctx); };

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) ||
        1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) ||
        1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()))
    {
        log_openssl_errors("decrypt_init");
        cleanup();
        throw std::runtime_error("AES-GCM init failed");
    }

    int len;
    if (!aad.empty()) EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size());

    bytes plaintext;
    plaintext.reserve(ciphertext.size());
    const size_t CHUNK = 4096;
    for (size_t i = 0; i < ciphertext.size(); i += CHUNK) {
        size_t n = std::min(CHUNK, ciphertext.size() - i);
        bytes out(n + 64);
        EVP_DecryptUpdate(ctx, out.data(), &len, ciphertext.data() + i, (int)n);
        out.resize(len);
        plaintext.insert(plaintext.end(), out.begin(), out.end());
    }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag.data());

    if (1 != EVP_DecryptFinal_ex(ctx, nullptr, &len)) {
        cleanup();
        throw std::runtime_error("Authentication failed — wrong key or tampered data");
    }

    cleanup();
    return plaintext;
}

void decrypt_file_or_folder(const std::string& input_path, const bytes& sk, OQS_KEM* kem) {
    const std::string version_str = "HYBRID-MLKEM-v1";
    const std::string info_str = "aes256-gcm-key";
    bytes info(info_str.begin(), info_str.end());

    bytes shared_secret(kem->length_shared_secret);
    bytes aes_key;
    bytes kem_ct_hash;
    bytes aad;

    fs::path out_dir = "decrypted";
    fs::create_directory(out_dir);

    if (fs::is_directory(input_path)) {
        fs::path kem_ct_path = fs::path(input_path) / "kem_ct.bin";
        if (!fs::exists(kem_ct_path))
            throw std::runtime_error("kem_ct.bin not found in encrypted folder");

        bytes kem_ct = read_file(kem_ct_path.string());

        if (OQS_KEM_decaps(kem, shared_secret.data(), kem_ct.data(), sk.data()) != OQS_SUCCESS)
            throw std::runtime_error("Decapsulation failed");

        aes_key = hkdf_sha256_derive(shared_secret, {}, info, 32);
        kem_ct_hash = sha256(kem_ct);
        aad.insert(aad.end(), version_str.begin(), version_str.end());
        aad.insert(aad.end(), kem_ct_hash.begin(), kem_ct_hash.end());

        for (const auto& entry : fs::recursive_directory_iterator(input_path)) {
            if (!fs::is_regular_file(entry) || !ends_with(entry.path().string(), ".enc"))
                continue;

            std::string rel_path = fs::relative(entry.path(), input_path).string();
            rel_path = rel_path.substr(0, rel_path.size() - 4);

            fs::path out_path = out_dir / rel_path;
            fs::create_directories(out_path.parent_path());

            bytes data = read_file(entry.path().string());

            bytes iv(data.begin(),     data.begin() + 12);
            bytes tag(data.begin() + 12, data.begin() + 28);
            bytes ct(data.begin() + 28, data.end());

            bytes pt = aes_256_gcm_decrypt_with_aad_stream(ct, tag, aes_key, iv, aad);
            write_file(out_path.string(), pt);
        }
    } else if (fs::is_regular_file(input_path) && ends_with(input_path, ".enc")) {
        bytes data = read_file(input_path);
        if (data.size() < kem->length_ciphertext + 28)
            throw std::runtime_error("Encrypted file too short");

        size_t pos = 0;
        bytes kem_ct(data.begin() + pos, data.begin() + pos + kem->length_ciphertext);
        pos += kem->length_ciphertext;
        bytes iv(data.begin() + pos, data.begin() + pos + 12); pos += 12;
        bytes tag(data.begin() + pos, data.begin() + pos + 16); pos += 16;
        bytes ct(data.begin() + pos, data.end());

        if (OQS_KEM_decaps(kem, shared_secret.data(), kem_ct.data(), sk.data()) != OQS_SUCCESS)
            throw std::runtime_error("Decapsulation failed");

        aes_key = hkdf_sha256_derive(shared_secret, {}, info, 32);
        kem_ct_hash = sha256(kem_ct);
        aad.insert(aad.end(), version_str.begin(), version_str.end());
        aad.insert(aad.end(), kem_ct_hash.begin(), kem_ct_hash.end());

        bytes pt = aes_256_gcm_decrypt_with_aad_stream(ct, tag, aes_key, iv, aad);

        fs::path out_file = out_dir / fs::path(input_path).stem();
        write_file(out_file.string(), pt);
    } else {
        throw std::runtime_error("Input must be a .enc file or encrypted folder");
    }

    std::cout << "Decryption complete! Original files saved to: ./" << out_dir << "/\n";
}