// dump_alg_info.cpp
#include <iostream>
#include <oqs/oqs.h>

void dump_hybrid_info_yaml(const char* kem_name) {
    std::cout << "hybrid_config:\n";
    std::cout << "  oqs_kem: " << kem_name << "\n";
    std::cout << "  key_derivation: HKDF-SHA256\n";
    std::cout << "  aead: AES-256-GCM\n";
    std::cout << "  aad_enabled: true\n";
    std::cout << "  aad_purpose: \"bind session context to prevent misuse\"\n";

    std::cout << "  oqs_algorithm_info:\n";

    OQS_KEM* kem = OQS_KEM_new(kem_name);
    if (!kem) {
        std::cout << "    status: disabled\n";
        return;
    }

    std::cout << "    claimed_nist_level: " << kem->claimed_nist_level << "\n";
    std::cout << "    ind_cca: " << kem->ind_cca << "\n";
    std::cout << "    length_public_key: " << kem->length_public_key << "\n";
    std::cout << "    length_secret_key: " << kem->length_secret_key << "\n";
    std::cout << "    length_ciphertext: " << kem->length_ciphertext << "\n";
    std::cout << "    length_shared_secret: " << kem->length_shared_secret << "\n";

    OQS_KEM_free(kem);
}
