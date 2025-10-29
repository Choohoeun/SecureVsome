#include <chrono>
#include <cstring>
#include <iostream>
#include <vector>

#include <vsomeip/crypto/x25519_crypto.hpp>

using namespace std::chrono;

int main() {
    using vsomeip_v3::crypto::KeyPair;
    using vsomeip_v3::crypto::generate_keypair;
    using vsomeip_v3::crypto::derive_shared_secret;
    using vsomeip_v3::crypto::aead_encrypt_chacha20_poly1305;
    using vsomeip_v3::crypto::aead_decrypt_chacha20_poly1305;

    const int loops = 1000;

    // Benchmark X25519 key agreement
    KeyPair a = generate_keypair();
    KeyPair b = generate_keypair();

    std::array<std::uint8_t, 32> ab{};
    std::array<std::uint8_t, 32> ba{};

    auto t0 = steady_clock::now();
    for (int i = 0; i < loops; ++i) {
        derive_shared_secret(a.private_key, b.public_key, ab);
    }
    auto t1 = steady_clock::now();
    for (int i = 0; i < loops; ++i) {
        derive_shared_secret(b.private_key, a.public_key, ba);
    }
    auto t2 = steady_clock::now();

    // Benchmark AEAD
    std::vector<std::uint8_t> key(32, 0x11);
    std::array<std::uint8_t, 12> nonce{};
    std::vector<std::uint8_t> pt(1024, 0x42);
    std::vector<std::uint8_t> ct;
    std::array<std::uint8_t, 16> tag{};

    auto t3 = steady_clock::now();
    for (int i = 0; i < loops; ++i) {
        aead_encrypt_chacha20_poly1305(key, nonce.data(), nullptr, 0, pt.data(), pt.size(), ct, tag);
    }
    auto t4 = steady_clock::now();

    std::vector<std::uint8_t> out;
    auto t5 = steady_clock::now();
    for (int i = 0; i < loops; ++i) {
        aead_decrypt_chacha20_poly1305(key, nonce.data(), nullptr, 0, ct.data(), ct.size(), tag.data(), out);
    }
    auto t6 = steady_clock::now();

    auto x25519_ab_ms = duration_cast<milliseconds>(t1 - t0).count();
    auto x25519_ba_ms = duration_cast<milliseconds>(t2 - t1).count();
    auto enc_ms = duration_cast<milliseconds>(t4 - t3).count();
    auto dec_ms = duration_cast<milliseconds>(t6 - t5).count();

    std::cout << "X25519 derive (" << loops << ") A->B: " << x25519_ab_ms << " ms\n";
    std::cout << "X25519 derive (" << loops << ") B->A: " << x25519_ba_ms << " ms\n";
    std::cout << "ChaCha20-Poly1305 encrypt (" << loops << ", 1024B): " << enc_ms << " ms\n";
    std::cout << "ChaCha20-Poly1305 decrypt (" << loops << ", 1024B): " << dec_ms << " ms\n";

    return 0;
}



