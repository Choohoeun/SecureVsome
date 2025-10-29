// Copyright (C) 2025
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_CRYPTO_X25519_CRYPTO_HPP
#define VSOMEIP_V3_CRYPTO_X25519_CRYPTO_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <vsomeip/export.hpp>

namespace vsomeip_v3 {
namespace crypto {

struct KeyPair {
    std::array<std::uint8_t, 32> private_key{};
    std::array<std::uint8_t, 32> public_key{};
};

// Generate an X25519 keypair
VSOMEIP_EXPORT KeyPair generate_keypair();

// Derive a shared secret via X25519(my_private, peer_public)
// Returns true on success and fills shared_secret with 32 bytes
VSOMEIP_EXPORT bool derive_shared_secret(const std::array<std::uint8_t, 32>& my_private,
                          const std::array<std::uint8_t, 32>& peer_public,
                          std::array<std::uint8_t, 32>& shared_secret);

// HKDF-SHA256 key derivation
VSOMEIP_EXPORT std::vector<std::uint8_t> hkdf_sha256(const std::uint8_t* ikm, std::size_t ikm_len,
                                      const std::uint8_t* salt, std::size_t salt_len,
                                      const std::uint8_t* info, std::size_t info_len,
                                      std::size_t out_len);

// ChaCha20-Poly1305 AEAD encrypt
// nonce must be 12 bytes. tag will be 16 bytes.
VSOMEIP_EXPORT bool aead_encrypt_chacha20_poly1305(const std::vector<std::uint8_t>& key,
                                    const std::uint8_t* nonce12,
                                    const std::uint8_t* aad, std::size_t aad_len,
                                    const std::uint8_t* plaintext, std::size_t plaintext_len,
                                    std::vector<std::uint8_t>& ciphertext,
                                    std::array<std::uint8_t, 16>& tag);

// ChaCha20-Poly1305 AEAD decrypt
VSOMEIP_EXPORT bool aead_decrypt_chacha20_poly1305(const std::vector<std::uint8_t>& key,
                                    const std::uint8_t* nonce12,
                                    const std::uint8_t* aad, std::size_t aad_len,
                                    const std::uint8_t* ciphertext, std::size_t ciphertext_len,
                                    const std::uint8_t* tag16,
                                    std::vector<std::uint8_t>& plaintext);

// Utility for secure random bytes
VSOMEIP_EXPORT bool random_bytes(std::uint8_t* out, std::size_t len);

} // namespace crypto
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_CRYPTO_X25519_CRYPTO_HPP




