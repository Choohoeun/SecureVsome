// Copyright (C) 2025
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <vector>

#include <vsomeip/crypto/x25519_crypto.hpp>

namespace vsomeip_v3 {
namespace crypto {

KeyPair generate_keypair() {
    KeyPair kp;
    // X25519 private keys are 32 random bytes with clamping done by OpenSSL when used
    random_bytes(kp.private_key.data(), kp.private_key.size());

    // Derive public key = X25519(private, basepoint)
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY* params = nullptr;
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY* peer = nullptr;

    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0) {
        if (pctx) EVP_PKEY_CTX_free(pctx);
        return kp;
    }
    // Create a temporary key to extract basepoint multiplication; we will set raw private
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return kp;
    }
    // Replace with our raw private key
    EVP_PKEY* raw = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, kp.private_key.data(), kp.private_key.size());
    if (raw) {
        // Extract public
        std::array<std::uint8_t, 32> pub{};
        size_t pub_len = pub.size();
        if (EVP_PKEY_get_raw_public_key(raw, pub.data(), &pub_len) == 1) {
            kp.public_key = pub;
        }
        EVP_PKEY_free(raw);
    }

    if (pkey) EVP_PKEY_free(pkey);
    if (params) EVP_PKEY_free(params);
    if (peer) EVP_PKEY_free(peer);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    return kp;
}

bool derive_shared_secret(const std::array<std::uint8_t, 32>& my_private,
                          const std::array<std::uint8_t, 32>& peer_public,
                          std::array<std::uint8_t, 32>& shared_secret) {
    EVP_PKEY* priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, my_private.data(), my_private.size());
    EVP_PKEY* pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_public.data(), peer_public.size());
    if (!priv || !pub) {
        if (priv) EVP_PKEY_free(priv);
        if (pub) EVP_PKEY_free(pub);
        return false;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
    if (!ctx) {
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        return false;
    }
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    if (EVP_PKEY_derive_set_peer(ctx, pub) <= 0) {
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    size_t secret_len = shared_secret.size();
    if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) <= 0 || secret_len != shared_secret.size()) {
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    EVP_PKEY_CTX_free(ctx);
    return true;
}

std::vector<std::uint8_t> hkdf_sha256(const std::uint8_t* ikm, std::size_t ikm_len,
                                      const std::uint8_t* salt, std::size_t salt_len,
                                      const std::uint8_t* info, std::size_t info_len,
                                      std::size_t out_len) {
    std::vector<std::uint8_t> out(out_len);
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) return {};
    if (EVP_PKEY_derive_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return {}; }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) { EVP_PKEY_CTX_free(pctx); return {}; }
    if (salt && salt_len > 0) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, static_cast<int>(salt_len)) <= 0) { EVP_PKEY_CTX_free(pctx); return {}; }
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, static_cast<int>(ikm_len)) <= 0) { EVP_PKEY_CTX_free(pctx); return {}; }
    if (info && info_len > 0) {
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, static_cast<int>(info_len)) <= 0) { EVP_PKEY_CTX_free(pctx); return {}; }
    }
    size_t len = out_len;
    if (EVP_PKEY_derive(pctx, out.data(), &len) <= 0 || len != out_len) { EVP_PKEY_CTX_free(pctx); return {}; }
    EVP_PKEY_CTX_free(pctx);
    return out;
}

bool aead_encrypt_chacha20_poly1305(const std::vector<std::uint8_t>& key,
                                    const std::uint8_t* nonce12,
                                    const std::uint8_t* aad, std::size_t aad_len,
                                    const std::uint8_t* plaintext, std::size_t plaintext_len,
                                    std::vector<std::uint8_t>& ciphertext,
                                    std::array<std::uint8_t, 16>& tag) {
    ciphertext.resize(plaintext_len);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    int outlen = 0;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) break;
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce12) != 1) break;
        if (aad && aad_len > 0) {
            if (EVP_EncryptUpdate(ctx, nullptr, &outlen, aad, static_cast<int>(aad_len)) != 1) break;
        }
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, plaintext, static_cast<int>(plaintext_len)) != 1) break;
        int tmplen = 0;
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &tmplen) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag.data()) != 1) break;
        ok = true;
    } while (false);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool aead_decrypt_chacha20_poly1305(const std::vector<std::uint8_t>& key,
                                    const std::uint8_t* nonce12,
                                    const std::uint8_t* aad, std::size_t aad_len,
                                    const std::uint8_t* ciphertext, std::size_t ciphertext_len,
                                    const std::uint8_t* tag16,
                                    std::vector<std::uint8_t>& plaintext) {
    plaintext.resize(ciphertext_len);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    int outlen = 0;
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) break;
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce12) != 1) break;
        if (aad && aad_len > 0) {
            if (EVP_DecryptUpdate(ctx, nullptr, &outlen, aad, static_cast<int>(aad_len)) != 1) break;
        }
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertext, static_cast<int>(ciphertext_len)) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<std::uint8_t*>(tag16)) != 1) break;
        int tmplen = 0;
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &tmplen) != 1) break;
        ok = true;
    } while (false);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool random_bytes(std::uint8_t* out, std::size_t len) {
    return RAND_bytes(out, static_cast<int>(len)) == 1;
}

} // namespace crypto
} // namespace vsomeip_v3




