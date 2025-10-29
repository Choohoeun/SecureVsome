// Copyright (C) 2025
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <map>
#include <mutex>
#include <unordered_map>

#include <vsomeip/plugins/crypto_provider.hpp>
#include <vsomeip/crypto/x25519_crypto.hpp>
#include <vsomeip/defines.hpp>

namespace vsomeip_v3 {

class endpoint;

namespace crypto_plugin {

class crypto_provider_impl : public plugin_impl<crypto_provider_impl>, public crypto_provider {
public:
    crypto_provider_impl() : plugin_impl("vsomeip crypto plugin", 1, plugin_type_e::APPLICATION_PLUGIN) {}
    ~crypto_provider_impl() override = default;

    void on_connect(const std::shared_ptr<endpoint>& _endpoint) override {
        (void)_endpoint;
        // Lazy: per-connection key may be established here if endpoint identity available.
    }

    void on_disconnect(const std::shared_ptr<endpoint>& _endpoint) override {
        (void)_endpoint;
    }

    bool encrypt(uint16_t service, uint16_t method, uint16_t instance,
                 std::vector<std::uint8_t>& buffer, std::size_t payload_base) override {
        (void)service; (void)method; (void)instance;
        if (buffer.size() <= payload_base) return false;

        // Example single static session for POC: derive once
        std::call_once(key_once_, [&]{
            auto kp = crypto::generate_keypair();
            // For POC, simulate peer public = our public (not secure, replace with real peer key exchange)
            std::array<std::uint8_t, 32> secret{};
            crypto::derive_shared_secret(kp.private_key, kp.public_key, secret);
            const std::uint8_t salt[] = {0};
            const std::uint8_t info[] = {'v','s','o','m','e','i','p','-','x','2','5','5','1','9'};
            session_key_ = crypto::hkdf_sha256(secret.data(), secret.size(), salt, sizeof(salt), info, sizeof(info), 32);
        });

        if (session_key_.empty()) return false;

        const std::uint8_t* aad = buffer.data();
        const std::size_t aad_len = payload_base; // protect SOME/IP header
        const std::uint8_t* pt = buffer.data() + payload_base;
        const std::size_t pt_len = buffer.size() - payload_base;

        std::array<std::uint8_t, 12> nonce{}; // zero nonce for POC; replace with per-message nonce
        std::vector<std::uint8_t> ct;
        std::array<std::uint8_t, 16> tag{};
        if (!crypto::aead_encrypt_chacha20_poly1305(session_key_, nonce.data(), aad, aad_len, pt, pt_len, ct, tag)) {
            return false;
        }
        // Rebuild buffer: header | nonce(12) | ct | tag(16)
        std::vector<std::uint8_t> out;
        out.reserve(payload_base + 12 + ct.size() + 16);
        out.insert(out.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(payload_base));
        out.insert(out.end(), nonce.begin(), nonce.end());
        out.insert(out.end(), ct.begin(), ct.end());
        out.insert(out.end(), tag.begin(), tag.end());
        buffer.swap(out);
        return true;
    }

    bool decrypt(uint16_t service, uint16_t method, uint16_t instance,
                 std::vector<std::uint8_t>& buffer, std::size_t payload_base) override {
        (void)service; (void)method; (void)instance;
        if (buffer.size() < payload_base + 12 + 16) return false;
        if (session_key_.empty()) return false;

        const std::uint8_t* aad = buffer.data();
        const std::size_t aad_len = payload_base;
        const std::uint8_t* nonce = buffer.data() + payload_base;
        const std::uint8_t* ct = buffer.data() + payload_base + 12;
        const std::size_t ct_len = buffer.size() - payload_base - 12 - 16;
        const std::uint8_t* tag = buffer.data() + buffer.size() - 16;

        std::vector<std::uint8_t> pt;
        if (!crypto::aead_decrypt_chacha20_poly1305(session_key_, nonce, aad, aad_len, ct, ct_len, tag, pt)) {
            return false;
        }
        // Rebuild buffer: header | pt
        std::vector<std::uint8_t> out;
        out.reserve(payload_base + pt.size());
        out.insert(out.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(payload_base));
        out.insert(out.end(), pt.begin(), pt.end());
        buffer.swap(out);
        return true;
    }

private:
    std::once_flag key_once_;
    std::vector<std::uint8_t> session_key_;
};

VSOMEIP_PLUGIN(vsomeip_v3::crypto_plugin::crypto_provider_impl)

} // namespace crypto_plugin
} // namespace vsomeip_v3





