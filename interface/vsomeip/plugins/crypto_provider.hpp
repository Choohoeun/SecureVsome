// Copyright (C) 2025
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_CRYPTO_PROVIDER_HPP
#define VSOMEIP_V3_CRYPTO_PROVIDER_HPP

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <vsomeip/export.hpp>
#include <vsomeip/plugin.hpp>

namespace vsomeip_v3 {

class endpoint;

namespace crypto_plugin {

class crypto_provider {
public:
    virtual ~crypto_provider() = default;

    // Called on new endpoint connection; implement DH handshake if needed per peer
    virtual void on_connect(const std::shared_ptr<endpoint>& _endpoint) = 0;
    virtual void on_disconnect(const std::shared_ptr<endpoint>& _endpoint) = 0;

    // Encrypt payload starting at payload_base; header before base must remain intact
    // Returns true if encryption applied; modifies buffer in place (may reallocate)
    virtual bool encrypt(uint16_t service, uint16_t method, uint16_t instance,
                         std::vector<std::uint8_t>& buffer, std::size_t payload_base) = 0;

    // Decrypt payload; returns true if decryption succeeded
    virtual bool decrypt(uint16_t service, uint16_t method, uint16_t instance,
                         std::vector<std::uint8_t>& buffer, std::size_t payload_base) = 0;
};

} // namespace crypto_plugin
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_CRYPTO_PROVIDER_HPP




