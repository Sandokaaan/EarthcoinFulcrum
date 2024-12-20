// Copyright (c) 2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "sha256.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace bitcoin {

/** A hasher class for HMAC-SHA-256. */
class CHMAC_SHA256 {
private:
    CSHA256 outer;
    CSHA256 inner;

public:
    static const size_t OUTPUT_SIZE = 32;

    CHMAC_SHA256(const uint8_t *key, size_t keylen);
    CHMAC_SHA256 &Write(const uint8_t *data, size_t len) {
        inner.Write(data, len);
        return *this;
    }
    void Finalize(uint8_t hash[OUTPUT_SIZE]);

    void Copy(CHMAC_SHA256* dest)
    {
        memcpy(dest, this, sizeof(CHMAC_SHA256));
    }

};

}
