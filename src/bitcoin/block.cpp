// todo - celé

// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "block.h"

#include "crypto/common.h"
#include "crypto/scrypt.h"
#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

namespace bitcoin {

/*void CBlockHeader::SetAuxpow (std::unique_ptr<CAuxPow> apow) {
    if (apow != nullptr) {
        auxpow.reset(apow.release());
        SetAuxpowFlag(true);
    } else {
        auxpow.reset();
        SetAuxpowFlag(false);
    }
}*/
	
uint256 CPureBlockHeader::GetHash() const {
    return SerializeHash(*this);
}

uint256 CPureBlockHeader::GetPoWHash() const {
    uint256 thash;
    scrypt_1024_1_1_256(BEGIN(nVersion), BEGIN(thash));
    return thash;
}	

/* //není treba, dedi se
uint256 CBlockHeader::GetHash() const {
    return SerializeHash(*this);
}
*/

std::string CBlock::ToString(bool fVerbose) const {
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, "
                   "hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, "
                   "vtx=%u)\n",
                   GetHash().ToString(), nVersion, hashPrevBlock.ToString(),
                   hashMerkleRoot.ToString(), nTime, nBits, nNonce, vtx.size());
    for (const auto &tx : vtx) {
        s << "  " << tx->ToString(fVerbose) << "\n";
    }
    return s.str();
}

/// auxpow



} // end namespace bitcoin
