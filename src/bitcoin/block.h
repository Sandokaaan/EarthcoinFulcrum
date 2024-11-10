//// todo-přidat CAuxPow - Auxpow je - ještě implementace v block.cpp


// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "transaction.h"
#include "serialize.h"
#include "uint256.h"

#include <utility>
#include <memory>
#include <vector>

#include <iostream>

namespace bitcoin {
// auxpowforkparams.h	
const int AUXPOW_CHAIN_ID = 0x205d;         // To be consistent with previous block version 0x20000000
const int AUXPOW_START_HEIGHT = 3450000;    // May 2021 ?	
const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

//class CAuxPow;
	
/**
 * Nodes collect new transactions into a block, hash them into a hash tree, and
 * scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements. When they solve the proof-of-work, they broadcast the block to
 * everyone and the block is added to the block chain. The first transaction in
 * the block is a special one that creates a new coin owned by the creator of
 * the block.
 */ 
class CPureBlockHeader {
public:
	static const int32_t VERSION_AUXPOW = (1 << 8);
	static const int32_t VERSION_CHAIN_START = (1 << 16);
    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    CPureBlockHeader() noexcept { 
//	std::cout << "CPureBlockHeader() constructor " << std::endl;
	SetNull(); 
    }

    SERIALIZE_METHODS(CPureBlockHeader, obj) {
        READWRITE(obj.nVersion);
        READWRITE(obj.hashPrevBlock);
        READWRITE(obj.hashMerkleRoot);
        READWRITE(obj.nTime);
        READWRITE(obj.nBits);
        READWRITE(obj.nNonce);
//	std::cout << "CPureBlockHeader::SERIALIZE_METHODS " << obj.nTime << " " << obj.nNonce << " " << obj.nVersion << std::endl;
    }

    void SetNull() noexcept {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0u;
        nBits = 0u;
        nNonce = 0u;
    }

    bool IsNull() const noexcept { return nBits == 0; }

    uint256 GetHash() const;
    uint256 GetPoWHash() const;

    int64_t GetBlockTime() const noexcept { return int64_t(nTime); }
	
	inline int32_t GetBaseVersion() const {
        return GetBaseVersion(nVersion);
    }
    static inline int32_t GetBaseVersion(int32_t ver) {
        return ver % VERSION_AUXPOW;
    }
	void SetBaseVersion(int32_t nBaseVersion, int32_t nChainId) {
//std::cout << "SetBaseVersion " << nBaseVersion << std::endl;
		assert(nBaseVersion >= 1 && nBaseVersion < VERSION_AUXPOW);
		assert(!IsAuxpow());
		nVersion = nBaseVersion | (nChainId * VERSION_CHAIN_START);		
	}	
	
	inline int32_t GetChainId() const {
        return nVersion >> 16;
    }
	inline void SetChainId(int32_t chainId) {
        nVersion %= VERSION_CHAIN_START;
        nVersion |= chainId * VERSION_CHAIN_START;
    }
	bool IsAuxpow() const {
		return nVersion & VERSION_AUXPOW;
	}
	bool IsLegacy() const {
		return ((nVersion & 0xff) < 4) || (GetChainId() != AUXPOW_CHAIN_ID);
	}
	inline void SetAuxpowFlag(bool auxpow) {
        if (auxpow)
            nVersion |= VERSION_AUXPOW;
        else
            nVersion &= ~VERSION_AUXPOW;
    }
};

/////////////
/// aux-pow
/** A transaction with a merkle branch linking it to the block chain. */
class CBaseMerkleTx
{
public:
    CTransactionRef tx;
    uint256 hashBlock;
    std::vector<uint256> vMerkleBranch;

    /* An nIndex == -1 means that hashBlock (in nonzero) refers to the earliest
     * block in the chain we know this or any in-wallet dependency conflicts
     * with. Older clients interpret nIndex == -1 as unconfirmed for backward
     * compatibility.
     */
    int nIndex;

    CBaseMerkleTx() {
        SetTx(MakeTransactionRef());
        Init();
    }

    explicit CBaseMerkleTx(CTransactionRef arg) {
        SetTx(std::move(arg));
        Init();
    }

    void Init() {
        hashBlock = uint256();
        nIndex = -1;
    }

    void SetTx(CTransactionRef arg) {
        tx = std::move(arg);
    }

    SERIALIZE_METHODS(CBaseMerkleTx, obj) {
        READWRITE(obj.tx);
        READWRITE(obj.hashBlock);
        READWRITE(obj.vMerkleBranch);
        READWRITE(obj.nIndex);
    }

    const uint256& GetHash() const { return tx->GetHash(); }
};

/**
 * Data for the merge-mining auxpow.  This uses a merkle tx (the parent block's
 * coinbase tx) and a manual merkle branch to link the actual Namecoin block
 * header to the parent block header, which is mined to satisfy the PoW.
 */
class CAuxPow
{
private:
  /**
   * The parent block's coinbase tx, which is used to link the auxpow from
   * the tx input to the parent block header.
   */
  CBaseMerkleTx coinbaseTx;

  /** The merkle branch connecting the aux block to our coinbase.  */
  std::vector<uint256> vChainMerkleBranch;

  /** Merkle tree index of the aux block header in the coinbase.  */
  int nChainIndex;

  /** Parent block header (on which the real PoW is done).  */
  CPureBlockHeader parentBlock;

  /**
   * Check a merkle branch.  This used to be in CBlock, but was removed
   * upstream.  Thus include it here now.
   */
//  static uint256 CheckMerkleBranch (uint256 hash,
//                                    const std::vector<uint256>& vMerkleBranch,
//                                    int nIndex);

  //friend UniValue AuxpowToJSON(const CAuxPow& auxpow);
  //friend class auxpow_tests::CAuxPowForTest;

public:
  /* Prevent accidental conversion.  */
  inline explicit CAuxPow (CTransactionRef txIn) : coinbaseTx (txIn) {}

  CAuxPow () = default;

  SERIALIZE_METHODS(CAuxPow, obj) {
//std::cout << "in CAuxPow SERIALIZE ..." << std::endl;
	READWRITE (obj.coinbaseTx);
//std::cout << "in CAuxPow SERIALIZE ...+1" << std::endl;
	READWRITE (obj.vChainMerkleBranch);
//std::cout << "in CAuxPow SERIALIZE ...+2" << std::endl;
	READWRITE (obj.nChainIndex);
//std::cout << "in CAuxPow SERIALIZE ...+3" << std::endl;
	READWRITE (obj.parentBlock);
// std::cout << "in CAuxPow SERIALIZE ...fin; chain index: " << obj.nChainIndex << std::endl;
  }

  /**
   * Check the auxpow, given the merge-mined block's hash and our chain ID.
   * Note that this does not verify the actual PoW on the parent block!  It
   * just confirms that all the merkle branches are valid.
   * @param hashAuxBlock Hash of the merge-mined block.
   * @param nChainId The auxpow chain ID of the block to check.
   * @param params Consensus parameters.
   * @return True if the auxpow is valid.
   */
  //bool check (const uint256& hashAuxBlock, int nChainId, const Consensus::Params& params) const;

  /**
   * Returns the parent block hash.  This is used to validate the PoW.
   */
  inline uint256 getParentBlockPoWHash () const  {
    return parentBlock.GetPoWHash ();
  }

  /**
   * Return parent block.  This is only used for the temporary parentblock
   * auxpow version check.
   * @return The parent block.
   */
  /* FIXME: Remove after the hardfork.  */
  inline const CPureBlockHeader& getParentBlock () const  {
    return parentBlock;
  }

  /**
   * Calculate the expected index in the merkle tree.  This is also used
   * for the test-suite.
   * @param nNonce The coinbase's nonce value.
   * @param nChainId The chain ID.
   * @param h The merkle block height.
   * @return The expected index for the aux hash.
   */
//  static int getExpectedIndex (uint32_t nNonce, int nChainId, unsigned h);

  /**
   * Constructs a minimal CAuxPow object for the given block header and
   * returns it.  The caller should make sure to set the auxpow flag on the
   * header already, since the block hash to which the auxpow commits depends
   * on that!
   */
//  static std::unique_ptr<CAuxPow> createAuxPow (const CPureBlockHeader& header);

  /**
   * Initialises the auxpow of the given block header.  This builds a minimal
   * auxpow object like createAuxPow and sets it on the block header.  Returns
   * a reference to the parent header so it can be mined as a follow-up.
   */
//  static CPureBlockHeader& initAuxPow (CBlockHeader& header);

};

//// end of auxpow

//////////////

class CBlockHeader : public CPureBlockHeader
{
public:

    // auxpow (if this is a merge-minded block)
    //std::shared_ptr<CAuxPow> auxpow = nullptr;
    CAuxPow auxpow;

    CBlockHeader() noexcept {
//	std::cout << "CBlockHeader() constructor " << std::endl;
        SetNull();
    }

    SERIALIZE_METHODS(CBlockHeader, obj) {
	READWRITEAS(CPureBlockHeader, obj);
	if (obj.IsAuxpow()) {
// std::cout << "in SERIALIZE CBlockHeader IsAuxPow " << obj.nTime << std::endl;

//            if (ser_action.ForRead())
//                obj.auxpow = std::make_shared<CAuxPow>();
//            assert(obj.auxpow != nullptr);
//            READWRITE(*(obj.auxpow));
            READWRITEAS(CAuxPow, obj.auxpow);
        } //else if (ser_action.ForRead())
            //auxpow.reset(); //= std::make_shared<CAuxPow>();
//	std::cout << "CBlockHeader::SERIALIZE_METHODS " << obj.nTime << " is AUX-POW? "  << obj.IsAuxpow() << std::endl;
    }

    void SetNull() noexcept {
        CPureBlockHeader::SetNull();
        //auxpow.reset();
    }

    /**
     * Set the block's auxpow (or unset it).  This takes care of updating
     * the version accordingly.
     */
    //void SetAuxpow (std::unique_ptr<CAuxPow> apow);
};

////

//////////

class CBlock : public CBlockHeader {
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    /// Litecoin only
    litecoin_bits::MimbleBlobPtr mw_blob;

    // memory only
    mutable bool fChecked;

    CBlock() noexcept { 
//	std::cout << "CBlock() constructor " << std::endl;
	SetNull(); 
    }

    CBlock(const CBlockHeader &header) {
        SetNull();
        *(static_cast<CBlockHeader *>(this)) = header;
    }

    SERIALIZE_METHODS(CBlock, obj) {
        READWRITEAS(CBlockHeader, obj);
        READWRITE(obj.vtx);
//	std::cout << "CBlock::SERIALIZE_METHODS " << obj.nTime << std::endl;
    }

    void SetNull() {
        CBlockHeader::SetNull();
        vtx.clear();
        mw_blob.reset();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const { return *this; }

    std::string ToString(bool fVerbose = false) const;
};


/**
 * Describes a place in the block chain to another node such that if the other
 * node doesn't have the same branch, it can find a recent common trunk.  The
 * further back it is, the further before the fork it may be.
 */
struct CBlockLocator {
    std::vector<uint256> vHave;

    constexpr CBlockLocator() noexcept {}

    explicit CBlockLocator(const std::vector<uint256> &vHaveIn)
        : vHave(vHaveIn) {}

    SERIALIZE_METHODS(CBlockLocator, obj) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH)) READWRITE(nVersion);
        READWRITE(obj.vHave);
    }

    void SetNull() { vHave.clear(); }

    bool IsNull() const { return vHave.empty(); }
};

} // end namespace bitcoin
