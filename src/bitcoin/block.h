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

namespace bitcoin {

// auxpowforkparams.h	
const int AUXPOW_CHAIN_ID = 0x205d;         // To be consistent with previous block version 0x20000000
const int AUXPOW_START_HEIGHT = 3450000;    // May 2021 ?	
const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

// pureblockheader.h
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
	SetNull(); 
    }

    SERIALIZE_METHODS(CPureBlockHeader, obj) {
        READWRITE(obj.nVersion);
        READWRITE(obj.hashPrevBlock);
        READWRITE(obj.hashMerkleRoot);
        READWRITE(obj.nTime);
        READWRITE(obj.nBits);
        READWRITE(obj.nNonce);
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

/// auxpow.h
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

public:
  /* Prevent accidental conversion.  */
  inline explicit CAuxPow (CTransactionRef txIn) : coinbaseTx (txIn) {}

  CAuxPow () = default;

  SERIALIZE_METHODS(CAuxPow, obj) {
	READWRITE (obj.coinbaseTx);
	READWRITE (obj.vChainMerkleBranch);
	READWRITE (obj.nChainIndex);
	READWRITE (obj.parentBlock);
  }

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
};

// block.h
class CBlockHeader : public CPureBlockHeader
{
public:
    // aux-pow data
    CAuxPow auxpow;

    CBlockHeader() noexcept {
        SetNull();
    }

    // copy constructor for verif in BTC.cpp
    CBlockHeader(const CPureBlockHeader & a) {
        nVersion = a.nVersion;
        hashPrevBlock = a.hashPrevBlock;
        hashMerkleRoot = a.hashMerkleRoot;
        nTime = a.nTime;
        nBits = a.nBits;
        nNonce = a.nNonce;
    }

    SERIALIZE_METHODS(CBlockHeader, obj) {
	READWRITEAS(CPureBlockHeader, obj);
	if (obj.IsAuxpow()) {
            READWRITEAS(CAuxPow, obj.auxpow);
        } 
    }

    void SetNull() noexcept {
        CPureBlockHeader::SetNull();
    }
};

class CBlock : public CBlockHeader {
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    /// Litecoin only
    litecoin_bits::MimbleBlobPtr mw_blob;

    // memory only
    mutable bool fChecked;

    CBlock() noexcept { 
	SetNull(); 
    }

    CBlock(const CBlockHeader &header) {
        SetNull();
        *(static_cast<CBlockHeader *>(this)) = header;
    }

    SERIALIZE_METHODS(CBlock, obj) {
        READWRITEAS(CBlockHeader, obj);
        READWRITE(obj.vtx);
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

    // compilation fix for older compillers
    // constexpr CBlockLocator() noexcept {}
    CBlockLocator() noexcept {}

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
