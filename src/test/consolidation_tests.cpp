// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <consensus/amount.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <test/util/setup_common.h>

#include <boost/test/tools/old/interface.hpp>
#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_FIXTURE_TEST_SUITE(consolidation_tests, BasicTestingSetup)

namespace {

struct ConsolidationTaproot
{
    CKey key;
    XOnlyPubKey internal_key;
    CScript script_pubkey;
    CScript tapscript;
    std::vector<unsigned char> control;
    uint256 merkle_root;
};

/** Build a taproot output with a key path and a single tapscript leaf of OP_CHECKCONSOLIDATION. */
ConsolidationTaproot MakeConsolidationTaproot()
{
    ConsolidationTaproot out;
    out.key.MakeNewKey(true);
    out.internal_key = XOnlyPubKey(out.key.GetPubKey());
    out.tapscript = CScript() << OP_CHECKCONSOLIDATION;

    TaprootBuilder builder;
    builder.Add(0, std::span<const unsigned char>{out.tapscript}, TAPROOT_LEAF_TAPSCRIPT);
    builder.Finalize(out.internal_key);
    const TaprootSpendData spenddata = builder.GetSpendData();

    out.merkle_root = spenddata.merkle_root;
    out.script_pubkey = GetScriptForDestination(builder.GetOutput());

    auto it = spenddata.scripts.find({std::vector<unsigned char>(out.tapscript.begin(), out.tapscript.end()), TAPROOT_LEAF_TAPSCRIPT});
    assert(it != spenddata.scripts.end());
    out.control = *it->second.begin();
    return out;
}

CMutableTransaction BuildBaseTx()
{
    CMutableTransaction mtx;
    // Key-path input
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256(0)), 0});
    // Script-path input
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256(1)), 0});
    // Output
    mtx.vout.emplace_back(COIN*2, CScript() << OP_1 << std::vector<unsigned char>(32, 0x01));
    return mtx;
}

void SetScriptPathSpend(CTxIn& in, const ConsolidationTaproot& tree)
{
    in.scriptWitness.stack.clear();
    in.scriptWitness.stack.emplace_back(tree.tapscript.begin(), tree.tapscript.end());
    in.scriptWitness.stack.push_back(tree.control);
}

void SignKeyPathInput(CTxIn& in, const ConsolidationTaproot& tree, const CMutableTransaction& mtx, unsigned int vin,
                      const CTxOut& prevout, const PrecomputedTransactionData& txdata)
{
    FlatSigningProvider provider;
    provider.keys.emplace(tree.key.GetPubKey().GetID(), tree.key);
    std::vector<unsigned char> sig;
    MutableTransactionSignatureCreator creator(mtx, vin, prevout.nValue, &txdata, SIGHASH_DEFAULT);
    BOOST_REQUIRE(creator.CreateSchnorrSig(provider, sig, tree.internal_key, nullptr, &tree.merkle_root, SigVersion::TAPROOT));
    in.scriptWitness.stack.clear();
    in.scriptWitness.stack.push_back(sig);
}

bool VerifyInput(const CTransaction& tx, unsigned int vin, const CTxOut& prevout,
                 const PrecomputedTransactionData& txdata, script_verify_flags flags)
{
    ScriptError err = SCRIPT_ERR_OK;
    return VerifyScript(tx.vin[vin].scriptSig, prevout.scriptPubKey, &tx.vin[vin].scriptWitness, flags,
                        TransactionSignatureChecker(&tx, vin, prevout.nValue, txdata, MissingDataBehavior::ASSERT_FAIL), &err);
}

void RunConsolidationCase(const ConsolidationTaproot& key_path_input, const ConsolidationTaproot& script_path_input, script_verify_flags flags)
{
    // Build transaction
    CMutableTransaction mtx = BuildBaseTx();
    SetScriptPathSpend(mtx.vin[1], script_path_input);
    const CTxOut prevout0{COIN, key_path_input.script_pubkey};
    const CTxOut prevout1{COIN, script_path_input.script_pubkey};
    PrecomputedTransactionData txdata;
    txdata.Init(CTransaction{mtx}, {prevout0, prevout1}, true);
    SignKeyPathInput(mtx.vin[0], key_path_input, mtx, 0, prevout0, txdata);

    // Check consolidation markers
    BOOST_REQUIRE_EQUAL(txdata.m_consolidation_markers.size(), 2U);
    BOOST_CHECK(!txdata.m_consolidation_markers[0]);
    const bool same_spk = (key_path_input.script_pubkey == script_path_input.script_pubkey);
    BOOST_CHECK_EQUAL(txdata.m_consolidation_markers[1], same_spk);

    // Verify inputs
    const CTransaction tx{mtx};
    // Key-path input should always verify
    BOOST_CHECK(VerifyInput(tx, 0, prevout0, txdata, flags));
    // Script-path input should verify when input SPKs are equal or when SCRIPT_VERIFY_CC is disabled
    BOOST_CHECK_EQUAL(VerifyInput(tx, 1, prevout1, txdata, flags), same_spk || (flags & SCRIPT_VERIFY_CC) == 0);
}

}

BOOST_AUTO_TEST_CASE(same_spk)
{
    // Same scriptPubKeys, post-activation
    const ConsolidationTaproot input = MakeConsolidationTaproot();
    RunConsolidationCase(input, input, MANDATORY_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_CC);
}

BOOST_AUTO_TEST_CASE(different_spks_post_activation)
{
    // Different scriptPubKeys, post-activation
    const ConsolidationTaproot key_path_input = MakeConsolidationTaproot();
    const ConsolidationTaproot script_path_input = MakeConsolidationTaproot();
    BOOST_REQUIRE(key_path_input.script_pubkey != script_path_input.script_pubkey);
    RunConsolidationCase(key_path_input, script_path_input, MANDATORY_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_CC);
}

BOOST_AUTO_TEST_CASE(different_spks_pre_activation)
{
    // Different scriptPubKeys, pre-activation
    const ConsolidationTaproot key_path_input = MakeConsolidationTaproot();
    const ConsolidationTaproot script_path_input = MakeConsolidationTaproot();
    BOOST_REQUIRE(key_path_input.script_pubkey != script_path_input.script_pubkey);
    RunConsolidationCase(key_path_input, script_path_input, MANDATORY_SCRIPT_VERIFY_FLAGS);
}

BOOST_AUTO_TEST_CASE(many_prevouts)
{
    // 3 spks, not sorted
    const ConsolidationTaproot spk1 = MakeConsolidationTaproot();
    const ConsolidationTaproot spk2 = MakeConsolidationTaproot();
    const ConsolidationTaproot spk3 = MakeConsolidationTaproot();
    BOOST_REQUIRE(spk1.script_pubkey != spk2.script_pubkey);
    BOOST_REQUIRE(spk2.script_pubkey != spk3.script_pubkey);
    BOOST_REQUIRE(spk1.script_pubkey != spk3.script_pubkey);
    const CTxOut prevout0{COIN, spk1.script_pubkey}; // 1st spk1, OP_CHECKCONSOLIDATION false
    const CTxOut prevout1{COIN, spk2.script_pubkey}; // 1st spk2, OP_CHECKCONSOLIDATION false
    const CTxOut prevout2{COIN, spk2.script_pubkey}; // 2nd spk2, OP_CHECKCONSOLIDATION true
    const CTxOut prevout3{COIN, spk2.script_pubkey}; // 3rd spk2, OP_CHECKCONSOLIDATION true
    const CTxOut prevout4{COIN, spk1.script_pubkey}; // 2nd spk1, OP_CHECKCONSOLIDATION true
    const CTxOut prevout5{COIN, spk3.script_pubkey}; // 1st spk3, OP_CHECKCONSOLIDATION false

    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256(0)), 0});
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256(1)), 0});
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256(2)), 0});
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256(3)), 0});
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256(4)), 0});
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256(5)), 0});
    mtx.vout.emplace_back(COIN*6, CScript() << OP_1 << std::vector<unsigned char>(32, 0x01));

    PrecomputedTransactionData txdata;
    txdata.Init(CTransaction{mtx}, {prevout0, prevout1, prevout2, prevout3, prevout4, prevout5}, true);

    BOOST_REQUIRE_EQUAL(txdata.m_consolidation_markers.size(), 6U);
    BOOST_CHECK(!txdata.m_consolidation_markers[0]);
    BOOST_CHECK(!txdata.m_consolidation_markers[1]);
    BOOST_CHECK(txdata.m_consolidation_markers[2]);
    BOOST_CHECK(txdata.m_consolidation_markers[3]);
    BOOST_CHECK(txdata.m_consolidation_markers[4]);
    BOOST_CHECK(!txdata.m_consolidation_markers[5]);
}

BOOST_AUTO_TEST_SUITE_END()
