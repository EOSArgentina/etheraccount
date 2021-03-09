#pragma once

#include <rlpvalue.h>
#include <sha3/sha3.h>
#include <ecc/uECC.h>

#include <etheraccount/utils.hpp>
#include <etheraccount/config.hpp>
#include <etheraccount/eth_address.hpp>

struct eth_transaction {

    enum transaction_type : uint8_t {
        ETH_TRANSFER,
        ERC20_TRANSFER,
        OTHER
    };

    u256              nonce;
    u256              gas_price;
    u256              gas_limit;
    eth_address       to;
    u256              value;
    bytes             data;
    eth_address       sender;
    bytes32           txhash;
    eosio::public_key pubkey;
    eosio::signature  signature;

    transaction_type  tx_type;

    bool is_erc20_transfer() {
        return tx_type == transaction_type::ERC20_TRANSFER;
    }

    bool is_eth_transfer() {
        return tx_type == transaction_type::ETH_TRANSFER;
    }

    bool is_transfer() {
        return is_eth_transfer() || is_erc20_transfer();
    }

    eth_address transfer_destination() {
        eosio::check(is_transfer(), "not a transfer");
        if( is_eth_transfer() ) {
            return to;
        }
        return eth_address::from_bytes(bytes(data.data()+16, data.data()+16+20));
    }

    asset get_fee() {
        return wei_to_eos(u512(gas_price)*u512(gas_limit));
    }

    extended_asset transfer_amount() {
        eosio::check(is_transfer(), "not a transfer");
        extended_asset res;
        if( is_eth_transfer() ) {
            res = extended_asset(wei_to_eos(value), "eosio.token"_n);
        } else if( is_erc20_transfer() ) {
            auto q = intx::be::unsafe::load<u256>(data.data()+4+32);
            eosio::check(q < u256(asset::max_amount), "invalid amount");
            res = extended_asset(static_cast<uint64_t>(q), to_extended_symbol(to.get_bytes()));
        }
        return res;
    }

    static eosio::signature get_signature(const RLPValue& v, const RLPValue r, const RLPValue s) {
        std::string txsig;
        txsig += v.getValStr();
        eosio::check(txsig.length() == 1, "invalid signature (v)");

        txsig += r.getValStr();
        eosio::check(txsig.length() == 33, "invalid signature (r)");

        txsig += s.getValStr();
        eosio::check(txsig.length() == 65, "invalid signature (s)");

        uint64_t vv = txsig[0];
        uint64_t chainId = (vv - 35) % 2;
        txsig[0] = (uint8_t)(chainId + 27 + 4);

        eosio::signature sig;
        sig.emplace<0>(*reinterpret_cast<ecc_signature*>(txsig.data()));
        return sig;
    }

    static bytes32 get_txhash(RLPValue& v) {
        v.resize(6);

        auto chain_id = RLPValue(RLPValue::VType::VBUF);
        chain_id.assign(std::vector<uint8_t>{eos_chain_id});

        auto zero = RLPValue(RLPValue::VType::VBUF);
        zero.assign(std::vector<uint8_t>{});

        v.push_back(chain_id);
        v.push_back(zero);
        v.push_back(zero);

        auto to_sign = v.write();
        return sha3(to_sign);
    }

    static eth_transaction from_rlp(const bytes& rlptx) {

        RLPValue v;
        size_t consumed, wanted;
        bool rrc = v.read(rlptx.data(), rlptx.size(), consumed, wanted);

        eosio::check(rrc && v.isArray() && v.size() == 9, "invalid transaction");
    
        eth_transaction ethtx;
        ethtx.nonce     = to_u256(v[0]);
        ethtx.gas_price = to_u256(v[1]);
        ethtx.gas_limit = to_u256(v[2]);
        ethtx.to        = eth_address::from_bytes(to_bytes(v[3]));
        ethtx.value     = to_u256(v[4]);
        ethtx.data      = to_bytes(v[5]);
        ethtx.signature = get_signature(v[6], v[7], v[8]);
        ethtx.txhash    = get_txhash(v);
        ethtx.pubkey    = recover_key(checksum256(ethtx.txhash), ethtx.signature);
        ethtx.sender    = eth_address::from_pubkey(ethtx.pubkey);

        if(!ethtx.data.size()) {
            ethtx.tx_type = transaction_type::ETH_TRANSFER;
        } else if (ethtx.data.size() == 4+32+32 && *reinterpret_cast<uint32_t*>(ethtx.data.data()) == __builtin_bswap32(transfer_method_id)) {
            ethtx.tx_type = transaction_type::ERC20_TRANSFER;
        } else {
            ethtx.tx_type = transaction_type::OTHER;
        }

        return ethtx;
    }
};
