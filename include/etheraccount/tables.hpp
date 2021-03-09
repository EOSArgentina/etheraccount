#pragma once

#include <eosio/eosio.hpp>
#include <eosio/fixed_bytes.hpp>

#include <etheraccount/types.hpp>

struct [[eosio::table]] [[eosio::contract("etheraccount")]] account {
    name     eos_account;
    bytes    eth_address;
    uint64_t nonce;

    uint64_t primary_key()const { return eos_account.value; }

    static checksum256 make_key(bytes data){
        check(data.size() == 20, "invalida size");
        bytes20 arr;
        std::copy_n(data.begin(), 20, arr.begin());
        return checksum256(arr);
    }

    checksum256 by_address()const { 
        return account::make_key(eth_address);
    }

    EOSLIB_SERIALIZE(account, (eos_account)(eth_address)(nonce));
};
typedef multi_index< "account"_n, account,
            indexed_by<"by.address"_n, const_mem_fun<account, checksum256, 
                    &account::by_address>> > account_table;
