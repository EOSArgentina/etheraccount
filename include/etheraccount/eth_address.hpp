#pragma once
#include <ecc/uECC.h>
#include <etheraccount/utils.hpp>

using namespace etheraccount::utils;

struct eth_address {

   bool        empty;
   bytes20     data;

   eth_address() : empty(true) {}

   bool is_empty(){ return empty; }
   const bytes20& get_bytes()const { return data; }

   static eth_address from_string(const std::string_view& s) {

      std::string_view ss(s);
      if( ss.find("0x") == 0 ) ss = ss.substr(2);

      check(ss.size() == 40, "invalid address length");

      eth_address res;
      auto size = from_hex(ss, res.data.data(), res.data.size());
      res.empty = false;

      return res;
   }

   static eth_address from_string(const std::string& s) {
      return from_string(std::string_view(s));
   }

   static eth_address from_pubkey(const public_key& pub) {
      auto compressed_pubkey = eosio::pack(pub);

      uint8_t uncompressed_pubkey[64];
      uECC_decompress((uint8_t*)compressed_pubkey.data()+1, uncompressed_pubkey, uECC_secp256k1());

      auto pubkey_hash = sha3((const char*)&uncompressed_pubkey[0], 64);
      eth_address res;
      memcpy(res.data.data(), pubkey_hash.data() + 12, res.data.size());
      res.empty = false;
      return res;
   }

   static eth_address from_bytes(const bytes& b) {
      eth_address res;
      check(b.empty() || res.data.size() == b.size(), "invalid size");
      res.empty = b.empty();
      if(!res.empty)
         memcpy(res.data.data(), b.data(), b.size());
      return res;
   }

};
