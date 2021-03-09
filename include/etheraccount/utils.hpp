#pragma once
#include <string_view>
#include <sha3/sha3.h>
#include <rlpvalue.h>

#include <eosio/transaction.hpp>

#include <etheraccount/config.hpp>
#include <etheraccount/types.hpp>
#include <eosio.system/exchange_state.hpp>

namespace etheraccount { namespace utils {

// sha3(pushEosTransaction(uint64,bytes)) = bafbb2080991eb6180fc9765cedaa1f901f54801099bbd60be14a9c74b5c640c
const uint32_t push_eos_transaction_method_id = 0xbafbb208;

// sha3(transfer(address,uint256)) = a9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b
const uint32_t transfer_method_id = 0xa9059cbb;

bytes32 sha3(const char* data, size_t len) {
   bytes32 message;
   sha3_ctx shactx;
   rhash_keccak_256_init(&shactx);
   rhash_keccak_update(&shactx, (const uint8_t*)data, len);
   rhash_keccak_final(&shactx, message.data());
   return message;
}

bytes32 sha3(const std::string& data) {
   return sha3(data.data(), data.length());
}

asset bytes_to_eos( uint32_t bytes ) {
   eosiosystem::rammarket market("eosio"_n, "eosio"_n.value);
   auto itr = market.find(eosiosystem::ramcore_symbol.raw());
   const int64_t ram_reserve   = itr->base.balance.amount;
   const int64_t eos_reserve   = itr->quote.balance.amount;
   const int64_t cost          = eosiosystem::exchange_state::get_bancor_input( ram_reserve, eos_reserve, bytes );
   const int64_t cost_plus_fee = cost / double(0.995);
   return asset{ cost_plus_fee, eosio::symbol(eosio::symbol_code("EOS"), 4) };
}

u256 to_u256(const RLPValue& v) {
   eosio::check(v.isBuffer() && v.size() <= 32, "unable to convert to u256");
   auto buff = v.get_str();
   uint8_t tmp[32] = {0};
   memcpy(tmp+32-buff.length(), buff.data(), buff.length());
   return intx::be::load<u256>(tmp);
}

u256 to_u256(const bytes& v) {
   eosio::check(v.size()==32, "invalid size");
   return intx::be::unsafe::load<u256>(v.data());
}

template <typename T>
asset wei_to_eos(const T& v) {
   auto r = v/T(1e14);
   eosio::check(r < asset::max_amount, "invalid amount");
   return asset(static_cast<uint64_t>(r), eosio::symbol(eosio::symbol_code("EOS"), 4));
}

extended_symbol to_extended_symbol(const bytes20& data) {
   return eosio::unpack<extended_symbol>((const char*)(data.data()), data.size());
}

bytes to_bytes(const u256& v) {
   bytes res(32,0);
   intx::be::unsafe::store(res.data(), v);
   return res;
}

bytes to_bytes(const RLPValue& v){
   auto tmp = v.get_str();
   return bytes{tmp.data(), tmp.data()+tmp.length()};
}

std::string to_lower(const std::string& s) {
    std::string res(s);
    std::transform(s.begin(), s.end(), res.begin(),
    [](unsigned char c){ return std::tolower(c); });
    return res;
}

uint8_t from_hex( char c ) {
   if( c >= '0' && c <= '9' )
      return c - '0';
   if( c >= 'a' && c <= 'f' )
      return c - 'a' + 10;
   if( c >= 'A' && c <= 'F' )
      return c - 'A' + 10;
   eosio::check( false, "Invalid hex character");
   return 0;
}

size_t from_hex( const std::string_view& hex_str, uint8_t* out_data, size_t out_data_len ) {
   std::string_view::const_iterator i = hex_str.begin();
   uint8_t* out_pos = (uint8_t*)out_data;
   uint8_t* out_end = out_pos + out_data_len;
   while( i != hex_str.end() && out_end != out_pos ) {
      *out_pos = from_hex( *i ) << 4;   
      ++i;
      if( i != hex_str.end() )  {
         *out_pos |= from_hex( *i );
         ++i;
      }
      ++out_pos;
   }
   return out_pos - (uint8_t*)out_data;
}

size_t from_hex( const std::string& hex_str, uint8_t* out_data, size_t out_data_len ) {
   return from_hex(std::string_view(hex_str), out_data, out_data_len);
}
   
std::string to_hex( const unsigned char* d, uint32_t s ) {
   std::string r;
   const char* to_hex="0123456789abcdef";
   uint8_t* c = (uint8_t*)d;
   for( uint32_t i = 0; i < s; ++i )
      (r += to_hex[(c[i]>>4)]) += to_hex[(c[i] &0x0f)];
   return r;
}

std::string to_hex( const std::vector<uint8_t>& data ) {
   return to_hex( data.data(), data.size() );
}

std::string to_hex( const bytes20& data ) {
   return to_hex( data.data(), data.size() );
}

std::tuple<std::string_view, name> get_memo_params(const std::string& s) {
   std::string_view addy(s);
   name newname;

   auto r = addy.find(",");
   if(r != std::string_view::npos) {
      newname = name(addy.substr(r+1));
      addy.remove_suffix(addy.size()-r); 
   }

   return std::make_tuple(addy, newname);
}

void pcg32_init(pcg32_random_t* rng) {
   auto size = read_transaction(nullptr, 0);
   char* buffer = (char*)malloc(size);
   check(buffer != nullptr, "malloc failed");
   read_transaction(buffer, size);
   auto h = sha256(buffer, size).extract_as_byte_array();
   *rng = *reinterpret_cast<pcg32_random_t*>(h.data());
}

uint32_t pcg32_random_r(pcg32_random_t* rng)
{
   uint64_t oldstate = rng->state;
   // Advance internal state
   rng->state = oldstate * 6364136223846793005ULL + (rng->inc|1);
   // Calculate output function (XSH RR), uses old state for max ILP
   uint32_t xorshifted = ((oldstate >> 18u) ^ oldstate) >> 27u;
   uint32_t rot = oldstate >> 59u;
   return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}

name generate_account_name() {
   pcg32_random_t rng;
   pcg32_init(&rng);
   static const char* charmap = "12345abcdefghijklmnopqrstuvwxyz";
   char tmp[13]={0};
   for(auto i=0; i<12; i++) {
      auto r = pcg32_random_r(&rng);
      tmp[i] = charmap[r % 31];
   }
   return name(tmp);
}

} //namespace utils
} //namespace etheraccount