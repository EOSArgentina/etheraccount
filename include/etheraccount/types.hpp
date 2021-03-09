#pragma once

#include <intx/intx.hpp>

using namespace eosio;

typedef intx::uint<256>         u256;
typedef intx::uint<512>         u512;
typedef uint8_t                 byte;
typedef std::vector<uint8_t>    bytes;
typedef std::array<uint8_t, 20> bytes20;
typedef std::array<uint8_t, 32> bytes32;
typedef struct { uint64_t state;  uint64_t inc; } pcg32_random_t;

struct key_weight {
   eosio::public_key  key;
   uint16_t           weight;

   // explicit serialization macro is not necessary, used here only to improve compilation time
   EOSLIB_SERIALIZE( key_weight, (key)(weight) )
};

struct permission_level_weight {
   permission_level  permission;
   uint16_t          weight;

   // explicit serialization macro is not necessary, used here only to improve compilation time
   EOSLIB_SERIALIZE( permission_level_weight, (permission)(weight) )
};

inline bool operator == ( const permission_level_weight& a, const permission_level_weight& b ) {
   return std::tie( a.permission, a.weight ) == std::tie( b.permission, b.weight );
}

inline bool operator < ( const permission_level_weight& a, const permission_level_weight& b ) {
   return std::tie(a.permission, a.weight) < std::tie(b.permission, b.weight);
}

struct wait_weight {
   uint32_t           wait_sec;
   uint16_t           weight;

   // explicit serialization macro is not necessary, used here only to improve compilation time
   EOSLIB_SERIALIZE( wait_weight, (wait_sec)(weight) )
};

struct authority {
   uint32_t                              threshold = 0;
   std::vector<key_weight>               keys;
   std::vector<permission_level_weight>  accounts;
   std::vector<wait_weight>              waits;

   // explicit serialization macro is not necessary, used here only to improve compilation time
   EOSLIB_SERIALIZE( authority, (threshold)(keys)(accounts)(waits) )
};

struct ethtx_payload {
   uint32_t             method_id;
   u256                 rp;
   u256                 actions_offset;
   u256                 actions_length;
   std::vector<action>  actions;

   static ethtx_payload from_bytes(const bytes& data) {
      ethtx_payload payload;
      datastream<const uint8_t*> ds(data.data(), data.size());
      ds >> payload;
      return payload;
   }

   EOSLIB_SERIALIZE( ethtx_payload, (method_id)(rp)(actions_offset)(actions_length)(actions) )
};


namespace eosio {

template<typename Stream>
inline datastream<Stream>& operator>>(datastream<Stream>& ds, u256& v) {
   bytes buffer(32,0);
   ds.read((char*)buffer.data(), 32);
   v = intx::be::unsafe::load<u256>(buffer.data());
   return ds;
}

}