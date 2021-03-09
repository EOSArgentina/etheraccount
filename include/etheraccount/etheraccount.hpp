#include <eosio/eosio.hpp>
using namespace eosio;

#include <etheraccount/types.hpp>

struct eth_address;

namespace etheraccount {

CONTRACT etheraccount : public contract {
   public:
      using contract::contract;

      ACTION pushtx( const bytes& rlptx, const asset& fee, uint32_t ram2buy );

      [[eosio::on_notify("*::transfer")]]
      void on_transfer(name from, name to, asset quantity, std::string memo);

   protected:
      asset create_new_account(name creator, const name& eos_account, const eth_address& address);
};

} // namespace etheraccount