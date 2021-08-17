#include <eosio/eosio.hpp>
#include <eosio/print.hpp>

#include <eosio/eosio.hpp>
#include <eosio/asset.hpp>
#include <eosio/crypto.hpp>
#include <eosio/transaction.hpp>
#include <eosio/action.hpp>

#include <eosio.system/exchange_state.hpp>

#include <etheraccount/utils.hpp>
#include <etheraccount/etheraccount.hpp>
#include <etheraccount/tables.hpp>
#include <etheraccount/eth_address.hpp>
#include <etheraccount/eth_transaction.hpp>
#include <etheraccount/config.hpp>

namespace etheraccount {

using namespace etheraccount::utils;

void etheraccount::on_transfer(name from, name to, asset quantity, std::string memo) {

   if( from == get_self() || from == "eosio.ram"_n ) return;
   check(to == get_self(), "not for me");

   auto amount = extended_asset{quantity, get_first_receiver()};
   check(amount.quantity.amount > 0, "amount must be positive");

   auto [address_str, account_name] = get_memo_params(memo);

   auto address = eth_address::from_string(address_str);
   check(!address.is_empty(), "memo must contain a valid eth address");

   account_table accounts(get_self(), get_self().value);
   auto inx = accounts.get_index<"by.address"_n>();

   auto itr = inx.find(address.get_bytes());
   if( itr != inx.end() ) {

      action(permission_level{ get_self(), "active"_n },
         amount.contract, "transfer"_n,
         std::make_tuple( get_self(), itr->eos_account, amount.quantity, std::string("") )
      ).send();

   } else {
      check( amount.get_extended_symbol() == EOS, "first transfer must be EOS");

      if ( account_name.value == 0 )
         account_name = generate_account_name();

      auto new_account_cost = create_new_account(get_self(), account_name, address);

      auto token_ram_cost = bytes_to_eos(token_ram);
      action(permission_level{ get_self(), "active"_n },
         "eosio"_n, "buyram"_n, 
         std::make_tuple( get_self(), get_self(), token_ram_cost )
      ).send();

      // forward remaining EOS
      auto remaining = quantity-(new_account_cost+token_ram_cost);
      check( remaining.amount >= 0, "unable to cover account creation costs");

      if( remaining.amount > 0 ) {
         action(permission_level{ get_self(), "active"_n },
            "eosio.token"_n, "transfer"_n,
            std::make_tuple( get_self(), account_name, remaining, std::string("") )
         ).send();
      }

   }
}

void etheraccount::pushtx( const bytes& rlptx, const asset& txfee, uint32_t ram2buy ) {

   asset fee = txfee;

   check(fee.symbol == symbol("EOS",4), "invalid fee symbol");
   check(fee.amount >= 0, "invalid fee amount");

   auto ethtx = eth_transaction::from_rlp(rlptx);

   account_table accounts(get_self(), get_self().value);
   auto inx = accounts.get_index<"by.address"_n>();

   auto from_itr = inx.find(ethtx.sender.get_bytes());
   check(from_itr != inx.end(), "sender not found");

   check(ethtx.nonce == u256(from_itr->nonce), "invalid nonce");

   auto rp = get_action(1, 0).authorization[0].actor.value;
   auto max_to_pay = ethtx.get_fee();
   check(fee <= max_to_pay, "invalid fee");

   if( ram2buy ) {
      auto ram2buy_cost = bytes_to_eos(ram2buy);
      action(permission_level{ from_itr->eos_account, "active"_n },
         "eosio"_n, "buyrambytes"_n, 
         std::make_tuple( from_itr->eos_account, from_itr->eos_account, ram2buy )
      ).send();
      fee -= ram2buy_cost;
   }

   if( ethtx.is_transfer() ) {

      auto destination_address = ethtx.transfer_destination();
      auto to_itr = inx.find(destination_address.get_bytes());

      name destination_eos_account;
      extended_asset amount = ethtx.transfer_amount();

      if( to_itr != inx.end() ) {
         destination_eos_account = to_itr->eos_account;
      } else {
         destination_eos_account = generate_account_name();
         auto cost = create_new_account(from_itr->eos_account, destination_eos_account, destination_address);
         fee -= cost;
      }

      action(permission_level{ from_itr->eos_account, "active"_n },
         amount.contract, "transfer"_n, 
         std::make_tuple( from_itr->eos_account, destination_eos_account, amount.quantity, std::string("") )
      ).send();

   } else {
      auto payload = ethtx_payload::from_bytes(ethtx.data);

      check(payload.method_id == __builtin_bswap32(push_eos_transaction_method_id), "invalid method id");
      check(static_cast<uint64_t>(payload.rp) == rp, "invalid rp");

      for(const auto& act : payload.actions) {
         for(const auto& auth : act.authorization) {
            check(auth.actor == from_itr->eos_account, "unable to authorize");
         }
         act.send();
      }
   }

   if( from_itr->nonce == 0 ) {
      auto newauth = authority{
         1, {{ethtx.pubkey, 1}},
         {{{get_self(), "active"_n}, 1}},{}
      };

      action(permission_level{ from_itr->eos_account, "active"_n },
         "eosio"_n, "updateauth"_n, 
         std::make_tuple( from_itr->eos_account, "active"_n, "owner"_n, newauth )
      ).send();

      action(permission_level{ from_itr->eos_account, "owner"_n },
         "eosio"_n, "updateauth"_n, 
         std::make_tuple( from_itr->eos_account, "owner"_n, name(), newauth )
      ).send();
   }

   inx.modify(from_itr, same_payer, [&](auto& row){
      row.nonce += 1;
   });

   check(fee.amount >= 0 || txfee.amount-fee.amount <= max_to_pay.amount, "transaction cost excedes max to pay");

   if( fee.amount > 0 ) {
      action(permission_level{ from_itr->eos_account, "active"_n },
         "eosio.token"_n, "transfer"_n, 
         std::make_tuple( from_itr->eos_account, rp, fee, std::string("fee") )
      ).send();
   }
}

asset etheraccount::create_new_account(name creator, const name& eos_account, const eth_address& address) {

   auto me = authority{
      1, {},
      {{{get_self(), "active"_n}, 1}},{}
   };

   action(permission_level{ creator, "active"_n },
      "eosio"_n, "newaccount"_n, 
      std::make_tuple( creator, eos_account, me, me )
   ).send();

   auto new_account_ram_cost = bytes_to_eos(new_account_ram);
   action(permission_level{ creator, "active"_n },
      "eosio"_n, "buyrambytes"_n, 
      std::make_tuple( creator, eos_account, new_account_ram )
   ).send();

   auto table_ram_cost = bytes_to_eos(table_ram);
   action(permission_level{ creator, "active"_n },
      "eosio"_n, "buyrambytes"_n, 
      std::make_tuple( creator, get_self(), table_ram )
   ).send();

   account_table accounts(get_self(), get_self().value);
   accounts.emplace(get_self(), [&](auto& row){
      auto arr = address.get_bytes();
      row.eos_account = eos_account;
      row.eth_address = bytes(arr.begin(), arr.begin()+arr.size());
      row.nonce = 0;
   });

   return new_account_ram_cost+table_ram_cost;
}


} //namespace etheraccount
