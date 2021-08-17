#pragma once

static constexpr uint8_t  eos_chain_id    = 59;
static constexpr auto     EOS             = eosio::extended_symbol{eosio::symbol("EOS",4), "eosio.token"_n};
static constexpr uint32_t new_account_ram = 1605;
static constexpr uint32_t table_ram       = 512;
static constexpr uint32_t token_ram       = 256;
