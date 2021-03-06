// Copyright 2014 BitPay Inc.
// Copyright 2015 Bitcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/licenses/mit-license.php.
#include <eosio/eosio.hpp>

#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdexcept>
#include <vector>
#include <limits>
#include <string>

#include "rlpvalue.h"

const std::vector<RLPValue>& RLPValue::getValues() const
{
    if (typ != VARR)
        eosio::check(false, "JSON value is not an object or array as expected");
    return values;
}

std::string RLPValue::get_str() const
{
    if (typ != VBUF)
        eosio::check(false, "JSON value is not a string as expected");
    return getValStr();
}

const RLPValue& RLPValue::get_array() const
{
    if (typ != VARR)
        eosio::check(false, "JSON value is not an array as expected");
    return *this;
}

