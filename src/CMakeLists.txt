cmake_minimum_required(VERSION 3.19)
project(etheraccount)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)

add_contract( etheraccount etheraccount 
    ${CMAKE_CURRENT_SOURCE_DIR}/etheraccount.cpp 
    
    ${CMAKE_CURRENT_SOURCE_DIR}/../external/eosio.system/exchange_state.cpp
    
    ${CMAKE_CURRENT_SOURCE_DIR}/../external/sha3/sha3.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../external/sha3/byte_order.c

    ${CMAKE_CURRENT_SOURCE_DIR}/../external/ecc/uECC.c

    ${CMAKE_CURRENT_SOURCE_DIR}/../external/rlpvalue/rlpvalue_get.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../external/rlpvalue/rlpvalue_read.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../external/rlpvalue/rlpvalue_write.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../external/rlpvalue/rlpvalue.cpp
)

target_include_directories( etheraccount PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../external
    ${CMAKE_CURRENT_SOURCE_DIR}/../external/rlpvalue
    ${CMAKE_CURRENT_SOURCE_DIR}/../external/sha3
    ${CMAKE_CURRENT_SOURCE_DIR}/../external/ecc
)

target_compile_definitions(etheraccount PRIVATE -DUSE_KECCAK -DuECC_SUPPORT_COMPRESSED_POINT=1 -DuECC_WORD_SIZE=8 )
