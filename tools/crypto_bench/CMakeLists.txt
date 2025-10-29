cmake_minimum_required(VERSION 3.4)
project(vsomeip_crypto_bench CXX)

add_executable(vsomeip_crypto_bench crypto_bench.cpp)

target_include_directories(vsomeip_crypto_bench PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../interface
)

find_package(OpenSSL REQUIRED)

target_link_libraries(vsomeip_crypto_bench PRIVATE
    vsomeip3-crypto-static
    OpenSSL::Crypto
)

install(TARGETS vsomeip_crypto_bench RUNTIME DESTINATION bin)


