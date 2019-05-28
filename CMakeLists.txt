cmake_minimum_required(VERSION 3.14)
project(e_vote)

set(CMAKE_CXX_STANDARD 17)

include_directories("${CMAKE_SOURCE_DIR}/.")
add_library(e_vote
        blockchain/blockchain.cpp
        blockchain/merkle.cpp
        network/kdht.cpp
        security/ecc.cpp
        security/identity.cpp
        utils/utils.cpp)


target_link_libraries(e_vote -lcryptopp -lopendht -lreadline -lpthread)

ADD_EXECUTABLE(peer peer.cpp)
target_link_libraries(peer e_vote)

ADD_EXECUTABLE(enctest enctest.cpp)
target_link_libraries(enctest e_vote)

install(TARGETS peer DESTINATION "${CMAKE_SOURCE_DIR}/.")
install(TARGETS enctest DESTINATION "${CMAKE_SOURCE_DIR}/.")