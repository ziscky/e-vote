cmake_minimum_required(VERSION 3.10)
project(e_vote)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(PythonLibs 2.7 REQUIRED)
find_package(Boost 1.70.0 REQUIRED COMPONENTS python)

include_directories("${CMAKE_SOURCE_DIR}/.")
add_library(e_vote
        blockchain/blockchain.cpp
        blockchain/merkle.cpp
        network/kdht.cpp
        security/ecc.cpp
        security/identity.cpp
        utils/utils.cpp)

add_library(identity
        security/ecc.cpp
        security/identity.cpp)

include_directories(${Boost_INCLUDE_DIR} "/usr/include/python2.7")

add_library(evotepy SHARED evote-py.cpp)
target_link_libraries(identity -lcryptopp)
target_link_libraries(evotepy -lboost_python27 -lpython2.7  identity)
set_target_properties(evotepy PROPERTIES PREFIX "")

target_link_libraries(e_vote -lcryptopp -lopendht -lreadline -lpthread)


ADD_EXECUTABLE(peer peer.cpp)
target_link_libraries(peer e_vote)

ADD_EXECUTABLE(enctest enctest.cpp)
target_link_libraries(enctest e_vote)

install(TARGETS peer DESTINATION "${CMAKE_SOURCE_DIR}/.")
install(TARGETS enctest DESTINATION "${CMAKE_SOURCE_DIR}/.")
install(TARGETS evotepy DESTINATION "${CMAKE_SOURCE_DIR}/.")