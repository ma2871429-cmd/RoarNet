cmake_minimum_required(VERSION 3.22.1)
project(roarnet_native LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(node SHARED IMPORTED)
set_target_properties(node PROPERTIES
    IMPORTED_LOCATION
    "${CMAKE_CURRENT_SOURCE_DIR}/libnode/bin/${ANDROID_ABI}/libnode.so"
)

add_library(native-lib SHARED
    src/main/cpp/native-lib.cpp
)

target_include_directories(native-lib PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/libnode/include/node"
)

find_library(log-lib log)

target_link_libraries(native-lib
    node
    ${log-lib}
)
