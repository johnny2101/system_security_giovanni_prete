cmake_minimum_required(VERSION 3.13.4)
project(CFAGeneratorPass)

find_package(LLVM REQUIRED CONFIG)

list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

add_library(CFAGeneratorPass MODULE CFAGeneratorPass.cpp)
target_link_libraries(CFAGeneratorPass PUBLIC LLVM)

# Support running opt with our pass
set_target_properties(CFAGeneratorPass PROPERTIES LINKER_LANGUAGE CXX)
