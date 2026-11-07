cmake_minimum_required(VERSION 3.14)
include("cmake/vcpkg_setup.cmake")
project(AMAS LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory("server")
add_subdirectory("frontend")