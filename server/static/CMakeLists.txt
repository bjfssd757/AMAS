set(NAME AMAStatic)

set(CORE_SOURCES
    src/binary.cpp
)

include(FindPkgConfig)
find_package(PkgConfig REQUIRED)

find_package(Rizin REQUIRED COMPONENTS Core)
find_package(triton REQUIRED)
find_package(capstone REQUIRED)
find_package(CLI11 REQUIRED)
find_package(unofficial-hash-library REQUIRED)
find_package(unofficial-libyara REQUIRED)
find_package(msgpack-c REQUIRED)
find_package(spdlog REQUIRED)
find_package(magic_enum REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(glaze REQUIRED)
pkg_check_modules(UNICORN REQUIRED IMPORTED_TARGET unicorn)

add_executable(${NAME} src/main.cpp ${CORE_SOURCES})

set(COMMON_LIBS
    Rizin::Core
    triton::triton
    capstone::capstone
    PkgConfig::UNICORN
    CLI11::CLI11
    unofficial::hash-library
    unofficial::libyara::libyara
    msgpack-c
    spdlog::spdlog
    magic_enum::magic_enum
    nlohmann_json::nlohmann_json
    glaze::glaze
)

target_link_libraries(${NAME} PRIVATE ${COMMON_LIBS})
target_include_directories(${NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(AMAS_BUILD_SERVER_STATIC_TESTS)
    find_package(doctest REQUIRED)

    set(TEST_NAME "${NAME}_Tests")

    add_executable(${TEST_NAME}
        tests/main.test.cpp
        tests/binary.test.cpp
        tests/scanner.yara.test.cpp
        tests/mock-elf64.cpp
        ${CORE_SOURCES}
    )

    target_link_libraries(${TEST_NAME} PRIVATE 
        ${COMMON_LIBS}
        doctest::doctest
    )
    
    target_include_directories(${TEST_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_definitions(${TEST_NAME} PRIVATE AMAS_TESTS_ENABLED)
endif()
