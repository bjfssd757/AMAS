if(POLICY CMP0218)
    cmake_policy(SET CMP0218 NEW)
endif()

option(AMAS_BUILD_SERVER_STATIC "Build server static analyze tool" ON)
option(AMAS_BUILD_SERVER_DYNAMIC "Build server dynamic analyze tool" ON)
option(AMAS_BUILD_FRONTEND "Build frontend" ON)

option(AMAS_BUILD_SERVER_STATIC_TESTS "Build server static tests" ON)
option(AMAS_BUILD_SERVER_DYNAMIC_TESTS "Build server dynamic tests" OFF)
option(AMAS_BUILD_FRONTEND_TESTS "Build frontend tests" OFF)

set(VCPKG_MANIFEST_FEATURES "")
get_cmake_property(_cache_vars CACHE_VARIABLES)

foreach(_var IN LISTS _cache_vars)
    if(_var MATCHES "^AMAS_BUILD_(.+)$" AND ${_var})
        string(TOLOWER "${CMAKE_MATCH_1}" _feature_name)
        string(REPLACE "_" "-" _feature_name "${_feature_name}")
        list(APPEND VCPKG_MANIFEST_FEATURES "${_feature_name}")
    endif()
endforeach()