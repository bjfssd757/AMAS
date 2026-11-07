if(AMAS_BUILD_SERVER_STATIC)
    add_subdirectory("static")
endif()

if(AMAS_BUILD_SERVER_DYNAMIC)
    add_subdirectory("dynamic")
endif()