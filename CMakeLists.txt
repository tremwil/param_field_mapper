cmake_minimum_required(VERSION 3.23)
project(
    param_field_mapper 
    VERSION 1.1.1
    LANGUAGES CXX C
)

set(CMAKE_CXX_STANDARD 20)

set(OUT_DIR ${CMAKE_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE}/)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${OUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${OUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${OUT_DIR})

file(GLOB_RECURSE DEPENDENCIES 
    "dependencies/*.h" 
    "dependencies/*.inc" 
    "dependencies/*.hpp" 
    "dependencies/*.cpp" 
    "dependencies/*.c"
)

file(GLOB_RECURSE SRC_FILES CONFIGURE_DEPENDS 
    "src/*.h" 
    "src/*.inc" 
    "src/*.hpp" 
    "src/*.cpp"
)

file(GLOB STATIC_LIBS CONFIGURE_DEPENDS "./lib/*.lib")

file(GLOB RESOURCES "resources/*")
foreach (FILE ${RESOURCES})
    get_filename_component(FILE_NAME "${FILE}" NAME)
    if (NOT EXISTS "${OUT_DIR}/${FILE_NAME}") 
        file(COPY ${FILE} DESTINATION ${OUT_DIR})
    endif()
endforeach()

set(CMAKE_SHARED_LIBRARY_PREFIX "")
add_library(param_field_mapper SHARED "${DEPENDENCIES};${SRC_FILES}")

target_include_directories(param_field_mapper PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR} 
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/dependencies
)

target_link_libraries(param_field_mapper PRIVATE ${STATIC_LIBS} "dbghelp.lib" "synchronization.lib")
target_compile_features(param_field_mapper PRIVATE cxx_std_20)

# Disable min/max macros to not override std::min and std::max, and _CRT_SECURE_NO_WARNINGS and __cpp_consteval (to fix source_location)
target_compile_definitions(param_field_mapper PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS __cpp_consteval)

add_subdirectory(launcher)
add_subdirectory(dependencies)