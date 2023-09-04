set(OUT_DIR ${CMAKE_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE}/)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${OUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${OUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${OUT_DIR})

add_executable(launcher "launcher.cpp")
target_compile_features(launcher PRIVATE cxx_std_20)
target_compile_definitions(launcher PRIVATE _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING)