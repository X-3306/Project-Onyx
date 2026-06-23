cmake_minimum_required(VERSION 3.25)
project(ProjectOnyx LANGUAGES C CXX RC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# The tested ONNX Runtime build uses the DLL CRT triplet (x64-windows-static-md).
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")

set(PROJECT_ONYX_ORT_ROOT
    "${CMAKE_CURRENT_SOURCE_DIR}/onnxruntime"
    CACHE PATH "Path to an ONNX Runtime source/build tree")
set(PROJECT_ONYX_ORT_BUILD_ROOT
    "${PROJECT_ONYX_ORT_ROOT}/build/Windows/Release"
    CACHE PATH "Path to the ONNX Runtime Release build root")
set(ORT_BUILD_DIR
    "${PROJECT_ONYX_ORT_BUILD_ROOT}/Release"
    CACHE PATH "Path containing ONNX Runtime static component libraries")
set(ORT_THIRD_PARTY_LIB_DIR
    "${PROJECT_ONYX_ORT_BUILD_ROOT}/vcpkg_installed/x64-windows-static-md/lib"
    CACHE PATH "Path containing ONNX Runtime third-party static libraries")

foreach(required_path IN ITEMS
    "${PROJECT_ONYX_ORT_ROOT}/include/onnxruntime/core/session/onnxruntime_cxx_api.h"
    "${ORT_BUILD_DIR}/onnxruntime_session.lib"
    "${ORT_THIRD_PARTY_LIB_DIR}"
)
    if(NOT EXISTS "${required_path}")
        message(FATAL_ERROR "Missing ONNX Runtime build artifact: ${required_path}")
    endif()
endforeach()

add_library(onnxruntime_static INTERFACE)

target_include_directories(onnxruntime_static INTERFACE
    "${PROJECT_ONYX_ORT_ROOT}/include"
    "${PROJECT_ONYX_ORT_ROOT}/include/onnxruntime/core/session"
)

file(GLOB ORT_THIRD_PARTY_LIBS CONFIGURE_DEPENDS "${ORT_THIRD_PARTY_LIB_DIR}/*.lib")

set(WASM3_SOURCES
    wasm3/source/m3_bind.c
    wasm3/source/m3_code.c
    wasm3/source/m3_compile.c
    wasm3/source/m3_core.c
    wasm3/source/m3_env.c
    wasm3/source/m3_exec.c
    wasm3/source/m3_function.c
    wasm3/source/m3_info.c
    wasm3/source/m3_module.c
    wasm3/source/m3_parse.c
)

set(ORT_STATIC_LIBS
    "${ORT_BUILD_DIR}/onnxruntime_session.lib"
    "${ORT_BUILD_DIR}/onnxruntime_framework.lib"
    "${ORT_BUILD_DIR}/onnxruntime_graph.lib"
    "${ORT_BUILD_DIR}/onnxruntime_optimizer.lib"
    "${ORT_BUILD_DIR}/onnxruntime_providers.lib"
    "${ORT_BUILD_DIR}/onnxruntime_util.lib"
    "${ORT_BUILD_DIR}/onnxruntime_common.lib"
    "${ORT_BUILD_DIR}/onnxruntime_flatbuffers.lib"
    "${ORT_BUILD_DIR}/onnxruntime_mlas.lib"
    "${ORT_BUILD_DIR}/onnxruntime_lora.lib"
    "${PROJECT_ONYX_ORT_BUILD_ROOT}/model_package/Release/model_package.lib"
)

target_link_libraries(onnxruntime_static INTERFACE
    ${ORT_STATIC_LIBS}
    ${ORT_THIRD_PARTY_LIBS}
)

add_executable(ProjectOnyx
    DiagnosticsTool.cpp
    DiagnosticsTool.rc
    ${WASM3_SOURCES}
)

target_include_directories(ProjectOnyx PRIVATE wasm3/source)
target_compile_definitions(ProjectOnyx PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(ProjectOnyx PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/W4 /permissive- /EHsc>)

target_link_libraries(ProjectOnyx PRIVATE
    onnxruntime_static
    bcrypt
    advapi32
    crypt32
    winhttp
    ws2_32
    dbghelp
    shlwapi
    secur32
    version
    setupapi
    dxgi
)