cmake_minimum_required(VERSION 3.29)

if (NOT DEFINED CMAKE_ANDROID_NDK)
    set(CMAKE_ANDROID_NDK D:/Android/SDK/ndk/27.0.11718014)
    set(CMAKE_TOOLCHAIN_FILE ${CMAKE_ANDROID_NDK}/build/cmake/android.toolchain.cmake)
    set(CMAKE_SYSTEM_NAME Android)
    set(CMAKE_SYSTEM_VERSION 24)
    set(CMAKE_ANDROID_ARCH_ABI arm64-v8a)
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    set(ANDROID_ABI arm64-v8a)
    set(ANDROID_PLATFORM android-26)
    set(ANDROID_NDK ${CMAKE_ANDROID_NDK})

    set(VCPKG_TARGET_TRIPLET "arm64-android")
    include(D:/WorkDir/vcpkg_clion/scripts/buildsystems/vcpkg.cmake)
else ()
    SET(ANDROID_STUDIO_BUILD true)
endif ()

project(AndroidBypassOverlay)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
        ${CMAKE_SOURCE_DIR}/outputs/${CMAKE_ANDROID_ARCH_ABI}/
)

add_executable(AndroidBypassOverlay main.cpp elf_util.cpp)
