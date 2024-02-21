# This File written by @h02332 David Hoyt for XNU Image Fuzzer
#
# The Config assumes you will name the Project xnuimagefuzzer and binary xnuimagefuzzer, adjust as necessary
#
# Compile Instructions
# mkdir build
# cd build
# cmake ..  -G  Xcode
# cmake --build . --config Debug
#
#
#
cmake_minimum_required(VERSION 3.15) # Ensure this is the first line to set the minimum required version of CMake
project(xnuimagefuzzer LANGUAGES C OBJC) # Project name changed to xnuimagefuzzer

# These lines ensure the project targets iOS correctly
set(CMAKE_SYSTEM_NAME iOS)
execute_process(COMMAND xcrun --sdk iphoneos --show-sdk-path OUTPUT_VARIABLE IOS_SDK_ROOT OUTPUT_STRIP_TRAILING_WHITESPACE)
set(CMAKE_OSX_SYSROOT "${IOS_SDK_ROOT}")
set(CMAKE_OSX_ARCHITECTURES arm64)
set(CMAKE_XCODE_ATTRIBUTE_IPHONEOS_DEPLOYMENT_TARGET "14.2")

if(CMAKE_BUILD_TYPE MATCHES Debug)
  # Enable debug symbols
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
  # Enable Address Sanitizer (ASAN)
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address")
  # Enable code coverage with Clang/LLVM
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fprofile-instr-generate -fcoverage-mapping")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fprofile-instr-generate -fcoverage-mapping")
  # Link with ASAN
  set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address")
endif()

# Define the executable with its new name and necessary source files
add_executable(xnuimagefuzzer main.m) # Executable name changed to xnuimagefuzzer

# Set the path to the Info.plist file
# set_target_properties(xnuimagefuzzer PROPERTIES
#  MACOSX_BUNDLE_INFO_PLIST ${CMAKE_SOURCE_DIR}/Info.plist
# )

# Since your project targets iOS, ensure it links against the correct frameworks
if(APPLE)
  target_link_libraries(xnuimagefuzzer
    "-framework UIKit"
    "-framework ImageIO"
    "-framework CoreGraphics"
    "-framework Foundation" # Ensure Foundation framework is linked
  )
endif()
