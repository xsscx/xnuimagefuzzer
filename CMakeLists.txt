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
set(CMAKE_XCODE_ATTRIBUTE_DEVELOPMENT_TEAM "YOUR_TEAM_ID")

if(CMAKE_BUILD_TYPE MATCHES Debug)
  # Enable debug symbols
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")

  # Enable Address Sanitizer (ASAN)
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address")
  # Link with ASAN
  set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address")
endif()

if(CMAKE_BUILD_TYPE MATCHES Debug)
  # Existing debug and ASAN settings
  
  # Enable code coverage with Clang/LLVM
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fprofile-instr-generate -fcoverage-mapping")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fprofile-instr-generate -fcoverage-mapping")
endif()

# Define the executable with its new name and necessary source files
add_executable(xnuimagefuzzer main.m) # Executable name changed to xnuimagefuzzer

# Since your project targets iOS, ensure it links against the correct frameworks
if(APPLE)
  target_link_libraries(xnuimagefuzzer
    "-framework UIKit"
    "-framework ImageIO"
    "-framework CoreGraphics"
    "-framework Foundation" # Ensure Foundation framework is linked
  )
endif()
