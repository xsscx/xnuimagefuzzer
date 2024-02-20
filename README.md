
# 🧾 Developer Info 
**Tool:** `XNU Image Fuzzer (XIF)`  
**Classification:** Format-aware mutational fuzzing engine  
**Target Surface:** macOS CoreGraphics stack, IOKit image decoders, kernel rasterization paths

Most importanly, no experience required. follow the instructions and open an Issue if you have questions or get stuck.

XIF builds from this Source using Xcode Cloud.

---

## 🔧 Tool Overview: **XNU Image Fuzzer (XIF)**

**XIF** is a precision image payload generator designed to exercise **low-level image parsing, decoding, and rendering paths** in macOS environments — particularly where these operations **interface with kernel-mode execution**, such as:

- `CoreGraphics` accelerated raster pipelines  
- `QuartzCore` image compositing stacks  
- `IOKit` pixel buffer subsystems  
- Custom or legacy image decode routines in userland-to-kernel transition zones

> Unlike general-purpose fuzzers, **XIF emphasizes structure-valid, logic-malformed input** — images that *pass superficial checks but destabilize deeper logic*.

---

## 🧪 Core Capabilities

| Capability                           | Description                                                                 |
|--------------------------------------|-----------------------------------------------------------------------------|
| **Endian-aware fuzzing**             | Crafts Big/Little Endian payloads to detect byte-order decoding flaws       |
| **Channel depth targeting**          | Supports `8-bit`, `16-bit`, and `32-bit float` pixel formats                |
| **Alpha/Blend logic attack vectors** | Premultiplied vs. non-premultiplied alpha, layer blending fuzz paths        |
| **Color inversion & entropy control**| Inverts RGB channels, applies high-entropy regions for overflow testing     |
| **Semantic compliance**              | Ensures images are syntactically parseable but semantically malformed       |

---

## 🧩 Use Cases

### 🔍 **1. Kernel Exploit Research**
- Exercise image decode paths that cross the user-kernel boundary
- Surface memory corruption in IOKit drivers (`IOGraphicsFamily`, `IOSurface`, etc.)
- Bypass sandbox checks via image-based decoding primitives

### 🖼️ **2. CoreGraphics Stability Analysis**
- Fuzz `CGImageCreate`, `CIImage`, or Quartz rendering entrypoints
- Detect unsafe assumptions in pixel format conversion
- Exploit vectorization/SIMD logic in alpha blending or HDR processing

### 🛡️ **3. Hardening Validation**
- Test custom decoding libraries for failure modes in:
  - Premultiplied alpha assumptions
  - Byte-swapped channel mappings
  - Color space overflows (e.g., HDR10 or 16-bit channel misreads)

### 🧵 **4. Coverage Pipeline Integration**
- Integrate XIF with coverage-guided engines like AFL++, libFuzzer:
  - Use XIF for corpus seeding
  - Pipe outputs into instrumented harnesses (`ImageIO`, `Preview.app`, etc.)

---

## 🧠 Integration Suggestions

| Target Stack         | Harness Strategy                      | Monitor Tools             |
|----------------------|----------------------------------------|---------------------------|
| `CoreGraphics`       | CI pipeline runner w/ fuzzed PNG input | `LLDB`, `Instruments`     |
| `IOKit (GFX)`        | Raw `IOSurface` or `IOAccelerator` input | `DTrace`, kernel logs      |
| `Userland Decoders`  | Inject into `ImageIO` or `QuickLook`  | `ASAN`, `XNU watchdog`     |
| `Remote Services`    | Image-based payload over AirDrop/web   | Monitor for panic/corruption|

---

## ⚠️ Operational Notes

- **Not coverage-aware by default**: best used in conjunction with sanitizer-wrapped harnesses  
- **High crash signal**: monitor for subtle visual artifacts, system instability, kernel logs  
- **Avoid abstraction**: operate on raw byte buffers; ensure transparency of pixel layout  

---

## 🧬 Summary

> **XIF** is a sharp instrument, not a blunt tool — **best suited for surgical fuzzing of image decoders** where precision input yields maximal fault exposure.

Leverage it when:
- You need kernel-level bugs via image processing.
- You're fuzzing GPU-assisted logic or sandbox-proximate services.
- You want rapid surfacing of decoder logic faults without brute force.

**Output = signal-rich, structure-valid, exploit-oriented image inputs.**


---

## Original Readme.md below

# XNU Image Fuzzer 

Last Updated: TUESDAY 25 MARCH 2025 1000 EDT by David Hoyt

## Coming Soon

The XNU Image Fuzzer (XIF) Project will integrate [IccMAX](https://github.com/InternationalColorConsortium/DemoIccMAX) for Image and Icc Profile Fuzzing.

XIF is being Ported to C++ for Cross Platform & Cross Toolchain Fuzzing.

ETA Wen: End of Q2/2025.

## 🛠️ PR119: iccMAX Tooling & Build System

**🔁 Last Updated:** 24-MAR-2025 by David Hoyt  
**📍 PR Link:** [PR119 on GitHub](https://github.com/InternationalColorConsortium/DemoIccMAX/pull/119)  
**🧪 CI Status:**  
[![PR119-Latest](https://github.com/xsscx/PatchIccMAX/actions/workflows/PR119-Latest.yaml/badge.svg)](https://github.com/xsscx/PatchIccMAX/actions/workflows/PR119-Latest.yaml)
[![PR119-Scan-Build](https://github.com/xsscx/PatchIccMAX/actions/workflows/pr119-ubuntu-clang-scan.yaml/badge.svg)](https://github.com/xsscx/PatchIccMAX/actions/workflows/pr119-ubuntu-clang-scan.yaml)

---

## Project Summary

The XNU Image Fuzzer Source Code contains a proof of concept implementation of an image fuzzer designed for XNU environments. It aims to demonstrate basic fuzzing techniques on image data to uncover potential vulnerabilities in image processing routines. The Objective-C Code implements 12 CGCreateBitmap & CGColorSpace Functions working with Raw Data and String Injection that are User Controllable Inputs.
- PermaLink https://srd.cx/xnu-image-fuzzer/
     
## Build & Install Status

| Build OS & Device Info | Build | Install |
|------------------------|-------|---------|
| macOS 14.5 X86_64      | ✅     | ✅       |
| macOS 14.5 arm         | ✅     | ✅       |
| iPadOS 17.5            | ✅     | ✅       |
| iPhoneOS 17.5         | ✅     | ✅       |
| VisionPro 1.2          | ✅     | ✅       |

#### Project Support
- Open an Issue

#### Project Documentation 
URL https://xss.cx/public/docs/xnuimagefuzzer/

### whoami
- I am David Hoyt
  - https://xss.cx
  - https://srd.cx
  - https://hoyt.net

## Quick Start
- Open as Xcode Project or Clone
- Update the Team ID
- Click Run
  - Share a File
    
## Copy Fuzzed Files
- Open the Files App on the Device
  - Tap Share to Transfer the new Fuzzed Images to your Desktop
    - Select All Files to AirDrop to your Desktop
- Screen Grab on iPhone 14 Pro MAX

<img src="https://xss.cx/2024/02/26/img/xnuimagefuzzer-arm64e-sample-output-files_app-sample-file-render-iphone14promax-001.png" alt="XNU Image Fuzzer iPhone 14 Pro Max Render #1" style="height:550px; width:330px;"/> <img src="https://xss.cx/2024/02/26/img/xnuimagefuzzer-arm64e-sample-output-files_app-sample-file-render-iphone14promax-002.png" alt="XNU Image Fuzzer iPhone 14 Pro Max Render #2" style="height:550px; width:330px;"/> 

## How-to Rebuild Xcode Project
- Open Terminal
- Delete the Build Directories from the Project Folder

```
xnuimagefuzzer % rm -rf CMakeCache.txt CMakeFiles CMakeScripts cmake_install.cmake build
```
### Create a Test Folder

```
xnuimagefuzzer % mkdir xcode_build
```
### Create the Xcode Project
```
xnuimagefuzzer % cd xcode_build
xnuimagefuzzer/xcode_build % cmake -G Xcode ../XNU\ Image\ Fuzzer/CMakeLists.txt
-- The C compiler identification is AppleClang 15.0.0.15000309
-- The OBJC compiler identification is AppleClang 15.0.0.15000309
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang - skipped
-- Detecting C compile features
-- Detecting C compile features - done
-- Detecting OBJC compiler ABI info
-- Detecting OBJC compiler ABI info - done
-- Check for working OBJC compiler: /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang - skipped
-- Configuring done (8.8s)
-- Generating done (0.0s)
-- Build files have been written to: /Users/xss/Developer/xnuimagefuzzer/xcode_build
```
### Open the Project, Run
```
xcode_build % open xnuimagefuzzer.xcodeproj/
```

## Purpose of Using Fuzzed Images in Fuzzing

### Overview
Embedding fault mechanisms into a generic image and further processing it through fuzzing enhances the effectiveness of testing by uncovering edge cases and potential vulnerabilities in image processing software.

### Benefits

#### Uncovering Edge Cases
- **Insight:** Fuzzed images introduce a wide range of potential edge cases.
- **Analysis:** Helps uncover rare bugs and vulnerabilities that might only occur with specific, unanticipated inputs.

#### Testing Robustness and Stability
- **Insight:** Stress-tests the robustness of image processing algorithms.
- **Analysis:** Ensures the software can handle diverse and unexpected inputs without crashing or producing incorrect results.

#### Finding Security Vulnerabilities
- **Insight:** Targets specific vulnerabilities through fault injections.
- **Analysis:** Exposes security weaknesses, such as buffer overflows, by providing inputs that cause unexpected behavior.

#### Ensuring Compatibility with Various Formats
- **Insight:** Tests the software's ability to handle different image formats and types.
- **Analysis:** Reduces the risk of compatibility issues by providing comprehensive testing coverage.

#### Automating the Testing Process
- **Insight:** Integrates with automated fuzzing frameworks like Jackalope.
- **Analysis:** Enables continuous and scalable testing, improving software robustness over time.

### Process
1. **Prepare the Image:**
   - Start with a generic image.
   - Apply initial fuzzing to introduce random mutations.
   - Embed specific fault mechanisms to target vulnerabilities.
2. **Submit to Fuzzing Harness:**
   - Load the processed image into a fuzzing framework like Jackalope.
   - Configure the tool to use the image as a seed for further automated fuzzing.
3. **Monitor and Analyze:**
   - Monitor for crashes, hangs, and other signs of vulnerabilities.
   - Collect and analyze the results to identify and understand the bugs found.

## XNU Image Tools
- https://github.com/xsscx/xnuimagetools
- Create random images for fuzzing

## Command Line Version
See URL https://github.com/xsscx/macos-research/tree/main/code/iOSOnMac
