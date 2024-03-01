# XNU Image Fuzzer 

Last Updated: February 29, 2024, 2107 EST

## Project summary

The Source Code contains a proof of concept implementation of an image fuzzer designed for XNU environments. It aims to demonstrate basic fuzzing techniques on image data to uncover potential vulnerabilities in image processing routines.
- PermaLink https://srd.cx/xnu-image-fuzzer/
  
### whoami
I am David Hoyt. I was in the Apple Security Research Device Program for 2021 & 2022. Apple sent me an iPhone 11 & iPhone 12 for A/B testing, very helpful. This Project is some of the Code I wrote for debugging on the SRD.

#### iPhone 14 Pro Max Render 
<img src="https://xss.cx/2024/02/26/img/xnuimagefuzzer-arm64e-sample-output-files_app-sample-file-render-iphone14promax-001.png" alt="XNU Image Fuzzer iPhone 14 Pro Max Render #1" style="height:550px; width:330px;"/> <img src="https://xss.cx/2024/02/26/img/xnuimagefuzzer-arm64e-sample-output-files_app-sample-file-render-iphone14promax-002.png" alt="XNU Image Fuzzer iPhone 14 Pro Max Render #2" style="height:550px; width:330px;"/> 

## Samples
- Project Zero Bug 2225 Seed <img src="https://xss.cx/2024/02/20/img/2225.png" alt="Seed - P0-2225" style="height:32px; width:32px;"/> Fuzz <img src="https://xss.cx/2024/02/20/img/xnuimagefuzzer-sample-output-pmg-image-rendering-horizontal-presentaion.png" alt="XNU Image Fuzzer Standard RBG #2" style="height:32px; width:352px;"/>
- Fuzzed RBG #1 <img src="https://xss.cx/2024/02/20/img/fuzzed_image_standard_rgb.png" alt="XNU Image Fuzzer Standard RBG" style="height:32px; width:32px;"/> Fuzzed RBG #2 <img src="https://xss.cx/2024/02/20/img/fuzzed_image_standard_rgb_series2.png" alt="XNU Image Fuzzer Standard RBG #2" style="height:32px; width:32px;"/>
- Fuzzed 16-bit Depth #1 <img src="https://xss.cx/2024/02/20/img/fuzzed_image_16bit_depth.png" alt="XNU Image Fuzzer 16-bit Depth" style="height:32px; width:32px;"/> Fuzzed 16-bit Depth #2 <img src="https://xss.cx/2024/02/20/img/fuzzed_image_16bit_depth_series2.png" alt="XNU Image Fuzzer 16-bit Depth #2" style="height:32px; width:32px;"/>
- HDR Float #1 <img src="https://xss.cx/2024/02/20/img/fuzzed_image_hdr_float.png" alt="XNU Image Fuzzer HDR Float" style="height:32px; width:32px;"/> HDR Float #2 <img src="https://xss.cx/2024/02/20/img/fuzzed_image_hdr_float_series2.png" alt="XNU Image Fuzzer HDR Float #2" style="height:32px; width:32px;"/>
- NonMultipliedAlpha #1 <img src="https://xss.cx/2024/02/20/img/fuzzed_image_non_premultiplied_alpha.png" alt="XNU Image Fuzzer NonPreMultipliedAlpha" style="height:32px; width:32px;"/> NonMultipliedAlpha #2 <img src="https://xss.cx/2024/02/20/img/fuzzed_image_non_premultiplied_alpha_series2.png" alt="XNU Image Fuzzer NonPreMultipliedAlpha #2" style="height:32px; width:32px;"/>
- MultipliedAlpha #1 <img src="https://xss.cx/2024/02/20/img/fuzzed_image_premultiplied_first_alpha.png" alt="XNU Image Fuzzer PreMultipliedAlpha" style="height:32px; width:32px;"/> MultipliedAlpha #2 <img src="https://xss.cx/2024/02/20/img/fuzzed_image_premultiplied_first_alpha_series2.png" alt="XNU Image Fuzzer PreMultipliedAlpha #2" style="height:32px; width:32px;"/>

## Quick Start
- Create a new iOS Application in Xcode
- Copy the Source File and Paste into main.m
- Copy the Flowers.exr, and any Image File Type into your XCode Project
- Edit the Scheme
  - For Arguments on Launch
    - Flowers.exr, or any Image File Type
    - -1
- Run

### Injection Strings Configuration
```
/**
@brief Configuration of strings for security testing.

@details Defines injection strings used for security testing, including identification tags,
URL handling checks, SQL injection simulations, and XSS vulnerability testing.
NUMBER_OF_STRINGS indicates the total count of these configured strings.
*/
// Strings for security testing and behavior monitoring
#define INJECT_STRING_1 "XNU Image Fuzzer" // Tag images processed for identification.
#define INJECT_STRING_2 "https://xss.cx?xnuimagefuzzer" // Check for unintended URL handling.
#define INJECT_STRING_3 "drop tables" // Simulate a basic SQL injection for security testing.
#define INJECT_STRING_4 "console.log(domain)" // Attempt to trigger JavaScript execution for XSS vulnerability testing.
#define NUMBER_OF_STRINGS 4 // The count of injection strings available for use.

// Array of injection strings for easy iteration and application in tests.
char* injectStrings[NUMBER_OF_STRINGS] = {
    INJECT_STRING_1,
    INJECT_STRING_2,
    INJECT_STRING_3,
    INJECT_STRING_4
};
*/
```
### Run Target Jailbroken Device
#### File Access
If you have an SRD, Jailbroken, Desktop or Virtual Device, you have access directly to the Fuzzed Files via Container.
```
Starting up...
Loading file: seed-small-7.png
Image path: /private/var/folders/pj/.../d/Wrapper/XNU Image Fuzzer.app/seed-small-7.png
...
Shift pixel values applied at Pixel[343, 407]
Enhanced fuzzing on bitmap context completed
Fuzzed image for '16bit_depth' context saved to /Users/.../Library/Containers/.../Data/Documents/fuzzed_image_16bit_depth.png
...
Fuzzed image for 'hdr_float' context saved to /Users/.../Library/Containers/.../Data/Documents/fuzzed_image_hdr_float.png
Modified UIImage with HDR and floating-point components created and saved successfully.
Completed image processing for permutation 6
```
You can copy the newly Fuzzed Files somewhere for permanent storage, perhaps more automated via .zsh.
```
cp /Users/.../Library/Containers/.../Data/Documents/fuzzed_image_16bit_depth.png ~/Documents/fuzzed/xnuimagefuzzer/png/date/time/
```
### Run Target arm64 & arm64e 
#### File Access
File Sharing is Enabled via Info.plist

#### Access Files via iTunes or the Files App

- iTunes File Sharing: Connect your iPhone to a computer, open iTunes, select your device, go to the "File Sharing" section, select your app, and you should see the files listed. You can then save them to your computer.

- Files App: Open the Files app on your iPhone, navigate to the "On My iPhone" section, find your app's folder, and you'll see the saved images. From here, you can select and share files via AirDrop. 

### Use More Cores
- XNU Image Fuzzer Example Code using the iOS Interposing Code in iOSOnMac [https://github.com/xsscx/macos-research/blob/main/code/iOSOnMac/xnuimagefuzzer.m]. 
- The iOSOnMac implementation offers a more robust method for Fuzzing and Collecting the post-processed Images. 

## Big Picture
- XNU Image Fuzzer
  	- This
	- Proof of Concept
	- Native Rendering of Fuzzed Images

- iOsOnMac
  - Based on XNU Image Fuzzer
  - XNU Image Fuzzing at Scale
  - Fuzzed Image File Collection
  - https://github.com/xsscx/macos-research/tree/main/code/iOSOnMac
    
- Jackalope Fuzzing Harnesses
  - Based on XNU Image Fuzzer
  - Image Fuzzing Harness Code
  - https://github.com/xsscx/macos-research/tree/main/code/imageio

The example Code provides the ability to change a few Numbers in a Function() and further Modify the Program Behavior, perhaps you will get a good Crash. 

For Crash Analysis, consider Reading https://srd.cx/xnu-crash-analysis/ and for arm64e Pointer Authentication Crashes, consider Reading https://srd.cx/possible-pointer-authentication-failure-data-abort/ for a quick snapshot of what may be Signal, or Noise.

- This Project is for anyone wanting to Learn Objective-C or XNU Image Fuzzing. 
- If you have Questions, then Open an Issue.

## XCode Crash
If you have completed the suggested Quick Start, and copied Flowers.exr into XCode, have you seen the EXR Crash for XCode yet?

If you have not yet received the XCode Crash, View Flowers.exr or Commit the Changes to your local Repository. When you attempt View the OpenEXR Distribution of Flowers.exr, the Rendering should Trigger a Crash in XCode due to the Sub-Sampling Issue described at URL https://github.com/xsscx/macos-research/blob/main/code/imageio/crashes/libAppleEXR-discussion-analysis.md.

If you use Finder or any App that Calls into libAppleEXR, and View Flowers.exr, you should get multiple Crashes. 
```
Process:               Xcode [30281]
Path:                  /Applications/Xcode.app/Contents/MacOS/Xcode
Identifier:            com.apple.dt.Xcode
Version:               15.2 (22503)
Build Info:            IDEApplication-22503000000000000~3 (15C500b)
...
Exception Type:        EXC_CRASH (SIGABRT)
Exception Codes:       0x0000000000000000, 0x0000000000000000

Termination Reason:    Namespace SIGNAL, Code 6 Abort trap: 6
Terminating Process:   Xcode [30281]

Application Specific Information:
abort() called


Thread 0::  Dispatch queue: com.apple.root.user-interactive-qos
0   libAppleEXR.dylib             	    0x7ffa0b328669 void _YCCAtoRGBA<half, 2u, 16>(half const*&, half const*&, half*&, YccMatrix const&, half const&) + 471
1   libAppleEXR.dylib             	    0x7ffa0b31cced void YCCAtoRGBA<half, 2u>(half const*, unsigned long, half const*, unsigned long, half*, unsigned long, double, YccMatrix const&, unsigned int, unsigned int, unsigned int) + 155
2   libAppleEXR.dylib             	    0x7ffa0b31c87f TileDecoder::ReadYccBlock(void*, unsigned long) + 1619
3   libdispatch.dylib             	    0x7ff804c915cd _dispatch_client_callout2 + 8
4   libdispatch.dylib             	    0x7ff804ca319d _dispatch_apply_invoke_and_wait + 214
5   libdispatch.dylib             	    0x7ff804ca26ab _dispatch_apply_with_attr_f + 1181
6   libAppleEXR.dylib             	    0x7ffa0b31bfce axr_error_t LaunchBlocks<ReadPixelsArgs>(void (*)(void*, unsigned long), ReadPixelsArgs const*, unsigned long, axr_flags_t) + 355
7   libAppleEXR.dylib             	    0x7ffa0b31f422 TileDecoder::ReadYccRGBAPixels(double, YccMatrix const&, void*, unsigned long) const + 2242
8   libAppleEXR.dylib             	    0x7ffa0b3115f9 Part::ReadRGBAPixels(axr_decoder*, void*, unsigned long, double, axr_flags_t) const + 2511
9   ImageIO                       	    0x7ff80fbafd25 EXRReadPlugin::decodeBlockAppleEXR(void*, unsigned long) + 337

```

## Roadmap
- Display Seed Image
- Fuzzing Instrumentation
- Distributed Fuzzing
  - Pull Seeds
  - Push PoC's
  - Analytics
- Crash Analysis

## Console log
```
cx.srd.xnuimagefuzzer (3276,0x1f4bba240) malloc: enabling scribbling to detect mods to free blocks
Starting up...
Loading file: Flowers.exr
Image path: /private/var/containers/Bundle/Application/.../cx.srd.xnuimagefuzzer.app/Flowers.exr
UIImage created: <UIImage:0x107e0c750 anonymous {784, 734} renderingMode=automatic(original)>, Size: {width: 784.00, height: 734.00}, Scale: 1.000000, Orientation: 0
CGImage created from UIImage. Dimensions: 784 x 734
Case: Creating bitmap context with Standard RGB settings
Chunk @ 0x102de0000
Chunk @ 0x102df0000
...
Successfully unmapped chunk @ 0x10b630000
...
Case: Creating bitmap context with 32-bit float, 4-component settings
Creating bitmap context with 32-bit float, 4-component settings
Applying enhanced fuzzing logic to the bitmap context
Starting enhanced fuzzing with injection string 1: XNU Image Fuzzer
Enhanced fuzzing with injection string 1: XNU Image Fuzzer completed
Starting enhanced fuzzing with injection string 2: https://xss.cx?xnuimagefuzzer
Enhanced fuzzing with injection string 2: https://xss.cx?xnuimagefuzzer completed
Starting enhanced fuzzing with injection string 3: drop tables
Enhanced fuzzing with injection string 3: drop tables completed
Starting enhanced fuzzing with injection string 4: console.log(domain)
Enhanced fuzzing with injection string 4: console.log(domain) completed
All enhanced fuzzing processes completed.
Fuzzed image for '32bit_float4' context saved to /var/mobile/Containers/Data/Application/.../Documents/fuzzed_image_32bit_float4.png
Modified UIImage with 32-bit float, 4-component settings created and saved successfully.
Completed image processing for permutation 12
[*] COMM_PAGE_SIGNATURE: commpage 64-bit
[*] COMM_PAGE_VERSION: 3
[*] COMM_PAGE_NCPUS: 8
[*] COMM_PAGE_CPU_CAPABILITIES64:
	MMX: false
	SSE: false
	SSE2: false
	SSE3: true
	Cache32: false
	Cache64: false
	Cache128: true
	FastThreadLocalStorage: true
	SupplementalSSE3: true
	64Bit: true
	SSE4_1: true
	SSE4_2: true
	AES: true
	InOrderPipeline: true
	Slow: true
	UP: false
	NumCPUs: 8
	AVX1_0: true
	RDRAND: true
	F16C: true
	ENFSTRG: false
	FMA: true
	AVX2_0: false
	BMI1: false
	BMI2: true
	RTM: true
	HLE: true
	ADX: false
	RDSEED: false
	MPX: true
	SGX: true
[*] Done dumping comm page.
Device Information:
  Name: iPad
  Model: iPad
  System Name: iPadOS
  System Version: 17.3
  Identifier For Vendor: 666-666-666
  Battery Level: 1.000000
  Battery State: 3
Kernel Version: 23.3.0
Hardware Model: 23.3.0
CPU Type: 23.3.0
Directory contents at /var/mobile/Containers/Data/Application/.../Documents: (
    "fuzzed_image_Big_Endian.png",
    "fuzzed_image_premultiplied_first_alpha_jpeg.jpg",
    "fuzzed_image_8Bit_InvertedColors.png",
    "fuzzed_image_hdr_float.png",
    "fuzzed_image_16bit_depth.png",
    "fuzzed_image_32bit_float4.png",
    "fuzzed_image_standard_rgb.png",
    "fuzzed_image_non_premultiplied_alpha.png",
    "fuzzed_image_Little_Endian.png",
    "fuzzed_image_premultiplied_first_alpha_png.png"
)
Loaded image: /var/mobile/Containers/Data/Application/.../Documents/fuzzed_image_Big_Endian.png
Loaded image: /var/mobile/Containers/Data/Application/.../Documents/fuzzed_image_premultiplied_first_alpha_jpeg.jpg
Loaded image: /var/mobile/Containers/Data/Application/.../Documents/fuzzed_image_8Bit_InvertedColors.png
Loaded image: /var/mobile/Containers/Data/Application/.../Documents/fuzzed_image_hdr_float.png
Loaded image: /var/mobile/Containers/Data/Application/.../Documents/fuzzed_image_16bit_depth.png
Loaded image: /var/mobile/Containers/Data/Application/.../Documents/fuzzed_image_32bit_float4.png
Loaded image: /var/mobile/Containers/Data/Application/.../Documents/fuzzed_image_standard_rgb.png
Loaded image: /var/mobile/Containers/Data/Application/.../Documents/fuzzed_image_non_premultiplied_alpha.png
Loaded image: /var/mobile/Containers/Data/Application/.../Documents/fuzzed_image_Little_Endian.png
Loaded image: /var/mobile/Containers/Data/Application/.../Documents/fuzzed_image_premultiplied_first_alpha_png.png
Loaded 10 images in total
```
