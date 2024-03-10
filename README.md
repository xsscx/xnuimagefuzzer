# XNU Image Fuzzer 

Last Updated: TUE 10 MAR 2024, 0815 EST

## Project Summary

The Source Code contains a proof of concept implementation of an image fuzzer designed for XNU environments. It aims to demonstrate basic fuzzing techniques on image data to uncover potential vulnerabilities in image processing routines. The Objective-C Code implements 12 CGCreateBitmap & CGColorSpace Functions working with Raw Data and String Injection that are User Controllable Inputs.
- PermaLink https://srd.cx/xnu-image-fuzzer/
     

### Build & Install Status
| Build OS & Device Info           | Build   |  Install  | 
| -------------------------------- | ------------- | ------------- | 
| macOS 14.4 X86_64       | ✅          | ✅          |       
| macOS 14.4 arm  | ✅          | ✅          |
| iPAD OS 17.4       | ✅          | ✅          |        
| iPhone OS 17.4  | ✅          | ✅          |

#### Project Support
- Open an Issue

### whoami
I am David Hoyt and participated in the Apple Security Research Device Program for 2021 & 2022. Apple sent me an iPhone 11 & iPhone 12 for A/B testing, very helpful. This Project is some of the Code I wrote for debugging on the SRD.

## Quick Start
- Open as Xcode Project or Clone
- Verify the Scheme
  - For Arguments on Launch
    - 2225.jpg, or any Image File Type
    - -1
<img src="https://xss.cx/2024/03/10/img/xnuimagefuzzer-xcode-args-pass-on-launch-example-002.png" alt="Xcode -> Product -> Edit Scheme" style="height:177px; width:307px;"/>
<img src="https://xss.cx/2024/03/10/img/xnuimagefuzzer-xcode-args-pass-on-launch-example-001.png" alt="Xcode -> Product -> Edit Scheme" style="height:507px; width:928px;"/>

- Click Run
  - Screen Grab on iPhone 14 Pro MAX
    
<img src="https://xss.cx/2024/02/26/img/xnuimagefuzzer-arm64e-sample-output-files_app-sample-file-render-iphone14promax-001.png" alt="XNU Image Fuzzer iPhone 14 Pro Max Render #1" style="height:550px; width:330px;"/> <img src="https://xss.cx/2024/02/26/img/xnuimagefuzzer-arm64e-sample-output-files_app-sample-file-render-iphone14promax-002.png" alt="XNU Image Fuzzer iPhone 14 Pro Max Render #2" style="height:550px; width:330px;"/> 

### Injection Strings Configuration
- User Controllable Input for Fuzzing
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

## Console log
```
cx.srd.xnuimagefuzzer (3276,0x1f4bba240) malloc: enabling scribbling to detect mods to free blocks
Starting up...
Loading file: Flowers.exr
Image path: /private/var/containers/Bundle/Application/.../cx.srd.xnuimagefuzzer.app/Flowers.exr
UIImage created: <UIImage:0x107e0c750 anonymous {784, 734} renderingMode=automatic(original)>, Size: {width: 784.00, height: 734.00}, Scale: 1.000000, Orientation: 0
CGImage created from UIImage. Dimensions: 784 x 734
Case: Creating bitmap context with Standard RGB settings
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
...
Fuzzed image for '32bit_float4' context saved to /Users/xss/Documents/fuzzed_image_32bit_float4.png
Modified UIImage with 32-bit float, 4-component settings created and saved successfully.
Completed image processing for permutation 12
XNU Image Fuzzer Version ✅ 2024-03-10 at 08:06:38
...
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

## Xcode Config - Optional
- Compress PNG Files Option in Xcode
 - Verify OFF
<img src="https://xss.cx/2024/03/10/img/xnuimagefuzzer-xcode-configuration-compress-png-files-no.png" alt="Set Xcode Compress PNG Option to OFF" style="height:161px; width:716px;"/>

## Bugs Identified with XNU Image Fuzzer
- A sample of Bugs found

### CVE 
- CVE-2023-46602 https://nvd.nist.gov/vuln/detail/CVE-2023-46602
- CVE-2023-46603 https://nvd.nist.gov/vuln/detail/CVE-2023-46603
- CVE-2023-46866 https://nvd.nist.gov/vuln/detail/CVE-2023-46866
- CVE-2023-46867 https://nvd.nist.gov/vuln/detail/CVE-2023-46867
- CVE-2023-47249 https://nvd.nist.gov/vuln/detail/CVE-2023-47249
- CVE-2023-48736 https://nvd.nist.gov/vuln/detail/CVE-2023-48736

### DemoIccMax Bug Reports & Pull Requests
- https://github.com/InternationalColorConsortium/DemoIccMAX/pull/53
- https://github.com/InternationalColorConsortium/DemoIccMAX/issues/54
- https://github.com/InternationalColorConsortium/DemoIccMAX/issues/58

### Apple Image dylib Crash Samples
- libAppleEXR in Function YCCAtoRGBA()
- AppleJPEG in Function decode_get_chroma_subsampling()
- MediaToolbox in Function 0x18f3c9000 + 6396752 

### Thanks
```
Argyll CMS change log
Version 3.0.3
-------------
* Made icc code a little more robust against bad profiles.
  (Thanks to David Hoyt).

Version 3.0.2  23 October 2023
```

## Samples
- Project Zero Bug 2225 Seed <img src="https://xss.cx/2024/02/20/img/2225.png" alt="Seed - P0-2225" style="height:32px; width:32px;"/> Fuzz <img src="https://xss.cx/2024/02/20/img/xnuimagefuzzer-sample-output-pmg-image-rendering-horizontal-presentaion.png" alt="XNU Image Fuzzer Standard RBG #2" style="height:32px; width:352px;"/>
- Fuzzed RBG #1 <img src="https://xss.cx/2024/02/20/img/fuzzed_image_standard_rgb.png" alt="XNU Image Fuzzer Standard RBG" style="height:32px; width:32px;"/> Fuzzed RBG #2 <img src="https://xss.cx/2024/02/20/img/fuzzed_image_standard_rgb_series2.png" alt="XNU Image Fuzzer Standard RBG #2" style="height:32px; width:32px;"/>
- Fuzzed 16-bit Depth #1 <img src="https://xss.cx/2024/02/20/img/fuzzed_image_16bit_depth.png" alt="XNU Image Fuzzer 16-bit Depth" style="height:32px; width:32px;"/> Fuzzed 16-bit Depth #2 <img src="https://xss.cx/2024/02/20/img/fuzzed_image_16bit_depth_series2.png" alt="XNU Image Fuzzer 16-bit Depth #2" style="height:32px; width:32px;"/>
- HDR Float #1 <img src="https://xss.cx/2024/02/20/img/fuzzed_image_hdr_float.png" alt="XNU Image Fuzzer HDR Float" style="height:32px; width:32px;"/> HDR Float #2 <img src="https://xss.cx/2024/02/20/img/fuzzed_image_hdr_float_series2.png" alt="XNU Image Fuzzer HDR Float #2" style="height:32px; width:32px;"/>
- NonMultipliedAlpha #1 <img src="https://xss.cx/2024/02/20/img/fuzzed_image_non_premultiplied_alpha.png" alt="XNU Image Fuzzer NonPreMultipliedAlpha" style="height:32px; width:32px;"/> NonMultipliedAlpha #2 <img src="https://xss.cx/2024/02/20/img/fuzzed_image_non_premultiplied_alpha_series2.png" alt="XNU Image Fuzzer NonPreMultipliedAlpha #2" style="height:32px; width:32px;"/>
- MultipliedAlpha #1 <img src="https://xss.cx/2024/02/20/img/fuzzed_image_premultiplied_first_alpha.png" alt="XNU Image Fuzzer PreMultipliedAlpha" style="height:32px; width:32px;"/> MultipliedAlpha #2 <img src="https://xss.cx/2024/02/20/img/fuzzed_image_premultiplied_first_alpha_series2.png" alt="XNU Image Fuzzer PreMultipliedAlpha #2" style="height:32px; width:32px;"/>
