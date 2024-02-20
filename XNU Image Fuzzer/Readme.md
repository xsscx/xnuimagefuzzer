# XNU Image Fuzzer 
<img src="https://xss.cx/2024/05/20/img/xnu-videotoolbox-fuzzer-objective-c-code-project-example.webp" alt="XNU Image Fuzzer OSS Project" style="height:1024px; width:1024px;"/>

Last Updated: SAT 25 MAY 2024, 1523 EDT

## Project Summary

The Source Code contains a proof of concept implementation of an image fuzzer designed for XNU environments. It aims to demonstrate basic fuzzing techniques on image data to uncover potential vulnerabilities in image processing routines. The Objective-C Code implements 12 CGCreateBitmap & CGColorSpace Functions working with Raw Data and String Injection that are User Controllable Inputs.
- PermaLink https://srd.cx/xnu-image-fuzzer/
     

### Build & Install Status
| Build OS & Device Info           | Build   |  Install  | 
| -------------------------------- | ------------- | ------------- | 
| macOS 14.5 X86_64       | ✅          | ✅          |       
| macOS 14.5 arm  | ✅          | ✅          |
| iPAD OS 17.5       | ✅          | ✅          |        
| iPhone OS 17.5  | ✅          | ✅          |
| VisionPro 1.2  | ✅          | ✅          |


#### Project Support
- Open an Issue

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

## Image Metrics

- Mean Squared Error (MSE): Measures the average squared difference between corresponding pixels. Lower values indicate higher similarity.
- Structural Similarity Index (SSIM): Measures perceived quality between images. Values range from -1 to 1, where 1 indicates perfect similarity.
- Perceptual Hash Difference: Compares perceptual hash values to quantify visual similarity.
- Entropy Measurement: Calculates the entropy of each image, indicating randomness or noise levels.

Comparison Report for images1/fuzzed_image_8Bit_InvertedColors_jpg.jpg and images2/fuzzed_image_8Bit_InvertedColors_jpg.jpg
```
MSE: 103.0693359375
SSIM: 0.006633667337892677
Perceptual Hash Difference: 36
Entropy of images1/fuzzed_image_8Bit_InvertedColors_jpg.jpg: 7.692337989807129
Entropy of images2/fuzzed_image_8Bit_InvertedColors_jpg.jpg: 7.721158027648926
```

## Code Metrics
```
          Total Lines   2851
           Code Lines   1396
        Comment Lines    950
            Functions     81
 Documented Functions     32
      Inline Comments    153
       Block Comments    130
          Blank Lines    505
        TODO Comments      0
       FIXME Comments      0
    Class Definitions      0
Variable Declarations    226
                Loops     35
         Conditionals    118

```

### Injection Strings Configuration
- User Controllable Input for Fuzzing
```
#define INJECT_STRING_1 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // Test buffer overflow.
#define INJECT_STRING_2 "<script>console.error('XNU Image Fuzzer');</script>" // Test for XSS.
#define INJECT_STRING_3 "' OR ''='" // SQL injection.
#define INJECT_STRING_4 "%d %s %d %s" // Format string vulnerabilities.
#define INJECT_STRING_5 "XNU Image Fuzzer" // Regular input for control.
#define INJECT_STRING_6 "123456; DROP TABLE users" // SQL command injection.
#define INJECT_STRING_7 "!@#$%^&*()_+=" // Special characters.
#define INJECT_STRING_8 "..//..//..//win" // Path traversal.
#define INJECT_STRING_9 "\0\0\0" // Null byte injection.
#define INJECT_STRING_10 "<?xml version=\"1.0\"?><!DOCTYPE replace [<!ENTITY example \"XNUImageFuzzer\"> ]><userInfo><firstName>XNUImageFuzzer<&example;></firstName></userInfo>" // XXE injection.
#define NUMBER_OF_STRINGS 10 // Total injection strings count.
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
Starting enhanced fuzzing with injection string 1: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Enhanced fuzzing with injection string 1: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA completed
Starting enhanced fuzzing with injection string 2: <script>console.error('XNU Image Fuzzer');</script>
Enhanced fuzzing with injection string 2: <script>console.error('XNU Image Fuzzer');</script> completed
Starting enhanced fuzzing with injection string 3: ' OR ''='
Enhanced fuzzing with injection string 3: ' OR ''=' completed
Starting enhanced fuzzing with injection string 4: %d %s %d %s
Enhanced fuzzing with injection string 4: %d %s %d %s completed
Starting enhanced fuzzing with injection string 5: XNU Image Fuzzer
Enhanced fuzzing with injection string 5: XNU Image Fuzzer completed
Starting enhanced fuzzing with injection string 6: 123456; DROP TABLE users
Enhanced fuzzing with injection string 6: 123456; DROP TABLE users completed
Starting enhanced fuzzing with injection string 7: !@#$%^&*()_+=
Enhanced fuzzing with injection string 7: !@#$%^&*()_+= completed
Starting enhanced fuzzing with injection string 8: ..//..//..//win
Enhanced fuzzing with injection string 8: ..//..//..//win completed
Starting enhanced fuzzing with injection string 9:
Enhanced fuzzing with injection string 9:  completed
Starting enhanced fuzzing with injection string 10: <?xml version="1.0"?><!DOCTYPE replace [<!ENTITY example "XNUImageFuzzer"> ]><userInfo><firstName>XNUImageFuzzer<&example;></firstName></userInfo>
Enhanced fuzzing with injection string 10: <?xml version="1.0"?><!DOCTYPE replace [<!ENTITY example "XNUImageFuzzer"> ]><userInfo><firstName>XNUImageFuzzer<&example;></firstName></userInfo> completed
All enhanced fuzzing processes completed.
Fuzzed image for '32bit_float4_png' context saved to /var/root/Documents/fuzzed_image_32bit_float4_png.png
Fuzzed image for '32bit_float4_jpg' context saved to /var/root/Documents/fuzzed_image_32bit_float4_jpg.jpg
Modified UIImage with 32-bit float, 4-component settings created and saved successfully for PNG and JPG.
Completed image processing for permutation 12
XNU Image Fuzzer Version ✅ 2024-03-10 at 08:06:38
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
