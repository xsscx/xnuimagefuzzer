# XNU Image Fuzzer 

Last Updated: February 26, 2024, 1508 EST

The Source Code contains a proof of concept implementation of an image fuzzer designed for XNU environments. It aims to demonstrate basic fuzzing techniques on image data to uncover potential vulnerabilities in image processing routines.
- PermaLink https://srd.cx/xnu-image-fuzzer/

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
  - For Arguements on Launch
    - Flowers.exr, or any Image File Type
    - -1
- Run

### Run Targets Jailbroken Device
1. If you have a Jailbroken or Virtual Device, you have access directly to the Fuzzed Files.
2. If you have an arm-based Mac, you can use it as the Run Target, and again you have access directly to the Fuzzed Files.
```
Starting up...
Loading file: seed-small-7.png
Image path: /private/var/folders/pj/.../d/Wrapper/XNU Image Fuzzer.app/seed-small-7.png
...
Shift pixel values applied at Pixel[343, 407]
Enhanced fuzzing on bitmap context completed
Fuzzed image for '16bit_depth' context saved to /Users/.../Library/Containers/.../Data/Documents/fuzzed_image_16bit_depth.png

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
Enable File Sharing for Your App
First, you need to enable iTunes File Sharing or make your app's documents available in the Files app:

- Modify Info.plist: Add the UIFileSharingEnabled (Application supports iTunes file sharing) key and set it to YES

Then, To make files accessible in the Files app, also add:
  - LSSupportsOpeningDocumentsInPlace key and set it to YES

#### Access Files via iTunes or the Files App

- iTunes File Sharing: Connect your iPhone to a computer, open iTunes, select your device, go to the "File Sharing" section, select your app, and you should see the files listed. You can then save them to your computer.

- Files App: Open the Files app on your iPhone, navigate to the "On My iPhone" section, find your app's folder, and you'll see the saved images. From here, you can select and share files via AirDrop or other 
## Background
I had been using Jackalope for Fuzzing and to confirm that it could find easy to identify Bugs. Looking deeper at Jackalope, I found minor UAF, OOB, NPTR that impacted some results given the Seeding. 

I wrote this Objective-C XNU Image Fuzzer for A/B Testing along side Jackalope, and the iOsOnMac Interposing Code. The Results were so Interesting I increased this Fuzzer Scope, then wrote Interposing Code that will drop to LLDB Debugger when the correct Signal is Indicated. 

My iOsOnMac Code also modified TinyInst and modifying the TinyInst main.cpp and instrumentation.cpp, using modified Headers to Anonymize Memory for Collaboration. See URL https://github.com/xsscx/macos-research/issues/2 for details on the TinyInst mods.

You can see the XNU Image Fuzzer Example Code running At Scale using the iOS Interposing Code in iOSOnMac [https://github.com/xsscx/macos-research/blob/main/code/iOSOnMac/xnuimagefuzzer.m]. The iOsOnMac implementation is a more robust method for Fuzzing and Collecting the post-processed Images. 

### Big Picture
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

This Project is for anyone wanting to Learn Objective-C or XNU Image Fuzzing. I Ported my C++ Code to Objective-C. If you have Questions, then Open an Issue.

### XCode Crash
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

### Roadmap
- Add Rendering via StoryBoard
  - Display Seed Image
  - Display Fuzzed Image
  - Fuzzing Instrumentation
- Distributed Fuzzing
  - Pull Seeds
  - Push PoC's
  - Analytics
- Crash Analysis

### Console log
```
cx.srd.img-fuzz-001(3276,0x1f4bba240) malloc: enabling scribbling to detect mods to free blocks
Starting up...
Loading file: Flowers.exr
Image path: /private/var/containers/Bundle/Application/CE39E385-81DC-4E89-A875-0E00B05337D0/cx.srd.img-fuzz-001.app/Flowers.exr
UIImage created: <UIImage:0x107e0c750 anonymous {784, 734} renderingMode=automatic(original)>, Size: {width: 784.00, height: 734.00}, Scale: 1.000000, Orientation: 0
CGImage created from UIImage. Dimensions: 784 x 734
Case: Creating bitmap context with Standard RGB settings
Chunk @ 0x102de0000
Chunk @ 0x102df0000
Chunk @ 0x102fc0000
Chunk @ 0x102fd0000
Chunk @ 0x102fe0000
Chunk @ 0x102ff0000
Chunk @ 0x103000000
Chunk @ 0x103010000
Chunk @ 0x103020000
Chunk @ 0x103030000
Chunk @ 0x103040000
Chunk @ 0x103050000
Chunk @ 0x103060000
Chunk @ 0x103070000
Chunk @ 0x103080000
Chunk @ 0x103090000
Chunk @ 0x1030a0000
Chunk @ 0x1030b0000
Chunk @ 0x1030c0000
Chunk @ 0x1030d0000
Chunk @ 0x1030e0000
Chunk @ 0x1030f0000
Chunk @ 0x103100000
Chunk @ 0x103110000
Chunk @ 0x103120000
Chunk @ 0x105bd0000
Chunk @ 0x105be0000
Chunk @ 0x105bf0000
Chunk @ 0x10b400000
Chunk @ 0x10b410000
Chunk @ 0x10b420000
Chunk @ 0x10b430000
Chunk @ 0x10b440000
Chunk @ 0x10b450000
Chunk @ 0x10b460000
Chunk @ 0x10b470000
Chunk @ 0x10b480000
Chunk @ 0x10b490000
Chunk @ 0x10b4a0000
Chunk @ 0x10b4b0000
Chunk @ 0x10b4c0000
Chunk @ 0x10b4d0000
Chunk @ 0x10b4e0000
Chunk @ 0x10b4f0000
Chunk @ 0x10b500000
Chunk @ 0x10b510000
Chunk @ 0x10b520000
Chunk @ 0x10b530000
Chunk @ 0x10b540000
Chunk @ 0x10b550000
Chunk @ 0x10b560000
Chunk @ 0x10b570000
Chunk @ 0x10b580000
Chunk @ 0x10b590000
Chunk @ 0x10b5a0000
Chunk @ 0x10b5b0000
Chunk @ 0x10b5c0000
Chunk @ 0x10b5d0000
Chunk @ 0x10b5e0000
Chunk @ 0x10b5f0000
Chunk @ 0x10b600000
Chunk @ 0x10b610000
Chunk @ 0x10b620000
Chunk @ 0x10b630000
Successfully unmapped chunk @ 0x102de0000
Successfully unmapped chunk @ 0x102df0000
Successfully unmapped chunk @ 0x102fc0000
Successfully unmapped chunk @ 0x102fd0000
Successfully unmapped chunk @ 0x102fe0000
Successfully unmapped chunk @ 0x102ff0000
Successfully unmapped chunk @ 0x103000000
Successfully unmapped chunk @ 0x103010000
Successfully unmapped chunk @ 0x103020000
Successfully unmapped chunk @ 0x103030000
Successfully unmapped chunk @ 0x103040000
Successfully unmapped chunk @ 0x103050000
Successfully unmapped chunk @ 0x103060000
Successfully unmapped chunk @ 0x103070000
Successfully unmapped chunk @ 0x103080000
Successfully unmapped chunk @ 0x103090000
Successfully unmapped chunk @ 0x1030a0000
Successfully unmapped chunk @ 0x1030b0000
Successfully unmapped chunk @ 0x1030c0000
Successfully unmapped chunk @ 0x1030d0000
Successfully unmapped chunk @ 0x1030e0000
Successfully unmapped chunk @ 0x1030f0000
Successfully unmapped chunk @ 0x103100000
Successfully unmapped chunk @ 0x103110000
Successfully unmapped chunk @ 0x103120000
Successfully unmapped chunk @ 0x105bd0000
Successfully unmapped chunk @ 0x105be0000
Successfully unmapped chunk @ 0x105bf0000
Successfully unmapped chunk @ 0x10b400000
Successfully unmapped chunk @ 0x10b410000
Successfully unmapped chunk @ 0x10b420000
Successfully unmapped chunk @ 0x10b430000
Successfully unmapped chunk @ 0x10b440000
Successfully unmapped chunk @ 0x10b450000
Successfully unmapped chunk @ 0x10b460000
Successfully unmapped chunk @ 0x10b470000
Successfully unmapped chunk @ 0x10b480000
Successfully unmapped chunk @ 0x10b490000
Successfully unmapped chunk @ 0x10b4a0000
Successfully unmapped chunk @ 0x10b4b0000
Successfully unmapped chunk @ 0x10b4c0000
Successfully unmapped chunk @ 0x10b4d0000
Successfully unmapped chunk @ 0x10b4e0000
Successfully unmapped chunk @ 0x10b4f0000
Successfully unmapped chunk @ 0x10b500000
Successfully unmapped chunk @ 0x10b510000
Successfully unmapped chunk @ 0x10b520000
Successfully unmapped chunk @ 0x10b530000
Successfully unmapped chunk @ 0x10b540000
Successfully unmapped chunk @ 0x10b550000
Successfully unmapped chunk @ 0x10b560000
Successfully unmapped chunk @ 0x10b570000
Successfully unmapped chunk @ 0x10b580000
Successfully unmapped chunk @ 0x10b590000
Successfully unmapped chunk @ 0x10b5a0000
Successfully unmapped chunk @ 0x10b5b0000
Successfully unmapped chunk @ 0x10b5c0000
Successfully unmapped chunk @ 0x10b5d0000
Successfully unmapped chunk @ 0x10b5e0000
Successfully unmapped chunk @ 0x10b5f0000
Successfully unmapped chunk @ 0x10b600000
Successfully unmapped chunk @ 0x10b610000
Successfully unmapped chunk @ 0x10b620000
Successfully unmapped chunk @ 0x10b630000
Creating bitmap context with Standard RGB settings and applying fuzzing
Drawing image into the bitmap context
Before fuzzing - Basic pixel logging executed.
Applying secondary fuzzing logic to the bitmap context
After fuzzing - Basic pixel logging executed.
Creating CGImage from the modified bitmap context
Fuzzed image saved to /var/mobile/Containers/Data/Application/64F831C7-A853-4D03-9DB1-727B57E5B732/Documents/fuzzed_image.png
Modified UIImage created successfully
New image size: {784, 734}, scale: 1.000000, rendering mode: 0
Bitmap context processing complete
Bitmap context with Standard RGB settings created and fuzzing applied
Completed image processing for permutation 1
Case: Creating bitmap context with Premultiplied First Alpha settings
Creating bitmap context with Premultiplied First Alpha settings and applying fuzzing
Drawing image into the bitmap context
Applying fuzzing logic to the bitmap context
Fuzzing applied to RGB components of the bitmap context
Creating CGImage from the modified bitmap context
Modified UIImage created successfully
New image size: {784, 734}, scale: 1.000000, rendering mode: 0
Bitmap context with Premultiplied First Alpha settings created and fuzzing applied
Completed image processing for permutation 2
Case: Creating bitmap context with Non-Premultiplied Alpha settings
Creating bitmap context with Non-Premultiplied Alpha settings and applying fuzzing

CGBitmapContextCreate: unsupported parameter combination:
 	RGB 
	8 bits/component, integer
 	3136 bytes/row
	kCGImageAlphaLast
	kCGImageByteOrderDefault
	kCGImagePixelFormatPacked
	Valid parameters for RGB color space model are:
	16  bits per pixel,		 5  bits per component,		 kCGImageAlphaNoneSkipFirst
	32  bits per pixel,		 8  bits per component,		 kCGImageAlphaNoneSkipFirst
	32  bits per pixel,		 8  bits per component,		 kCGImageAlphaNoneSkipLast
	32  bits per pixel,		 8  bits per component,		 kCGImageAlphaPremultipliedFirst
	32  bits per pixel,		 8  bits per component,		 kCGImageAlphaPremultipliedLast
	32  bits per pixel,		 10 bits per component,		 kCGImageAlphaNone|kCGImagePixelFormatRGBCIF10|kCGImageByteOrder16Little
	64  bits per pixel,		 16 bits per component,		 kCGImageAlphaPremultipliedLast
	64  bits per pixel,		 16 bits per component,		 kCGImageAlphaNoneSkipLast
	64  bits per pixel,		 16 bits per component,		 kCGImageAlphaPremultipliedLast|kCGBitmapFloatComponents|kCGImageByteOrder16Little
	64  bits per pixel,		 16 bits per component,		 kCGImageAlphaNoneSkipLast|kCGBitmapFloatComponents|kCGImageByteOrder16Little
	128 bits per pixel,		 32 bits per component,		 kCGImageAlphaPremultipliedLast|kCGBitmapFloatComponents
	128 bits per pixel,		 32 bits per component,		 kCGImageAlphaNoneSkipLast|kCGBitmapFloatComponents
See Quartz 2D Programming Guide (available online) for more information.
Failed to create bitmap context with Non-Premultiplied Alpha settings
Completed image processing for permutation 3
Case: Creating bitmap context with 16-bit depth settings
Creating bitmap context with 16-bit Depth settings and applying fuzzing

CGBitmapContextCreate: unsupported parameter combination:
 	RGB 
	16 bits/component, integer
 	6272 bytes/row
	kCGImageAlphaPremultipliedFirst
	kCGImageByteOrderDefault
	kCGImagePixelFormatPacked
	Valid parameters for RGB color space model are:
	16  bits per pixel,		 5  bits per component,		 kCGImageAlphaNoneSkipFirst
	32  bits per pixel,		 8  bits per component,		 kCGImageAlphaNoneSkipFirst
	32  bits per pixel,		 8  bits per component,		 kCGImageAlphaNoneSkipLast
	32  bits per pixel,		 8  bits per component,		 kCGImageAlphaPremultipliedFirst
	32  bits per pixel,		 8  bits per component,		 kCGImageAlphaPremultipliedLast
	32  bits per pixel,		 10 bits per component,		 kCGImageAlphaNone|kCGImagePixelFormatRGBCIF10|kCGImageByteOrder16Little
	64  bits per pixel,		 16 bits per component,		 kCGImageAlphaPremultipliedLast
	64  bits per pixel,		 16 bits per component,		 kCGImageAlphaNoneSkipLast
	64  bits per pixel,		 16 bits per component,		 kCGImageAlphaPremultipliedLast|kCGBitmapFloatComponents|kCGImageByteOrder16Little
	64  bits per pixel,		 16 bits per component,		 kCGImageAlphaNoneSkipLast|kCGBitmapFloatComponents|kCGImageByteOrder16Little
	128 bits per pixel,		 32 bits per component,		 kCGImageAlphaPremultipliedLast|kCGBitmapFloatComponents
	128 bits per pixel,		 32 bits per component,		 kCGImageAlphaNoneSkipLast|kCGBitmapFloatComponents
See Quartz 2D Programming Guide (available online) for more information.
Failed to create bitmap context with 16-bit Depth settings
Completed image processing for permutation 4
Grayscale image processing is currently pending implementation.
...
Random noise applied at Pixel[699, 733]
Shift pixel values applied at Pixel[700, 733]
Conditional color swap at Pixel[701, 733]
Random color set at Pixel[702, 733]
Random noise applied at Pixel[703, 733]
Inversion applied at Pixel[704, 733]
Inversion applied at Pixel[705, 733]
Random noise applied at Pixel[706, 733]
Conditional color swap at Pixel[707, 733]
Shift pixel values applied at Pixel[708, 733]
Random noise applied at Pixel[709, 733]
Conditional color swap at Pixel[710, 733]
Shift pixel values applied at Pixel[711, 733]
Extreme contrast adjustment at Pixel[712, 733]
Inversion applied at Pixel[713, 733]
Extreme contrast adjustment at Pixel[714, 733]
Extreme contrast adjustment at Pixel[715, 733]
Shift pixel values applied at Pixel[716, 733]
Random color set at Pixel[717, 733]
Random color set at Pixel[718, 733]
Shift pixel values applied at Pixel[719, 733]
Shift pixel values applied at Pixel[720, 733]
Shift pixel values applied at Pixel[721, 733]
Random noise applied at Pixel[722, 733]
Random noise applied at Pixel[723, 733]
Random noise applied at Pixel[724, 733]
Random color set at Pixel[725, 733]
Conditional color swap at Pixel[726, 733]
Random noise applied at Pixel[727, 733]
Random color set at Pixel[728, 733]
Shift pixel values applied at Pixel[729, 733]
Random color set at Pixel[730, 733]
Inversion applied at Pixel[731, 733]
Inversion applied at Pixel[732, 733]
Random color set at Pixel[733, 733]
Random color set at Pixel[734, 733]
Extreme contrast adjustment at Pixel[735, 733]
Conditional color swap at Pixel[736, 733]
Random noise applied at Pixel[737, 733]
Random color set at Pixel[738, 733]
Extreme contrast adjustment at Pixel[739, 733]
Random color set at Pixel[740, 733]
Inversion applied at Pixel[741, 733]
Random noise applied at Pixel[742, 733]
Random color set at Pixel[743, 733]
Extreme contrast adjustment at Pixel[744, 733]
Random color set at Pixel[745, 733]
Random color set at Pixel[746, 733]
Random noise applied at Pixel[747, 733]
Random color set at Pixel[748, 733]
Random noise applied at Pixel[749, 733]
Random color set at Pixel[750, 733]
Extreme contrast adjustment at Pixel[751, 733]
Shift pixel values applied at Pixel[752, 733]
Inversion applied at Pixel[753, 733]
Extreme contrast adjustment at Pixel[754, 733]
Shift pixel values applied at Pixel[755, 733]
Random noise applied at Pixel[756, 733]
Extreme contrast adjustment at Pixel[757, 733]
Conditional color swap at Pixel[758, 733]
Extreme contrast adjustment at Pixel[759, 733]
Random color set at Pixel[760, 733]
Random noise applied at Pixel[761, 733]
Random noise applied at Pixel[762, 733]
Inversion applied at Pixel[763, 733]
Random noise applied at Pixel[764, 733]
Random noise applied at Pixel[765, 733]
Random noise applied at Pixel[766, 733]
Shift pixel values applied at Pixel[767, 733]
Inversion applied at Pixel[768, 733]
Inversion applied at Pixel[769, 733]
Shift pixel values applied at Pixel[770, 733]
Inversion applied at Pixel[771, 733]
Random color set at Pixel[772, 733]
Inversion applied at Pixel[773, 733]
Shift pixel values applied at Pixel[774, 733]
Random color set at Pixel[775, 733]
Extreme contrast adjustment at Pixel[776, 733]
Shift pixel values applied at Pixel[777, 733]
Extreme contrast adjustment at Pixel[778, 733]
Random color set at Pixel[779, 733]
Random color set at Pixel[780, 733]
Shift pixel values applied at Pixel[781, 733]
Random noise applied at Pixel[782, 733]
Shift pixel values applied at Pixel[783, 733]
Enhanced fuzzing on bitmap context completed
After fuzzing - Logging 5 random pixels:
After fuzzing - Pixel[188, 620]: R=0, G=0, B=0, A=0
After fuzzing - Pixel[112, 699]: R=128, G=128, B=128, A=0
After fuzzing - Pixel[597, 467]: R=0, G=24, B=0, A=13
After fuzzing - Pixel[160, 183]: R=37, G=126, B=125, A=0
After fuzzing - Pixel[624, 224]: R=0, G=0, B=0, A=0
Creating CGImage from the modified bitmap context
Fuzzed image saved to /var/mobile/Containers/Data/Application/1CBCFB1E-BC2F-4F6C-88D0-A57BFE378ACF/Documents/fuzzed_image.png
Modified UIImage created successfully
New image size: {784, 734}, scale: 1.000000, rendering mode: 0
Bitmap context processing complete
Bitmap context with Standard RGB settings created and fuzzing applied
Completed image processing for permutation 1
Case: Creating bitmap context with Premultiplied First Alpha settings
Creating bitmap context with Premultiplied First Alpha settings and applying fuzzing
Drawing image into the bitmap context
Applying fuzzing logic to the bitmap context
Fuzzing applied to RGB components of the bitmap context
Creating CGImage from the modified bitmap context
Modified UIImage created successfully
New image size: {784, 734}, scale: 1.000000, rendering mode: 0
Bitmap context with Premultiplied First Alpha settings created and fuzzing applied
Completed image processing for permutation 2
Case: Creating bitmap context with Non-Premultiplied Alpha settings
Creating bitmap context with Non-Premultiplied Alpha settings and applying fuzzing

CGBitmapContextCreate: unsupported parameter combination:
	RGB | 8 bits/component, integer | 3136 bytes/row.
	kCGImageAlphaLast | kCGImageByteOrderDefault | kCGImagePixelFormatPacked
Set CGBITMAP_CONTEXT_LOG_ERRORS environmental variable to see more details.
Failed to create bitmap context with Non-Premultiplied Alpha settings
Completed image processing for permutation 3
Case: Creating bitmap context with 16-bit depth settings
Creating bitmap context with 16-bit Depth settings and applying fuzzing

CGBitmapContextCreate: unsupported parameter combination:
	RGB | 16 bits/component, integer | 6272 bytes/row.
	kCGImageAlphaPremultipliedFirst | kCGImageByteOrderDefault | kCGImagePixelFormatPacked
Set CGBITMAP_CONTEXT_LOG_ERRORS environmental variable to see more details.
Failed to create bitmap context with 16-bit Depth settings
Completed image processing for permutation 4
Grayscale image processing is currently pending implementation.
End of Run...
```
