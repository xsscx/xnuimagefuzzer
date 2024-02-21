/**
 * @file       ios-image-fuzzer-example.m
 * @brief      Proof of concept XNU Image Fuzzer
 * @author     @h02332 | David Hoyt
 * @date       Modified 20 Nov 2024 | 2000 EST
 *
 * Detailed description of the file, if necessary.
 *
 * @section    CHANGES
 * [Date] [Author] - [Description of Changes]
 * - [26/11/2023] [h02332] - Initial commit
 * - [27/11/2023] [h02332] - Removed Grayscale Feature pending Implementation
 * - [28/11/2023] [h02332] - Refactor Code & fuzzing
 * - [29/11/2023] [h02332] - Refactor Code & fuzzing & logging
 * - [20/02/2023] [h02332] - Refactor Code & fuzzing & logging
 *
 * @section    TODO
 * - [ ] Grayscale Implementation
 * - [ ] ICC Color Profiles
 * - [ ] Refactor Example Fuzzer
 * - [ ] Add Logging Toggle as global variable  - testing in createBitmapContextStandardRGB function
 * Compile : xcrun -sdk iphoneos clang -arch arm64 -framework UIKit -framework Foundation -framework CoreGraphics -miphoneos-version-min=12.0 -g -o imagefuzzer ios-image-fuzzer-example.m  interpose.dylib
 *
 */

#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>
#include <CoreGraphics/CoreGraphics.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

// Define constants for ALL and MAX_PERMUTATION
#define ALL -1
#define MAX_PERMUTATION 12

// Global variable to control verbosity
int verboseLogging = 1; // Set to 1 for detailed logging, 0 for minimal logging

// Function declarations
BOOL isValidImagePath(NSString *path);
UIImage *loadImageFromFile(NSString *path);
void processImage(UIImage *image, int permutation);
void Data(unsigned char *rawData, size_t width, size_t height, const char *message);
NSString *createUniqueDirectoryForSavingImages(void);

// Permutation functions
void createBitmapContextStandardRGB(CGImageRef cgImg, int permutation);
void createBitmapContextPremultipliedFirstAlpha(CGImageRef cgImg);
void createBitmapContextNonPremultipliedAlpha(CGImageRef cgImg);
void createBitmapContext16BitDepth(CGImageRef cgImg);
void createBitmapContextGrayscale(CGImageRef cgImg);
void createBitmapContextHDRFloatComponents(CGImageRef cgImg);
void createBitmapContextAlphaOnly(CGImageRef cgImg);
void createBitmapContext1BitMonochrome(CGImageRef cgImg);
void createBitmapContextBigEndian(CGImageRef cgImg);
void createBitmapContextLittleEndian(CGImageRef cgImg);
void createBitmapContext8BitInvertedColors(CGImageRef cgImg);
void createBitmapContext32BitFloat4Component(CGImageRef cgImg);
void applyFuzzingToBitmapContext(unsigned char *rawData, size_t width, size_t height);
void logPixelData(unsigned char *rawData, size_t width, size_t height, const char *message);
void applyEnhancedFuzzingToBitmapContext(unsigned char *rawData, size_t width, size_t height, BOOL verboseLogging);

NSString *createUniqueDirectoryForSavingImages(void) {
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    [formatter setDateFormat:@"yyyy-MM-dd_HH-mm-ss-SSS"];
    NSString *dateString = [formatter stringFromDate:[NSDate date]];

    // Generating a random component to append to the directory name for uniqueness
    uint32_t randomComponent = arc4random_uniform(10000);
    NSString *uniqueDirectoryName = [NSString stringWithFormat:@"%@_%u", dateString, randomComponent];

    NSString *documentsDirectory = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *uniqueDirPath = [documentsDirectory stringByAppendingPathComponent:uniqueDirectoryName];

    NSError *error;
    if (![[NSFileManager defaultManager] createDirectoryAtPath:uniqueDirPath withIntermediateDirectories:YES attributes:nil error:&error]) {
        NSLog(@"Error creating directory for saving images: %@", error.localizedDescription);
        // Consider additional error handling logic here, depending on application requirements
        return nil;
    }

    return uniqueDirPath;
}

void logPixelData(unsigned char *rawData, size_t width, size_t height, const char *message) {
    if (!rawData || width == 0 || height == 0) {
        NSLog(@"%s - Invalid data or dimensions. Logging aborted.", message);
        return;
    }

    const int numberOfPixelsToLog = 5; // Number of random pixels to log

    if (verboseLogging) {
        NSLog(@"%s - Logging %d random pixels:", message, numberOfPixelsToLog);

        for (int i = 0; i < numberOfPixelsToLog; i++) {
            unsigned int randomX = arc4random_uniform((unsigned int)width);
            unsigned int randomY = arc4random_uniform((unsigned int)height);
            size_t pixelIndex = (randomY * width + randomX) * 4;

            if (pixelIndex + 3 < width * height * 4) {
                NSLog(@"%s - Pixel[%u, %u]: R=%d, G=%d, B=%d, A=%d",
                      message, randomX, randomY,
                      rawData[pixelIndex], rawData[pixelIndex + 1],
                      rawData[pixelIndex + 2], rawData[pixelIndex + 3]);
            } else {
                NSLog(@"%s - Out of bounds pixel access prevented at [%u, %u].", message, randomX, randomY);
            }
        }
    } else {
        NSLog(@"%s - Basic pixel logging executed.", message);
    }
}

void Data(unsigned char *rawData, size_t width, size_t height, const char *message) {
    if (!rawData || width == 0 || height == 0) {
        NSLog(@"%s - Invalid data or dimensions. Logging aborted.", message);
        return;
    }

    const int numberOfPixelsToLog = 5; // Number of random pixels to log

    if (verboseLogging) {
        NSLog(@"%s - Logging %d random pixels:", message, numberOfPixelsToLog);

        for (int i = 0; i < numberOfPixelsToLog; i++) {
            unsigned int randomX = arc4random_uniform((unsigned int)width);
            unsigned int randomY = arc4random_uniform((unsigned int)height);
            size_t pixelIndex = (randomY * width + randomX) * 4;

            if (pixelIndex + 3 < width * height * 4) {
                NSLog(@"%s - Pixel[%u, %u]: R=%d, G=%d, B=%d, A=%d",
                      message, randomX, randomY,
                      rawData[pixelIndex], rawData[pixelIndex + 1],
                      rawData[pixelIndex + 2], rawData[pixelIndex + 3]);
            } else {
                NSLog(@"%s - Out of bounds pixel access prevented at [%u, %u].", message, randomX, randomY);
            }
        }
    } else {
        NSLog(@"%s - Basic pixel logging executed.", message);
    }
}

void applyEnhancedFuzzingToBitmapContext(unsigned char *rawData, size_t width, size_t height, BOOL verboseLogging) {
    if (!rawData || width == 0 || height == 0) {
        NSLog(@"No valid raw data or dimensions available for enhanced fuzzing.");
        return;
    }

    if (verboseLogging) {
        NSLog(@"Starting enhanced fuzzing on bitmap context");
    }

    for (size_t y = 0; y < height; y++) {
        for (size_t x = 0; x < width; x++) {
            size_t pixelIndex = (y * width + x) * 4; // Assuming RGBA format
            int fuzzMethod = arc4random_uniform(6); // Six methods

            switch (fuzzMethod) {
                case 0: // Inversion
                    if (verboseLogging) {
                        NSLog(@"Inversion applied at Pixel[%zu, %zu]", x, y);
                    }
                    for (int i = 0; i < 3; i++) { // Apply inversion to RGB
                        rawData[pixelIndex + i] = 255 - rawData[pixelIndex + i];
                    }
                    break;
                case 1: // Random noise
                    if (verboseLogging) {
                        NSLog(@"Random noise applied at Pixel[%zu, %zu]", x, y);
                    }
                    for (int i = 0; i < 4; i++) { // Including alpha channel
                        int noise = arc4random_uniform(101) - 50; // Noise range [-50, 50]
                        int newValue = rawData[pixelIndex + i] + noise;
                        rawData[pixelIndex + i] = (unsigned char)fmax(0, fmin(255, newValue));
                    }
                    break;
                case 2: // Random color
                    if (verboseLogging) {
                        NSLog(@"Random color set at Pixel[%zu, %zu]", x, y);
                    }
                    // Assign random colors to RGB, leaving alpha unchanged
                    for (int i = 0; i < 3; i++) {
                        rawData[pixelIndex + i] = arc4random_uniform(256);
                    }
                    break;
                case 3: // Shift pixel values
                    if (verboseLogging) {
                        NSLog(@"Shift pixel values applied at Pixel[%zu, %zu]", x, y);
                    }
                    // Circular shift right for RGB values
                    unsigned char temp = rawData[pixelIndex + 2]; // Temporarily store the Blue value
                    rawData[pixelIndex + 2] = rawData[pixelIndex + 1]; // Move Green to Blue
                    rawData[pixelIndex + 1] = rawData[pixelIndex]; // Move Red to Green
                    rawData[pixelIndex] = temp; // Move original Blue to Red
                    break;
                case 4: // Extreme contrast adjustment
                    if (verboseLogging) {
                        NSLog(@"Extreme contrast adjustment at Pixel[%zu, %zu]", x, y);
                    }
                    for (int i = 0; i < 3; i++) {
                        rawData[pixelIndex + i] = rawData[pixelIndex + i] < 128 ? 0 : 255;
                    }
                    break;
                case 5: // Conditional color swap
                    if (verboseLogging) {
                        NSLog(@"Conditional color swap at Pixel[%zu, %zu]", x, y);
                    }
                    // Swap Red and Blue based on a simple condition
                    if ((x + y) % 2 == 0) { // Changed condition for more frequent swaps
                        unsigned char temp = rawData[pixelIndex]; // Store Red
                        rawData[pixelIndex] = rawData[pixelIndex + 2]; // Blue to Red
                        rawData[pixelIndex + 2] = temp; // Red to Blue
                    }
                    break;
            }
        }
    }

    if (verboseLogging) {
        NSLog(@"Enhanced fuzzing on bitmap context completed");
    }
}

void applyFuzzingToBitmapContext(unsigned char *rawData, size_t width, size_t height) {
    
    for (size_t y = 0; y < height; y++) {
        for (size_t x = 0; x < width; x++) {
            size_t pixelIndex = (y * width + x) * 4; // 4 bytes per pixel (RGBA)
            
            // Fuzzing each color component (R, G, B) within the range of 0-255
            for (int i = 0; i < 3; i++) { // Looping over R, G, B components
                int fuzzFactor = rand() % 51 - 25; // Random number between -25 and 25
                int newValue = rawData[pixelIndex + i] + fuzzFactor;
                rawData[pixelIndex + i] = (unsigned char) fmax(0, fmin(255, newValue));
            }
            // Alpha (offset + 3) is not altered
        }
    }
    NSLog(@"Fuzzing applied to RGB components of the bitmap context");
}

void debugMemoryHandling(void) {
    const size_t sz = 0x10000;
    char* chunks[64] = { NULL };
    for (int i = 0; i < 64; i++) {
        char* chunk = (char *)mmap(0, sz, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (chunk == MAP_FAILED) {
            NSLog(@"Failed to map memory for chunk %d", i);
            continue;
        }
        memset(chunk, 0x41, sz);
        NSLog(@"Chunk @ %p", chunk);
        chunks[i] = chunk;
    }

    for (int i = 0; i < 64; i++) {
        if (chunks[i] != NULL) {
            if (munmap(chunks[i], sz) == -1) {
                NSLog(@"Failed to unmap chunk @ %p", chunks[i]);
            } else {
                NSLog(@"Successfully unmapped chunk @ %p", chunks[i]);
            }
        }
    }
}

void saveFuzzedImage(UIImage *image, NSString *contextDescription) {
    // Ensure contextDescription is valid to prevent file path issues
    if (contextDescription == nil || [contextDescription length] == 0) {
        NSLog(@"Context description is invalid.");
        return;
    }

    // Generate file name based on the context description
    NSString *fileName = [NSString stringWithFormat:@"fuzzed_image_%@.png", contextDescription];
    
    // Fetch the documents directory path
    NSString *documentsDirectory = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *filePath = [documentsDirectory stringByAppendingPathComponent:fileName];
    
    // Convert UIImage to PNG data
    NSData *imageData = UIImagePNGRepresentation(image);
    BOOL success = [imageData writeToFile:filePath atomically:YES];
    
    if (success) {
        NSLog(@"Fuzzed image for '%@' context saved to %@", contextDescription, filePath);
    } else {
        NSLog(@"Failed to save fuzzed image for '%@' context", contextDescription);
    }
}

int main(int argc, const char * argv[]) {
    NSLog(@"Starting up...");
    debugMemoryHandling(); // Call the debug function
    setenv("CGBITMAP_CONTEXT_LOG_ERRORS", "1", 1);
    setenv("CG_PDF_VERBOSE", "1", 1);
    setenv("CG_CONTEXT_SHOW_BACKTRACE", "1", 1);
    setenv("CG_CONTEXT_SHOW_BACKTRACE_ON_ERROR", "1", 1);
    setenv("CG_IMAGE_SHOW_MALLOC", "1", 1);
    setenv("CG_LAYER_SHOW_BACKTRACE", "1", 1);
    setenv("CGBITMAP_CONTEXT_LOG", "1", 1);
    setenv("CGCOLORDATAPROVIDER_VERBOSE", "1", 1);
    setenv("CGPDF_LOG_PAGES", "1", 1);
    setenv("MALLOC_CHECK_", "1", 1);
    setenv("NSZombieEnabled", "YES", 1);
    setenv("NSAssertsEnabled", "YES", 1);
    setenv("NSShowAllViews", "YES", 1);
    setenv("IDELogRedirectionPolicy", "oslogToStdio", 1);
    @autoreleasepool {
        if (argc < 3) {
            NSLog(@"Usage: %s image_name permutation_number", argv[0]);
            return 0;
        }

        NSString* imageName = [NSString stringWithUTF8String:argv[1]];
        int permutation = atoi(argv[2]);

        UIImage *image = loadImageFromFile(imageName);
        if (!image) {
            NSLog(@"Failed to load image: %@", imageName);
            return 1;
        }

        processImage(image, permutation);
        NSLog(@"End of Run...");
    }

    return 0;
}

BOOL isValidImagePath(NSString *path) {
    BOOL fileExists = [[NSFileManager defaultManager] fileExistsAtPath:path];
    NSLog(fileExists ? @"Valid image path: %@" : @"Invalid image path: %@", path);
    return fileExists;
}

UIImage *loadImageFromFile(NSString *imageName) {
    NSLog(@"Loading file: %@", imageName);
    NSString *imagePath = [[NSBundle mainBundle] pathForResource:imageName ofType:nil];
    if (!imagePath) {
        NSLog(@"Failed to find path for image: %@", imageName);
        return nil;
    }
    NSLog(@"Image path: %@", imagePath);

    NSData *content = [NSData dataWithContentsOfFile:imagePath];
    if (!content) {
        NSLog(@"Failed to load data from file: %@", imagePath);
        return nil;
    }

    UIImage *image = [UIImage imageWithData:content];
    if (!image) {
        NSLog(@"Failed to create UIImage from data.");
        return nil;
    }

    // Retrieve the size of the image
    CGSize imageSize = image.size;

    // Logging additional details about the image
//    debugMemoryHandling(); // Call the debug function
    NSLog(@"UIImage created: %@, Size: {width: %.2f, height: %.2f}, Scale: %f, Orientation: %ld",
          image, imageSize.width, imageSize.height, image.scale, (long)image.imageOrientation);

    return image;
}

void processImage(UIImage *image, int permutation) {
    CGImageRef cgImg = [image CGImage];
    if (!cgImg) {
        NSLog(@"Failed to get CGImage from UIImage.");
        return;
    }
    NSLog(@"CGImage created from UIImage. Dimensions: %zu x %zu", CGImageGetWidth(cgImg), CGImageGetHeight(cgImg));

    if (permutation == -1) {
        for (int i = 1; i <= 12; i++) {
            switch (i) {
                case 1:
                    NSLog(@"Case: Creating bitmap context with Standard RGB settings");
                    createBitmapContextStandardRGB(cgImg, permutation);
                    break;
                case 2:
                    NSLog(@"Case: Creating bitmap context with Premultiplied First Alpha settings");
                    createBitmapContextPremultipliedFirstAlpha(cgImg);
                    break;
                case 3:
                    NSLog(@"Case: Creating bitmap context with Non-Premultiplied Alpha settings");
                    createBitmapContextNonPremultipliedAlpha(cgImg);
                    break;
                case 4:
                    NSLog(@"Case: Creating bitmap context with 16-bit depth settings");
                    createBitmapContext16BitDepth(cgImg);
                    break;
                case 5:
                    NSLog(@"Grayscale image processing is currently pending implementation.");
                    break;
                case 6:
                    NSLog(@"Case: Creating bitmap context with HDR Float Components settings");
                    createBitmapContextHDRFloatComponents(cgImg);
                    break;
                case 7:
                    NSLog(@"Case: Creating bitmap context with Alpha Only settings");
                    createBitmapContextAlphaOnly(cgImg);
                    break;
                case 8:
                    NSLog(@"Case: Creating bitmap context with 1-bit Monochrome settings");
                    createBitmapContext1BitMonochrome(cgImg);
                    break;
                case 9:
                    NSLog(@"Case: Creating bitmap context with Big Endian pixel format settings");
                    createBitmapContextBigEndian(cgImg);
                    break;
                case 10:
                    NSLog(@"Case: Creating bitmap context with Little Endian pixel format settings");
                    createBitmapContextLittleEndian(cgImg);
                    break;
                case 11:
                    NSLog(@"Case: Creating bitmap context with 8-bit depth, inverted colors settings");
                    createBitmapContext8BitInvertedColors(cgImg);
                    break;
                case 12:
                    NSLog(@"Case: Creating bitmap context with 32-bit float, 4-component settings");
                    createBitmapContext32BitFloat4Component(cgImg);
                    break;
                default:
                    NSLog(@"Case: Invalid permutation number %d", permutation);
                    break;
            }
            NSLog(@"Completed image processing for permutation %d", i);
        }
    } else {
        switch (permutation) {
            case 1:
                NSLog(@"Case: Creating bitmap context with Standard RGB settings");
                createBitmapContextStandardRGB(cgImg, permutation);
                break;
            case 2:
                NSLog(@"Case: Creating bitmap context with Premultiplied First Alpha settings");
                createBitmapContextPremultipliedFirstAlpha(cgImg);
                break;
            case 3:
                NSLog(@"Case: Creating bitmap context with Non-Premultiplied Alpha settings");
                createBitmapContextNonPremultipliedAlpha(cgImg);
                break;
            case 4:
                NSLog(@"Case: Creating bitmap context with 16-bit depth settings");
                createBitmapContext16BitDepth(cgImg);
                break;
            case 5:
                NSLog(@"Grayscale image processing is currently pending implementation.");
                return;
            case 6:
                NSLog(@"Case: Creating bitmap context with HDR Float Components settings");
                createBitmapContextHDRFloatComponents(cgImg);
                break;
            case 7:
                NSLog(@"Case: Creating bitmap context with Alpha Only settings");
                createBitmapContextAlphaOnly(cgImg);
                break;
            case 8:
                NSLog(@"Case: Creating bitmap context with 1-bit Monochrome settings");
                createBitmapContext1BitMonochrome(cgImg);
                break;
            case 9:
                NSLog(@"Case: Creating bitmap context with Big Endian pixel format settings");
                createBitmapContextBigEndian(cgImg);
                break;
            case 10:
                NSLog(@"Case: Creating bitmap context with Little Endian pixel format settings");
                createBitmapContextLittleEndian(cgImg);
                break;
            case 11:
                NSLog(@"Case: Creating bitmap context with 8-bit depth, inverted colors settings");
                createBitmapContext8BitInvertedColors(cgImg);
                break;
            case 12:
                NSLog(@"Case: Creating bitmap context with 32-bit float, 4-component settings");
                createBitmapContext32BitFloat4Component(cgImg);
                break;
            default:
                NSLog(@"Case: Invalid permutation number %d", permutation);
                break;        }
        NSLog(@"Completed image processing for permutation %d", permutation);
    }
}

void createBitmapContextStandardRGB(CGImageRef cgImg, int permutation) {
    NSLog(@"Creating bitmap context with Standard RGB settings and applying fuzzing");
    debugMemoryHandling();
    
    if (!cgImg) {
        NSLog(@"Invalid CGImageRef provided.");
        return;
    }

    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    size_t bytesPerRow = width * 4; // 4 bytes per pixel (RGBA)

    unsigned char *rawData = (unsigned char *)calloc(height * bytesPerRow, sizeof(unsigned char));
    if (!rawData) {
        NSLog(@"Failed to allocate memory for image processing");
        debugMemoryHandling();
        return;
    }

    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    if (!colorSpace) {
        NSLog(@"Failed to create color space");
        free(rawData);
        debugMemoryHandling();
        return;
    }

    CGBitmapInfo bitmapInfo = kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big;
    CGContextRef ctx = CGBitmapContextCreate(rawData, width, height, 8, bytesPerRow, colorSpace, bitmapInfo);

    CGColorSpaceRelease(colorSpace);

    if (!ctx) {
        NSLog(@"Failed to create bitmap context");
        free(rawData);
        debugMemoryHandling();
        return;
    }

    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImg);

    NSLog(@"Applying enhanced fuzzing logic to the bitmap context");
    applyEnhancedFuzzingToBitmapContext(rawData, width, height, verboseLogging);

    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg);

        saveFuzzedImage(newImage, @"standard_rgb");

        NSLog(@"Modified UIImage created and saved successfully.");
    }

    CGContextRelease(ctx);
    free(rawData);
    debugMemoryHandling();
}

void createBitmapContextPremultipliedFirstAlpha(CGImageRef cgImg) {
    NSLog(@"Creating bitmap context with Premultiplied First Alpha settings");

    debugMemoryHandling();

    if (!cgImg) {
        NSLog(@"Invalid CGImageRef provided.");
        return;
    }

    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    size_t bytesPerRow = width * 4;

    unsigned char *rawData = (unsigned char *)calloc(height * bytesPerRow, sizeof(unsigned char));
    if (!rawData) {
        NSLog(@"Failed to allocate memory for image processing");
        debugMemoryHandling();
        return;
    }

    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    if (!colorSpace) {
        NSLog(@"Failed to create color space");
        free(rawData);
        debugMemoryHandling();
        return;
    }

    CGBitmapInfo bitmapInfo = kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Big;
    CGContextRef ctx = CGBitmapContextCreate(rawData, width, height, 8, bytesPerRow, colorSpace, bitmapInfo);

    CGColorSpaceRelease(colorSpace);

    if (!ctx) {
        NSLog(@"Failed to create bitmap context");
        free(rawData);
        debugMemoryHandling();
        return;
    }

    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImg);

    NSLog(@"Applying enhanced fuzzing logic to the bitmap context");
    applyEnhancedFuzzingToBitmapContext(rawData, width, height, verboseLogging);

    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg);

        saveFuzzedImage(newImage, @"premultiplied_first_alpha");

        NSLog(@"Modified UIImage created and saved successfully.");
    }

    CGContextRelease(ctx);
    free(rawData);
    debugMemoryHandling();
}

void createBitmapContextNonPremultipliedAlpha(CGImageRef cgImg) {
    NSLog(@"Creating bitmap context with Non-Premultiplied Alpha settings and applying fuzzing");
    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    size_t bytesPerRow = width * 4; // 4 bytes per pixel for RGBA
    unsigned char *rawData = (unsigned char *)malloc(height * bytesPerRow);

    if (!rawData) {
        NSLog(@"Failed to allocate memory for image processing");
        return;
    }

    CGContextRef ctx = CGBitmapContextCreate(rawData, width, height, 8, bytesPerRow, CGColorSpaceCreateDeviceRGB(), kCGImageAlphaLast);
    if (!ctx) {
        NSLog(@"Failed to create bitmap context with Non-Premultiplied Alpha settings");
        free(rawData);
        return;
    }

    // Draw the image into the context
    NSLog(@"Drawing image into the bitmap context");
    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImg);

    // Apply fuzzing logic
    NSLog(@"Applying fuzzing logic to the bitmap context");
    applyFuzzingToBitmapContext(rawData, width, height);

    // Optionally, you can convert back to UIImage to see the result
    NSLog(@"Creating CGImage from the modified bitmap context");
    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg);

        // Here, newImage contains the modified image
        // You can log or use newImage as needed
        NSLog(@"Modified UIImage created successfully");

        // Example: Logging newImage details
        NSLog(@"New image size: %@, scale: %f, rendering mode: %ld",
              NSStringFromCGSize(newImage.size),
              newImage.scale,
              (long)newImage.renderingMode);
    }

    CGContextRelease(ctx);
    free(rawData);

    NSLog(@"Bitmap context with Non-Premultiplied Alpha settings created and fuzzing applied");
}

void createBitmapContext16BitDepth(CGImageRef cgImg) {
    NSLog(@"Creating bitmap context with 16-bit Depth settings and applying fuzzing");
    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    size_t bytesPerRow = width * 8; // 8 bytes per pixel for 16-bit RGBA
    unsigned char *rawData = (unsigned char *)malloc(height * bytesPerRow);

    if (!rawData) {
        NSLog(@"Failed to allocate memory for image processing");
        return;
    }

    CGContextRef ctx = CGBitmapContextCreate(rawData, width, height, 16, bytesPerRow, CGColorSpaceCreateDeviceRGB(), kCGImageAlphaPremultipliedFirst);
    if (!ctx) {
        NSLog(@"Failed to create bitmap context with 16-bit Depth settings");
        free(rawData);
        return;
    }

    // Draw the image into the context
    NSLog(@"Drawing image into the bitmap context");
    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImg);

    // Apply fuzzing logic
    NSLog(@"Applying fuzzing logic to the bitmap context");
    applyFuzzingToBitmapContext(rawData, width, height);

    // Optionally, you can convert back to UIImage to see the result
    NSLog(@"Creating CGImage from the modified bitmap context");
    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg);

        // Here, newImage contains the modified image
        // You can log or use newImage as needed
        NSLog(@"Modified UIImage created successfully");

        // Example: Logging newImage details
        NSLog(@"New image size: %@, scale: %f, rendering mode: %ld",
              NSStringFromCGSize(newImage.size),
              newImage.scale,
              (long)newImage.renderingMode);
    }

    CGContextRelease(ctx);
    free(rawData);

    NSLog(@"Bitmap context with 16-bit Depth settings created and fuzzing applied");
}

void createBitmapContextGrayscale(CGImageRef cgImg) {
    NSLog(@"Grayscale image processing is not yet implemented.");
    // No further processing or memory allocations
}

void createBitmapContextHDRFloatComponents(CGImageRef cgImg) {
    NSLog(@"Creating bitmap context with HDR Float Components settings and applying fuzzing");
    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    size_t bytesPerRow = width * 16; // 16 bytes per pixel for HDR RGBA (4 components x 4 bytes per component)

    unsigned char *rawData = (unsigned char *)malloc(height * bytesPerRow);
    if (!rawData) {
        NSLog(@"Failed to allocate memory for HDR image processing");
        return;
    }

    CGContextRef ctx = CGBitmapContextCreate(rawData, width, height, 32, bytesPerRow, CGColorSpaceCreateDeviceRGB(), kCGImageAlphaPremultipliedLast | kCGBitmapFloatComponents);
    if (!ctx) {
        NSLog(@"Failed to create bitmap context with HDR Float Components settings");
        free(rawData);
        return;
    }

    // Draw the image into the context
    NSLog(@"Drawing image into the HDR bitmap context");
    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImg);

    // Apply fuzzing logic
    NSLog(@"Applying fuzzing logic to the HDR bitmap context");
    applyFuzzingToBitmapContext(rawData, width, height);

    // Optionally, you can convert back to UIImage to see the result
    NSLog(@"Creating CGImage from the modified HDR bitmap context");
    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from HDR context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg);

        // Here, newImage contains the modified HDR image
        // You can log or use newImage as needed
        NSLog(@"Modified HDR UIImage created successfully");

        // Example: Logging newImage details
        NSLog(@"New HDR image size: %@, scale: %f",
              NSStringFromCGSize(newImage.size),
              newImage.scale);
    }

    CGContextRelease(ctx);
    free(rawData);

    NSLog(@"Bitmap context with HDR Float Components settings created and fuzzing applied");
}

void createBitmapContextAlphaOnly(CGImageRef cgImg) {
    NSLog(@"Creating bitmap context with Alpha Only settings");
    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    CGContextRef ctx = CGBitmapContextCreate(NULL, width, height, 8, width, NULL, kCGImageAlphaOnly);
    if (!ctx) {
        NSLog(@"Failed to create bitmap context with Alpha Only settings");
        return;
    }
    NSLog(@"Bitmap context with Alpha Only settings created successfully");
    CGContextRelease(ctx);
}

void createBitmapContext1BitMonochrome(CGImageRef cgImg) {
    NSLog(@"Creating bitmap context with 1-bit Monochrome settings");
    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    CGContextRef ctx = CGBitmapContextCreate(NULL, width, height, 1, width / 8, NULL, kCGImageAlphaNone);
    if (!ctx) {
        NSLog(@"Failed to create bitmap context with 1-bit Monochrome settings");
        return;
    }
    NSLog(@"Bitmap context with 1-bit Monochrome settings created successfully");
    CGContextRelease(ctx);
}

void createBitmapContextBigEndian(CGImageRef cgImg) {
    NSLog(@"Creating bitmap context with Big Endian settings");
    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    CGContextRef ctx = CGBitmapContextCreate(NULL, width, height, 8, width * 4, CGColorSpaceCreateDeviceRGB(), kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    if (!ctx) {
        NSLog(@"Failed to create bitmap context with Big Endian settings");
        return;
    }
    NSLog(@"Bitmap context with Big Endian settings created successfully");
    CGContextRelease(ctx);
}

void createBitmapContextLittleEndian(CGImageRef cgImg) {
    NSLog(@"Creating bitmap context with Little Endian settings");
    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    CGContextRef ctx = CGBitmapContextCreate(NULL, width, height, 8, width * 4, CGColorSpaceCreateDeviceRGB(), kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
    if (!ctx) {
        NSLog(@"Failed to create bitmap context with Little Endian settings");
        return;
    }
    NSLog(@"Bitmap context with Little Endian settings created successfully");
    CGContextRelease(ctx);
}

void createBitmapContext8BitInvertedColors(CGImageRef cgImg) {
    NSLog(@"Creating bitmap context with 8-bit depth, inverted colors");
    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    CGContextRef ctx = CGBitmapContextCreate(NULL, width, height, 8, width * 4, CGColorSpaceCreateDeviceRGB(), kCGImageAlphaNoneSkipLast | kCGBitmapByteOrder32Little);
    if (!ctx) {
        NSLog(@"Failed to create bitmap context with 8-bit depth, inverted colors");
        return;
    }
    // Additional processing
    NSLog(@"Bitmap context with 8-bit depth, inverted colors created successfully");
    CGContextRelease(ctx);
}

void createBitmapContext32BitFloat4Component(CGImageRef cgImg) {
    NSLog(@"Creating bitmap context with 32-bit float, 4-component settings");
    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    CGContextRef ctx = CGBitmapContextCreate(NULL, width, height, 32, width * 16, CGColorSpaceCreateDeviceRGB(), kCGImageAlphaPremultipliedLast | kCGBitmapFloatComponents);
    if (!ctx) {
        NSLog(@"Failed to create bitmap context with 32-bit float, 4-component settings");
        return;
    }
    // Additional processing
    NSLog(@"Bitmap context with 32-bit float, 4-component settings created successfully");
    CGContextRelease(ctx);
}
