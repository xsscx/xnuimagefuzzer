/**
 * @file       xnuimagefuzzer.m
 * @brief      Proof of concept XNU Image Fuzzer
 * @author     @h02332 | David Hoyt
 * @date       Modified 27 FEB 2024
 * @time       1645 EST
 *
 * License: GPL3
 *
 * @section    CHANGES
 * [Date] [Author] - [Description of Changes]
 * - [26/11/2023] [h02332] - Initial commit
 * - [27/11/2023] [h02332] - Removed Grayscale Feature pending Implementation
 * - [28/11/2023] [h02332] - Refactor Code & Fuzzing
 * - [29/11/2023] [h02332] - Refactor Code & Fuzzing & Logging
 * - [20/02/2024] [h02332] - Refactor Code & Fuzzing & Logging
 * - [21/02/2024] [h02332] - Refactor Fuzzing Contexts for Floats & Alpha, Fix Coverage, Math & Programming Mistakes
 * - [21/02/2024] [h02332] - PermaLink https://srd.cx/xnu-image-fuzzer/
 * - [27/02/2024] [h02332] - Refactor Code & Fuzzing & Logging & Injected Strings
 *
 * @section    TODO
 * - [ ] Grayscale Implementation
 * - [ ] ICC Color Profiles
 * - [ ] Refactor Example Fuzzer
 * - [ ] Add Logging Toggle as global variable  - testing in createBitmapContextStandardRGB function
 *
 */
#pragma mark - Headers

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreGraphics/CoreGraphics.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <math.h>
#include <stdbool.h>
#include <float.h>
#include <string.h>

#pragma mark - Constants

#define ALL -1 // A special flag used to indicate an operation applies to all items or states.
#define MAX_PERMUTATION 12 // The maximum number of permutations or variations to be applied in image processing.


#pragma mark - Injection Strings Configuration

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

#pragma mark - Debugging Macros

#ifdef DEBUG
#define DebugLog(fmt, ...) NSLog((@"%s [Line %d] " fmt), __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__);
#else
#define DebugLog(...)
#endif

#define AssertWithMessage(condition, message, ...) \
    do { \
        if (!(condition)) { \
            NSLog((@"Assertion failed: %s " message), #condition, ##__VA_ARGS__); \
            assert(condition); \
        } \
    } while(0)

#pragma mark - Global Variables

static int verboseLogging = 0; // Enable detailed logging: 1 for yes, 0 for no

#pragma mark - Utility Function Prototypes

BOOL isValidImagePath(NSString *path);
UIImage *loadImageFromFile(NSString *path);
void processImage(UIImage *image, int permutation);
// void LogRandomPixelData(unsigned char *rawData, size_t width, size_t height, const char *message);
NSString *createUniqueDirectoryForSavingImages(void);
void addAdditiveNoise(float *pixel);
void applyMultiplicativeNoise(float *pixel);
void invertColor(float *pixel);
void applyExtremeValues(float *pixel);
void assignSpecialFloatValues(float *pixel);
unsigned long hashString(const char* str);

#pragma mark - Image Processing Prototypes

// Create a bitmap context with standard RGB color space. This context is suitable for most images and supports a wide range of colors.
void createBitmapContextStandardRGB(CGImageRef cgImg, int permutation);

// Create a bitmap context with premultiplied first alpha. Premultiplied alpha is used in many graphics processes because it simplifies blending operations.
void createBitmapContextPremultipliedFirstAlpha(CGImageRef cgImg);

// Create a bitmap context where the alpha is not premultiplied. This is useful for precise color manipulation and when working with images that require direct manipulation of alpha values.
void createBitmapContextNonPremultipliedAlpha(CGImageRef cgImg);

// Create a bitmap context with 16-bit depth per component. This allows for high-fidelity image processing, suitable for professional photography or detailed graphical work.
void createBitmapContext16BitDepth(CGImageRef cgImg);

// Create a bitmap context for grayscale images. This simplifies processing for images where color is not a factor, focusing on luminance values.
void createBitmapContextGrayscale(CGImageRef cgImg);

// Create a bitmap context with HDR (High Dynamic Range) using floating-point components. This is ideal for images with a wide range of luminance values, providing more detail in both shadows and highlights.
void createBitmapContextHDRFloatComponents(CGImageRef cgImg);

// Create a bitmap context that only processes the alpha channel. This is useful for working with or generating mask images.
void createBitmapContextAlphaOnly(CGImageRef cgImg);

// Create a bitmap context for 1-bit monochrome images. This context simplifies images to black and white, useful for stark contrasts or stylistic effects.
void createBitmapContext1BitMonochrome(CGImageRef cgImg);

// Create a bitmap context with a big endian pixel format. Endianness may affect how pixel data is read and written, important for compatibility with certain systems or file formats.
void createBitmapContextBigEndian(CGImageRef cgImg);

// Create a bitmap context with a little endian pixel format. Like big endian, this is related to the way data is stored and is crucial for ensuring correct image representation.
void createBitmapContextLittleEndian(CGImageRef cgImg);

// Create a bitmap context that inverts the colors of the 8-bit image. Inverting colors can highlight differences or be used for visual effects.
void createBitmapContext8BitInvertedColors(CGImageRef cgImg);

// Create a bitmap context with a 32-bit floating-point format per component, supporting four components. This allows for extremely detailed and wide-range image processing, accommodating HDR content and advanced color grading.
void createBitmapContext32BitFloat4Component(CGImageRef cgImg);

// Apply fuzzing to a bitmap context's raw pixel data. Fuzzing introduces random changes to test the resilience of image processing algorithms and uncover bugs.
void applyFuzzingToBitmapContext(unsigned char *rawData, size_t width, size_t height);

// Log pixel data from a bitmap context for analysis or debugging, with an option to include verbose output.
void logPixelData(unsigned char *rawData, size_t width, size_t height, const char *message, bool verbose);

// Apply enhanced fuzzing to a bitmap context's raw pixel data, with a parameter to enable verbose logging. This provides a more aggressive testing approach to uncover potential issues.
void applyEnhancedFuzzingToBitmapContext(unsigned char *rawData, size_t width, size_t height, BOOL verbose);

// Convert the raw pixel data of an image to 1-bit monochrome, simplifying the image to basic black and white. This can be used for stylistic effects or to reduce complexity for certain processing tasks.
void convertTo1BitMonochrome(unsigned char *rawData, size_t width, size_t height);

// Save a monochrome image with a specified identifier. This function is useful for persisting processed images, allowing for easy retrieval or comparison.
void saveMonochromeImage(UIImage *image, NSString *identifier);

#pragma mark - Conversion and Saving Functions

/**
 Converts image data to 1-bit monochrome using a simple thresholding technique.

 @param rawData Pointer to the image data.
 @param width The width of the image in pixels.
 @param height The height of the image in pixels.
 */
extern void convertTo1BitMonochrome(unsigned char *rawData, size_t width, size_t height) {
    size_t bytesPerRow = (width + 7) / 8; // Calculate the bytes per row for 1bpp
    unsigned char threshold = 127; // Midpoint threshold for black/white conversion

    for (size_t y = 0; y < height; y++) {
        for (size_t x = 0; x < width; x++) {
            size_t byteIndex = y * bytesPerRow + x / 8;
            unsigned char pixelValue = rawData[y * width + x]; // Assuming rawData is in a format where each pixel is a byte
            unsigned char bit = (pixelValue > threshold) ? 1 : 0; // Apply threshold

            rawData[byteIndex] &= ~(1 << (7 - (x % 8))); // Clear the bit
            rawData[byteIndex] |= (bit << (7 - (x % 8))); // Set the bit based on threshold
        }
    }
}

/**
 Saves a monochrome UIImage with a specified identifier to the documents directory.

 @param image The UIImage to save.
 @param identifier A unique identifier for the image file.
 */
extern void saveMonochromeImage(UIImage *image, NSString *identifier) {
    NSData *imageData = UIImagePNGRepresentation(image);
    NSString *docsDir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *filePath = [docsDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@.png", identifier]];
    
    if ([imageData writeToFile:filePath atomically:YES]) {
        NSLog(@"Saved monochrome image with identifier %@ at %@", identifier, filePath);
    } else {
        NSLog(@"Error saving monochrome image with identifier %@", identifier);
    }
}

#pragma mark - Directory Management

/**
 Creates a unique directory for saving images within the documents directory. The directory name includes a timestamp and a random component to ensure uniqueness.

 @return The path to the newly created unique directory, or nil if an error occurred.
 */
NSString *createUniqueDirectoryForSavingImages(void) {
    // Initialize date formatter for timestamp
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    [formatter setDateFormat:@"yyyy-MM-dd_HH-mm-ss-SSS"];
    
    // Generate unique directory name with current date-time and a random component
    NSString *dateString = [formatter stringFromDate:[NSDate date]];
    uint32_t randomComponent = arc4random_uniform(10000); // Ensures additional uniqueness
    NSString *uniqueDirectoryName = [NSString stringWithFormat:@"%@_%u", dateString, randomComponent];
    
    // Retrieve path to the documents directory
    NSString *documentsDirectory = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    
    // Construct the path for the new unique directory
    NSString *uniqueDirPath = [documentsDirectory stringByAppendingPathComponent:uniqueDirectoryName];

    // Attempt to create the directory
    NSError *error = nil;
    if (![[NSFileManager defaultManager] createDirectoryAtPath:uniqueDirPath withIntermediateDirectories:YES attributes:nil error:&error]) {
        NSLog(@"Error creating directory for saving images: %@", error);
        return nil; // Return nil in case of failure
    }

    // Return the path of the successfully created directory
    return uniqueDirPath;
}

#pragma mark - Pixel Logging Data

/**
 Logs information about a random set of pixels from an image's raw data, with optional verbose output that includes decoded character data from the pixel values.

 @param rawData The raw pixel data of the image.
 @param width The width of the image in pixels.
 @param height The height of the image in pixels.
 @param message A message or identifier to include in the log for context.
 @param verboseLogging If true, logs detailed information including decoded data; if false, performs basic logging.
*/
void logPixelData(unsigned char *rawData, size_t width, size_t height, const char *message, bool verboseLogging) {
    if (!rawData || width == 0 || height == 0) {
        NSLog(@"%s - Invalid data or dimensions. Logging aborted.", message);
        return;
    }

    const int numberOfPixelsToLog = 5; // Number of random pixels to log

    if (verboseLogging) {
        NSLog(@"%s - Logging %d random pixels:", message, numberOfPixelsToLog);

        for (int i = 0; i < numberOfPixelsToLog; i++) {
            // Using arc4random_uniform() for better randomness and to avoid modulo bias
            unsigned int randomX = arc4random_uniform((unsigned int)width);
            unsigned int randomY = arc4random_uniform((unsigned int)height);
            size_t pixelIndex = (randomY * width + randomX) * 4; // Assumes 4 bytes per pixel (RGBA)

            if (pixelIndex + 3 < width * height * 4) {
                NSLog(@"%s - Pixel[%u, %u]: R=%d, G=%d, B=%d, A=%d",
                      message, randomX, randomY,
                      rawData[pixelIndex], rawData[pixelIndex + 1],
                      rawData[pixelIndex + 2], rawData[pixelIndex + 3]);

                // Decoding embedded data from pixels
                unsigned char decodedChar = 0;
                for (int bit = 0; bit < 3; bit++) {
                    decodedChar |= (rawData[pixelIndex + bit] & 0x01) << (bit*2);
                }
                NSLog(@"%s - Decoded data from Pixel[%u, %u]: %c",
                      message, randomX, randomY, decodedChar);
            } else {
                NSLog(@"%s - Out of bounds pixel access prevented at [%u, %u].", message, randomX, randomY);
            }
        }
    } else {
        NSLog(@"%s - Basic pixel logging executed.", message);
    }
}

#pragma mark - LogRandomPixelData

/**
 Logs information about a random set of pixels from an image's raw data.

 @param rawData The raw pixel data of the image.
 @param width The width of the image in pixels.
 @param height The height of the image in pixels.
 @param message A message or identifier to include in the log for context.
*/
void LogRandomPixelData(unsigned char *rawData, size_t width, size_t height, const char *message) {
    if (!rawData || width == 0 || height == 0) {
        NSLog(@"%s - Invalid data or dimensions. Logging aborted.", message);
        return;
    }

    const int numberOfPixelsToLog = 5; // Number of random pixels to log
    NSLog(@"%s - Logging %d random pixels:", message, numberOfPixelsToLog);

    for (int i = 0; i < numberOfPixelsToLog; i++) {
        unsigned int randomX = arc4random_uniform((unsigned int)width);
        unsigned int randomY = arc4random_uniform((unsigned int)height);
        size_t pixelIndex = (randomY * width + randomX) * 4; // Assumes 4 bytes per pixel (RGBA)

        if (pixelIndex + 3 < width * height * 4) {
            NSLog(@"%s - Pixel[%u, %u]: R=%d, G=%d, B=%d, A=%d",
                  message, randomX, randomY,
                  rawData[pixelIndex], rawData[pixelIndex + 1],
                  rawData[pixelIndex + 2], rawData[pixelIndex + 3]);
        } else {
            NSLog(@"%s - Out of bounds pixel access prevented at [%u, %u].", message, randomX, randomY);
        }
    }
}

#pragma mark - applyEnhancedFuzzingToBitmapContext

/**
 * Applies enhanced fuzzing techniques to a bitmap context to test image processing resilience and security.
 *
 * This function iteratively processes each pixel in the given bitmap data, applying a range of fuzzing methods.
 * These methods include injecting specific strings into the pixel data, applying visual distortions such as inversion,
 * adding random noise, setting random colors, shifting pixel values, adjusting contrast, and swapping colors under
 * certain conditions. This is designed to simulate various types of input data that an image processing system might
 * encounter in the wild, helping to identify and rectify potential vulnerabilities and ensure robust handling of
 * unexpected or maliciously crafted input.
 *
 * Parameters:
 * @param rawData Pointer to the raw pixel data of the bitmap context. This data is modified in place.
 * @param width The width of the bitmap in pixels.
 * @param height The height of the bitmap in pixels.
 * @param verboseLogging If true, logs detailed information about the fuzzing process and the specific transformations
 *                       applied to the bitmap data. This is useful for debugging and understanding the fuzzing impact.
 *
 * Note:
 * - The rawData buffer is expected to be in RGBA format, with each pixel represented by four consecutive bytes
 *   corresponding to the red, green, blue, and alpha (transparency) values, respectively.
 * - The function does not return a value but instead modifies the rawData buffer directly.
 * - It is assumed that the rawData buffer is large enough to contain width * height pixels, each with 4 bytes of data.
 * - This function demonstrates a range of image processing attacks and tests, making it a valuable tool for security
 *   analysis and improvement of image handling routines.
 */
void applyEnhancedFuzzingToBitmapContext(unsigned char *rawData, size_t width, size_t height, bool verboseLogging) {
    if (!rawData || width == 0 || height == 0) {
        NSLog(@"No valid raw data or dimensions available for enhanced fuzzing.");
        return;
    }

    size_t stringIndex = 0; // Index to track which string to inject
    size_t injectIndex = 0; // Index to track injection progress within a string
    size_t totalStringsInjected = 0; // Total number of strings injected

    if (verboseLogging) {
        NSLog(@"Starting enhanced fuzzing on bitmap context");
    }

    for (size_t y = 0; y < height; y++) {
        for (size_t x = 0; x < width; x++) {
            size_t pixelIndex = (y * width + x) * 4; // Assuming RGBA format

            // Using arc4random_uniform for random number generation
            int fuzzMethod = arc4random_uniform(6); // Six methods

            if (totalStringsInjected < NUMBER_OF_STRINGS) {
                char *currentString = injectStrings[stringIndex];
                size_t stringLength = strlen(currentString);

                if (injectIndex < stringLength) {
                    // Encode a character into the least significant bits of the first three channels of a pixel
                    for (int i = 0; i < 3; i++) {
                        // Clear the least significant bit
                        rawData[pixelIndex + i] &= 0xFE;
                        // Set the bit based on the current character's bit
                        rawData[pixelIndex + i] |= (currentString[injectIndex] >> (i*2)) & 0x01;
                    }
                    injectIndex++;
                    if (injectIndex == stringLength) {
                        injectIndex = 0; // Reset the injection index for the next string
                        stringIndex++; // Move to the next string
                        totalStringsInjected++; // Increment the count of strings injected
                    }
                }
            }
            
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
                        int noise = (rand() % 101) - 50; // Noise range [-50, 50]
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
                        rawData[pixelIndex + i] = rand() % 256;
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

#pragma mark - applyEnhancedFuzzingToBitmapContextWithFloats

/**
 * Applies advanced fuzzing techniques to a bitmap context using floating-point pixel data, based on an injection string index.
 * This function is designed to test the resilience and security of image processing algorithms by applying a range of
 * fuzzing methods that alter the pixel data in ways that could represent real-world corrupt or maliciously crafted inputs.
 * The specific fuzzing technique applied is determined by hashing the injection string selected by the stringIndex parameter,
 * allowing for a deterministic yet varied approach to fuzzing based on the content of the injection strings.
 *
 * Parameters:
 * @param rawData Pointer to the raw pixel data of the bitmap context, represented as floating-point numbers. This data
 *                is modified in place. Each pixel is expected to consist of four consecutive floats representing the
 *                red, green, blue, and alpha (transparency) channels, respectively.
 * @param width The width of the bitmap in pixels.
 * @param height The height of the bitmap in pixels.
 * @param verboseLogging If YES, detailed logging is enabled to provide insights into the fuzzing process, including
 *                       the specific techniques applied and their effects on the pixel data.
 * @param stringIndex An index into an array of strings that are used to select the fuzzing method. The string at this
 *                    index is hashed, and the hash value determines the specific fuzzing technique applied.
 *
 * Note:
 * - The function checks for valid input parameters, including non-null rawData, positive dimensions (width and height),
 *   and a valid stringIndex within the range of available injection strings.
 * - It utilizes different fuzzing techniques such as additive and multiplicative noise, inversion of color values,
 *   setting pixels to extreme floating-point values (FLT_MAX, FLT_MIN), and introducing special floating-point values
 *   (NAN, INFINITY, -INFINITY) to challenge the robustness of image processing routines.
 * - The rawData buffer is directly modified to reflect the fuzzing effects, enabling immediate observation and analysis
 *   of how such data alterations could impact image processing outcomes.
 * - This function serves as a tool for developers and security analysts to preemptively identify and address potential
 *   vulnerabilities in image processing algorithms, ensuring they can handle a wide variety of input scenarios safely.
 */
void applyEnhancedFuzzingToBitmapContextWithFloats(float *rawData, size_t width, size_t height, BOOL verboseLogging, int stringIndex) {
    if (!rawData || width == 0 || height == 0 || stringIndex < 0 || stringIndex >= NUMBER_OF_STRINGS) {
        NSLog(@"Invalid parameters for enhanced fuzzing.");
        return;
    }

    if (verboseLogging) {
        NSLog(@"Starting enhanced fuzzing with injection string: %s", injectStrings[stringIndex]);
    }

    // Hash the selected injection string to determine the fuzzing method
    unsigned long hash = hashString(injectStrings[stringIndex]) % 5; // Modulo by 5 to fit our method range

    for (size_t y = 0; y < height; y++) {
        for (size_t x = 0; x < width; x++) {
            size_t pixelIndex = (y * width + x) * 4; // Assuming RGBA format

            // Apply fuzzing based on hash of injection string
            switch (hash) {
                case 0:
                    // Additive noise
                    for (int i = 0; i < 4; i++) {
                        rawData[pixelIndex + i] += ((float)rand() / RAND_MAX * 2.0f - 1.0f); // Noise range [-1, 1]
                    }
                    break;
                case 1:
                    // Multiplicative noise (scale)
                    for (int i = 0; i < 4; i++) {
                        rawData[pixelIndex + i] *= ((float)rand() / RAND_MAX * 2.0f); // Scale range [0, 2]
                    }
                    break;
                case 2:
                    // Inversion
                    for (int i = 0; i < 3; i++) { // Skipping alpha for inversion
                        rawData[pixelIndex + i] = 1.0f - rawData[pixelIndex + i];
                    }
                    break;
                case 3:
                    // Extreme values
                    for (int i = 0; i < 4; i++) {
                        rawData[pixelIndex + i] = (rand() % 2) ? FLT_MAX : FLT_MIN;
                    }
                    break;
                case 4:
                    // Special floating-point values
                    for (int i = 0; i < 4; i++) {
                        switch (rand() % 3) {
                            case 0: rawData[pixelIndex + i] = NAN; break;
                            case 1: rawData[pixelIndex + i] = INFINITY; break;
                            case 2: rawData[pixelIndex + i] = -INFINITY; break;
                        }
                    }
                    break;
            }
        }
    }

    if (verboseLogging) {
        NSLog(@"Enhanced fuzzing with injection string completed");
    }
}

#pragma mark - Hash Function

unsigned long hashString(const char* str) {
    unsigned long hash = 5381;
    int c;

    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }

    return hash;
}

#pragma mark - applyEnhancedFuzzingToBitmapContextAlphaOnly

/**
 * Applies enhanced fuzzing techniques specifically to the alpha channel of a bitmap's pixel data. This function
 * is designed to test and improve the resilience of image processing routines against unusual or extreme alpha
 * values. It manipulates the alpha transparency data of an image in various ways to simulate potential edge cases
 * or malicious inputs that an application might encounter.
 *
 * Parameters:
 * @param alphaData Pointer to the alpha channel data of the bitmap context. Unlike RGBA data, this buffer contains
 *                  only the alpha (transparency) values for each pixel, with one byte per pixel.
 * @param width The width of the bitmap, indicating how many pixels are in a row.
 * @param height The height of the bitmap, indicating the number of rows of pixels.
 * @param verboseLogging A boolean flag that, when set to YES, enables detailed logging of the fuzzing operations
 *                       performed on the alpha data. This can be useful for debugging purposes or for analyzing
 *                       the effects of different fuzzing techniques.
 *
 * The function iterates over each pixel's alpha value and applies one of several fuzzing methods at random:
 * - Inversion of the alpha value, which could reveal handling issues for semi-transparent pixels.
 * - Randomly setting pixels to be fully transparent or fully opaque, testing extremes of the alpha range.
 * - Adding random noise to the alpha value, simulating more subtle variations in transparency.
 *
 * Each method is designed to challenge the handling of alpha transparency in downstream image processing, aiding
 * in the identification and correction of potential issues. By ensuring robust handling of varied alpha values,
 * applications can better manage images with diverse transparency characteristics, enhancing visual quality and
 * security.
 *
 * Note:
 * - The function directly modifies the `alphaData` buffer, reflecting the applied fuzzing effects.
 * - Validity checks at the beginning ensure that the function operates on a valid data buffer with positive
 *   dimensions, aborting with a log message if any parameters are invalid.
 */
void applyEnhancedFuzzingToBitmapContextAlphaOnly(unsigned char *alphaData, size_t width, size_t height, BOOL verboseLogging) {
    if (!alphaData || width == 0 || height == 0) {
        NSLog(@"No valid alpha data or dimensions available for enhanced fuzzing.");
        return;
    }

    if (verboseLogging) {
        NSLog(@"Starting enhanced fuzzing on Alpha-only bitmap context");
    }

    for (size_t y = 0; y < height; y++) {
        for (size_t x = 0; x < width; x++) {
            size_t pixelIndex = y * width + x; // Direct index as we're dealing with 1 byte per pixel
            
            // Randomly decide on a fuzzing method
            switch (arc4random_uniform(3)) { // Example with 3 simple fuzzing methods
                case 0: // Invert alpha value
                    alphaData[pixelIndex] = 255 - alphaData[pixelIndex];
                    break;
                case 1: // Set to fully transparent or fully opaque
                    if (arc4random_uniform(2) == 0) {
                        alphaData[pixelIndex] = 0; // Fully transparent
                    } else {
                        alphaData[pixelIndex] = 255; // Fully opaque
                    }
                    break;
                case 2: // Apply random noise
                    {
                        int noise = (arc4random_uniform(51)) - 25; // Random noise between -25 and 25
                        int newAlpha = (int)alphaData[pixelIndex] + noise;
                        alphaData[pixelIndex] = (unsigned char)fmax(0, fmin(255, newAlpha)); // Clamp between 0 and 255
                    }
                    break;
            }
        }
    }

    if (verboseLogging) {
        NSLog(@"Enhanced fuzzing on Alpha-only bitmap context completed");
    }
}

#pragma mark - applyFuzzingToBitmapContext

/**
 * This function is designed to apply a fuzzing process to the RGB components of each pixel in a bitmap context
 * and optionally encode additional data into the alpha channel of the first row of pixels. Fuzzing, in this context,
 * involves introducing small, random variations to the RGB values of each pixel, which can be useful for testing
 * the resilience of image processing algorithms to variations in input data.
 *
 * Parameters:
 * @param rawData A pointer to the bitmap's raw pixel data, which is assumed to be in RGBA format, with 4 bytes per
 *                pixel. The data is modified in-place, with the RGB components of each pixel being adjusted by
 *                a random fuzz factor and the alpha channel of certain pixels being optionally used to encode data.
 * @param width The width of the bitmap in pixels, indicating how many pixels are in each row.
 * @param height The height of the bitmap in pixels, indicating the total number of rows in the bitmap.
 *
 * The fuzzing process iterates over every pixel in the bitmap, applying a random adjustment within a range of
 * -25 to +25 to the R, G, and B components of each pixel. This range was chosen to introduce noticeable variations
 * without drastically altering the original image. The alpha component of each pixel is left unchanged to preserve
 * transparency data, except for specific pixels in the first row where additional data may be encoded.
 *
 * The function includes an optional feature to encode data into the alpha channel of the first row of pixels.
 * This encoding uses the lengths of predefined strings, stored in an array named `injectStrings`, as the alpha
 * values for the first few pixels. This technique demonstrates a simple method of embedding metadata or other
 * information within an image in a manner that is likely to be preserved across various image processing operations.
 *
 * Note:
 * - The use of `arc4random_uniform` ensures a more uniform distribution of fuzz factors and avoids the modulo bias
 *   associated with simpler random number generation methods.
 * - This function directly modifies the input `rawData`, reflecting the applied changes. Users of this function
 *   should ensure that any necessary copies of the original data are made before calling this function if the
 *   original, unmodified data is needed later.
 * - The decision to not alter the alpha component for most of the image ensures that the visual impact of the fuzzing
 *   is limited to color changes, with transparency remaining as originally defined.
 */
void applyFuzzingToBitmapContext(unsigned char *rawData, size_t width, size_t height) {
    NSLog(@"Beginning fuzzing operation on bitmap context.");

    for (size_t y = 0; y < height; y++) {
        for (size_t x = 0; x < width; x++) {
            size_t pixelIndex = (y * width + x) * 4; // 4 bytes per pixel (RGBA)
            
            // Fuzzing each color component (R, G, B) within the range of 0-255
            for (int i = 0; i < 3; i++) { // Looping over R, G, B components
                // Using arc4random_uniform for a more uniform distribution and to avoid modulo bias
                int fuzzFactor = (int)arc4random_uniform(51) - 25; // Random number between -25 and 25
                int newValue = rawData[pixelIndex + i] + fuzzFactor;
                rawData[pixelIndex + i] = (unsigned char) fmax(0, fmin(255, newValue));
            }
            // Alpha (offset + 3) is not altered
            
            // Optionally, inject encoded data into the alpha channel for testing purposes
            if (x < NUMBER_OF_STRINGS && y == 0) { // Simple method to inject data at the start of the image
                rawData[pixelIndex + 3] = strlen(injectStrings[x]); // Use the length of each string as a simple data point
            }
        }
    }
    
    NSLog(@"Fuzzing applied to RGB components of the bitmap context. Injection data encoded in the alpha channel of the first row.");
}

#pragma mark - debugMemoryHandling

/**
 * This function demonstrates the allocation and deallocation of memory using memory mapping.
 * It is designed to help in debugging memory handling by programmatically allocating and
 * then freeing a fixed number of memory chunks. This can be particularly useful for testing
 * the behavior of an application in scenarios where memory availability fluctuates, as well
 * as for understanding and demonstrating the use of the mmap and munmap system calls.
 *
 * The function operates by attempting to allocate 64 chunks of memory, each of size 0x10000
 * bytes (64 KB), and then deallocating them. The allocations are done via the mmap system call,
 * which maps pages of memory into the process's address space, and the deallocations are
 * performed using the munmap system call, which unmaps previously mapped pages.
 *
 * Steps performed by the function:
 * 1. Initialize an array of pointers, `chunks`, to keep track of the memory addresses of the
 *    allocated chunks.
 * 2. For each chunk:
 *    a. Attempt to allocate it using mmap with the flags MAP_ANONYMOUS and MAP_PRIVATE, indicating
 *       that the mapping is not backed by any file and that updates to the mapping are not
 *       visible to other processes.
 *    b. If the allocation fails (mmap returns MAP_FAILED), log an error message and continue
 *       to the next chunk.
 *    c. If the allocation succeeds, fill the allocated memory with the byte 0x41 (ASCII 'A')
 *       using memset, to simulate initializing the memory, and log the address of the allocated
 *       chunk.
 *    d. Store the address of the allocated chunk in the `chunks` array for later deallocation.
 * 3. After all allocations are attempted, iterate over the `chunks` array to deallocate each
 *    chunk of memory using munmap.
 *    a. If munmap succeeds, log a success message.
 *    b. If munmap fails (returns -1), log an error message.
 *
 * This function is useful for:
 * - Demonstrating how mmap and munmap can be used for memory management.
 * - Debugging and testing the memory allocation and deallocation behavior of applications.
 * - Learning about the handling of memory at a lower level than what high-level languages
 *   typically expose.
 *
 * Note:
 * - This function uses NSLog for logging, which is common in Objective-C environments, especially
 *   on macOS or iOS platforms. This logging mechanism can be substituted with other logging
 *   approaches depending on the target environment or platform.
 * - The specific size of each memory chunk (0x10000 bytes) and the number of chunks (64) are
 *   arbitrary and can be adjusted based on the needs of the application or the debugging scenario.
 */
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

#pragma mark - saveFuzzedImage

/**
 * Saves a modified (fuzzed) UIImage to the documents directory with a filename based on a given context description.
 *
 * @param image The UIImage object that has been modified and needs to be saved.
 * @param contextDescription A NSString describing the context in which the image was fuzzed,
 *        used to generate a unique file name for the image.
 *
 * The function performs several key steps:
 * 1. Validation of `contextDescription` to ensure it is non-nil and non-empty. This prevents
 *    potential file path issues or overwriting files due to invalid or duplicate filenames.
 * 2. Generation of a unique filename using the `contextDescription`, prefixed with "fuzzed_image_"
 *    and suffixed with ".png" to indicate the file format.
 * 3. Retrieval of the documents directory path, which is a common location for storing user-generated
 *    or application-generated files. The use of `NSSearchPathForDirectoriesInDomains` with
 *    `NSDocumentDirectory` ensures compatibility across iOS devices and versions.
 * 4. Creation of the full file path by appending the generated filename to the documents directory path.
 * 5. Conversion of the UIImage to PNG data using `UIImagePNGRepresentation`, which prepares the image
 *    for saving by encoding it in a widely supported format.
 * 6. Writing the PNG data to the file system at the specified path using `writeToFile:atomically:`,
 *    with atomic writing enabled to ensure data integrity in case the write operation is interrupted.
 * 7. Logging the outcome of the save operation, indicating success or failure along with the relevant
 *    context description and file path. This feedback is valuable for debugging and user notifications.
 *
 * Usage scenarios:
 * - Saving images after applying test or experimental modifications, such as fuzzing for security testing.
 * - Persisting user-modified images in applications that allow for image editing or customization.
 * - Generating and saving a series of images programmatically for later review or analysis.
 *
 * Note:
 * - This function assumes the presence of a valid UIImage object and an appropriate context description.
 *   Callers should handle scenarios where the image or description might not meet these requirements.
 * - The function uses NSLog for logging, which is suitable for development and debugging. For production
 *   applications, consider using a more flexible logging framework or handling errors more gracefully.
 */
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

#pragma mark - main function

/**
 * Entry point of the application, responsible for initializing the environment,
 * parsing command-line arguments, loading an image, applying a processing algorithm,
 * and managing resources efficiently.
 *
 * Environment Variables Setup:
 * - Various environment variables are set at the beginning of the function to enable
 *   detailed logging and debugging for different parts of the Core Graphics framework
 *   and the Objective-C runtime. These settings can help diagnose issues related to
 *   memory management, PDF processing, bitmap context errors, and more.
 *
 * Command-Line Arguments:
 * - The function checks if the required number of command-line arguments is provided.
 *   It expects at least three arguments: the executable name, the image name, and the
 *   permutation number to dictate the processing logic.
 * - If insufficient arguments are provided, it prints usage instructions and exits.
 *
 * Image Processing:
 * - Converts the second command-line argument into an NSString to use it for loading an image.
 * - Converts the third command-line argument into an integer to determine the permutation
 *   for the image processing function.
 * - Attempts to load the specified image. If the image cannot be loaded, it logs an error
 *   message and exits with a failure status.
 * - Calls `processImage` with the loaded image and the permutation number to apply the
 *   specified image processing technique.
 *
 * @param argc The count of command-line arguments passed to the program.
 * @param argv An array of C strings representing the command-line arguments.
 *
 * @return Returns 0 on successful execution, or 1 if the image fails to load.
 *
 * Notes:
 * - The usage of `@autoreleasepool` is crucial for managing the memory of objects
 *   created during the execution of the program, especially in a command-line
 *   application context where the run loop is not managing the autorelease pool.
 * - Environment variable configurations at the beginning are geared towards
 *   debugging and should be adjusted or removed based on the deployment needs.
 * - This function demonstrates a pattern for command-line utility development
 *   in Objective-C, combining traditional C elements with Objective-C frameworks.
 */
int main(int argc, const char * argv[]) {
    NSLog(@"Starting up...");
//    debugMemoryHandling(); // Call the debug function
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

#pragma mark - isImagePathValid
/**
 * Validates whether the specified path points to an existing file.
 * This function is particularly useful in contexts where the existence
 * of an image file at a given path is critical before proceeding with
 * further processing or operations.
 *
 * @param path A string representing the file path to be validated.
 *
 * @return Returns YES if the file exists at the specified path; otherwise, NO.
 *
 * Implementation Details:
 * - Utilizes NSFileManager's fileExistsAtPath: method to check file existence.
 * - Logs the validation result, providing immediate feedback on the file path's validity.
 * - This function can be easily repurposed or extended to validate paths for other
 *   types of files or resources, making it a versatile utility in broader applications.
 *
 * Example Usage:
 * BOOL valid = isValidImagePath(@"/path/to/image.png");
 * if (valid) {
 *     NSLog(@"The image path is valid. Proceed with loading or processing.");
 * } else {
 *     NSLog(@"The image path is invalid. Check the path or notify the user.");
 * }
 */
BOOL isValidImagePath(NSString *path) {
    BOOL fileExists = [[NSFileManager defaultManager] fileExistsAtPath:path];
    NSLog(fileExists ? @"Valid image path: %@" : @"Invalid image path: %@", path);
    return fileExists;
}

#pragma mark - loadImageFromFile

/**
 * Loads an image from the application bundle into a UIImage object.
 * This function is essential for iOS applications that need to display or process images
 * stored within the app's resources.
 *
 * @param imageName The name of the image file (including extension) to be loaded.
 *
 * @return A UIImage object initialized with the contents of the specified image file.
 *         Returns nil if the image could not be loaded.
 *
 * Implementation Details:
 * - First, it attempts to retrieve the path for the specified image using NSBundle's
 *   pathForResource:ofType: method. This step is crucial as it abstracts the file system's
 *   structure, allowing developers to focus on resource names rather than their locations.
 * - If the path is successfully found, it reads the file's contents into an NSData object.
 *   This intermediate step is necessary because UIImage's imageWithData: initializer
 *   expects image data in the form of NSData.
 * - Finally, it attempts to create a UIImage object from the NSData. If successful,
 *   it logs details about the image, such as its dimensions and scale, which can be
 *   useful for debugging or informational purposes.
 * - The function includes a commented-out call to debugMemoryHandling(), suggesting a
 *   place where memory management debugging could be integrated, highlighting the
 *   importance of memory management in handling large or numerous image files.
 *
 * Example Usage:
 * UIImage *loadedImage = loadImageFromFile(@"exampleImage.png");
 * if (loadedImage) {
 *     NSLog(@"Image loaded successfully.");
 * } else {
 *     NSLog(@"Failed to load image.");
 * }
 *
 * This function is a foundational utility for iOS apps that manage images, providing a
 * straightforward way to load and utilize image assets while handling potential errors.
 */
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

    NSLog(@"UIImage created: %@, Size: {width: %.2f, height: %.2f}, Scale: %f, Orientation: %ld",
          image, image.size.width, image.size.height, image.scale, (long)image.imageOrientation);

    return image;
}

#pragma mark - Process Image

/**
 * Processes an image by creating various bitmap contexts based on the specified permutation parameter.
 * This function serves as a central point for testing different configurations of bitmap contexts for image processing.
 * It supports a wide range of bitmap context configurations, including various color spaces, alpha channel settings,
 * bit depths, and pixel formats. The function can process all permutations in a loop or a specific permutation, based on the input parameter.
 *
 * @param image The UIImage object to be processed. It must be valid and contain a CGImage.
 * @param permutation An integer specifying which bitmap context configuration to apply.
 *        If set to -1, the function iterates through all available configurations.
 *        Otherwise, it applies the configuration corresponding to the permutation number.
 *
 * The function first attempts to retrieve the CGImage from the UIImage. If unsuccessful, it logs an error and exits.
 * For each configuration, it logs the action being performed and calls the corresponding function to create and process the bitmap context.
 * This includes handling standard RGB settings, premultiplied and non-premultiplied alpha settings, various bit depths,
 * HDR settings, monochrome settings, and different endian pixel formats, among others.
 *
 * It's important to note that the actual processing logic for each bitmap context configuration is implemented in separate functions,
 * which this function calls based on the permutation parameter. This modular approach allows for easy expansion or modification
 * of the image processing capabilities.
 *
 * Usage Example:
 * To process an image with all available bitmap context configurations, pass the image and -1 as the permutation:
 * processImage(myImage, -1);
 *
 * To process an image with a specific bitmap context configuration, pass the image and the corresponding permutation number:
 * processImage(myImage, 3); // Processes the image with Non-Premultiplied Alpha settings
 */
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

#pragma mark - createBitmapContextStandardRBG

/**
 * Creates a bitmap context with standard RGB settings, applies a fuzzing process to alter the image,
 * and saves the fuzzed image. This function is useful for testing image processing functionalities
 * or creating varied visual effects.
 *
 * @param cgImg The source image from which to create the bitmap context.
 * @param permutation An integer representing the type or level of fuzzing to apply. This parameter
 *        could dictate different fuzzing algorithms or intensities, although it's not directly used in
 *        this simplified example.
 *
 * Process:
 * 1. Validates the input CGImageRef for nullity to ensure a source image is provided.
 * 2. Retrieves the dimensions of the source image and calculates the necessary bytes per row,
 *    assuming a pixel format of RGBA (4 bytes per pixel).
 * 3. Allocates memory for the raw pixel data of the entire image.
 * 4. Creates a CGColorSpaceRef for device RGB color space, which is suitable for most image processing tasks.
 * 5. Specifies the bitmap information, including alpha channel handling and byte order.
 * 6. Creates the bitmap context using the allocated memory, color space, and bitmap info.
 * 7. Draws the source image onto the newly created bitmap context, effectively copying the image
 *    into the context's memory.
 * 8. Applies a fuzzing algorithm to the raw pixel data, demonstrating how to manipulate image data directly.
 * 9. Creates a new CGImageRef from the modified bitmap context, converts it to a UIImage, and saves it.
 * 10. Releases allocated resources, including the bitmap context and the raw pixel data memory.
 *
 * Note:
 * - The function demonstrates careful memory management, including the release of the color space and
 *   the bitmap context, as well as the freeing of dynamically allocated memory.
 * - The function includes commented-out calls to `debugMemoryHandling`, illustrating points where
 *   memory diagnostics could be inserted for debugging purposes.
 * - The `permutation` parameter is included to demonstrate how the function might be extended to
 *   apply different types of fuzzing based on input parameters. In this simplified example, it's not used.
 * - This example uses NSLog for logging purposes, which is appropriate for debugging. In production code,
 *   consider using a more sophisticated logging framework.
 * - The actual fuzzing logic is abstracted into the `applyEnhancedFuzzingToBitmapContext` function,
 *   emphasizing the separation of concerns and making the code more modular and maintainable.
 */
void createBitmapContextStandardRGB(CGImageRef cgImg, int permutation) {
    NSLog(@"Creating bitmap context with Standard RGB settings and applying fuzzing");
//    debugMemoryHandling();
    
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
//        debugMemoryHandling();
        return;
    }

    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    if (!colorSpace) {
        NSLog(@"Failed to create color space");
        free(rawData);
//        debugMemoryHandling();
        return;
    }

    CGBitmapInfo bitmapInfo = kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big;
    CGContextRef ctx = CGBitmapContextCreate(rawData, width, height, 8, bytesPerRow, colorSpace, bitmapInfo);

    CGColorSpaceRelease(colorSpace);

    if (!ctx) {
        NSLog(@"Failed to create bitmap context");
        free(rawData);
//        debugMemoryHandling();
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
//    debugMemoryHandling();
}

#pragma mark - createBitmapContextPremultipliedFirstAlpha

/**
 * Creates a bitmap graphics context with Premultiplied First Alpha settings for a given CGImage.
 * This function is designed to allocate a new bitmap context, draw the provided image into this context,
 * apply specific image processing algorithms, and then save the modified image. It uses premultiplied alpha
 * to handle the alpha channel, which can affect how pixel colors are blended.
 *
 * Premultiplication refers to the process of multiplying the RGB components of a pixel by its alpha component
 * before performing any operations that blend this pixel with another. This approach is often used in graphics
 * processing for efficiency and to avoid rendering artifacts.
 *
 * The function performs several key steps:
 * 1. Validates the provided CGImageRef to ensure it is not NULL.
 * 2. Allocates memory for raw pixel data, ensuring there's enough space based on the image's dimensions.
 * 3. Creates a Device RGB color space to interpret the image's colors.
 * 4. Sets up a bitmap context with specific parameters including bit depth, bytes per row, color space, and bitmap info
 *    flags that indicate premultiplied first alpha and the byte order.
 * 5. Draws the provided CGImage into the newly created bitmap context.
 * 6. Applies a custom "enhanced fuzzing" algorithm to the pixel data, intended to modify the image's appearance.
 * 7. Creates a new CGImage from the modified bitmap context, converts it to a UIImage, and saves it with a specific label.
 * 8. Cleans up allocated resources including the bitmap context and raw pixel data.
 *
 * Parameters:
 * - cgImg: The CGImageRef representing the image to be processed. This image is the source for the bitmap context.
 *
 * Note: This function includes diagnostic logging at various stages to assist with debugging and validation of the
 * processing steps. It also has commented-out calls to a hypothetical `debugMemoryHandling` function, suggesting
 * a mechanism was considered (or is available) for tracking memory allocation and release during development.
 */
void createBitmapContextPremultipliedFirstAlpha(CGImageRef cgImg) {
    NSLog(@"Creating bitmap context with Premultiplied First Alpha settings");

//    debugMemoryHandling();

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
//        debugMemoryHandling();
        return;
    }

    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    if (!colorSpace) {
        NSLog(@"Failed to create color space");
        free(rawData);
//        debugMemoryHandling();
        return;
    }

    CGBitmapInfo bitmapInfo = kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Big;
    CGContextRef ctx = CGBitmapContextCreate(rawData, width, height, 8, bytesPerRow, colorSpace, bitmapInfo);

    CGColorSpaceRelease(colorSpace);

    if (!ctx) {
        NSLog(@"Failed to create bitmap context");
        free(rawData);
//        debugMemoryHandling();
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
//    debugMemoryHandling();
}

#pragma mark - createBitmapContextNonPremultipliedAlpha

/**
 * Creates a bitmap graphics context with Non-Premultiplied Alpha settings for processing a CGImage.
 * This function is aimed at handling images where the alpha channel is not premultiplied into the color channels.
 * Non-premultiplied alpha can be beneficial for certain types of image processing where direct manipulation of
 * the alpha channel is required or where the premultiplication could lead to loss of quality or detail.
 *
 * The function encompasses the following main activities:
 * 1. Checks the validity of the provided CGImageRef, ensuring it's not NULL.
 * 2. Calculates the necessary dimensions and allocates memory for the raw pixel data, based on the image's size.
 * 3. Initiates a Device RGB color space for the bitmap context to interpret the image's colors accurately.
 * 4. Sets up the bitmap context with a specific configuration that excludes premultiplication of the alpha channel,
 *    using the bitmap info flags to specify the alpha handling and byte order.
 * 5. Renders the provided CGImage into the bitmap context, capturing the image's raw pixel data.
 * 6. Applies a specified "enhanced fuzzing" process to the bitmap's data, potentially modifying the image based
 *    on custom logic designed to alter its appearance or attributes.
 * 7. Generates a new CGImage from the context, encapsulates it into a UIImage, and saves this modified image,
 *    marking it with an identifier that denotes the non-premultiplied alpha processing.
 * 8. Releases all allocated resources, including the bitmap context and the raw data buffer, to avoid memory leaks.
 *
 * Parameters:
 * - cgImg: A CGImageRef that represents the source image to be processed. This image's data is used to populate
 *          the newly created bitmap context.
 *
 * Note: This function includes logging at critical steps for debugging purposes and has placeholders for memory
 * diagnostics to assist with development and troubleshooting. These diagnostic points, commented out, suggest
 * potential locations for memory management checks or debugging output.
 */
void createBitmapContextNonPremultipliedAlpha(CGImageRef cgImg) {
    NSLog(@"Creating bitmap context with Non-Premultiplied Alpha settings");

    // Pre-operation memory diagnostic
//    debugMemoryHandling();

    if (!cgImg) {
        NSLog(@"Invalid CGImageRef provided.");
        return;
    }

    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    size_t bytesPerRow = width * 4; // RGBA format

    // Allocate memory for raw image data
    unsigned char *rawData = (unsigned char *)calloc(height * bytesPerRow, sizeof(unsigned char));
    if (!rawData) {
        NSLog(@"Failed to allocate memory for image processing");
//        debugMemoryHandling(); // Post-failure diagnostic
        return;
    }

    // Create a color space for the bitmap context
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    if (!colorSpace) {
        NSLog(@"Failed to create color space");
        free(rawData);
//        debugMemoryHandling(); // Diagnostic before early exit
        return;
    }

    // Define bitmap info with non-premultiplied alpha
    CGBitmapInfo bitmapInfo = kCGImageAlphaNoneSkipLast | kCGBitmapByteOrder32Big;
    CGContextRef ctx = CGBitmapContextCreate(rawData, width, height, 8, bytesPerRow, colorSpace, bitmapInfo);
    CGColorSpaceRelease(colorSpace);

    if (!ctx) {
        NSLog(@"Failed to create bitmap context");
        free(rawData);
//        debugMemoryHandling(); // Diagnostic if context creation fails
        return;
    }

    // Draw the CGImage into the bitmap context
    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImg);

    // Apply fuzzing logic directly to the bitmap's raw data
    NSLog(@"Applying enhanced fuzzing logic to the bitmap context with non-premultiplied alpha");
    applyEnhancedFuzzingToBitmapContext(rawData, width, height, YES); // Assuming verbose logging is desired

    // Create a new image from the modified context
    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg);

        // Save the fuzzed image with a context-specific identifier
        saveFuzzedImage(newImage, @"non_premultiplied_alpha");

        NSLog(@"Modified UIImage with non-premultiplied alpha created and saved successfully.");
    }

    // Cleanup
    CGContextRelease(ctx);
    free(rawData);
//    debugMemoryHandling(); // Post-operation diagnostic
}

#pragma mark - createBitmapContext16BitDepth

/**
 * Creates a bitmap graphics context specifically configured for 16-bit depth per channel.
 * This enhanced color depth allows for a much broader range of colors and gradients,
 * significantly reducing banding and other artifacts that can occur with lower color depths.
 * It is particularly useful in high-quality image processing, editing, or any application
 * where maintaining the highest possible fidelity of color information is important.
 *
 * The function follows these steps:
 * 1. Validates the input CGImageRef to ensure it's not NULL, logging an error if it is.
 * 2. Retrieves the width and height of the input image to calculate the necessary dimensions
 *    for the bitmap context and the buffer to hold the raw image data.
 * 3. Allocates a memory buffer for the image's raw pixel data, considering the increased memory
 *    requirements of 16-bit depth per channel (8 bytes per pixel for RGBA).
 * 4. Creates a Device RGB color space for accurate color representation within the context.
 * 5. Sets up the bitmap context with a configuration that supports 16-bit depth per color channel,
 *    including premultiplied alpha for consistent alpha blending.
 * 6. Renders the input CGImage into the newly created bitmap context, capturing the image in a
 *    format that supports the high color depth.
 * 7. Applies a custom "enhanced fuzzing" process to the bitmap's data, potentially altering the
 *    image for specific effects or analysis, with an assumption of verbose logging for diagnostic purposes.
 * 8. Generates a new CGImage from the modified bitmap context and encapsulates it into a UIImage,
 *    then saves this modified image with an identifier highlighting its 16-bit depth processing.
 * 9. Releases all allocated resources, including the bitmap context and the raw data buffer, to
 *    prevent memory leaks and ensure clean operation.
 *
 * Parameters:
 * - cgImg: A CGImageRef representing the source image to be processed within the 16-bit depth bitmap context.
 *
 * Note: This function includes strategic logging for critical steps and errors, as well as placeholders
 * for memory diagnostics (commented out), suggesting points where memory management and debugging checks
 * could be beneficial, especially given the higher memory usage associated with 16-bit depth processing.
 */
void createBitmapContext16BitDepth(CGImageRef cgImg) {
    NSLog(@"Creating bitmap context with 16-bit depth per channel");

    // Pre-operation memory diagnostic
//    debugMemoryHandling();

    if (!cgImg) {
        NSLog(@"Invalid CGImageRef provided.");
        return;
    }

    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    // Considering 8 bytes per pixel (2 bytes per component * 4 components: RGBA)
    size_t bytesPerRow = width * 8;

    // Allocate memory for raw image data
    unsigned char *rawData = (unsigned char *)calloc(height * bytesPerRow, sizeof(unsigned char));
    if (!rawData) {
        NSLog(@"Failed to allocate memory for image processing");
//        debugMemoryHandling(); // Post-failure diagnostic
        return;
    }

    // Create a color space for the bitmap context
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    if (!colorSpace) {
        NSLog(@"Failed to create color space");
        free(rawData);
//        debugMemoryHandling(); // Diagnostic before early exit
        return;
    }

    // Define bitmap info for 16-bit depth per channel
    CGBitmapInfo bitmapInfo = kCGImageAlphaPremultipliedLast | kCGBitmapByteOrderDefault;
    CGContextRef ctx = CGBitmapContextCreate(rawData, width, height, 16, bytesPerRow, colorSpace, bitmapInfo);
    CGColorSpaceRelease(colorSpace);

    if (!ctx) {
        NSLog(@"Failed to create bitmap context");
        free(rawData);
//        debugMemoryHandling(); // Diagnostic if context creation fails
        return;
    }

    // Draw the CGImage into the bitmap context
    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImg);

    // Apply fuzzing logic directly to the bitmap's raw data
    NSLog(@"Applying enhanced fuzzing logic to the bitmap context with 16-bit depth");
    applyEnhancedFuzzingToBitmapContext(rawData, width, height, YES); // Assuming verbose logging is desired

    // Create a new image from the modified context
    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg);

        // Save the fuzzed image with a context-specific identifier
        saveFuzzedImage(newImage, @"16bit_depth");

        NSLog(@"Modified UIImage with 16-bit depth created and saved successfully.");
    }

    // Cleanup
    CGContextRelease(ctx);
    free(rawData);
//    debugMemoryHandling(); // Post-operation diagnostic
}

#pragma mark - createBitmapContextGrayscale

void createBitmapContextGrayscale(CGImageRef cgImg) {
    NSLog(@"Grayscale image processing is not yet implemented.");
    // No further processing or memory allocations
}

#pragma mark - createBitmapContextHDRFloatComponents

/**
 * Initializes a bitmap context optimized for HDR (High Dynamic Range) content with floating-point components,
 * enabling precise manipulation of image data across a wide luminance range. This setup is critical for
 * processing images with extended color and brightness information, far beyond what is possible with standard
 * 8-bit or even 16-bit per channel formats.
 *
 * The function executes the following operations:
 * 1. Validates the CGImage reference input to ensure it's not NULL.
 * 2. Calculates the image dimensions and allocates a memory buffer for the floating-point raw data,
 *    considering the substantial data size required for HDR processing (16 bytes per pixel).
 * 3. Creates an HDR-compatible color space (`kCGColorSpaceExtendedLinearSRGB`), specifically designed
 *    to handle the broader gamut and luminance levels of HDR images.
 * 4. Sets up the bitmap context with 32 bits per component, using floating-point values for each color
 *    and alpha channel, thereby allowing for the nuanced representation of HDR content.
 * 5. Renders the input CGImage into this context, capturing it in a format that supports HDR's high precision.
 * 6. Applies a custom fuzzing process to the bitmap's data. This example utilizes a mechanism to cycle
 *    through predefined strings, altering the image based on these strings to test or demonstrate specific
 *    effects. This process is indicative of the function's potential use in dynamic image manipulation experiments.
 * 7. Generates a new CGImage from the context and creates a UIImage object from this, allowing for further
 *    use within UIKit applications.
 * 8. Saves the processed image using a utility function, tagging it with a context-relevant identifier.
 * 9. Releases all allocated resources, including the color space and the bitmap context, as well as the
 *    allocated buffer for raw data, ensuring no memory leaks occur.
 *
 * Parameters:
 * - cgImg: A CGImageRef representing the source image to be processed in the HDR bitmap context.
 *
 * Note: The function assumes that enhanced fuzzing and the selection of injection strings are part of a larger
 * testing or image processing workflow. It uses a static index to cycle through a set of predefined strings,
 * demonstrating how different data or parameters might influence the fuzzing process in a repeatable manner.
 */
void createBitmapContextHDRFloatComponents(CGImageRef cgImg) {
    NSLog(@"Creating bitmap context with HDR and floating-point components");

    if (!cgImg) {
        NSLog(@"Invalid CGImageRef provided.");
        return;
    }

    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    size_t bytesPerRow = width * 16; // Considering 16 bytes per pixel for HDR

    // Allocate memory for raw image data
    float *rawData = (float *)calloc(height * bytesPerRow, sizeof(float));
    if (!rawData) {
        NSLog(@"Failed to allocate memory for image processing");
        return;
    }

    CGColorSpaceRef colorSpace = CGColorSpaceCreateWithName(kCGColorSpaceExtendedLinearSRGB);
    if (!colorSpace) {
        NSLog(@"Failed to create HDR color space");
        free(rawData);
        return;
    }

    CGBitmapInfo bitmapInfo = kCGImageAlphaPremultipliedLast | kCGBitmapFloatComponents | kCGBitmapByteOrder32Little;
    CGContextRef ctx = CGBitmapContextCreate(rawData, width, height, 32, bytesPerRow, colorSpace, bitmapInfo);
    CGColorSpaceRelease(colorSpace);

    if (!ctx) {
        NSLog(@"Failed to create bitmap context for HDR");
        free(rawData);
        return;
    }

    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImg);

    NSLog(@"Applying enhanced fuzzing logic to the HDR bitmap context");

    // Cycle through injection strings or select based on specific criteria
    static int currentStringIndex = 0; // Example: simple cycling mechanism
    applyEnhancedFuzzingToBitmapContextWithFloats(rawData, width, height, YES, currentStringIndex);
    currentStringIndex = (currentStringIndex + 1) % NUMBER_OF_STRINGS; // Move to the next string for the next call

    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from HDR context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg);

        saveFuzzedImage(newImage, @"hdr_float");
        NSLog(@"Modified UIImage with HDR and floating-point components created and saved successfully.");
    }

    CGContextRelease(ctx);
    free(rawData);
}

#pragma mark - createBitmapContextAlphaOnly

/**
 * Creates and manipulates a bitmap context specifically for the alpha channel of an input CGImageRef. This function
 * is tailored for applications that need to isolate, examine, or modify the transparency information of images without
 * affecting their color data. It's particularly useful in graphics editing applications, custom rendering processes,
 * or any scenario where managing image transparency is a requirement.
 *
 * The function performs the following operations:
 * 1. Validates the input CGImageRef to ensure it is not NULL and suitable for processing.
 * 2. Retrieves the dimensions of the input image to accurately configure the bitmap context.
 * 3. Allocates memory dedicated to storing the alpha channel data, with one byte per pixel representing opacity levels.
 * 4. Creates a bitmap context without a color space since color information is irrelevant for this operation, focusing solely on alpha data.
 * 5. Draws the input image into the newly created context, effectively extracting the alpha channel information.
 * 6. Applies a custom "fuzzing" logic to the alpha data, which could involve modifying transparency values to achieve various effects or to stress-test the image processing pipeline.
 * 7. Releases the allocated resources, including the bitmap context and the alpha data array, to prevent memory leaks.
 *
 * Parameters:
 * - cgImg: A CGImageRef representing the source image from which the alpha channel will be extracted and processed.
 *
 * Implementation Notes:
 * - The function assumes that the input image already contains an alpha channel. If the source image lacks transparency, the resulting alpha data might not be meaningful.
 * - The 'applyEnhancedFuzzingToBitmapContextAlphaOnly' function, referenced within, must be designed to handle alpha data specifically. This could involve adjusting opacity levels in a manner that tests the resilience of image processing algorithms or enhances the visual aesthetics of the alpha channel.
 * - Creating a new image from the processed alpha data isn't straightforward, as this function only deals with transparency information. Utilizing the modified alpha channel effectively may require combining it with color data from another image or using it as a mask.
 * - The commented-out 'debugMemoryHandling' calls suggest points where memory diagnostics could be performed to ensure efficient resource management, especially important in environments with limited memory availability.
 *
 * This approach to handling the alpha channel separately from color data enables precise control over transparency effects, providing a foundation for advanced image manipulation techniques.
 */
void createBitmapContextAlphaOnly(CGImageRef cgImg) {
    NSLog(@"Creating bitmap context for Alpha channel only");

    // Pre-operation memory diagnostic
//    debugMemoryHandling();

    if (!cgImg) {
        NSLog(@"Invalid CGImageRef provided.");
        return;
    }

    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    size_t bytesPerRow = width; // 1 byte per pixel for Alpha only

    // Allocate memory for raw alpha data
    unsigned char *alphaData = (unsigned char *)calloc(height * bytesPerRow, sizeof(unsigned char));
    if (!alphaData) {
        NSLog(@"Failed to allocate memory for alpha channel processing");
//        debugMemoryHandling(); // Post-failure diagnostic
        return;
    }

    // Since we're dealing with alpha only, no color space is required
    // Adjusting bitmap info to accommodate alpha data correctly
    CGBitmapInfo bitmapInfo = kCGImageAlphaOnly | kCGBitmapByteOrderDefault;

    CGContextRef ctx = CGBitmapContextCreate(alphaData, width, height, 8, bytesPerRow, NULL, bitmapInfo);

    if (!ctx) {
        NSLog(@"Failed to create bitmap context for Alpha channel");
        free(alphaData);
//        debugMemoryHandling(); // Diagnostic if context creation fails
        return;
    }

    // Drawing the alpha channel into the context
    // Assuming the cgImg already contains the alpha channel we want to process
    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImg);

    // Apply fuzzing logic directly to the alpha data
    NSLog(@"Applying enhanced fuzzing logic to the Alpha-only bitmap context");
    // Note: The applyEnhancedFuzzingToBitmapContext function needs to be adjusted to work with alphaData
    applyEnhancedFuzzingToBitmapContextAlphaOnly(alphaData, width, height, YES); // Assuming verbose logging is desired

    // Creating a new image from the modified context might not be directly applicable
    // as we're dealing with alpha channel only. Further processing might be required
    // to utilize this alpha data with another image or for masking.

    // Cleanup and resource management
    CGContextRelease(ctx);
    free(alphaData);
//    debugMemoryHandling(); // Post-operation diagnostic

    NSLog(@"Alpha-only bitmap context processing completed.");
}

#pragma mark - createBitmapContext1BitMonochrome

/**
 * Creates and processes a bitmap context for a 1-bit monochrome image from an input CGImageRef. This function is
 * designed for scenarios requiring the conversion of color or grayscale images to monochrome (black and white)
 * representations using only 1 bit per pixel. This process significantly reduces the image's data size, making it
 * ideal for low-bandwidth or memory-constrained environments, or for achieving a specific stylistic effect.
 *
 * The operation sequence includes:
 * 1. Validating the input CGImageRef to ensure it's not NULL.
 * 2. Determining the dimensions of the input image to set up the bitmap context appropriately.
 * 3. Calculating the minimum bytes per row needed for 1-bit representation, adjusting for byte-alignment.
 * 4. Creating a bitmap context with no color space (since it's monochrome) and no alpha channel.
 * 5. Initializing the bitmap with a white background to ensure a consistent base for monochrome conversion.
 * 6. Drawing the input image into this context, which implicitly converts the image to a 1-bit color depth based on
 *    current color values and the context's drawing operations.
 * 7. Directly manipulating the bitmap data to apply or refine the monochrome conversion process, if necessary.
 * 8. Generating a new CGImage from the context, encapsulating the monochrome conversion result.
 * 9. Creating a UIImage from the new CGImage for easy integration with UIKit-based interfaces or further processing.
 * 10. Optionally saving the monochrome image with an identifying tag, facilitating storage or retrieval in application-specific contexts.
 * 11. Releasing all allocated resources, including the bitmap context, to prevent memory leaks.
 *
 * Parameters:
 * - cgImg: A CGImageRef representing the source image for conversion to 1-bit monochrome.
 *
 * Note: The conversion process might include specific optimizations or adjustments tailored to the characteristics
 * of the input image or desired output qualities. This function demonstrates a straightforward approach to monochrome
 * conversion, but more sophisticated techniques could be applied within the `convertTo1BitMonochrome` operation to
 * handle nuances like dithering, contrast adjustment, or edge enhancement, depending on application requirements.
 */
void createBitmapContext1BitMonochrome(CGImageRef cgImg) {
    if (!cgImg) {
        NSLog(@"Invalid CGImageRef provided.");
        return;
    }

    NSLog(@"Creating bitmap context with 1-bit Monochrome settings");

    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    // Calculate bytes per row for 1 bit per pixel, rounded up to the nearest byte
    size_t bytesPerRow = (width + 7) / 8; // Round up to account for partial bytes
    CGContextRef ctx = CGBitmapContextCreate(NULL, width, height, 1, bytesPerRow, NULL, kCGImageAlphaNone);
    if (!ctx) {
        NSLog(@"Failed to create bitmap context with 1-bit Monochrome settings");
        return;
    }

    // Set the fill color to white and fill the context to start with a blank slate
    CGContextSetFillColorWithColor(ctx, [UIColor whiteColor].CGColor);
    CGContextFillRect(ctx, CGRectMake(0, 0, width, height));

    // Draw the CGImage into the bitmap context, adjusting it to fit the 1-bit color depth
    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImg);

    // Access the raw pixel data
    unsigned char *rawData = CGBitmapContextGetData(ctx);
    if (rawData) {
        NSLog(@"Converting bitmap data to 1-bit Monochrome");
        convertTo1BitMonochrome(rawData, width, height);
    }

    // Create a new image from the modified context
    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from 1-bit Monochrome context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg); // Release the created CGImage

        // Save the monochrome image with a context-specific identifier
        saveMonochromeImage(newImage, @"1Bit_Monochrome");
        NSLog(@"Modified UIImage with 1-bit Monochrome settings created and saved successfully.");
    }

    NSLog(@"Bitmap context with 1-bit Monochrome settings created and handled successfully");
    CGContextRelease(ctx);
}

#pragma mark - createBitmapContextBigEndian

/**
 * Creates a bitmap context with Big Endian settings and applies enhanced fuzzing logic to the image data.
 *
 * This function initiates by validating the provided CGImageRef to ensure it's not null. It proceeds
 * to create a color space suitable for RGB data manipulation and sets up a bitmap context with Big Endian
 * byte ordering. The main purpose of specifying Big Endian format is to ensure that the most significant byte
 * comes first in the memory representation of each pixel's color data, which is crucial for consistency in
 * systems or applications where this byte order is expected.
 *
 * After drawing the original CGImage into the bitmap context, the function accesses the raw pixel data to
 * apply a specific "enhanced fuzzing logic." This step is designed to alter pixel values in a way that can test
 * the resilience of image processing algorithms, simulate various visual effects, or introduce artistic noise.
 * Once the pixel manipulation is complete, a new CGImage is created from the context to encapsulate the modifications.
 *
 * The function concludes by releasing allocated resources, such as the color space and bitmap context, to ensure
 * responsible memory management. The modified image is then saved with a unique identifier, marking the end of
 * the transformation process. This documentation block provides an overview of the function's workflow and its
 * purpose in the broader context of image processing and manipulation.
 *
 * @param cgImg The CGImageRef representing the original image to be processed. Must not be NULL.
 *
 */
void createBitmapContextBigEndian(CGImageRef cgImg) {
    if (!cgImg) {
        NSLog(@"Invalid CGImageRef provided.");
        return;
    }

    NSLog(@"Creating bitmap context with Big Endian settings");

    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB(); // Create color space
    if (!colorSpace) {
        NSLog(@"Failed to create color space for Big Endian settings");
        return;
    }

    CGContextRef ctx = CGBitmapContextCreate(NULL, width, height, 8, width * 4, colorSpace, kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    CGColorSpaceRelease(colorSpace); // Release the color space object

    if (!ctx) {
        NSLog(@"Failed to create bitmap context with Big Endian settings");
        return;
    }

    // Draw the CGImage into the bitmap context
    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImg);

    // Access the raw pixel data
    unsigned char *rawData = CGBitmapContextGetData(ctx);
    if (rawData) {
        NSLog(@"Applying enhanced fuzzing logic to the Big Endian bitmap context");
        applyEnhancedFuzzingToBitmapContext(rawData, width, height, YES);
    }

    // Create a new image from the modified context
    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from Big Endian context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg); // Release the created CGImage

        // Save the fuzzed image with a context-specific identifier
        saveFuzzedImage(newImage, @"Big_Endian");
        NSLog(@"Modified UIImage with Big Endian settings created and saved successfully.");
    }

    NSLog(@"Bitmap context with Big Endian settings created and handled successfully");
    CGContextRelease(ctx); // Release the bitmap context
}

#pragma mark - createBitmapContextLittleEndian

/**
 * Initializes and manages a bitmap graphics context with Little Endian settings for a given CGImageRef,
 * applying enhanced fuzzing logic to the pixel data. The process involves creating a specific color space
 * for RGB data, establishing a bitmap context with settings optimized for Little Endian byte ordering,
 * and manipulating the image's pixel data through a predefined fuzzing algorithm. The function concludes
 * by creating a new CGImage from the context, encapsulating the modifications, and saving the resulting
 * image with a designated identifier.
 *
 * The Little Endian format dictates that the least significant byte is stored first in memory. This setting
 * is vital for compatibility with systems and applications that expect this byte order. By drawing the original
 * image into the context and then accessing the raw pixel data, the function allows for direct manipulation of
 * the image's pixels according to the "enhanced fuzzing logic," which is intended to test image processing algorithms,
 * generate artistic effects, or simulate visual distortions.
 *
 * Proper resource management practices are followed to ensure efficient memory usage, including the release
 * of the color space and bitmap context upon completion of the task. The function highlights the integration
 * of external routines for the fuzzing logic and image saving process, necessitating the implementation of
 * these methods elsewhere within the application's codebase.
 *
 * @param cgImg A CGImageRef that represents the image to be transformed. The parameter must not be NULL.
 *
 */
void createBitmapContextLittleEndian(CGImageRef cgImg) {
    if (!cgImg) {
        NSLog(@"Invalid CGImageRef provided.");
        return;
    }

    NSLog(@"Creating bitmap context with Little Endian settings");

    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB(); // Create color space
    if (!colorSpace) {
        NSLog(@"Failed to create color space for Little Endian settings");
        return;
    }

    CGContextRef ctx = CGBitmapContextCreate(NULL, width, height, 8, width * 4, colorSpace, kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
    CGColorSpaceRelease(colorSpace); // Release the color space object

    if (!ctx) {
        NSLog(@"Failed to create bitmap context with Little Endian settings");
        return;
    }

    // Draw the CGImage into the bitmap context
    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImg);

    // Access the raw pixel data
    unsigned char *rawData = CGBitmapContextGetData(ctx);
    if (rawData) {
        NSLog(@"Applying enhanced fuzzing logic to the Little Endian bitmap context");
        applyEnhancedFuzzingToBitmapContext(rawData, width, height, YES);
    }

    // Create a new image from the modified context
    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from Little Endian context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg); // Release the created CGImage

        // Save the fuzzed image with a context-specific identifier
        saveFuzzedImage(newImage, @"Little_Endian");
        NSLog(@"Modified UIImage with Little Endian settings created and saved successfully.");
    }

    NSLog(@"Bitmap context with Little Endian settings created successfully");
    CGContextRelease(ctx); // Release the bitmap context
}

#pragma mark - createBitmapContext8BitInvertedColors

/**
 * Creates and manipulates a bitmap graphics context specifically for processing a given CGImageRef
 * to invert its colors and apply an 8-bit color depth format. This function is designed to transform
 * the image's color representation by inverting the RGB values of each pixel, while preserving the alpha channel
 * untouched, and further applies an "enhanced fuzzing logic" to the modified pixel data. The inversion process
 * converts each color component to its complementary color, creating a visual negative of the original image.
 * This method can be particularly useful for creating visual effects, enhancing the contrast for certain image
 * processing applications, or testing the robustness of image processing algorithms.
 *
 * The function sets up a bitmap context with parameters tailored for the inversion effect, including the use
 * of a specific byte order and alpha channel handling. It iterates over the raw pixel data to invert the colors
 * manually and calls an external routine for enhanced fuzzing, indicating a customization point for additional
 * pixel manipulation. The process culminates in the creation of a new CGImage from the context, encapsulating
 * all modifications, and the saving of this new image with an appropriate identifier.
 *
 * Resource management practices are observed to ensure the efficient use of memory, with explicit release
 * calls for allocated objects. The function's reliance on external methods for fuzzing and saving the image
 * necessitates their implementation elsewhere within the application's codebase.
 *
 * @param cgImg A CGImageRef representing the source image to be transformed. The parameter must not be NULL.
 *
 */
void createBitmapContext8BitInvertedColors(CGImageRef cgImg) {
    if (!cgImg) {
        NSLog(@"Invalid CGImageRef provided.");
        return;
    }

    NSLog(@"Creating bitmap context with 8-bit depth, inverted colors");

    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB(); // Create color space
    if (!colorSpace) {
        NSLog(@"Failed to create color space for 8-bit depth, inverted colors");
        return;
    }

    CGContextRef ctx = CGBitmapContextCreate(NULL, width, height, 8, width * 4, colorSpace, kCGImageAlphaNoneSkipLast | kCGBitmapByteOrder32Little);
    CGColorSpaceRelease(colorSpace); // Release the color space object

    if (!ctx) {
        NSLog(@"Failed to create bitmap context with 8-bit depth, inverted colors");
        return;
    }

    // Draw the CGImage into the bitmap context
    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImg);

    // Access the raw pixel data
    unsigned char *rawData = CGBitmapContextGetData(ctx);
    if (rawData) {
        // Invert colors for each pixel
        for (size_t i = 0; i < width * height * 4; i += 4) {
            rawData[i] = 255 - rawData[i]; // Invert Red
            rawData[i + 1] = 255 - rawData[i + 1]; // Invert Green
            rawData[i + 2] = 255 - rawData[i + 2]; // Invert Blue
            // Alpha is skipped
        }

        // Apply enhanced fuzzing with string injection logic
        applyEnhancedFuzzingToBitmapContext(rawData, width, height, YES);
    }

    // Create a new image from the modified context
    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from 8-bit depth, inverted colors");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg); // Release the created CGImage

        // Save the fuzzed image with a specific identifier
        saveFuzzedImage(newImage, @"8Bit_InvertedColors");
        NSLog(@"Modified UIImage with createBitmapContext8BitInvertedColors settings created and saved successfully.");
    }

    CGContextRelease(ctx); // Release the bitmap context
}

#pragma mark - createBitmapContext32BitFloat4Component

/**
 * Creates a bitmap graphics context optimized for high dynamic range (HDR) image processing with 32-bit
 * floating-point precision for each component in the RGBA color model. This function configures a bitmap context
 * to support advanced image manipulation techniques that require the extended range and precision provided
 * by floating-point calculations. It is particularly useful for applications involving color grading,
 * exposure adjustments, or any scenario where the nuances of high-fidelity image data are critical.
 *
 * Upon successful creation of the context, the source CGImage is drawn into this specialized context,
 * allowing for subsequent image processing operations that leverage the full capabilities of 32-bit
 * floating-point components. This setup facilitates the application of complex algorithms, including
 * "enhanced fuzzing logic," which introduces controlled perturbations to the image data for testing or
 * artistic purposes. The function demonstrates an approach to iterating over predefined strings, each
 * potentially corresponding to different fuzzing strategies or parameters, thereby illustrating a method
 * for dynamic manipulation based on external criteria.
 *
 * Following the application of image processing routines, the function generates a new CGImage from
 * the modified bitmap context. This image is then saved with a unique identifier, showcasing the end-to-end
 * workflow from source image manipulation to storage of the resultant image. Essential cleanup and resource
 * management steps ensure the efficient use of system resources.
 *
 * @param cgImg A CGImageRef representing the source image to be processed. Must not be NULL.
 *
 */
void createBitmapContext32BitFloat4Component(CGImageRef cgImg) {
    if (!cgImg) {
        NSLog(@"Invalid CGImageRef provided.");
        return;
    }

    NSLog(@"Creating bitmap context with 32-bit float, 4-component settings");

    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    // Considering 16 bytes per pixel (4 components: RGBA, each with 32-bit float)
    size_t bytesPerRow = width * 4 * sizeof(float);

    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    if (!colorSpace) {
        NSLog(@"Failed to create color space");
        return;
    }

    CGBitmapInfo bitmapInfo = kCGImageAlphaPremultipliedLast | kCGBitmapFloatComponents;
    CGContextRef ctx = CGBitmapContextCreate(NULL, width, height, 32, bytesPerRow, colorSpace, bitmapInfo);
    CGColorSpaceRelease(colorSpace); // Release the color space as it's no longer needed

    if (!ctx) {
        NSLog(@"Failed to create bitmap context with 32-bit float, 4-component settings");
        return;
    }

    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImg);

    NSLog(@"Applying enhanced fuzzing logic to the bitmap context");

    // Cycle through injection strings or select based on specific criteria
    static int currentStringIndex = 0; // Example: simple cycling mechanism
    applyEnhancedFuzzingToBitmapContextWithFloats((float*)CGBitmapContextGetData(ctx), width, height, YES, currentStringIndex);
    currentStringIndex = (currentStringIndex + 1) % NUMBER_OF_STRINGS; // Move to the next string for the next call

    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg); // Release the created CGImage

        saveFuzzedImage(newImage, @"32bit_float4");
        NSLog(@"Modified UIImage with 32-bit float, 4-component settings created and saved successfully.");
    }

    CGContextRelease(ctx); // Release the context to free up resources
}
