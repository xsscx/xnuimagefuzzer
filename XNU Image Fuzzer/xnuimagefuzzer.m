/*!
 *  @file xnuimagefuzzer.m
 *  @brief XNU Image Fuzzer
 *  @author David Hoyt
 *  @date 01 JUN 2024
 *  @version 1.8.1
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *  @section CHANGES
 *  - 26/11/2023, h02332: Initial commit
 *  - 21/02/2024, h02332: Refactor Programming Mistakes
 *  - 21/02/2024, h02332: PermaLink https://srd.cx/xnu-image-fuzzer/
 *  - 01/06/2024, h02332: Syntax Changes for Documentation Tools
 *
 *  @section ROADMAP
 *  - Grayscale Implementation
 *  - ICC Color Profiles ✅ Implemented: ICC profile embedding, color space diversity
 *  - Iteration Chaining ✅ Implemented: Multi-pass fuzzing with varied mutations
 *  - Output Metrics ✅ Implemented: File size, entropy, histogram, provenance naming
 */

#pragma mark - Headers

/*!
* @brief Core and external libraries necessary for the fuzzer functionality.
*
* @details This section includes the necessary headers for the Foundation framework, UIKit, Core Graphics,
* standard input/output, standard library, memory management, mathematical functions,
* Boolean type, floating-point limits, and string functions. These libraries support
* image processing, UI interaction, and basic C operations essential for the application.
*/
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import "AppDelegate.h"
#import <os/log.h>
#import <os/signpost.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <math.h>
#include <stdbool.h>
#include <float.h>
#include <string.h>
#include <stdint.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <dirent.h>
#include <CommonCrypto/CommonDigest.h>
#import <ImageIO/ImageIO.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h> // For UTTypePNG

// LLVM coverage runtime — resolved at runtime via dlsym to avoid linker errors
// when building without -fprofile-instr-generate
typedef int (*llvm_profile_write_file_fn)(void);
typedef void (*llvm_profile_set_filename_fn)(const char *);

#pragma mark - Verbose Logging

static int verboseLogging = 0; // 1 enables detailed logging, 0 disables it.

#pragma mark - Constants

/*!
 * @brief Defines constants for general application configuration.
 *
 * This section includes definitions for constants used throughout the application to control its behavior and configuration. These constants are pivotal for ensuring the application operates within defined parameters and accesses system resources correctly.
 *
 * - `ALL`: A special flag used to indicate an operation applies to all items or states. Useful for functions that require a broad application of their logic.
 * - `MAX_PERMUTATION`: Defines the upper limit on the number of permutations that can be applied in image processing tasks. This constant helps in preventing excessive processing time and resource consumption.
 * - `COMM_PAGE64_BASE_ADDRESS`: The base memory address for the comm page, which is a reserved area of memory used by the system to store variables that are accessed frequently.
 * - `COMM_PAGE_CPU_CAPABILITIES64`: An offset from `COMM_PAGE64_BASE_ADDRESS` that points to the CPU capabilities. Useful for quickly determining the hardware capabilities of the system.
 *
 * ## Example Usage:
 * @code
 * if (operationMode == ALL) {
 *     // Apply operation to all items
 * }
 *
 * int permutations = MAX_PERMUTATION;
 * uint64_t commPageAddress = COMM_PAGE64_BASE_ADDRESS;
 * uint64_t cpuCapabilitiesAddress = COMM_PAGE_CPU_CAPABILITIES64;
 * @endcode
 *
 * @note These constants are designed to be used across various components of the application, providing a centralized point of reference for important values and system parameters.
 */
#define ALL -1 // Special flag for operations applicable to all items or states.
#define MAX_PERMUTATION 15 // Maximum permutations in image processing.
#define MAX_ITERATIONS 10 // Default max chained fuzzing iterations.
#define NUM_NAMED_COLORSPACES 7 // Named color spaces for diversity permutations.
#ifdef __arm64__
#define COMM_PAGE64_BASE_ADDRESS        (0x0000000FFFFFC000ULL)
#elif defined(__x86_64__)
#define COMM_PAGE64_BASE_ADDRESS        (0x00007fffffe00000ULL)
#else
#define COMM_PAGE64_BASE_ADDRESS        (0x0000000FFFFFC000ULL)
#endif

#define COMM_PAGE_CPU_CAPABILITIES64    (COMM_PAGE64_BASE_ADDRESS + 0x010)
#define COMM_PAGE_VERSION               (COMM_PAGE64_BASE_ADDRESS + 0x01E)
#define COMM_PAGE_NCPUS                 (COMM_PAGE64_BASE_ADDRESS + 0x022)
#define COMM_PAGE_CACHE_LINESIZE        (COMM_PAGE64_BASE_ADDRESS + 0x026)
#define COMM_PAGE_SCHED_GEN             (COMM_PAGE64_BASE_ADDRESS + 0x028)
#define COMM_PAGE_MEMORY_PRESSURE       (COMM_PAGE64_BASE_ADDRESS + 0x02c)
#define COMM_PAGE_SPIN_COUNT            (COMM_PAGE64_BASE_ADDRESS + 0x030)
#define COMM_PAGE_KDEBUG_ENABLE         (COMM_PAGE64_BASE_ADDRESS + 0x044)
#define COMM_PAGE_ATM_DIAGNOSTIC_CONFIG (COMM_PAGE64_BASE_ADDRESS + 0x048)
#define COMM_PAGE_BOOTTIME_USEC         (COMM_PAGE64_BASE_ADDRESS + 0x0C8)
#define COMM_PAGE_ACTIVE_CPUS           (COMM_PAGE64_BASE_ADDRESS + 0x034)
#define COMM_PAGE_PHYSICAL_CPUS         (COMM_PAGE64_BASE_ADDRESS + 0x035)
#define COMM_PAGE_LOGICAL_CPUS          (COMM_PAGE64_BASE_ADDRESS + 0x036)
#define COMM_PAGE_MEMORY_SIZE           (COMM_PAGE64_BASE_ADDRESS + 0x038)
#define COMM_PAGE_CPUFAMILY             (COMM_PAGE64_BASE_ADDRESS + 0x040)

#pragma mark - Color Definitions

/*!
 * @brief Provides ANSI color codes for enhancing console output readability.
 *
 * @details Use these definitions to add color to console logs, improving the distinction between different types of messages. Each macro wraps a given string with the ANSI code for a specific color and automatically resets the color to default after the string. This ensures that only the intended text is colored, without affecting subsequent console output.
 *
 * - `MAG(string)`: Magenta colored text.
 * - `BLUE(string)`: Blue colored text.
 * - `RED(string)`: Red colored text for errors or warnings.
 * - `WHT(string)`: White colored text.
 * - `GRN(string)`: Green colored text for success messages.
 * - `YEL(string)`: Yellow colored text for cautionary messages.
 * - `CYN(string)`: Cyan colored text for informational messages.
 * - `HWHT(string)`: High-intensity white colored text.
 * - `NORMAL_COLOR(string)`: Resets text color to default console color.
 * - `RESET_COLOR`: ANSI code to reset text color to default.
 *
 * ## Example Usage:
 * @code
 * NSLog(@"%@", RED("Error: Invalid input"));
 * NSLog(@"%@", GRN("Operation completed successfully"));
 * @endcode
 *
 * @note The effectiveness and appearance of these color codes can vary based on the terminal or console application used. Ensure your development and deployment environments support ANSI color codes.
 */
#define _XOPEN_SOURCE
#define MAG(string)  "\x1b[0;35m" string RESET_COLOR
#define BLUE(string) "\x1b[34m" string RESET_COLOR
#define RED(string)  "\x1b[31m" string RESET_COLOR
#define WHT(string)  "\x1b[0;37m" string RESET_COLOR
#define GRN(string)  "\x1b[0;32m" string RESET_COLOR
#define YEL(string)  "\x1b[0;33m" string RESET_COLOR
#define CYN(string)  "\x1b[0;36m" string RESET_COLOR
#define HWHT(string) "\x1b[0;97m" string RESET_COLOR
#define NORMAL_COLOR(string) "\x1B[0m" string RESET_COLOR
#define RESET_COLOR "\x1b[0m"

#pragma mark - Injection Strings Configuration

/*!
 * @brief Configures robust strings for security testing within the application.
 *
 * These strings are tailored to simulate a variety of inputs aimed at testing the application's resilience against common and uncommon vulnerabilities. They include tests for SQL injections, XSS, buffer overflows, and more.
 *
 * - `INJECT_STRING_1` to `INJECT_STRING_10`: Each string targets different aspects of security handling, from special character processing to injection attacks.
 *
 * `NUMBER_OF_STRINGS`: Denotes the total number of defined injection strings, aiding in their application across varied test scenarios.
 *
 * ## Example Usage:
 * @code
 * for (int i = 0; i < NUMBER_OF_STRINGS; i++) {
 *     testFunctionWithInjectionString(INJECT_STRINGS[i]);
 * }
 * @endcode
 *
 * @note Use these strings in a controlled environment to ensure they help identify potential security flaws without causing unintended harm.
 */
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

// Array for iteration and application in tests.
const char* injectStrings[NUMBER_OF_STRINGS] = {
    INJECT_STRING_1,
    INJECT_STRING_2,
    INJECT_STRING_3,
    INJECT_STRING_4,
    INJECT_STRING_5,
    INJECT_STRING_6,
    INJECT_STRING_7,
    INJECT_STRING_8,
    INJECT_STRING_9,
    INJECT_STRING_10
};

#pragma mark - Debugging Macros

/*!
 * @brief Provides macros for enhanced logging and assertions during development.
 *
 * This section defines two key macros designed to assist in the debugging process, ensuring that developers can log detailed information and perform assertions with customized messages. These macros are especially useful in DEBUG builds, where additional context can significantly aid in diagnosing issues.
 *
 * ## Features:
 * - `DebugLog`: This macro is used for logging detailed debug information, including the name of the current function and the line number from where it's called. It's instrumental in tracing the execution flow or pinpointing the location of specific events or states in the code.
 * - `AssertWithMessage`: This macro allows for the execution of assertions that, upon failure, log a custom message. It's valuable for validating assumptions within the code and providing immediate feedback if those assumptions are violated.
 *
 * ## Usage:
 *
 * ### DebugLog
 * Use the `DebugLog` macro to log messages with additional context, such as the function name and line number. This macro is only active in DEBUG builds, helping to avoid the potential exposure of sensitive information in release builds.
 *
 * @code
 * DebugLog(@"An informative debug message with context.");
 * @endcode
 */
#ifdef DEBUG
#define DebugLog(fmt, ...) NSLog((@"%s [Line %d] " fmt), __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define DebugLog(...)
#endif

#pragma mark - Assertion
/*!
 * @brief Asserts a condition and logs a custom message upon failure.
 *
 * Use the `AssertWithMessage` macro to assert conditions and provide immediate feedback with a custom message if the condition is false. This macro logs the assertion and message before performing a standard assert.
 *
 * @param condition The condition to evaluate.
 * @param message The custom message to log if the assertion fails.
 *
 * @example Usage:
 * @code
 * AssertWithMessage(x > 0, "x must be greater than 0");
 * @endcode
 */
#define AssertWithMessage(condition, message, ...) \
    do { \
        if (!(condition)) { \
            NSLog((@"Assertion failed: %s " message), #condition, ##__VA_ARGS__); \
            assert(condition); \
        } \
    } while(0)

#pragma mark - Date and Time Utilities

/*!
 * @brief Formats the current date and time into a standardized, human-readable string.
 *
 * @return NSString representing the current date and time, formatted according to 'yyyy-MM-dd at HH:mm:ss'.
 *
 * Leverages `NSDateFormatter` to generate a string from the current date (`NSDate`), using the specified format. This encapsulates the process of obtaining a formatted current date and time, abstracting the configuration of `NSDateFormatter`.
 *
 * @example
 * @code
 * NSString *currentDateTimeString = formattedCurrentDateTime();
 * NSLog(@"Current Date and Time: %@", currentDateTimeString);
 * @endcode
 */
NSString* formattedCurrentDateTime(void) {
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"yyyy-MM-dd HH:mm:ss"];
    NSString *formattedDate = [dateFormatter stringFromDate:[NSDate date]];
    return formattedDate;
}

#pragma mark - Signature

/*!
 * @brief Retrieves a signature from a predefined memory address.
 *
 * This function allocates memory and copies a 16-byte signature from a specified base address in memory,
 * commonly used for retrieving system or application-specific signatures stored in a secure memory region.
 *
 * The memory is allocated with calloc, ensuring all bytes are initialized to zero, including the byte following
 * the signature, effectively null-terminating the string.
 *
 * @return A pointer to a null-terminated string containing the signature. The caller is responsible for freeing
 * this memory using free(). Returns NULL if memory allocation fails.
 *
 * @note This function directly accesses memory and should be used with caution, ensuring that
 * COMM_PAGE64_BASE_ADDRESS points to a valid, accessible memory address to prevent undefined behavior.
 *
 * @example
 * @code
 * char *sig = signature();
 * if (sig) {
 *     printf("Signature: %s\n", sig);
 *     free(sig);
 * } else {
 *     fprintf(stderr, "Failed to retrieve signature.\n");
 * }
 * @endcode
 */
char *signature(void) {
    // Allocate memory using calloc; +1 for null terminator, initializing all bits to zero
    char *signature = calloc(1, 0x10 + 1); // Replaces malloc(0x10 + 1) and initializes memory
    if (!signature) {
        fprintf(stderr, "Error: Failed to allocate memory for signature.\n");
        return NULL;
    }

    // Ensure that COMM_PAGE64_BASE_ADDRESS is valid and not NULL before using memcpy
    const char *base_address = (const char *)COMM_PAGE64_BASE_ADDRESS;
    if (!base_address) {
        fprintf(stderr, "Error: COMM_PAGE64_BASE_ADDRESS is null.\n");
        free(signature);
        return NULL;
    }

    // Copy data safely
    memcpy(signature, base_address, 0x10);

    // No need to explicitly set the null terminator since calloc initializes the memory to zero
    return signature;
}

#pragma mark - iOS Device Information

/*!
 * @brief Logs comprehensive information about the current device.
 *
 * This utility function leverages the `UIDevice` class to access and log a wide range of information about the device on which the application is running. It covers basic device identifiers, operating system details, and battery status, providing a holistic view of the device's configuration and state.
 *
 * The function temporarily enables battery monitoring to retrieve the current battery level and state, supplementing the device information with power status. This could be particularly useful for applications that need to adjust their behavior or performance based on the device's power status.
 *
 * @warning Battery information is specific to iOS and iPadOS devices and might not reflect real-time changes accurately due to system optimizations and power management.
 *
 * @code
 * dumpDeviceInfo();
 * @endcode
 * This example demonstrates how to call dumpDeviceInfo to log device information. This can be particularly useful during development and debugging to understand the environment in which the application is operating.
 *
 * @note Ensure that you check the device's capability to provide battery information and handle any potential inaccuracies in the reported levels and states. Consider the privacy implications of logging and handling the unique identifier for the vendor (identifierForVendor).
 *
 * @see UIDevice for detailed documentation on accessing device properties.
 */
void dumpDeviceInfo(void) {
UIDevice *device = [UIDevice currentDevice];
NSLog(@"Device Information:");
NSLog(@"  Name: %@", device.name);
NSLog(@"  Model: %@", device.model);
NSLog(@"  System Name: %@", device.systemName);
NSLog(@"  System Version: %@", device.systemVersion);
NSLog(@"  Identifier For Vendor: %@", device.identifierForVendor.UUIDString);

device.batteryMonitoringEnabled = YES; // Enable battery monitoring
NSLog(@"  Battery Level: %f", device.batteryLevel * 100); // Convert to percentage
NSString *batteryState;
switch (device.batteryState) {
    case UIDeviceBatteryStateUnknown:
        batteryState = @"Unknown";
        break;
    case UIDeviceBatteryStateUnplugged:
        batteryState = @"Unplugged";
        break;
    case UIDeviceBatteryStateCharging:
        batteryState = @"Charging";
        break;
    case UIDeviceBatteryStateFull:
        batteryState = @"Full";
        break;
    default:
        batteryState = @"Not Available";
        break;
}
NSLog(@"  Battery State: %@", batteryState);
device.batteryMonitoringEnabled = NO; // Disable battery monitoring after fetching information
}

#pragma mark - macOS System Information

/*!
 * @brief Logs system information for macOS devices.
 *
 * This function is specifically designed to fetch and log key pieces of system information for macOS devices, utilizing the `sysctl` interface. It provides insights into the kernel version, hardware model, and CPU type, among others, offering a clear snapshot of the underlying hardware and operating system specifics.
 *
 * ## Key Information Retrieved:
 * - **Kernel Version**: The version of the Darwin kernel the system is running.
 * - **Hardware Model**: The specific model of the macOS device, useful for identifying hardware capabilities.
 * - **CPU Type**: Details about the CPU, including its brand and specifications, which can inform performance expectations and compatibility.
 *
 * ## Usage:
 * This function is tailor-made for macOS environments and can be invoked directly to log the system information to the console:
 * @code
 * dumpMacDeviceInfo();
 * @endcode
 *
 * Example Output:
 * ```
 * System Information:
 * Kernel Version: Darwin 20.3.0
 * Hardware Model: MacBookPro15,1
 * CPU Type: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
 * ```
 *
 * @note While this function is designed with macOS in mind, accessing system information via sysctl is a method that could potentially be adapted for other Unix-like systems with appropriate modifications.
 *
 * @see For more in-depth details on using sysctl, refer to the man pages (man sysctl) or the official documentation for the sysctl interface.
 */
void dumpMacDeviceInfo(void) {
    char str[128];
    size_t size = sizeof(str);
    
    // Query and log the kernel version
    sysctlbyname("kern.osrelease", str, &size, NULL, 0);
    NSLog(@"Kernel Version: %s", str);
    
    // Reset size for the next sysctlbyname call
    size = sizeof(str);
    // Query and log the hardware model
    sysctlbyname("hw.model", str, &size, NULL, 0);
    NSLog(@"Hardware Model: %s", str);
    
    // Reset size for the next sysctlbyname call
    size = sizeof(str);
    // Query and log the CPU type
    sysctlbyname("machdep.cpu.brand_string", str, &size, NULL, 0);
    NSLog(@"CPU Type: %s", str);
    
}

#pragma mark - CPU Cap Strings

/*!
 * @brief Identifies the CPU's supported capabilities.
 *
 * This section enumerates various CPU capabilities and instruction sets that modern processors might support. These capabilities enhance the processor's performance and security features. Identifiers for these capabilities are used to represent specific hardware features and instruction sets, such as Multimedia Extensions, Streaming SIMD Extensions, Advanced Encryption Standard instruction sets, and others.
 *
 * ## Usage:
 * The identifiers provided are used to map the CPU capability bits to human-readable strings. This mapping aids developers and system administrators in understanding the features supported by the CPU on a given device, facilitating optimizations and security enhancements.
 *
 * ## Key Identifiers:
 * - `MMX`: Refers to Multimedia Extensions that enhance multimedia and communication tasks.
 * - `SSE`, `SSE2`, `SSE3`, `SSE4_1`, `SSE4_2`: Streaming SIMD Extensions and their versions, improving performance on floating point and integer operations.
 * - `AES`: Denotes support for the Advanced Encryption Standard instruction set, crucial for fast and secure data encryption.
 * - `AVX1_0`, `AVX2_0`: Advanced Vector Extensions that improve performance for applications requiring high computational throughput.
 * - `BMI1`, `BMI2`: Bit Manipulation Instruction Sets, enhancing the efficiency of certain data processing tasks.
 * - `RTM`: Restricted Transactional Memory, supporting transactional memory synchronization.
 * - `HLE`: Hardware Lock Elision, aimed at improving the performance of lock-based concurrent algorithms.
 * - `ADX`: Multi-Precision Add-Carry Instruction Extensions, useful in cryptographic algorithms.
 * - `RDSEED`, `MPX`, `SGX`: Various security and protection extensions, including random number generation, memory protection, and trusted execution.
 *
 * ## Note:
 * The availability and support for these capabilities are highly dependent on the CPU model and the architecture of the device's processor. Detection and utilization of these features typically require querying through system-specific interfaces or leveraging instruction sets designed for this purpose.
 *
 * @see Consult the documentation for your processor or use system utilities designed to query and report CPU capabilities for detailed information on the supported features.
 */
const char *cpu_cap_strings[] = {
    "MMX", "SSE", "SSE2", "SSE3", "Cache32", "Cache64", "Cache128",
    "FastThreadLocalStorage", "SupplementalSSE3", "64Bit", "SSE4_1", "SSE4_2",
    "AES", "InOrderPipeline", "Slow", "UP", "NumCPUs", "AVX1_0", "RDRAND",
    "F16C", "ENFSTRG", "FMA", "AVX2_0", "BMI1", "BMI2", "RTM", "HLE", "ADX",
    "RDSEED", "MPX", "SGX"
};

#pragma mark - Dump Comm Page

/*!
 * @brief Dumps key communication page details for diagnostic purposes.
 *
 * This function extracts and logs essential details from the system's communication page, such as the signature, version, and number of CPUs, along with CPU capabilities. It utilizes the `READ_COMM_PAGE_VALUE` macro to read values directly from specified memory addresses, facilitating a low-level inspection of system configurations and capabilities.
 *
 * ## Behavior:
 * 1. Retrieves and logs the communication page signature. If the signature cannot be read, logs an error message.
 * 2. Logs the communication page version and number of CPU cores by reading from predefined offsets within the communication page.
 * 3. Enumerates and logs CPU capabilities based on the `COMM_PAGE_CPU_CAPABILITIES64` address. Each capability is checked and logged, indicating whether it is supported.
 *
 * ## Parameters:
 * This function does not take any parameters.
 *
 * ## Return:
 * This function does not return a value.
 *
 * ## Example Output:
 * - `[*] COMM_PAGE_SIGNATURE: <signature_value>` or `[*] COMM_PAGE_SIGNATURE: Error reading signature.`
 * - `[*] COMM_PAGE_VERSION: <version_number>`
 * - `[*] COMM_PAGE_NCPUS: <cpu_count>`
 * - Lists CPU capabilities as true/false based on the current system's hardware configuration.
 *
 * ## Note:
 * - The actual information logged will depend on the specific system and its configuration.
 * - The `READ_COMM_PAGE_VALUE` macro is crucial for the function's operation, casting the specified address to the appropriate type before dereferencing.
 *
 * ## See Also:
 * - `READ_COMM_PAGE_VALUE` macro for how memory addresses are read.
 * - System documentation for the communication page structure and definitions.
 *
 * ### Usage:
 * @code
 * dump_comm_page(); // Logs the communication page details for the current system.
 * @endcode
 */
#define READ_COMM_PAGE_VALUE(type, address) (*((type *)(address)))

void dump_comm_page(void) {
    char *sig = signature();
    if (sig) {
        NSLog(@"[*] COMM_PAGE_SIGNATURE: %s", sig);
        free(sig);
    } else {
        NSLog(@"[*] COMM_PAGE_SIGNATURE: Error reading signature.");
    }

    // Utilizing macro for simplified reading
    NSLog(@"[*] COMM_PAGE_VERSION: %d", READ_COMM_PAGE_VALUE(uint16_t, COMM_PAGE64_BASE_ADDRESS + 0x01E));
    NSLog(@"[*] COMM_PAGE_NCPUS: %d", READ_COMM_PAGE_VALUE(uint8_t, COMM_PAGE64_BASE_ADDRESS + 0x022));
    // Additional comm page details could be added here

    NSLog(@"[*] COMM_PAGE_CPU_CAPABILITIES64:");
    uint64_t cpu_caps = READ_COMM_PAGE_VALUE(uint64_t, COMM_PAGE_CPU_CAPABILITIES64);
    for (int i = 0, shift = 0; i < (int)(sizeof(cpu_cap_strings) / sizeof(char *)); i++) {
        if (i == 16) { // Special handling for NumCPUs
            NSLog(@"\t%s: %d", cpu_cap_strings[i], (int)(cpu_caps >> 16) & 0xFF);
            shift = 24; // Skip to the next relevant bit
            continue;
        }
        NSLog(@"\t%s: %@", cpu_cap_strings[i], (cpu_caps & (1ULL << shift)) ? @"true" : @"false");
        shift++;
    }
    NSLog(@"[*] Done dumping comm page.");
}

#pragma mark - Print Color Function

/*!
 * @brief Prints a message with specified ANSI color to the console.
 *
 * This utility function enhances console log visibility by allowing messages to be printed in different colors. It wraps a provided message with the specified ANSI color code, ensuring the message stands out in the console output. After printing the message, it resets the console color back to its default, maintaining the terminal's readability for subsequent outputs.
 *
 * @param color The ANSI color code that dictates the color of the message. This parameter expects a string representation of ANSI color codes (e.g., "\033[31m" for red).
 * @param message The text message to be printed. This string is the content that will be displayed in the specified color in the console.
 *
 * @note This function relies on the terminal or console's support for ANSI color codes. If the terminal does not support these codes, the message will be printed without color formatting, and escape codes may be visible.
 *
 * ### Example Usage:
 * @code
 * printColored("\033[31m", "Error: File not found.");
 * @endcode
 *
 * This example demonstrates how to use the printColored function to print an error message in red, making it more noticeable in the console output.
 *
 * See Also:
 * ANSI color codes documentation for more information on how colors are represented in terminals.
 */
void printColored(const char* color, const char* message) {
    NSLog(@"%s%s%s", color, message, RESET_COLOR);
}

#pragma mark - Function Prototypes

/*!
 * @brief Prototypes for utility functions used in image processing.
 *
 * @details This section declares functions essential for the image processing pipeline,
 * ranging from path validation to image manipulation and utility operations. These functions
 * facilitate tasks such as validating image paths, loading images from files, applying various
 * image processing permutations, and managing output directories and string hashing.
 *
 * - `isValidImagePath`: Validates the specified image path.
 * - `loadImageFromFile`: Loads an image from the given file path.
 * - `processImage`: Processes the image with a specified permutation algorithm.
 * - Additional utilities include noise application, color inversion, value adjustments, and string hashing.
 *
 * @return Various return types depending on the function's purpose.
 *
 * @note Some functions, such as `processImage`, might modify the input image directly.
 */
BOOL isValidImagePath(NSString *path);
unsigned long hashString(const char* str);
UIImage *loadImageFromFile(NSString *filePath);
// NSString* formattedCurrentDateTime(void);
// NSString *createUniqueDirectoryForSavingImages(void);
NSData* UIImageGIFRepresentation(UIImage *image);
NSData* generateFuzzedImageData(size_t width, size_t height, CFStringRef imageType);
void processImage(UIImage *image, int permutation);
// void performAllImagePermutations(void);
void addAdditiveNoise(float *pixel);
void applyMultiplicativeNoise(float *pixel);
void invertColor(float *pixel);
void applyExtremeValues(float *pixel);
void assignSpecialFloatValues(float *pixel);
void applyColorShift(unsigned char *data, size_t index);
void applyPixelScramble(unsigned char *data, size_t index);
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
void createBitmapContextCMYK(CGImageRef cgImg);
void createBitmapContextHDRFloat16(CGImageRef cgImg);
void createBitmapContextIndexedColor(CGImageRef cgImg);
void applyFuzzingToBitmapContext(unsigned char *rawData, size_t width, size_t height);
void applyEnhancedFuzzingToBitmapContext(unsigned char *rawData, size_t width, size_t height, BOOL verbose);
void applyEnhancedFuzzingToBitmapContext16Bit(unsigned char *rawData, size_t width, size_t height, BOOL verbose);
void logPixelData(unsigned char *rawData, size_t width, size_t height, const char *message, BOOL verbose);
void convertTo1BitMonochrome(unsigned char *rawData, size_t width, size_t height);
void saveMonochromeImage(UIImage *image, NSString *identifier);
NSData* applyPostEncodingCorruption(NSData *encodedData, NSString *format);
// void dumpDeviceInfo(void);
// void dumpMacDeviceInfo(void);
// void dump_comm_page(void);

// ICC profile embedding and color space diversity
NSData* embedICCProfile(NSData *imageData, NSString *iccProfilePath, NSString *format);
NSData* embedICCProfileData(NSData *imageData, NSData *iccData, NSString *format);
NSData* mutateICCProfile(NSData *profileData);
NSArray<NSString *>* loadICCProfilePaths(void);
CGColorSpaceRef createNamedColorSpace(int index);

// ICC variant generation for fuzzer seed diversity
void saveFuzzedImageWithICCVariants(UIImage *image, NSString *contextDescription);
NSData* encodeImageWithICCProfile(CGImageRef image, NSData *iccData, CFStringRef utType);
NSData* encodeImageStrippingColorSpace(CGImageRef image, CFStringRef utType);
NSData* encodeImageWithMismatchedProfile(CGImageRef image, CFStringRef utType);

// Multi-format encoding
NSData* encodeImageAs(CGImageRef image, CFStringRef utType, NSDictionary *options);
NSDictionary<NSString *, NSData *>* encodeImageMultiFormat(CGImageRef image);
NSData* createTIFFThumbnail(CGImageRef image, size_t maxDim);

// Provenance naming and output metrics
NSString* provenanceFileName(NSString *inputName, int permutation, int injection, NSString *iccName, int seq, NSString *ext);
NSDictionary* measureOutput(NSData *inputData, NSData *outputData, NSString *outputPath);
void writeMetricsJSON(NSDictionary *metrics, NSString *outputPath);
void writeMetricsSummaryCSV(NSArray<NSDictionary *> *allMetrics, NSString *outputDir);

// Iteration chaining and batch processing
void performChainedFuzzing(NSString *inputPath, int iterations, BOOL allPermutations);
void performBatchFuzzing(NSString *inputDir, int iterations);
void performPipelineFuzzing(NSString *inputDir, int iterations);
NSArray<NSString *>* scanDirectoryForImages(NSString *directory);

#pragma mark - IO Handling

#pragma mark - saveFuzzedImage

/*!
 * @brief Saves a modified (fuzzed) UIImage to the documents directory.
 * @details This function takes a UIImage object that has undergone modifications (e.g., fuzzing) and saves it to the documents directory with a unique filename derived from a provided context description. It's designed to facilitate the persistence of images altered through security testing, experimental modifications, or user interactions within an application. The process includes validation of input parameters, generation of a unique filename, and the actual saving of the image in specified formats including PNG, JPEG, and GIF.
 *
 * @param image The modified UIImage object to be saved.
 * @param contextDescription A description of the context in which the image was modified, used to generate a unique file name.
 *
 * @note The function includes several key steps:
 * - **Validation**: Checks `contextDescription` for validity to avoid file path issues.
 * - **Filename Generation**: Creates a unique filename with "fuzzed_image_" prefix and appropriate file extension.
 * - **Directory Retrieval**: Uses `NSSearchPathForDirectoriesInDomains` to find the documents directory, ensuring iOS compatibility.
 * - **File Path Creation**: Combines the directory path with the filename.
 * - **Image Conversion**: Encodes the UIImage as PNG, JPEG, or GIF data.
 * - **File Writing**: Atomically writes the image data to the filesystem.
 * - **Logging**: Outputs the result of the operation for debugging and verification.
 *
 * ### Usage Scenarios:
 * - Ideal for applications that need to save images after applying security-related fuzzing or other modifications.
 * - Supports persisting images modified by user actions in editing or customization features.
 * - Facilitates the creation and storage of a series of programmatically altered images for analysis or review.
 *
 * ### Implementation Notes:
 * - Assumes the UIImage and context description are valid and appropriate for the intended save operation.
 * - Utilizes NSLog for logging, suitable for debugging but may require adaptation for production-level error handling or logging.
 */
void saveFuzzedImage(UIImage *image, NSString *contextDescription) {
    // Ensure contextDescription is valid to prevent file path issues
    if (contextDescription == nil || [contextDescription length] == 0) {
        NSLog(@"Context description is invalid.");
        return;
    }

    // Determine the image format and file extension from contextDescription
    NSString *fileExtension = @"png"; // Default to PNG
    NSData *imageData;
    
    if ([contextDescription containsString:@"jpeg"] || [contextDescription containsString:@"jpg"]) {
        fileExtension = @"jpg";
        imageData = UIImageJPEGRepresentation(image, 0.9); // Using a JPEG quality factor of 0.9
        NSLog(@"Saving image as JPEG");
    } else if ([contextDescription containsString:@"gif"]) {
        fileExtension = @"gif";
        imageData = UIImageGIFRepresentation(image);
        if (imageData) {
            NSLog(@"Successfully created GIF data");
        } else {
            NSLog(@"Failed to create GIF data");
        }
    } else if ([contextDescription containsString:@"tiff"]) {
        fileExtension = @"tiff";
        NSMutableData *tiffData = [NSMutableData data];
        CGImageDestinationRef dest = CGImageDestinationCreateWithData(
            (CFMutableDataRef)tiffData, (__bridge CFStringRef)UTTypeTIFF.identifier, 1, NULL);
        if (dest) {
            CGImageDestinationAddImage(dest, image.CGImage, NULL);
            if (CGImageDestinationFinalize(dest)) {
                imageData = tiffData;
                NSLog(@"Successfully created TIFF data");
            } else {
                NSLog(@"Failed to finalize TIFF data");
            }
            CFRelease(dest);
        } else {
            NSLog(@"Failed to create TIFF image destination");
        }
    } else if ([contextDescription containsString:@"premultipliedfirstalpha"]) {
        // Handle PremultipliedFirstAlpha specific logic here
        imageData = UIImagePNGRepresentation(image);
        NSLog(@"Saving image as PNG with premultipliedfirstalpha");
    } else {
        // Default case handles PNG and other unspecified formats as PNG
        imageData = UIImagePNGRepresentation(image);
        NSLog(@"Saving image as PNG");
    }

    // Generate file name: strip trailing format suffix since extension is added separately
    NSString *baseName = contextDescription;
    for (NSString *suffix in @[@"_png", @"_jpeg", @"_jpg", @"_gif", @"_tiff"]) {
        if ([baseName hasSuffix:suffix]) {
            baseName = [baseName substringToIndex:[baseName length] - [suffix length]];
            break;
        }
    }
    NSString *fileName = [NSString stringWithFormat:@"fuzzed_image_%@.%@", baseName, fileExtension];
    
    // Use FUZZ_OUTPUT_DIR env var if set (for CI), otherwise use Documents directory
    NSString *outputDirectory;
    const char *envDir = getenv("FUZZ_OUTPUT_DIR");
    if (envDir) {
        outputDirectory = [NSString stringWithUTF8String:envDir];
    } else {
        outputDirectory = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    }
    NSString *filePath = [outputDirectory stringByAppendingPathComponent:fileName];
    
    // Save the image data to the file
    BOOL success = [imageData writeToFile:filePath atomically:YES];
    
    if (success) {
        NSLog(@"Fuzzed image for '%@' context saved to %@", contextDescription, filePath);
        // Generate ICC variants for TIFF and PNG outputs (most useful for CFL fuzzers)
        if ([contextDescription containsString:@"tiff"] || [contextDescription containsString:@"png"]) {
            saveFuzzedImageWithICCVariants(image, contextDescription);
        }
    } else {
        NSLog(@"Failed to save fuzzed image for '%@' context", contextDescription);
    }
}

#pragma mark - GIF UIImage

/*!
 * @brief Creates a GIF representation of a UIImage.
 * This custom function handles the conversion of a UIImage to GIF data using the Image I/O framework.
 *
 * @param image The UIImage to be converted.
 * @return NSData containing the GIF representation of the image.
 */
NSData* UIImageGIFRepresentation(UIImage *image) {
    // Check for valid input
    if (!image) {
        NSLog(@"UIImageGIFRepresentation: Invalid image input.");
        return nil;
    }

    // Create a mutable data object to hold the GIF data
    NSMutableData *gifData = [NSMutableData data];
    
    // Create an image destination for the GIF data
    CGImageDestinationRef destination = CGImageDestinationCreateWithData((CFMutableDataRef)gifData, (__bridge CFStringRef)UTTypeGIF.identifier, 1, NULL);
    
    if (!destination) {
        NSLog(@"UIImageGIFRepresentation: Failed to create image destination for GIF.");
        return nil;
    }
    
    // Set GIF properties (e.g., loop count)
    NSDictionary *gifProperties = @{
        (__bridge id)kCGImagePropertyGIFDictionary: @{
            (__bridge id)kCGImagePropertyGIFLoopCount: @0 // 0 means loop forever
        }
    };
    
    // Add the image to the destination
    CGImageDestinationAddImage(destination, image.CGImage, (__bridge CFDictionaryRef)gifProperties);
    
    // Finalize the image destination
    if (!CGImageDestinationFinalize(destination)) {
        NSLog(@"UIImageGIFRepresentation: Failed to finalize the GIF image destination.");
        CFRelease(destination);
        return nil;
    }
    
    CFRelease(destination);
    return gifData;
}


#pragma mark - MonoConversionFunction

/*!
 * @brief Converts image data to 1-bit monochrome using a simple thresholding technique.
 * @details This function iterates over each pixel in the input image data, applying a fixed threshold to determine if a pixel should be black or white in the resulting monochrome image. This is a basic form of binarization, suitable for simplifying images or preparing them for certain types of processing where color is not needed.
 *
 * @param rawData Pointer to the image data.
 * @param width The width of the image in pixels.
 * @param height The height of the image in pixels.
 *
 * ### Example Usage:
 * @code
 * uint8_t *rawData = ...; // Assume this is already allocated and populated with image data
 * size_t width = ...;   // The width of the image
 * size_t height = ...;  // The height of the image
 * convertTo1BitMonochrome(rawData, width, height);
 * @endcode
 */
extern void convertTo1BitMonochrome(unsigned char *rawData, size_t width, size_t height) {
    size_t bytesPerRow = (width + 7) / 8;

    // The 1-bit context data is already packed (1 bit per pixel).
    // Apply fuzzing by randomly flipping bits to exercise edge cases.
    for (size_t y = 0; y < height; y++) {
        for (size_t x = 0; x < width; x++) {
            size_t byteIndex = y * bytesPerRow + x / 8;
            unsigned char bitPos = 7 - (x % 8);

            // Flip ~25% of bits randomly for fuzzing variation
            if (arc4random_uniform(4) == 0) {
                rawData[byteIndex] ^= (1 << bitPos);
            }
        }
    }
}

#pragma mark - MonoSavingFunction

/*!
 * @brief Saves a monochrome UIImage with a specified identifier to the documents directory.
 * @details This function saves the provided UIImage object as a PNG file in the application's documents directory, using the specified identifier as part of the file name. It's useful for persisting processed images for later retrieval, sharing, or comparison.
 *
 * @param image The UIImage to save.
 * @param identifier A unique identifier for the image file.
 *
 * ### Example Usage:
 * @code
 * UIImage *monochromeImage = ...; // Assume this is a valid UIImage
 * NSString *identifier = @"example_monochrome_image";
 * saveMonochromeImage(monochromeImage, identifier);
 * @endcode
 */
extern void saveMonochromeImage(UIImage *image, NSString *identifier) {
    NSData *imageData = UIImagePNGRepresentation(image);
    NSString *docsDir;
    const char *envDir = getenv("FUZZ_OUTPUT_DIR");
    if (envDir) {
        docsDir = [NSString stringWithUTF8String:envDir];
    } else {
        docsDir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    }
    NSString *filePath = [docsDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@.png", identifier]];
    
    if ([imageData writeToFile:filePath atomically:YES]) {
        NSLog(@"Saved monochrome image with identifier %@ at %@", identifier, filePath);
    } else {
        NSLog(@"Error saving monochrome image with identifier %@", identifier);
    }
}

#pragma mark - Directory Management

/*!
 * @brief Creates a unique directory for saving images within the documents directory.
 *
 * @details Generates a unique directory name by combining the current date-time stamp and a random component,
 * ensuring uniqueness. This directory is created within the application's documents directory, intended for
 * storing processed images. Useful in scenarios requiring organized storage without naming conflicts, maintaining
 * chronological order. The inclusion of a random component further ensures directory name uniqueness, even when
 * created in rapid succession.
 *
 * @return The path to the newly created unique directory, or nil if an error occurred. This path can be used
 * directly to save files within the new directory.
 */
NSString *createUniqueDirectoryForSavingImages(void) {
    // Initialize date formatter for timestamp
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy-MM-dd_HH-mm-ss-SSS";
    
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
        NSLog(@"Error creating directory for saving images: %@", error.localizedDescription);
        return nil; // Return nil in case of failure
    }

    // Return the path of the successfully created directory
    return uniqueDirPath;
}

#pragma mark - Pixel Logging

#pragma mark - Raw Image Data

/*!
 * @brief Logs information about a random set of pixels from an image's raw data.
 *
 * @details Selects a random set of pixels from the provided image data and logs their RGBA components.
 * If verbose logging is enabled, it decodes and logs character data embedded within the pixel values,
 * providing insights into the image's content or image processing results. Assumes RGBA format for pixel data.
 *
 * @param rawData The raw pixel data of the image.
 * @param width The width of the image in pixels.
 * @param height The height of the image in pixels.
 * @param message A contextual message or identifier for the log.
 * @param verboseLogging Enables detailed information logging, including decoded data, when set to true.
 *
 * @note Ensure the provided raw data correctly corresponds to the specified width and height to avoid out-of-bounds access.
 */
void logPixelData(unsigned char *rawData, size_t width, size_t height, const char *message, BOOL verboseLogging) {
    if (!rawData || width == 0 || height == 0) {
        NSLog(@"%s - Invalid data or dimensions. Logging aborted.", message);
        return;
    }

    const int numberOfPixelsToLog = 5; // Number of random pixels to log

    NSLog(@"%s - %s logging %d random pixels:", message, verboseLogging ? "Verbose" : "Basic", numberOfPixelsToLog);

    for (int i = 0; i < numberOfPixelsToLog; i++) {
        unsigned int randomX = arc4random_uniform((unsigned int)width);
        unsigned int randomY = arc4random_uniform((unsigned int)height);
        size_t pixelIndex = (randomY * width + randomX) * 4; // Index for RGBA

        if (pixelIndex + 3 < width * height * 4) {
            unsigned char r = rawData[pixelIndex];
            unsigned char g = rawData[pixelIndex + 1];
            unsigned char b = rawData[pixelIndex + 2];
            unsigned char a = rawData[pixelIndex + 3];

            NSLog(@"%s - Pixel[%u, %u]: R=%u, G=%u, B=%u, A=%u", message, randomX, randomY, r, g, b, a);

            if (verboseLogging) {
                // Decoding embedded character data from pixel values as an example
                unsigned char decodedChar = (r & 1) | ((g & 1) << 1) | ((b & 1) << 2);
                NSLog(@"%s - Decoded data from Pixel[%u, %u]: %c", message, randomX, randomY, decodedChar);
            }
        } else {
            NSLog(@"%s - Out of bounds pixel access prevented at [%u, %u].", message, randomX, randomY);
        }
    }
}

#pragma mark - Random Image Data

/*!
 * @brief Logs information about a random set of pixels from an image's raw data.
 * @details This function is designed to offer a quick diagnostic look at the content of an image by logging the color values of a randomly selected set of pixels. It's particularly useful for debugging and for verifying the effects of image processing algorithms. By providing a message or identifier, developers can contextualize the log output, making it easier to track logs related to specific images or operations. The function provides a high-level overview of pixel data without detailed analysis or decoding.
 *
 * @param rawData The raw pixel data of the image. This should be a pointer to the start of the pixel data array.
 * @param width The width of the image in pixels. This is used to calculate the position of pixels within the raw data array.
 * @param height The height of the image in pixels. Along with width, this determines the total number of pixels that can be logged.
 * @param message A message or identifier to include in the log for context. This helps to identify the log output related to specific images or processing steps.
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

#pragma mark - Fuzzing Functions

#pragma mark - applyColorShift
/*!
 * @brief Applies a color shift to a specific pixel within the image data.
 * @details This method modifies the RGB values of the specified pixel by randomly increasing or decreasing these values, which can simulate color distortion effects useful in fuzzing tests.
 * @param data The raw image data array.
 * @param index The index of the pixel within the data array where the color shift will be applied.
 */
void applyColorShift(unsigned char *data, size_t index) {
    for (int i = 0; i < 3; i++) { // Affecting RGB channels
        int shift = (arc4random_uniform(2) == 0) ? -15 : 15; // Randomly decide to increase or decrease color value
        int newValue = data[index + i] + shift;
        data[index + i] = (unsigned char)fmax(0, fmin(255, newValue)); // Ensure the new value is within the byte range
    }
}

#pragma mark - Pixel Scramble

/*!
 * @brief Randomly scrambles the RGB values of a pixel.
 * @details This method swaps the values of two RGB channels at the given pixel index, which can help in uncovering issues related to incorrect channel processing or assumptions in color models.
 * @param data The raw image data.
 * @param index The index of the pixel where the RGB channels will be scrambled.
 */
void applyPixelScramble(unsigned char *data, size_t index) {
    unsigned char temp;
    int swapIndex = arc4random_uniform(3); // Choose a random channel to swap with another
    temp = data[index + swapIndex];
    data[index + swapIndex] = data[index + (swapIndex + 1) % 3];
    data[index + (swapIndex + 1) % 3] = temp;
}

#pragma mark - applyEnhancedFuzzingToBitmapContext

/*!
 * @brief Applies enhanced fuzzing techniques to bitmap data.
 *
 * This function targets the robustness of image processing routines by applying a comprehensive set of fuzzing techniques directly to the raw pixel data of a bitmap. Techniques include string injections to simulate security testing scenarios, visual distortions such as inversion, noise addition, random color adjustments, pixel value shifts, contrast modifications, and color swapping under predefined conditions. The goal is to simulate a variety of real-world inputs, both benign and malicious, thereby uncovering potential vulnerabilities and ensuring the image processing system can handle unexpected inputs gracefully.
 *
 * @param rawData Pointer to the raw pixel data of the bitmap, which is modified in place. This data should be in RGBA format, where each pixel is represented by four bytes for red, green, blue, and alpha components.
 * @param width The width of the bitmap in pixels, used to navigate the pixel data array.
 * @param height The height of the bitmap in pixels, indicating the total number of pixel rows in the rawData.
 * @param verboseLogging If enabled (true), the function logs detailed information about each fuzzing action and its effect on the pixel data, facilitating debugging and providing insights into the impact of different fuzzing techniques on the bitmap.
 *
 * @note The rawData buffer is expected to accommodate width * height pixels, each represented by 4 bytes. The function directly modifies this buffer, reflecting the applied fuzzing techniques without returning any value. It serves as a critical tool for enhancing the security and robustness of image processing algorithms by exposing them to a broad spectrum of test conditions.
 */
void applyEnhancedFuzzingToBitmapContext(unsigned char *rawData, size_t width, size_t height, BOOL verboseLogging) {
    if (!rawData || width == 0 || height == 0) {
        NSLog(@"No valid raw data or dimensions available for enhanced fuzzing.");
        return;
    }

    size_t stringIndex = 0;
    size_t injectIndex = 0;
    size_t totalStringsInjected = 0;
    const size_t numFuzzMethods = 8; // Increased number of fuzz methods

    if (verboseLogging) {
        NSLog(@"Starting enhanced fuzzing on bitmap context");
    }

    for (size_t y = 0; y < height; y++) {
        for (size_t x = 0; x < width; x++) {
            size_t pixelIndex = (y * width + x) * 4; // Assuming RGBA format
            int fuzzMethod = arc4random_uniform(numFuzzMethods); // Now selecting from eight methods

            if (totalStringsInjected < NUMBER_OF_STRINGS) {
                if (injectIndex == 0 && verboseLogging) {
                    NSLog(@"Starting injection of string %zu: %s", stringIndex + 1, injectStrings[stringIndex]);
                }

                const char *currentString = injectStrings[stringIndex];
                size_t stringLength = strlen(currentString);

                if (injectIndex < stringLength) {
                    // Encode a character into both the MSB and LSB of the pixel data
                    for (int i = 0; i < 3; i++) { // Affecting RGB channels
                        // Encoding into the Least Significant Bit
                        rawData[pixelIndex + i] &= 0xFE; // Clear the least significant bit
                        rawData[pixelIndex + i] |= (currentString[injectIndex] & 0x01); // Set the least significant bit

                        // Encoding into the Most Significant Bit
                        rawData[pixelIndex + i] &= 0x7F; // Clear the most significant bit
                        rawData[pixelIndex + i] |= (currentString[injectIndex] & 0x80); // Set the most significant bit if needed
                    }
                    injectIndex++;
                }
                    
                    if (injectIndex == stringLength) {
                        if (verboseLogging) {
                            NSLog(@"Completed injection of string %zu: %s", stringIndex + 1, currentString);
                        }
                        injectIndex = 0; // Reset the injection index for the next string
                        stringIndex = (stringIndex + 1) % NUMBER_OF_STRINGS; // Cycle through strings
                        totalStringsInjected++;
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
                        int noise = (arc4random_uniform(101) - 50); // Noise range [-50, 50]
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
                    if ((x + y) % 2 == 0) {
                        unsigned char temp = rawData[pixelIndex];
                        rawData[pixelIndex] = rawData[pixelIndex + 2];
                        rawData[pixelIndex + 2] = temp;
                    }
                    break;
                case 6:
                    applyColorShift(rawData, pixelIndex);
                    if (verboseLogging) {
                        NSLog(@"Color Shift applied at Pixel[%zu, %zu]", x, y);
                    }
                    break;
                case 7:
                    applyPixelScramble(rawData, pixelIndex);
                    if (verboseLogging) {
                        NSLog(@"Pixel Scramble applied at Pixel[%zu, %zu]", x, y);
                    }
                    break;
            }
        }
    }

    if (verboseLogging) {
        if (totalStringsInjected == NUMBER_OF_STRINGS) {
            NSLog(@"Successfully injected all %zu strings.", totalStringsInjected);
        } else {
            NSLog(@"Error: Not all strings were successfully injected. Total injected: %zu", totalStringsInjected);
        }
        NSLog(@"Enhanced fuzzing on bitmap context completed.");
    }
}

#pragma mark - applyEnhancedFuzzingToBitmapContextWithFloats

/*!
 * @brief Applies enhanced fuzzing techniques to bitmap data using 32-bit floating-point precision.
 *
 * This function is designed to test the robustness of image processing algorithms by applying a variety of fuzzing techniques to the raw pixel data of a bitmap. It iterates through a predefined set of strings, each dictating a specific fuzzing method based on its hash value. Techniques include additive and multiplicative noise, color inversion, setting extreme values, and applying special floating-point values such as NaN or Infinity. The function aims to uncover potential vulnerabilities by simulating real-world inputs and ensuring that the image processing system can gracefully handle unexpected or malicious inputs.
 *
 * @param rawData Pointer to the raw pixel data of the bitmap, which is modified in place. The data is assumed to be in RGBA format, with each pixel represented by four 32-bit floating-point values for red, green, blue, and alpha components.
 * @param width The width of the bitmap in pixels, used to calculate the location of each pixel in the rawData array.
 * @param height The height of the bitmap in pixels, used along with the width to navigate through the rawData array.
 * @param verboseLogging A boolean value that, when set to YES, enables detailed logging of each fuzzing action and its effects on the pixel data. This facilitates debugging and provides insights into how different fuzzing techniques impact the bitmap.
 *
 * @note The function modifies the rawData buffer in place, reflecting the applied fuzzing techniques. The buffer is expected to accommodate width * height pixels, with each pixel's data represented by four 32-bit floating-point values. It is a critical tool for enhancing the security and robustness of image processing algorithms by exposing them to a broad spectrum of test conditions.
 *
 * ### Example usage:
 * @code
 * float *rawData = ...; // Assume this is already allocated and populated with image data
 * size_t width = ...;   // The width of the image
 * size_t height = ...;  // The height of the image
 * BOOL verboseLogging = YES; // Enable detailed logging
 * applyEnhancedFuzzingToBitmapContextWithFloats(rawData, width, height, verboseLogging);
 * @endcode
 */
void applyEnhancedFuzzingToBitmapContextWithFloats(float *rawData, size_t width, size_t height, BOOL verboseLogging) {
    if (!rawData || width == 0 || height == 0) {
        NSLog(@"Invalid parameters for enhanced fuzzing.");
        return;
    }

    for (int stringIndex = 0; stringIndex < NUMBER_OF_STRINGS; stringIndex++) {
        // Log the start of fuzzing with the specific injection string
        if (verboseLogging) {
            NSLog(@"Starting enhanced fuzzing with injection string %d: %s", stringIndex + 1, injectStrings[stringIndex]);
        }

        // Hash the selected injection string to determine the fuzzing method
        unsigned long hash = hashString(injectStrings[stringIndex]) % 8; // Modulo by 8 for expanded method range

        for (size_t y = 0; y < height; y++) {
            for (size_t x = 0; x < width; x++) {
                size_t pixelIndex = (y * width + x) * 4; // Assuming RGBA format

                // Apply fuzzing based on hash of injection string
                switch (hash) {
                    case 0:
                        // Additive noise
                        for (int i = 0; i < 4; i++) {
                            rawData[pixelIndex + i] += ((float)arc4random() / UINT32_MAX * 2.0f - 1.0f); // Noise range [-1, 1]
                        }
                        break;
                    case 1:
                        // Multiplicative noise (scale)
                        for (int i = 0; i < 4; i++) {
                            rawData[pixelIndex + i] *= ((float)arc4random() / UINT32_MAX * 2.0f); // Scale range [0, 2]
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
                            rawData[pixelIndex + i] = (arc4random_uniform(6) % 2) ? FLT_MAX : FLT_MIN;
                        }
                        break;
                    case 4:
                        // Special floating-point values
                        for (int i = 0; i < 4; i++) {
                            switch (arc4random_uniform(6) % 3) {
                                case 0: rawData[pixelIndex + i] = NAN; break;
                                case 1: rawData[pixelIndex + i] = INFINITY; break;
                                case 2: rawData[pixelIndex + i] = -INFINITY; break;
                            }
                        }
                        break;
                    case 5:
                        // Subnormal/denormalized floats — stress float-to-int conversion
                        for (int i = 0; i < 4; i++) {
                            switch (arc4random_uniform(4)) {
                                case 0: rawData[pixelIndex + i] = FLT_MIN * 0.5f; break;
                                case 1: rawData[pixelIndex + i] = -0.0f; break;
                                case 2: rawData[pixelIndex + i] = FLT_EPSILON; break;
                                case 3: rawData[pixelIndex + i] = -FLT_MIN; break;
                            }
                        }
                        break;
                    case 6:
                        // Premultiplied alpha violation: R,G,B > A (invalid for premultiplied)
                        rawData[pixelIndex] = 1.0f;
                        rawData[pixelIndex + 1] = 1.0f;
                        rawData[pixelIndex + 2] = 1.0f;
                        rawData[pixelIndex + 3] = 0.01f; // Very low alpha
                        break;
                    case 7:
                        // Bit-level float corruption via type punning
                        for (int i = 0; i < 4; i++) {
                            union { float f; uint32_t u; } pun;
                            pun.f = rawData[pixelIndex + i];
                            pun.u ^= (1u << arc4random_uniform(32));
                            rawData[pixelIndex + i] = pun.f;
                        }
                        break;
                }
            }
        }

        // Log completion of the fuzzing for the specific injection string
        if (verboseLogging) {
            NSLog(@"Enhanced fuzzing with injection string %d: %s completed", stringIndex + 1, injectStrings[stringIndex]);
        }
    }
    
    // Final log to indicate completion of all fuzzing processes
    if (verboseLogging) {
        NSLog(@"All enhanced fuzzing processes completed.");
    }
}

#pragma mark - applyEnhancedFuzzingToBitmapContextAlphaOnly

/*!
 * @brief Applies enhanced fuzzing techniques to the alpha channel of bitmap pixel data.
 * @details This function focuses on testing and improving the resilience of image processing routines to handle unusual or extreme alpha values effectively. By manipulating the alpha transparency data in various ways, it simulates edge cases or malicious inputs that could occur in real-world applications. The function employs several fuzzing methods, including alpha inversion, setting random transparency extremes, and introducing noise, to challenge and enhance the robustness of image processing algorithms.
 *
 * @param alphaData Pointer to the alpha channel data of the bitmap context. This buffer contains only the alpha (transparency) values for each pixel, represented by one byte per pixel.
 * @param width The width of the bitmap in pixels, defining the row length in the alpha data array.
 * @param height The height of the bitmap in pixels, indicating the total number of rows in the alpha data.
 * @param verboseLogging When YES, enables detailed logging of each fuzzing operation and its impact on the alpha channel, aiding in debugging and analysis of the fuzzing effects.
 *
 * @note The function iteratively applies fuzzing techniques to each alpha value, directly modifying the `alphaData` buffer to reflect these changes. It includes initial validity checks to ensure that operations are conducted on valid data with positive dimensions, and logs a message before aborting if parameters are found to be invalid. The goal is to ensure that image processing systems are capable of handling a wide range of transparency variations, thereby enhancing both the visual quality and security of applications that rely on such routines.
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

#pragma mark - applyEnhancedFuzzingToBitmapContext16Bit

/*!
 * @brief Applies enhanced fuzzing to 16-bit per component bitmap data.
 * @details Properly handles 16-bit RGBA data (8 bytes per pixel, 2 bytes per component).
 * Applies bit-level flips, boundary values, and channel swaps targeting 16-bit decoder paths.
 */
void applyEnhancedFuzzingToBitmapContext16Bit(unsigned char *rawData, size_t width, size_t height, BOOL verboseLogging) {
    if (!rawData || width == 0 || height == 0) {
        NSLog(@"No valid raw data for 16-bit fuzzing.");
        return;
    }

    uint16_t *data16 = (uint16_t *)rawData;
    size_t totalComponents = width * height * 4; // RGBA, 4 components per pixel

    for (size_t i = 0; i < totalComponents; i++) {
        switch (arc4random_uniform(8)) {
            case 0: // Inversion
                data16[i] = 0xFFFF - data16[i];
                break;
            case 1: // Random noise ±500
                {
                    int noise = (int)arc4random_uniform(1001) - 500;
                    int newVal = (int)data16[i] + noise;
                    data16[i] = (uint16_t)fmax(0, fmin(0xFFFF, newVal));
                }
                break;
            case 2: // Boundary values
                switch (arc4random_uniform(4)) {
                    case 0: data16[i] = 0x0000; break;
                    case 1: data16[i] = 0xFFFF; break;
                    case 2: data16[i] = 0x7FFF; break; // Mid-range
                    case 3: data16[i] = 0x0001; break; // Just above zero
                }
                break;
            case 3: // Bit-level flip at random position
                data16[i] ^= (1 << arc4random_uniform(16));
                break;
            case 4: // High byte corruption (leave low byte intact)
                data16[i] = (data16[i] & 0x00FF) | (arc4random_uniform(256) << 8);
                break;
            case 5: // Low byte corruption (leave high byte intact)
                data16[i] = (data16[i] & 0xFF00) | arc4random_uniform(256);
                break;
            case 6: // Complete random replacement
                data16[i] = (uint16_t)arc4random_uniform(0x10000);
                break;
            case 7: // Channel swap (swap with next component if not alpha)
                if (i % 4 < 3 && i + 1 < totalComponents) {
                    uint16_t tmp = data16[i];
                    data16[i] = data16[i + 1];
                    data16[i + 1] = tmp;
                }
                break;
        }
    }

    if (verboseLogging) {
        NSLog(@"16-bit enhanced fuzzing completed on %zu components", totalComponents);
    }
}

#pragma mark - applyPostEncodingCorruption

/*!
 * @brief Corrupts encoded image data at the byte level to stress decoder paths.
 * @details After an image is encoded (PNG/JPEG/GIF/TIFF), this function corrupts
 * specific bytes in the encoded stream to trigger edge cases in format parsers.
 * Preserves the magic bytes so the decoder attempts to parse the corrupted data.
 */
NSData* applyPostEncodingCorruption(NSData *encodedData, NSString *format) {
    if (!encodedData || [encodedData length] < 16) {
        return encodedData;
    }

    NSMutableData *corrupted = [encodedData mutableCopy];
    unsigned char *bytes = (unsigned char *)[corrupted mutableBytes];
    NSUInteger len = [corrupted length];

    // Preserve first 8 bytes (magic/signature) to ensure decoder attempts parsing
    size_t safeStart = 8;

    // Strategy 1: Flip random bits in 2% of bytes after the header
    size_t flipCount = (len - safeStart) / 50;
    for (size_t i = 0; i < flipCount; i++) {
        size_t offset = safeStart + arc4random_uniform((uint32_t)(len - safeStart));
        bytes[offset] ^= (1 << arc4random_uniform(8));
    }

    // Strategy 2: Structure-aware mutations for each format
    if ([format containsString:@"png"] && len > 33) {
        // PNG structure: 8-byte signature + chunks (length[4] + type[4] + data[N] + CRC[4])
        uint32_t mutation = arc4random_uniform(6);
        switch (mutation) {
            case 0: {
                // Corrupt IHDR dimensions (width at 16-19, height at 20-23)
                bytes[16 + arc4random_uniform(4)] ^= arc4random_uniform(256);
                NSLog(@"Corrupted PNG IHDR width/height field");
                break;
            }
            case 1: {
                // Corrupt IHDR color type / bit depth (byte 24 = bit depth, 25 = color type)
                if (arc4random_uniform(2) == 0) {
                    bytes[24] = (uint8_t[]){0, 1, 2, 4, 8, 16, 99, 255}[arc4random_uniform(8)];
                    NSLog(@"Corrupted PNG IHDR bit depth to %u", bytes[24]);
                } else {
                    bytes[25] = (uint8_t[]){0, 2, 3, 4, 6, 7, 255}[arc4random_uniform(7)];
                    NSLog(@"Corrupted PNG IHDR color type to %u", bytes[25]);
                }
                break;
            }
            case 2: {
                // Corrupt chunk CRCs — walk chunks and flip CRC bytes
                size_t pos = 8; // skip PNG signature
                int corrupted = 0;
                while (pos + 12 <= len && corrupted < 3) {
                    uint32_t chunkLen = ((uint32_t)bytes[pos] << 24) | ((uint32_t)bytes[pos+1] << 16) |
                                        ((uint32_t)bytes[pos+2] << 8) | bytes[pos+3];
                    if (chunkLen > len - pos - 12) break;
                    size_t crcOffset = pos + 8 + chunkLen;
                    if (crcOffset + 4 <= len && arc4random_uniform(3) == 0) {
                        bytes[crcOffset + arc4random_uniform(4)] ^= arc4random_uniform(256);
                        NSLog(@"Corrupted PNG chunk CRC at offset %zu (chunk type: %.4s)", crcOffset, &bytes[pos+4]);
                        corrupted++;
                    }
                    pos = crcOffset + 4;
                }
                break;
            }
            case 3: {
                // Truncate IDAT stream — find first IDAT and zero out trailing portion
                size_t pos = 8;
                while (pos + 12 <= len) {
                    uint32_t chunkLen = ((uint32_t)bytes[pos] << 24) | ((uint32_t)bytes[pos+1] << 16) |
                                        ((uint32_t)bytes[pos+2] << 8) | bytes[pos+3];
                    if (chunkLen > len - pos - 12) break;
                    if (memcmp(&bytes[pos+4], "IDAT", 4) == 0 && chunkLen > 4) {
                        size_t dataStart = pos + 8;
                        size_t truncAt = dataStart + arc4random_uniform((uint32_t)(chunkLen / 2)) + chunkLen / 2;
                        if (truncAt < dataStart + chunkLen) {
                            memset(&bytes[truncAt], 0, dataStart + chunkLen - truncAt);
                            NSLog(@"Truncated PNG IDAT at offset %zu (%zu bytes zeroed)", truncAt, dataStart + chunkLen - truncAt);
                        }
                        break;
                    }
                    pos += 8 + chunkLen + 4;
                }
                break;
            }
            case 4: {
                // Corrupt PLTE entries if present
                size_t pos = 8;
                while (pos + 12 <= len) {
                    uint32_t chunkLen = ((uint32_t)bytes[pos] << 24) | ((uint32_t)bytes[pos+1] << 16) |
                                        ((uint32_t)bytes[pos+2] << 8) | bytes[pos+3];
                    if (chunkLen > len - pos - 12) break;
                    if (memcmp(&bytes[pos+4], "PLTE", 4) == 0 && chunkLen >= 3) {
                        size_t numCorrupt = 1 + arc4random_uniform((uint32_t)(chunkLen < 12 ? chunkLen : 12));
                        for (size_t c = 0; c < numCorrupt; c++) {
                            bytes[pos + 8 + arc4random_uniform((uint32_t)chunkLen)] ^= arc4random_uniform(256);
                        }
                        NSLog(@"Corrupted %zu PLTE bytes in PNG palette chunk", numCorrupt);
                        break;
                    }
                    pos += 8 + chunkLen + 4;
                }
                break;
            }
            case 5: {
                // Insert invalid chunk type at random position after IHDR
                // Find end of IHDR (8 sig + 25 IHDR = 33 bytes)
                if (len > 40) {
                    size_t insertPos = 33 + arc4random_uniform((uint32_t)(len - 40));
                    if (insertPos + 4 <= len) {
                        // Overwrite 4 bytes with invalid chunk type
                        const char *badTypes[] = {"zZzZ", "XXXX", "\x00\x00\x00\x00", "\xFF\xFF\xFF\xFF"};
                        memcpy(&bytes[insertPos], badTypes[arc4random_uniform(4)], 4);
                        NSLog(@"Injected invalid chunk type at offset %zu", insertPos);
                    }
                }
                break;
            }
        }
    } else if ([format containsString:@"jpeg"] && len > 20) {
        // JPEG: corrupt a random marker length field
        for (size_t i = safeStart; i < len - 2; i++) {
            if (bytes[i] == 0xFF && bytes[i+1] >= 0xC0 && bytes[i+1] <= 0xFE && bytes[i+1] != 0xFF) {
                if (i + 4 < len && arc4random_uniform(4) == 0) {
                    bytes[i + 2] ^= arc4random_uniform(256);
                    NSLog(@"Corrupted JPEG marker 0xFF%02X length at offset %zu", bytes[i+1], i+2);
                    break;
                }
            }
        }
    } else if ([format containsString:@"tiff"] && len > 16) {
        // TIFF structure: header(8) + IFD entries (12 bytes each) + data
        // Byte order: II (little-endian) or MM (big-endian)
        BOOL isLE = (bytes[0] == 'I' && bytes[1] == 'I');
        BOOL isBE = (bytes[0] == 'M' && bytes[1] == 'M');

        uint32_t ifdOffset = 0;
        if ((isLE || isBE) && len >= 8) {
            if (isLE) {
                ifdOffset = bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24);
            } else {
                ifdOffset = (bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7];
            }
        }

        uint32_t mutation = arc4random_uniform(8);
        switch (mutation) {
            case 0: {
                // Corrupt IFD entry count to extremely large value
                if (ifdOffset + 2 <= len) {
                    uint16_t badCounts[] = {0, 1, 0xFF, 0xFFFF, 0x7FFF, 3000};
                    uint16_t val = badCounts[arc4random_uniform(6)];
                    if (isLE) {
                        bytes[ifdOffset] = val & 0xFF;
                        bytes[ifdOffset + 1] = (val >> 8) & 0xFF;
                    } else {
                        bytes[ifdOffset] = (val >> 8) & 0xFF;
                        bytes[ifdOffset + 1] = val & 0xFF;
                    }
                    NSLog(@"Corrupted TIFF IFD entry count to %u at offset %u", val, ifdOffset);
                }
                break;
            }
            case 1: {
                // Corrupt IFD tag type fields — set invalid TIFF data types
                if (ifdOffset + 2 <= len) {
                    uint16_t numEntries = isLE ? (bytes[ifdOffset] | (bytes[ifdOffset+1] << 8))
                                               : ((bytes[ifdOffset] << 8) | bytes[ifdOffset+1]);
                    if (numEntries > 0 && numEntries < 100 && ifdOffset + 2 + numEntries * 12 <= len) {
                        uint32_t entry = arc4random_uniform(numEntries);
                        size_t typeOff = ifdOffset + 2 + entry * 12 + 2;
                        uint16_t badTypes[] = {0, 14, 15, 99, 0xFF, 0xFFFF};
                        uint16_t val = badTypes[arc4random_uniform(6)];
                        if (isLE) {
                            bytes[typeOff] = val & 0xFF;
                            bytes[typeOff + 1] = (val >> 8) & 0xFF;
                        } else {
                            bytes[typeOff] = (val >> 8) & 0xFF;
                            bytes[typeOff + 1] = val & 0xFF;
                        }
                        NSLog(@"Corrupted TIFF IFD entry %u type to %u", entry, val);
                    }
                }
                break;
            }
            case 2: {
                // Corrupt strip offsets to point out of bounds
                if (ifdOffset + 2 <= len) {
                    uint16_t numEntries = isLE ? (bytes[ifdOffset] | (bytes[ifdOffset+1] << 8))
                                               : ((bytes[ifdOffset] << 8) | bytes[ifdOffset+1]);
                    if (numEntries > 0 && numEntries < 100) {
                        for (uint16_t e = 0; e < numEntries && ifdOffset + 2 + (e+1) * 12 <= len; e++) {
                            size_t tagOff = ifdOffset + 2 + e * 12;
                            uint16_t tag = isLE ? (bytes[tagOff] | (bytes[tagOff+1] << 8))
                                                : ((bytes[tagOff] << 8) | bytes[tagOff+1]);
                            if (tag == 273 || tag == 279) { // StripOffsets or StripByteCounts
                                size_t valOff = tagOff + 8;
                                uint32_t badVals[] = {0, 0xFFFFFFFF, (uint32_t)len + 1000, 0xDEADBEEF};
                                uint32_t val = badVals[arc4random_uniform(4)];
                                if (isLE) {
                                    bytes[valOff] = val & 0xFF; bytes[valOff+1] = (val>>8) & 0xFF;
                                    bytes[valOff+2] = (val>>16) & 0xFF; bytes[valOff+3] = (val>>24) & 0xFF;
                                } else {
                                    bytes[valOff] = (val>>24) & 0xFF; bytes[valOff+1] = (val>>16) & 0xFF;
                                    bytes[valOff+2] = (val>>8) & 0xFF; bytes[valOff+3] = val & 0xFF;
                                }
                                NSLog(@"Corrupted TIFF tag %u value to 0x%08X", tag, val);
                                break;
                            }
                        }
                    }
                }
                break;
            }
            case 3: {
                // Reorder IFD entries (violates TIFF spec requirement for ascending tag order)
                if (ifdOffset + 2 <= len) {
                    uint16_t numEntries = isLE ? (bytes[ifdOffset] | (bytes[ifdOffset+1] << 8))
                                               : ((bytes[ifdOffset] << 8) | bytes[ifdOffset+1]);
                    if (numEntries >= 2 && ifdOffset + 2 + numEntries * 12 <= len) {
                        uint32_t a = arc4random_uniform(numEntries);
                        uint32_t b = arc4random_uniform(numEntries);
                        if (a != b) {
                            unsigned char tmp[12];
                            size_t offA = ifdOffset + 2 + a * 12;
                            size_t offB = ifdOffset + 2 + b * 12;
                            memcpy(tmp, &bytes[offA], 12);
                            memcpy(&bytes[offA], &bytes[offB], 12);
                            memcpy(&bytes[offB], tmp, 12);
                            NSLog(@"Swapped TIFF IFD entries %u and %u (tag reorder)", a, b);
                        }
                    }
                }
                break;
            }
            case 4: {
                // Set next-IFD pointer to create circular reference
                if (ifdOffset + 2 <= len) {
                    uint16_t numEntries = isLE ? (bytes[ifdOffset] | (bytes[ifdOffset+1] << 8))
                                               : ((bytes[ifdOffset] << 8) | bytes[ifdOffset+1]);
                    if (numEntries < 200) {
                        size_t nextIFDOff = ifdOffset + 2 + numEntries * 12;
                        if (nextIFDOff + 4 <= len) {
                            // Point back to first IFD (circular) or to invalid offset
                            uint32_t targets[] = {ifdOffset, 0, 0xFFFFFFFF, 8, (uint32_t)(len - 1)};
                            uint32_t val = targets[arc4random_uniform(5)];
                            if (isLE) {
                                bytes[nextIFDOff] = val & 0xFF; bytes[nextIFDOff+1] = (val>>8) & 0xFF;
                                bytes[nextIFDOff+2] = (val>>16) & 0xFF; bytes[nextIFDOff+3] = (val>>24) & 0xFF;
                            } else {
                                bytes[nextIFDOff] = (val>>24) & 0xFF; bytes[nextIFDOff+1] = (val>>16) & 0xFF;
                                bytes[nextIFDOff+2] = (val>>8) & 0xFF; bytes[nextIFDOff+3] = val & 0xFF;
                            }
                            NSLog(@"Set TIFF next-IFD pointer to 0x%08X (circular/invalid)", val);
                        }
                    }
                }
                break;
            }
            case 5: {
                // Corrupt ICC Profile tag (34675) data length to trigger OOB read
                if (ifdOffset + 2 <= len) {
                    uint16_t numEntries = isLE ? (bytes[ifdOffset] | (bytes[ifdOffset+1] << 8))
                                               : ((bytes[ifdOffset] << 8) | bytes[ifdOffset+1]);
                    for (uint16_t e = 0; e < numEntries && ifdOffset + 2 + (e+1) * 12 <= len; e++) {
                        size_t tagOff = ifdOffset + 2 + e * 12;
                        uint16_t tag = isLE ? (bytes[tagOff] | (bytes[tagOff+1] << 8))
                                            : ((bytes[tagOff] << 8) | bytes[tagOff+1]);
                        if (tag == 34675) { // TIFFTAG_ICCPROFILE
                            size_t countOff = tagOff + 4;
                            uint32_t badSizes[] = {0, 1, 0xFFFFFF, 0x7FFFFFFF, (uint32_t)len * 2};
                            uint32_t val = badSizes[arc4random_uniform(5)];
                            if (isLE) {
                                bytes[countOff] = val & 0xFF; bytes[countOff+1] = (val>>8) & 0xFF;
                                bytes[countOff+2] = (val>>16) & 0xFF; bytes[countOff+3] = (val>>24) & 0xFF;
                            } else {
                                bytes[countOff] = (val>>24) & 0xFF; bytes[countOff+1] = (val>>16) & 0xFF;
                                bytes[countOff+2] = (val>>8) & 0xFF; bytes[countOff+3] = val & 0xFF;
                            }
                            NSLog(@"Corrupted TIFF ICC Profile tag count to 0x%08X", val);
                            break;
                        }
                    }
                }
                break;
            }
            case 6: {
                // Inject BigTIFF magic (0x002B instead of 0x002A) — confuses parsers
                if (len >= 4) {
                    if (isLE) {
                        bytes[2] = 0x2B; bytes[3] = 0x00; // BigTIFF version
                    } else if (isBE) {
                        bytes[2] = 0x00; bytes[3] = 0x2B;
                    }
                    NSLog(@"Injected BigTIFF magic (0x002B) into standard TIFF");
                }
                break;
            }
            case 7: {
                // Corrupt image dimensions (width/height tags 256/257)
                if (ifdOffset + 2 <= len) {
                    uint16_t numEntries = isLE ? (bytes[ifdOffset] | (bytes[ifdOffset+1] << 8))
                                               : ((bytes[ifdOffset] << 8) | bytes[ifdOffset+1]);
                    for (uint16_t e = 0; e < numEntries && ifdOffset + 2 + (e+1) * 12 <= len; e++) {
                        size_t tagOff = ifdOffset + 2 + e * 12;
                        uint16_t tag = isLE ? (bytes[tagOff] | (bytes[tagOff+1] << 8))
                                            : ((bytes[tagOff] << 8) | bytes[tagOff+1]);
                        if (tag == 256 || tag == 257) { // ImageWidth or ImageLength
                            size_t valOff = tagOff + 8;
                            uint32_t badDims[] = {0, 1, 0xFFFF, 0x7FFFFFFF, 100000};
                            uint32_t val = badDims[arc4random_uniform(5)];
                            if (isLE) {
                                bytes[valOff] = val & 0xFF; bytes[valOff+1] = (val>>8) & 0xFF;
                                bytes[valOff+2] = (val>>16) & 0xFF; bytes[valOff+3] = (val>>24) & 0xFF;
                            } else {
                                bytes[valOff] = (val>>24) & 0xFF; bytes[valOff+1] = (val>>16) & 0xFF;
                                bytes[valOff+2] = (val>>8) & 0xFF; bytes[valOff+3] = val & 0xFF;
                            }
                            NSLog(@"Corrupted TIFF tag %u (dimension) to %u", tag, val);
                        }
                    }
                }
                break;
            }
        }
    }

    // Strategy 3: Insert premultiplied alpha violation patterns in raw chunks
    if (arc4random_uniform(4) == 0 && len > 64) {
        size_t offset = safeStart + arc4random_uniform((uint32_t)(len - safeStart - 4));
        // Write R > A pattern (invalid for premultiplied formats)
        bytes[offset] = 0xFF;     // R
        bytes[offset+1] = 0xFF;   // G
        bytes[offset+2] = 0xFF;   // B
        bytes[offset+3] = 0x01;   // A (very low — R,G,B > A is invalid premultiplied)
        NSLog(@"Injected premultiplied alpha violation at offset %zu", offset);
    }

    NSLog(@"Post-encoding corruption: %zu bit flips applied to %lu byte %@ blob", flipCount, (unsigned long)len, format);
    return corrupted;
}

#pragma mark - applyFuzzingToBitmapContext

/*!
 * @brief Applies fuzzing to the RGB components of each pixel in a bitmap context.
 * @details This function introduces small, random variations to the RGB values of each pixel to test the resilience of image processing algorithms to input data variations. The fuzzing process adjusts the R, G, and B components of each pixel within a specified range, while optionally encoding additional data into the alpha channel of the first row of pixels. This method is useful for evaluating how image processing systems handle slight inconsistencies or errors in visual data.
 *
 * @param rawData Pointer to the bitmap's raw pixel data, modified in-place. Assumes RGBA format, with 4 bytes per pixel. RGB components are randomly adjusted, and the alpha channel of certain pixels may encode additional data.
 * @param width The width of the bitmap in pixels, determining the row length in the data array.
 * @param height The height of the bitmap in pixels, indicating the total number of rows.
 *
 * @note The function iterates over every pixel, applying a random adjustment of -25 to +25 to the RGB values, chosen to introduce noticeable yet non-drastic variations. The alpha channel is generally preserved to maintain transparency, except in the first row where specific pixels might encode data, demonstrating a technique for embedding metadata. This fuzzing aims to reveal how slight data variations affect image processing outcomes, with an optional feature for data encoding that showcases a method for preserving information through image transformations.
 *
 * - Utilizes `arc4random_uniform` for a uniform distribution of fuzz factors, avoiding biases.
 * - Directly modifies the `rawData`, requiring users to back up original data if preservation is needed.
 * - Maintains original transparency for most pixels, focusing visual impact on color variations only.
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

#pragma mark - Memory Handling

#pragma mark - debugMemoryHandling

/*!
 * @brief Allocates and deallocates memory chunks using mmap and munmap for debugging.
 *
 * @details This function facilitates memory handling debugging by allocating and then deallocating a predetermined number of memory chunks. It utilizes the mmap and munmap system calls, offering a lower-level look at memory management beyond what high-level languages typically provide. This approach is useful for examining application behavior under various memory conditions and demonstrating memory mapping techniques.
 *
 * - **Allocation**: Allocates 64 chunks of memory, each 64 KB in size, using the MAP_ANONYMOUS and MAP_PRIVATE flags with mmap, simulating a scenario where memory is used but not backed by any file.
 * - **Initialization**: Each allocated chunk is filled with the byte 0x41 ('A'), which can help in identifying how memory content changes over time or remains unaltered after certain operations.
 * - **Deallocation**: Utilizes munmap to free each allocated chunk, ensuring no memory leaks and providing a clean state post-execution.
 *
 * @note This function is instrumental for developers looking to understand or teach memory management intricacies, debug memory allocation issues, or test how their applications respond to specific memory usage patterns. It logs the address of each allocated and subsequently deallocated chunk, enhancing transparency in memory management operations.
 *
 * ### Example Usage:
 * @code
 * // Call debugMemoryHandling to observe memory allocation and deallocation behavior
 * debugMemoryHandling();
 *
 * // Output will include the address of allocated memory chunks and confirmation of their deallocation
 * @endcode
 *
 * - The use of NSLog for logging makes this function readily applicable in macOS or iOS development environments. However, the logging mechanism can be adapted for use in other environments as needed.
 * - The chosen memory chunk size (0x10000 bytes) and the number of chunks (64) can be modified to suit different debugging needs or to test application behavior under various memory load scenarios.
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

#pragma mark - Hash

#pragma mark - Hash String

/*!
 * @brief Computes a hash value for a given string.
 * @details This function implements the djb2 algorithm, a simple and effective hash function for strings. The algorithm iterates over each character in the input string, combining the previous hash value and the current character to produce a new hash. This method is known for its simplicity and decent distribution properties, making it suitable for a variety of hashing needs where extreme cryptographic security is not required.
 *
 * @param str Pointer to the input string to be hashed. The string is assumed to be null-terminated.
 * @return Returns an unsigned long representing the hash value of the input string.
 *
 * @note The hash value is computed using a specific formula: hash * 33 + c, where hash is the current hash value, and c is the ASCII value of the current character. This formula is applied iteratively over each character of the string, starting with an initial hash value of 5381, which is a commonly used starting point for the djb2 algorithm.
 */
unsigned long hashString(const char* str) {
    unsigned long hash = 5381; // Initial value for djb2 algorithm
    int c;

    // Iteratively compute the hash value for each character
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }

    return hash; // Return the computed hash value
}

#pragma mark - Random Images

#pragma mark - performAllImagePermutations

/*!
 * @brief Generates a random image and processes it with all permutation strategies.
 *
 * @details This function defines the dimensions and image type for a generated image,
 * creates the image data, writes it to a temporary file, loads the image, and processes
 * it with permutation -1, indicating all permutations.
 *
 * - **Image Generation**: Creates a random image with specified dimensions and type.
 * - **File Handling**: Writes the generated image data to a temporary file.
 * - **Image Loading**: Loads the generated image from the file.
 * - **Image Processing**: Processes the image with all permutations.
 *
 * @note This function is used when no command-line arguments are provided to automatically
 * generate and process an image.
 */
void performAllImagePermutations(void) {
    // Generate diverse seed images with varied dimensions and process each
    // through a different bitmap context permutation for maximum code coverage.
    // Minimum seed dimension is 16×16 to exercise meaningful decoder code paths.
    // Includes 3 new color spaces: CMYK, HDR Float16, Indexed Color.
    struct { size_t width; size_t height; int permutation; } specs[] = {
        { 64,  64,  1},  // Small square — StandardRGB
        {128, 128,  3},  // Medium square — NonPremultipliedAlpha
        {256, 256,  4},  // Large square — 16BitDepth
        {100, 200,  6},  // Tall rectangle — HDRFloat
        {200, 100,  7},  // Wide rectangle — AlphaOnly
        { 32,  32,  8},  // Tiny square — 1BitMonochrome
        {512, 512,  9},  // Large square — BigEndian
        { 80, 120, 10},  // Odd aspect — LittleEndian
        {160, 160, 11},  // Medium square — 8BitInvertedColors
        { 96,  96, 12},  // Small square — 32BitFloat4Component
        { 16,  16,  1},  // Small square — StandardRGB (was 1×1)
        { 24,  24,  5},  // Non-power-of-2 square — Grayscale (was 13×7)
        { 16,  32,  2},  // Narrow rectangle — PremultipliedFirstAlpha (was 3×1)
        { 32,  16,  4},  // Wide rectangle — 16BitDepth (was 1×100)
        { 48,  48, 13},  // Medium square — CMYK
        { 64,  32, 14},  // Wide rectangle — HDRFloat16
        { 32,  64, 15},  // Tall rectangle — IndexedColor
    };
    int count = sizeof(specs) / sizeof(specs[0]);

    CFStringRef imageType = (__bridge CFStringRef)UTTypePNG.identifier;
    const char *envDir = getenv("FUZZ_OUTPUT_DIR");
    NSArray<NSString *> *iccProfiles = loadICCProfilePaths();
    NSMutableArray<NSDictionary *> *allMetrics = [NSMutableArray array];

    NSString *outputDir;
    if (envDir) {
        outputDir = [NSString stringWithUTF8String:envDir];
    } else {
        outputDir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    }

    for (int i = 0; i < count; i++) {
        NSLog(@"=== Generating fuzzed image %d/%d: %zux%zu, permutation %d ===",
              i + 1, count, specs[i].width, specs[i].height, specs[i].permutation);

        NSData *fuzzedImage = generateFuzzedImageData(specs[i].width, specs[i].height, imageType);
        if (!fuzzedImage) {
            NSLog(@"Failed to generate fuzzed image data for spec %d", i + 1);
            continue;
        }

        // Save seed image with provenance name
        NSString *seedName = provenanceFileName(@"seed", specs[i].permutation, -1, nil, i + 1, @"png");
        NSString *seedPath = [outputDir stringByAppendingPathComponent:seedName];
        [fuzzedImage writeToFile:seedPath atomically:YES];
        NSLog(@"Seed image saved to %@", seedPath);

        // Also save a post-encoding corrupted variant of the seed
        NSData *corruptedPNG = applyPostEncodingCorruption(fuzzedImage, @"png");
        NSString *corruptedName = provenanceFileName(@"corrupted", specs[i].permutation, -1, nil, i + 1, @"png");
        NSString *corruptedPath = [outputDir stringByAppendingPathComponent:corruptedName];
        [corruptedPNG writeToFile:corruptedPath atomically:YES];
        NSLog(@"Corrupted seed saved to %@", corruptedPath);

        // Embed ICC profile if available (round-robin across profiles)
        if ([iccProfiles count] > 0) {
            NSString *iccPath = iccProfiles[i % [iccProfiles count]];
            NSString *iccName = [[iccPath lastPathComponent] stringByDeletingPathExtension];
            NSData *iccImage = embedICCProfile(fuzzedImage, iccPath, @"png");
            NSString *iccFileName = provenanceFileName(@"seed_icc", specs[i].permutation, -1, iccName, i + 1, @"png");
            NSString *iccFilePath = [outputDir stringByAppendingPathComponent:iccFileName];
            [iccImage writeToFile:iccFilePath atomically:YES];
            NSLog(@"ICC-embedded seed saved to %@", iccFilePath);

            // Collect metrics for ICC variant
            NSDictionary *iccMetrics = measureOutput(fuzzedImage, iccImage, iccFilePath);
            [allMetrics addObject:iccMetrics];
            writeMetricsJSON(iccMetrics, iccFilePath);
        }

        UIImage *image = [UIImage imageWithData:fuzzedImage];
        if (!image) {
            NSLog(@"Failed to load seed image %d from %@", i + 1, seedPath);
            continue;
        }

        processImage(image, specs[i].permutation);

        // Collect metrics for seed
        NSDictionary *seedMetrics = measureOutput(nil, fuzzedImage, seedPath);
        [allMetrics addObject:seedMetrics];
        writeMetricsJSON(seedMetrics, seedPath);

        NSLog(@"=== Completed image %d/%d ===", i + 1, count);
    }

    writeMetricsSummaryCSV(allMetrics, outputDir);
    NSLog(@"All %d fuzzed images generated successfully", count);
}

#pragma mark - generateFuzzedImageData

/*!
 * @brief Generates a random image for fuzzing.
 *
 * @details This function creates a random image with specified width, height, and type,
 * fills it with random data, and returns the generated image data.
 *
 * - **Parameters**:
 *   - width: The width of the generated image.
 *   - height: The height of the generated image.
 *   - imageType: The type of the generated image (e.g., PNG, JPEG).
 *
 * - **Image Data**: Allocates a buffer and fills it with random data.
 * - **Graphics Context**: Creates a bitmap graphics context and generates an image.
 * - **Image Destination**: Adds the image to a destination and finalizes it.
 *
 * @param width The width of the generated image.
 * @param height The height of the generated image.
 * @param imageType The type of the generated image.
 * @return NSData containing the generated image data.
 */
NSData* generateFuzzedImageData(size_t width, size_t height, CFStringRef imageType) {
    size_t bytesPerPixel = 4; // Assuming RGBA
    size_t bitsPerComponent = 8;
    size_t bytesPerRow = width * bytesPerPixel;
    size_t bufferSize = bytesPerRow * height;
    
    uint8_t *buffer = (uint8_t *)malloc(bufferSize);
    if (!buffer) {
        NSLog(@"Failed to allocate buffer for fuzzed image data");
        return nil;
    }
    for (size_t i = 0; i < bufferSize; i++) {
        buffer[i] = arc4random_uniform(256);
    }
    
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = CGBitmapContextCreate(buffer, width, height, bitsPerComponent, bytesPerRow, colorSpace, (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
    if (!context) {
        NSLog(@"Failed to create bitmap context in generateFuzzedImageData");
        CGColorSpaceRelease(colorSpace);
        free(buffer);
        return nil;
    }
    CGImageRef imageRef = CGBitmapContextCreateImage(context);
    if (!imageRef) {
        NSLog(@"Failed to create CGImage in generateFuzzedImageData");
        CGColorSpaceRelease(colorSpace);
        CGContextRelease(context);
        free(buffer);
        return nil;
    }
    
    NSMutableData *imageData = [NSMutableData data];
    CGImageDestinationRef destination = CGImageDestinationCreateWithData((CFMutableDataRef)imageData, imageType, 1, NULL);
    if (!destination) {
        NSLog(@"Failed to create image destination in generateFuzzedImageData");
        CGColorSpaceRelease(colorSpace);
        CGContextRelease(context);
        CGImageRelease(imageRef);
        free(buffer);
        return nil;
    }
    CGImageDestinationAddImage(destination, imageRef, NULL);
    CGImageDestinationFinalize(destination);
    
    CGColorSpaceRelease(colorSpace);
    CGContextRelease(context);
    CGImageRelease(imageRef);
    CFRelease(destination);
    free(buffer);
    
    return imageData;
}

#pragma mark - ICC Profile Embedding

/*!
 * @brief Embeds an ICC color profile into encoded image data.
 * @param imageData The source image data (PNG, TIFF, or JPEG).
 * @param iccProfilePath Path to the .icc profile file.
 * @param format The image format identifier (e.g., @"png", @"tiff", @"jpeg").
 * @return New NSData with the ICC profile embedded, or the original data on failure.
 */
NSData* embedICCProfile(NSData *imageData, NSString *iccProfilePath, NSString *format) {
    if (!imageData || !iccProfilePath) return imageData;

    NSData *iccData = [NSData dataWithContentsOfFile:iccProfilePath];
    if (!iccData) {
        NSLog(@"Failed to load ICC profile from %@", iccProfilePath);
        return imageData;
    }
    NSLog(@"Embedding ICC profile: %@ (%lu bytes)", [iccProfilePath lastPathComponent], (unsigned long)[iccData length]);

    // Create a color space from the ICC profile data
    CGColorSpaceRef iccColorSpace = CGColorSpaceCreateWithICCData((CFDataRef)iccData);
    if (!iccColorSpace) {
        NSLog(@"Failed to create color space from ICC profile (may be malformed — keeping as-is for fuzzing)");
        // For fuzzing purposes, embed the raw ICC data into the image properties
        // even if the color space can't be parsed — this exercises error paths
    }

    CGImageSourceRef source = CGImageSourceCreateWithData((CFDataRef)imageData, NULL);
    if (!source) {
        if (iccColorSpace) CGColorSpaceRelease(iccColorSpace);
        NSLog(@"Failed to create image source for ICC embedding");
        return imageData;
    }

    CGImageRef cgImage = CGImageSourceCreateImageAtIndex(source, 0, NULL);
    CFRelease(source);
    if (!cgImage) {
        if (iccColorSpace) CGColorSpaceRelease(iccColorSpace);
        NSLog(@"Failed to decode image for ICC embedding");
        return imageData;
    }

    // Re-render with the ICC color space if valid
    CGImageRef recoloredImage = cgImage;
    if (iccColorSpace) {
        // Determine number of components from the ICC color space
        size_t numComponents = CGColorSpaceGetNumberOfComponents(iccColorSpace);
        size_t width = CGImageGetWidth(cgImage);
        size_t height = CGImageGetHeight(cgImage);

        // Only re-render if the ICC space is RGB-compatible (3 components)
        if (numComponents == 3) {
            size_t bytesPerRow = width * 4;
            CGBitmapInfo bitmapInfo = (CGBitmapInfo)kCGImageAlphaPremultipliedLast;
            CGContextRef ctx = CGBitmapContextCreate(NULL, width, height, 8, bytesPerRow, iccColorSpace, bitmapInfo);
            if (ctx) {
                CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImage);
                CGImageRef rendered = CGBitmapContextCreateImage(ctx);
                if (rendered) {
                    CGImageRelease(cgImage);
                    recoloredImage = rendered;
                }
                CGContextRelease(ctx);
            }
        } else {
            NSLog(@"ICC profile has %zu components (not RGB) — attaching without re-render", numComponents);
        }
    }

    // Determine output UTType
    CFStringRef utType = (__bridge CFStringRef)UTTypePNG.identifier;
    if ([format containsString:@"tiff"]) {
        utType = (__bridge CFStringRef)UTTypeTIFF.identifier;
    } else if ([format containsString:@"jpeg"] || [format containsString:@"jpg"]) {
        utType = (__bridge CFStringRef)UTTypeJPEG.identifier;
    }

    NSMutableData *outputData = [NSMutableData data];
    CGImageDestinationRef dest = CGImageDestinationCreateWithData((CFMutableDataRef)outputData, utType, 1, NULL);
    if (!dest) {
        CGImageRelease(recoloredImage);
        if (iccColorSpace) CGColorSpaceRelease(iccColorSpace);
        NSLog(@"Failed to create image destination for ICC embedding");
        return imageData;
    }

    CGImageDestinationAddImage(dest, recoloredImage, NULL);
    BOOL ok = CGImageDestinationFinalize(dest);
    CFRelease(dest);
    CGImageRelease(recoloredImage);
    if (iccColorSpace) CGColorSpaceRelease(iccColorSpace);

    if (ok) {
        NSLog(@"ICC profile embedded successfully (%lu → %lu bytes)",
              (unsigned long)[imageData length], (unsigned long)[outputData length]);
        return outputData;
    }
    NSLog(@"Failed to finalize ICC-embedded image");
    return imageData;
}

/*!
 * @brief Loads ICC profile paths from FUZZ_ICC_DIR environment variable.
 * @return Array of .icc file paths, or empty array if none found.
 */
NSArray<NSString *>* loadICCProfilePaths(void) {
    const char *iccDir = getenv("FUZZ_ICC_DIR");
    if (!iccDir) return @[];

    NSString *dirPath = [NSString stringWithUTF8String:iccDir];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *error = nil;
    NSArray *contents = [fm contentsOfDirectoryAtPath:dirPath error:&error];
    if (error) {
        NSLog(@"Failed to scan FUZZ_ICC_DIR=%@: %@", dirPath, error.localizedDescription);
        return @[];
    }

    NSMutableArray *profiles = [NSMutableArray array];
    for (NSString *file in contents) {
        if ([[file pathExtension] caseInsensitiveCompare:@"icc"] == NSOrderedSame ||
            [[file pathExtension] caseInsensitiveCompare:@"icm"] == NSOrderedSame) {
            [profiles addObject:[dirPath stringByAppendingPathComponent:file]];
        }
    }
    NSLog(@"Found %lu ICC profiles in %@", (unsigned long)[profiles count], dirPath);
    return profiles;
}

#pragma mark - Color Space Diversity

/*!
 * @brief Creates a named color space by index for diversity testing.
 * @param index Color space index (0-6).
 * @return A CGColorSpaceRef (caller must release), or NULL on failure.
 */
CGColorSpaceRef createNamedColorSpace(int index) {
    CFStringRef names[] = {
        kCGColorSpaceSRGB,
        kCGColorSpaceAdobeRGB1998,
        kCGColorSpaceDisplayP3,
        kCGColorSpaceGenericRGBLinear,
        kCGColorSpaceGenericGrayGamma2_2,
        kCGColorSpaceACESCGLinear,
        kCGColorSpaceExtendedLinearSRGB
    };
    if (index < 0 || index >= NUM_NAMED_COLORSPACES) return NULL;
    CGColorSpaceRef cs = CGColorSpaceCreateWithName(names[index]);
    if (cs) {
        NSLog(@"Created color space: %@", (__bridge NSString *)CGColorSpaceCopyName(cs));
    }
    return cs;
}

#pragma mark - ICC Variant Generation

/*!
 * @brief Encodes a CGImage with a specific ICC profile embedded via color space re-rendering.
 * @details Creates a CGColorSpace from raw ICC data using CGColorSpaceCreateWithICCData(),
 * re-renders the image through that color space, and encodes the result. ImageIO
 * automatically embeds the ICC profile from the image's color space into the output.
 * This exercises the ICC parsing path in downstream consumers (sips, ColorSync, CFL
 * fuzzers). Only works for 3-component (RGB) ICC profiles.
 * @param image Source CGImageRef.
 * @param iccData Raw ICC profile bytes to embed.
 * @param utType Output format UTType (PNG, TIFF, JPEG).
 * @return Encoded image data with ICC profile attached, or nil on failure.
 */
NSData* encodeImageWithICCProfile(CGImageRef image, NSData *iccData, CFStringRef utType) {
    if (!image || !iccData) return nil;

    // Create a color space from the ICC profile data
    CGColorSpaceRef iccColorSpace = CGColorSpaceCreateWithICCData((CFDataRef)iccData);
    if (!iccColorSpace) {
        NSLog(@"ICC color space creation failed — embedding raw ICC via re-render fallback");
        // Fallback: encode the image as-is (no ICC attached)
        return nil;
    }

    // Re-render the image through the ICC color space
    size_t width = CGImageGetWidth(image);
    size_t height = CGImageGetHeight(image);
    size_t nComp = CGColorSpaceGetNumberOfComponents(iccColorSpace);

    // Only re-render for RGB-compatible (3-component) color spaces
    if (nComp != 3) {
        NSLog(@"ICC profile has %zu components (not RGB) — skipping re-render", nComp);
        CGColorSpaceRelease(iccColorSpace);
        return nil;
    }

    CGContextRef ctx = CGBitmapContextCreate(NULL, width, height, 8, width * 4,
        iccColorSpace, (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
    CGColorSpaceRelease(iccColorSpace);
    if (!ctx) return nil;

    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), image);
    CGImageRef iccImage = CGBitmapContextCreateImage(ctx);
    CGContextRelease(ctx);
    if (!iccImage) return nil;

    // Encode — ImageIO embeds the ICC profile from the image's color space
    NSMutableData *outputData = [NSMutableData data];
    CGImageDestinationRef dest = CGImageDestinationCreateWithData(
        (CFMutableDataRef)outputData, utType, 1, NULL);
    if (!dest) {
        CGImageRelease(iccImage);
        return nil;
    }

    CGImageDestinationAddImage(dest, iccImage, NULL);
    BOOL ok = CGImageDestinationFinalize(dest);
    CFRelease(dest);
    CGImageRelease(iccImage);

    return ok && [outputData length] > 0 ? outputData : nil;
}

/*!
 * @brief Encodes a CGImage with its color space stripped to DeviceRGB.
 * @details Re-renders the image through a DeviceRGB context (no ICC profile attached),
 * producing an image with no embedded ICC data. This exercises parsers' fallback
 * behavior when no color management information is present.
 * @param image Source CGImageRef.
 * @param utType Output format UTType.
 * @return Encoded image data without ICC profile, or nil on failure.
 */
NSData* encodeImageStrippingColorSpace(CGImageRef image, CFStringRef utType) {
    if (!image) return nil;

    size_t width = CGImageGetWidth(image);
    size_t height = CGImageGetHeight(image);
    CGColorSpaceRef deviceRGB = CGColorSpaceCreateDeviceRGB();
    if (!deviceRGB) return nil;

    CGContextRef ctx = CGBitmapContextCreate(NULL, width, height, 8, width * 4,
        deviceRGB, (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
    CGColorSpaceRelease(deviceRGB);
    if (!ctx) return nil;

    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), image);
    CGImageRef stripped = CGBitmapContextCreateImage(ctx);
    CGContextRelease(ctx);
    if (!stripped) return nil;

    NSMutableData *outputData = [NSMutableData data];
    CGImageDestinationRef dest = CGImageDestinationCreateWithData(
        (CFMutableDataRef)outputData, utType, 1, NULL);
    if (!dest) {
        CGImageRelease(stripped);
        return nil;
    }

    CGImageDestinationAddImage(dest, stripped, NULL);
    BOOL ok = CGImageDestinationFinalize(dest);
    CFRelease(dest);
    CGImageRelease(stripped);

    return ok && [outputData length] > 0 ? outputData : nil;
}

/*!
 * @brief Encodes a CGImage with a deliberately mismatched ICC profile.
 * @details Attaches an ICC profile whose color space (e.g., CMYK, Gray, Lab) does not
 * match the image's actual pixel data (typically RGB). This exercises error handling
 * and color space conversion fallback paths in ICC consumers. Cycles through 4
 * mismatch strategies per call using a static counter.
 * @param image Source CGImageRef.
 * @param utType Output format UTType.
 * @return Encoded image data with mismatched ICC profile, or nil on failure.
 */
NSData* encodeImageWithMismatchedProfile(CGImageRef image, CFStringRef utType) {
    if (!image) return nil;

    static int mismatchCounter = 0;
    int strategy = mismatchCounter++ % 4;

    // Build a synthetic ICC profile header with wrong color space
    // Minimal valid-looking 128-byte header + empty tag table
    uint8_t header[132];
    memset(header, 0, sizeof(header));

    // Profile size (132 bytes)
    header[0] = 0; header[1] = 0; header[2] = 0; header[3] = 132;
    // Version 4.4
    header[8] = 0x04; header[9] = 0x40;
    // 'acsp' magic at offset 36
    header[36] = 'a'; header[37] = 'c'; header[38] = 's'; header[39] = 'p';
    // Tag count = 0 at offset 128
    header[128] = 0; header[129] = 0; header[130] = 0; header[131] = 0;

    switch (strategy) {
        case 0:
            // CMYK profile on RGB image
            header[12] = 'p'; header[13] = 'r'; header[14] = 't'; header[15] = 'r'; // prtr
            header[16] = 'C'; header[17] = 'M'; header[18] = 'Y'; header[19] = 'K'; // CMYK
            header[20] = 'L'; header[21] = 'a'; header[22] = 'b'; header[23] = ' '; // Lab PCS
            NSLog(@"ICC mismatch: CMYK profile on RGB image");
            break;
        case 1:
            // Gray profile on RGB image
            header[12] = 'm'; header[13] = 'n'; header[14] = 't'; header[15] = 'r'; // mntr
            header[16] = 'G'; header[17] = 'R'; header[18] = 'A'; header[19] = 'Y'; // GRAY
            header[20] = 'X'; header[21] = 'Y'; header[22] = 'Z'; header[23] = ' '; // XYZ PCS
            NSLog(@"ICC mismatch: Gray profile on RGB image");
            break;
        case 2:
            // Lab profile as device class (abstract)
            header[12] = 'a'; header[13] = 'b'; header[14] = 's'; header[15] = 't'; // abst
            header[16] = 'L'; header[17] = 'a'; header[18] = 'b'; header[19] = ' '; // Lab
            header[20] = 'L'; header[21] = 'a'; header[22] = 'b'; header[23] = ' '; // Lab PCS
            NSLog(@"ICC mismatch: Abstract Lab profile on RGB image");
            break;
        case 3:
            // Truncated profile (size says 1024 but only 132 bytes)
            header[0] = 0; header[1] = 0; header[2] = 4; header[3] = 0; // size=1024
            header[12] = 'm'; header[13] = 'n'; header[14] = 't'; header[15] = 'r'; // mntr
            header[16] = 'R'; header[17] = 'G'; header[18] = 'B'; header[19] = ' '; // RGB
            header[20] = 'X'; header[21] = 'Y'; header[22] = 'Z'; header[23] = ' '; // XYZ PCS
            NSLog(@"ICC mismatch: truncated RGB profile (132 of 1024 bytes)");
            break;
    }

    // PCS illuminant D50 at offset 68-79
    // X=0.9642 Y=1.0000 Z=0.8249 as s15Fixed16Number
    header[68] = 0x00; header[69] = 0x00; header[70] = 0xF6; header[71] = 0xD6; // 0.9642
    header[72] = 0x00; header[73] = 0x01; header[74] = 0x00; header[75] = 0x00; // 1.0000
    header[76] = 0x00; header[77] = 0x00; header[78] = 0xD3; header[79] = 0x2D; // 0.8249

    NSData *fakeProfile = [NSData dataWithBytes:header length:sizeof(header)];
    return encodeImageWithICCProfile(image, fakeProfile, utType);
}

/*!
 * @brief Saves ICC variants alongside the base fuzzed image.
 * @details For each bitmap context output, generates up to 4 additional variants:
 *   1. With a real ICC profile from FUZZ_ICC_DIR (if available)
 *   2. With color space stripped (no ICC, DeviceRGB only)
 *   3. With a deliberately mismatched ICC profile
 *   4. With a mutated ICC profile (if FUZZ_ICC_DIR available)
 * This dramatically increases seed diversity for CFL fuzzers.
 * @param image The fuzzed UIImage from a bitmap context.
 * @param contextDescription The context name (e.g., "standard_rgb_tiff").
 */
void saveFuzzedImageWithICCVariants(UIImage *image, NSString *contextDescription) {
    if (!image || !image.CGImage) return;

    CGImageRef cgImage = image.CGImage;
    static NSArray<NSString *> *cachedICCPaths = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cachedICCPaths = loadICCProfilePaths();
    });

    // Determine output directory
    NSString *outputDir;
    const char *envDir = getenv("FUZZ_OUTPUT_DIR");
    if (envDir) {
        outputDir = [NSString stringWithUTF8String:envDir];
    } else {
        outputDir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    }

    // Determine base name and format UTType
    NSString *baseName = contextDescription;
    CFStringRef utType = (__bridge CFStringRef)UTTypePNG.identifier;
    NSString *ext = @"png";

    if ([contextDescription containsString:@"tiff"]) {
        utType = (__bridge CFStringRef)UTTypeTIFF.identifier;
        ext = @"tiff";
    } else if ([contextDescription containsString:@"jpeg"] || [contextDescription containsString:@"jpg"]) {
        utType = (__bridge CFStringRef)UTTypeJPEG.identifier;
        ext = @"jpg";
    }

    // Strip format suffix from base name
    for (NSString *suffix in @[@"_png", @"_jpeg", @"_jpg", @"_gif", @"_tiff"]) {
        if ([baseName hasSuffix:suffix]) {
            baseName = [baseName substringToIndex:[baseName length] - [suffix length]];
            break;
        }
    }

    // Variant 1: Real ICC profile from FUZZ_ICC_DIR (round-robin)
    if ([cachedICCPaths count] > 0) {
        static int iccRoundRobin = 0;
        NSString *iccPath = cachedICCPaths[iccRoundRobin % [cachedICCPaths count]];
        iccRoundRobin++;
        NSData *iccData = [NSData dataWithContentsOfFile:iccPath];
        if (iccData) {
            NSData *withICC = encodeImageWithICCProfile(cgImage, iccData, utType);
            if (withICC) {
                NSString *iccName = [[iccPath lastPathComponent] stringByDeletingPathExtension];
                NSString *fileName = [NSString stringWithFormat:@"fuzzed_image_%@_icc_%@.%@", baseName, iccName, ext];
                NSString *filePath = [outputDir stringByAppendingPathComponent:fileName];
                [withICC writeToFile:filePath atomically:YES];
                NSLog(@"ICC variant saved: %@ (%lu bytes)", fileName, (unsigned long)[withICC length]);
            }

            // Variant 4: Mutated ICC profile
            NSData *mutatedICC = mutateICCProfile(iccData);
            NSData *withMutated = encodeImageWithICCProfile(cgImage, mutatedICC, utType);
            if (withMutated) {
                NSString *fileName = [NSString stringWithFormat:@"fuzzed_image_%@_icc_mutated.%@", baseName, ext];
                NSString *filePath = [outputDir stringByAppendingPathComponent:fileName];
                [withMutated writeToFile:filePath atomically:YES];
                NSLog(@"Mutated ICC variant saved: %@ (%lu bytes)", fileName, (unsigned long)[withMutated length]);
            }
        }
    }

    // Variant 2: Stripped color space (no ICC, DeviceRGB only)
    NSData *stripped = encodeImageStrippingColorSpace(cgImage, utType);
    if (stripped) {
        NSString *fileName = [NSString stringWithFormat:@"fuzzed_image_%@_no_icc.%@", baseName, ext];
        NSString *filePath = [outputDir stringByAppendingPathComponent:fileName];
        [stripped writeToFile:filePath atomically:YES];
        NSLog(@"No-ICC variant saved: %@ (%lu bytes)", fileName, (unsigned long)[stripped length]);
    }

    // Variant 3: Mismatched ICC profile (CMYK/Gray/Lab on RGB, truncated)
    NSData *mismatched = encodeImageWithMismatchedProfile(cgImage, utType);
    if (mismatched) {
        NSString *fileName = [NSString stringWithFormat:@"fuzzed_image_%@_icc_mismatch.%@", baseName, ext];
        NSString *filePath = [outputDir stringByAppendingPathComponent:fileName];
        [mismatched writeToFile:filePath atomically:YES];
        NSLog(@"Mismatched ICC variant saved: %@ (%lu bytes)", fileName, (unsigned long)[mismatched length]);
    }
}

#pragma mark - Provenance File Naming

/*!
 * @brief Generates a structured file name encoding full provenance.
 * @param inputName Base name of the input image (without extension).
 * @param permutation The permutation index applied.
 * @param injection The injection string index used (-1 for none).
 * @param iccName The ICC profile name (nil for none).
 * @param seq Sequence number in a chain.
 * @param ext File extension (e.g., @"png").
 * @return A filename like: inputName_perm06_inj03_sRGB2014_001.png
 */
NSString* provenanceFileName(NSString *inputName, int permutation, int injection, NSString *iccName, int seq, NSString *ext) {
    NSString *injPart = (injection >= 0) ? [NSString stringWithFormat:@"_inj%02d", injection] : @"";
    NSString *iccPart = (iccName && [iccName length] > 0) ? [NSString stringWithFormat:@"_%@", iccName] : @"";
    return [NSString stringWithFormat:@"%@_perm%02d%@%@_%03d.%@",
            inputName, permutation, injPart, iccPart, seq, ext];
}

#pragma mark - Output Metrics

/*!
 * @brief Computes Shannon entropy of raw data.
 */
static double shannonEntropy(NSData *data) {
    if ([data length] == 0) return 0.0;
    unsigned long freq[256] = {0};
    const uint8_t *bytes = (const uint8_t *)[data bytes];
    NSUInteger len = [data length];
    for (NSUInteger i = 0; i < len; i++) {
        freq[bytes[i]]++;
    }
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)len;
        entropy -= p * log2(p);
    }
    return entropy;
}

/*!
 * @brief Computes SHA-256 hex digest of data.
 */
static NSString* sha256Hex(NSData *data) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256([data bytes], (CC_LONG)[data length], digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hex appendFormat:@"%02x", digest[i]];
    }
    return hex;
}

/*!
 * @brief Measures output image quality and provenance.
 * @param inputData The original input image data (may be nil for generated seeds).
 * @param outputData The fuzzed output image data.
 * @param outputPath The path where the output was saved.
 * @return Dictionary of metrics suitable for JSON serialization.
 */
NSDictionary* measureOutput(NSData *inputData, NSData *outputData, NSString *outputPath) {
    NSMutableDictionary *metrics = [NSMutableDictionary dictionary];
    metrics[@"output_path"] = outputPath ?: @"unknown";
    metrics[@"output_size"] = @([outputData length]);
    metrics[@"output_sha256"] = sha256Hex(outputData);
    metrics[@"output_entropy"] = @(shannonEntropy(outputData));
    metrics[@"timestamp"] = formattedCurrentDateTime();

    if (inputData) {
        metrics[@"input_size"] = @([inputData length]);
        metrics[@"input_sha256"] = sha256Hex(inputData);
        metrics[@"input_entropy"] = @(shannonEntropy(inputData));
        long delta = (long)[outputData length] - (long)[inputData length];
        metrics[@"size_delta"] = @(delta);
    }

    NSLog(@"Metrics: size=%lu entropy=%.4f sha256=%@",
          (unsigned long)[outputData length],
          [metrics[@"output_entropy"] doubleValue],
          metrics[@"output_sha256"]);
    return metrics;
}

/*!
 * @brief Writes metrics dictionary as JSON sidecar file.
 */
void writeMetricsJSON(NSDictionary *metrics, NSString *outputPath) {
    NSString *jsonPath = [[outputPath stringByDeletingPathExtension] stringByAppendingString:@".metrics.json"];
    NSError *error = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:metrics
                                                      options:NSJSONWritingPrettyPrinted
                                                        error:&error];
    if (jsonData && !error) {
        [jsonData writeToFile:jsonPath atomically:YES];
        NSLog(@"Metrics written to %@", jsonPath);
    } else {
        NSLog(@"Failed to write metrics JSON: %@", error.localizedDescription);
    }
}

/*!
 * @brief Writes a summary CSV of all metrics collected during a run.
 */
void writeMetricsSummaryCSV(NSArray<NSDictionary *> *allMetrics, NSString *outputDir) {
    if ([allMetrics count] == 0) return;
    NSString *csvPath = [outputDir stringByAppendingPathComponent:@"fuzz_metrics_summary.csv"];
    NSMutableString *csv = [NSMutableString string];
    [csv appendString:@"output_path,output_size,output_entropy,output_sha256,input_size,size_delta,timestamp\n"];
    for (NSDictionary *m in allMetrics) {
        [csv appendFormat:@"%@,%@,%.4f,%@,%@,%@,%@\n",
         m[@"output_path"] ?: @"",
         m[@"output_size"] ?: @"0",
         [m[@"output_entropy"] doubleValue],
         m[@"output_sha256"] ?: @"",
         m[@"input_size"] ?: @"",
         m[@"size_delta"] ?: @"",
         m[@"timestamp"] ?: @""];
    }
    [csv writeToFile:csvPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"Summary CSV written to %@ (%lu entries)", csvPath, (unsigned long)[allMetrics count]);
}

#pragma mark - Directory Scanning

/*!
 * @brief Scans a directory for image files suitable as fuzzer input.
 * @param directory Path to scan.
 * @return Array of full paths to image files.
 */
NSArray<NSString *>* scanDirectoryForImages(NSString *directory) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *error = nil;
    NSArray *contents = [fm contentsOfDirectoryAtPath:directory error:&error];
    if (error) {
        NSLog(@"Failed to scan directory %@: %@", directory, error.localizedDescription);
        return @[];
    }

    NSSet *imageExts = [NSSet setWithArray:@[
        @"png", @"jpg", @"jpeg", @"tiff", @"tif", @"gif", @"bmp", @"heic", @"heif",
        @"webp", @"jp2", @"exr", @"dng", @"tga", @"ico", @"icns", @"pbm", @"pdf",
        @"astc", @"ktx"
    ]];
    NSMutableArray *images = [NSMutableArray array];
    for (NSString *file in contents) {
        NSString *ext = [[file pathExtension] lowercaseString];
        if ([imageExts containsObject:ext]) {
            [images addObject:[directory stringByAppendingPathComponent:file]];
        }
    }
    NSLog(@"Found %lu image files in %@", (unsigned long)[images count], directory);
    return images;
}

#pragma mark - Chained Fuzzing

/*!
 * @brief Performs multi-pass chained fuzzing on a single input image.
 * @details Each iteration loads the previous output, applies a different permutation
 *          and injection string, optionally embeds an ICC profile, and measures the output.
 * @param inputPath Path to the initial input image.
 * @param iterations Number of chained passes.
 * @param allPermutations If YES, runs all 15 permutations per iteration.
 */
void performChainedFuzzing(NSString *inputPath, int iterations, BOOL allPermutations) {
    NSLog(@"=== Chained Fuzzing: %@ (%d iterations) ===", [inputPath lastPathComponent], iterations);

    NSString *outputDir;
    const char *envDir = getenv("FUZZ_OUTPUT_DIR");
    if (envDir) {
        outputDir = [NSString stringWithUTF8String:envDir];
    } else {
        outputDir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    }

    NSArray<NSString *> *iccProfiles = loadICCProfilePaths();
    NSMutableArray<NSDictionary *> *allMetrics = [NSMutableArray array];
    NSString *inputBaseName = [[inputPath lastPathComponent] stringByDeletingPathExtension];
    NSString *currentInputPath = inputPath;

    for (int iter = 0; iter < iterations; iter++) {
        NSLog(@"--- Chain iteration %d/%d ---", iter + 1, iterations);

        NSData *inputData = [NSData dataWithContentsOfFile:currentInputPath];
        if (!inputData) {
            NSLog(@"Failed to load input: %@", currentInputPath);
            break;
        }

        UIImage *image = [UIImage imageWithData:inputData];
        if (!image) {
            NSLog(@"Failed to decode image: %@", currentInputPath);
            break;
        }

        // Vary permutation and injection per iteration
        int perm = (iter % MAX_PERMUTATION) + 1;
        int injIdx = iter % NUMBER_OF_STRINGS;

        if (allPermutations) {
            processImage(image, ALL);
        } else {
            processImage(image, perm);
        }

        // Determine ICC profile for this iteration (round-robin)
        NSString *iccName = nil;
        NSString *iccPath = nil;
        if ([iccProfiles count] > 0) {
            iccPath = iccProfiles[iter % [iccProfiles count]];
            iccName = [[iccPath lastPathComponent] stringByDeletingPathExtension];
        }

        // Generate output with provenance name
        NSString *ext = @"png";
        NSString *fileName = provenanceFileName(inputBaseName, perm, injIdx, iccName, iter + 1, ext);
        NSString *outputPath = [outputDir stringByAppendingPathComponent:fileName];

        // Re-encode the processed image
        NSData *outputData = UIImagePNGRepresentation(image);
        if (!outputData) {
            NSLog(@"Failed to encode output at iteration %d", iter + 1);
            continue;
        }

        // Embed ICC profile if available
        if (iccPath) {
            outputData = embedICCProfile(outputData, iccPath, ext);
        }

        // Apply post-encoding corruption only on final iteration
        // (intermediate outputs must remain decodable for chaining)
        if (iter == iterations - 1) {
            outputData = applyPostEncodingCorruption(outputData, ext);
        }

        [outputData writeToFile:outputPath atomically:YES];
        NSLog(@"Chain output saved: %@", outputPath);

        // Measure and record metrics
        NSDictionary *metrics = measureOutput(inputData, outputData, outputPath);
        NSMutableDictionary *enriched = [metrics mutableCopy];
        enriched[@"iteration"] = @(iter + 1);
        enriched[@"permutation"] = @(perm);
        enriched[@"injection_index"] = @(injIdx);
        enriched[@"icc_profile"] = iccName ?: @"none";
        [allMetrics addObject:enriched];
        writeMetricsJSON(enriched, outputPath);

        // Feed output back as next iteration's input
        currentInputPath = outputPath;
    }

    writeMetricsSummaryCSV(allMetrics, outputDir);
    NSLog(@"=== Chained Fuzzing complete: %lu outputs ===", (unsigned long)[allMetrics count]);
}

#pragma mark - Batch Fuzzing

/*!
 * @brief Processes all images in a directory through chained fuzzing.
 * @param inputDir Directory containing input images.
 * @param iterations Number of chained iterations per image.
 */
void performBatchFuzzing(NSString *inputDir, int iterations) {
    NSArray<NSString *> *images = scanDirectoryForImages(inputDir);
    if ([images count] == 0) {
        NSLog(@"No images found in %@", inputDir);
        return;
    }
    NSLog(@"=== Batch Fuzzing: %lu images, %d iterations each ===",
          (unsigned long)[images count], iterations);
    for (NSString *imagePath in images) {
        performChainedFuzzing(imagePath, iterations, NO);
    }
    NSLog(@"=== Batch Fuzzing complete ===");
}

#pragma mark - Multi-Format Encoding

/*!
 * @brief Encodes a CGImageRef into the specified UTType format.
 * @param image Source image.
 * @param utType UTType identifier (e.g., UTTypePNG.identifier).
 * @param options Optional encoding properties (compression quality, etc.).
 * @return Encoded image data, or nil on failure.
 */
NSData* encodeImageAs(CGImageRef image, CFStringRef utType, NSDictionary *options) {
    if (!image || !utType) return nil;

    NSMutableData *outputData = [NSMutableData data];
    CGImageDestinationRef dest = CGImageDestinationCreateWithData(
        (CFMutableDataRef)outputData, utType, 1, NULL);
    if (!dest) return nil;

    CGImageDestinationAddImage(dest, image, (__bridge CFDictionaryRef)options);
    BOOL ok = CGImageDestinationFinalize(dest);
    CFRelease(dest);
    return ok && [outputData length] > 0 ? outputData : nil;
}

/*!
 * @brief Creates a TIFF thumbnail by scaling down the image.
 * @param image Source image.
 * @param maxDim Maximum width or height for the thumbnail.
 * @return TIFF-encoded thumbnail data.
 */
NSData* createTIFFThumbnail(CGImageRef image, size_t maxDim) {
    if (!image) return nil;

    size_t origW = CGImageGetWidth(image);
    size_t origH = CGImageGetHeight(image);
    CGFloat scale = (CGFloat)maxDim / MAX(origW, origH);
    if (scale >= 1.0) scale = 1.0;
    size_t thumbW = (size_t)(origW * scale);
    size_t thumbH = (size_t)(origH * scale);
    if (thumbW < 1) thumbW = 1;
    if (thumbH < 1) thumbH = 1;

    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(NULL, thumbW, thumbH, 8, thumbW * 4,
        cs, (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
    CGColorSpaceRelease(cs);
    if (!ctx) return nil;

    CGContextSetInterpolationQuality(ctx, kCGInterpolationHigh);
    CGContextDrawImage(ctx, CGRectMake(0, 0, thumbW, thumbH), image);
    CGImageRef thumbImage = CGBitmapContextCreateImage(ctx);
    CGContextRelease(ctx);
    if (!thumbImage) return nil;

    // Encode with LZW compression for TIFF
    NSDictionary *tiffOpts = @{
        (__bridge NSString *)kCGImagePropertyTIFFDictionary: @{
            (__bridge NSString *)kCGImagePropertyTIFFCompression: @5  // LZW
        }
    };
    NSData *result = encodeImageAs(thumbImage, (__bridge CFStringRef)UTTypeTIFF.identifier, tiffOpts);
    CGImageRelease(thumbImage);
    NSLog(@"TIFF thumbnail: %zux%zu → %zux%zu (%lu bytes)",
          origW, origH, thumbW, thumbH, (unsigned long)[result length]);
    return result;
}

/*!
 * @brief Encodes a CGImageRef into all supported image formats.
 * @details Produces outputs in PNG, JPEG (multiple qualities), TIFF (uncompressed + LZW),
 * BMP, GIF, HEIC, WebP, TIFF thumbnail, and OpenEXR where available.
 * Uses CGImageDestination with UTType identifiers for maximum format coverage.
 * @param image Source CGImageRef.
 * @return Dictionary mapping "format.ext" → encoded NSData.
 */
NSDictionary<NSString *, NSData *>* encodeImageMultiFormat(CGImageRef image) {
    if (!image) return @{};

    NSMutableDictionary<NSString *, NSData *> *results = [NSMutableDictionary dictionary];

    // Format table: { display name, UTType identifier string, file extension, options }
    // Core formats always available on Apple platforms
    struct {
        CFStringRef utType;
        const char *ext;
        const char *label;
        float quality; // -1 = no quality param
    } formats[] = {
        { (__bridge CFStringRef)UTTypePNG.identifier,  "png",  "PNG",           -1 },
        { (__bridge CFStringRef)UTTypeJPEG.identifier, "jpg",  "JPEG-high",     0.95 },
        { (__bridge CFStringRef)UTTypeJPEG.identifier, "jpeg", "JPEG-low",      0.10 },
        { (__bridge CFStringRef)UTTypeTIFF.identifier, "tiff", "TIFF",          -1 },
        { (__bridge CFStringRef)UTTypeGIF.identifier,  "gif",  "GIF",           -1 },
        { (__bridge CFStringRef)UTTypeBMP.identifier,  "bmp",  "BMP",           -1 },
        { (__bridge CFStringRef)UTTypeICO.identifier,  "ico",  "ICO",           -1 },
    };
    int numFormats = sizeof(formats) / sizeof(formats[0]);

    for (int i = 0; i < numFormats; i++) {
        NSDictionary *opts = nil;
        if (formats[i].quality >= 0) {
            opts = @{ (__bridge NSString *)kCGImageDestinationLossyCompressionQuality:
                      @(formats[i].quality) };
        }
        NSData *encoded = encodeImageAs(image, formats[i].utType, opts);
        if (encoded) {
            results[[NSString stringWithUTF8String:formats[i].ext]] = encoded;
            NSLog(@"  %-12s → %lu bytes", formats[i].label, (unsigned long)[encoded length]);
        }
    }

    // TIFF with LZW compression
    NSDictionary *lzwOpts = @{
        (__bridge NSString *)kCGImagePropertyTIFFDictionary: @{
            (__bridge NSString *)kCGImagePropertyTIFFCompression: @5
        }
    };
    NSData *tiffLZW = encodeImageAs(image, (__bridge CFStringRef)UTTypeTIFF.identifier, lzwOpts);
    if (tiffLZW) {
        results[@"tiff-lzw.tiff"] = tiffLZW;
        NSLog(@"  %-12s → %lu bytes", "TIFF-LZW", (unsigned long)[tiffLZW length]);
    }

    // TIFF thumbnail (64px max dimension)
    NSData *thumb = createTIFFThumbnail(image, 64);
    if (thumb) {
        results[@"thumb.tiff"] = thumb;
    }

    // HEIC — may not be available on all platforms, try dynamically
    CFStringRef heicType = (__bridge CFStringRef)@"public.heic";
    NSData *heic = encodeImageAs(image, heicType, @{
        (__bridge NSString *)kCGImageDestinationLossyCompressionQuality: @(0.8)
    });
    if (heic) {
        results[@"heic"] = heic;
        NSLog(@"  %-12s → %lu bytes", "HEIC", (unsigned long)[heic length]);
    }

    // HEIF
    CFStringRef heifType = (__bridge CFStringRef)@"public.heif";
    NSData *heif = encodeImageAs(image, heifType, @{
        (__bridge NSString *)kCGImageDestinationLossyCompressionQuality: @(0.8)
    });
    if (heif) {
        results[@"heif"] = heif;
        NSLog(@"  %-12s → %lu bytes", "HEIF", (unsigned long)[heif length]);
    }

    // WebP — available on macOS 14+ / iOS 17+
    CFStringRef webpType = (__bridge CFStringRef)@"org.webmproject.webp";
    NSData *webp = encodeImageAs(image, webpType, @{
        (__bridge NSString *)kCGImageDestinationLossyCompressionQuality: @(0.8)
    });
    if (webp) {
        results[@"webp"] = webp;
        NSLog(@"  %-12s → %lu bytes", "WebP", (unsigned long)[webp length]);
    }

    // JPEG 2000
    CFStringRef jp2Type = (__bridge CFStringRef)@"public.jpeg-2000";
    NSData *jp2 = encodeImageAs(image, jp2Type, @{
        (__bridge NSString *)kCGImageDestinationLossyCompressionQuality: @(0.8)
    });
    if (jp2) {
        results[@"jp2"] = jp2;
        NSLog(@"  %-12s → %lu bytes", "JPEG2000", (unsigned long)[jp2 length]);
    }

    // OpenEXR — may not be available
    CFStringRef exrType = (__bridge CFStringRef)@"com.ilm.openexr-image";
    NSData *exr = encodeImageAs(image, exrType, nil);
    if (exr) {
        results[@"exr"] = exr;
        NSLog(@"  %-12s → %lu bytes", "OpenEXR", (unsigned long)[exr length]);
    }

    // Adobe DNG — attempt via UTType
    CFStringRef dngType = (__bridge CFStringRef)@"com.adobe.raw-image";
    NSData *dng = encodeImageAs(image, dngType, nil);
    if (dng) {
        results[@"dng"] = dng;
        NSLog(@"  %-12s → %lu bytes", "DNG", (unsigned long)[dng length]);
    }

    // PBMRAW — Portable Bitmap
    CFStringRef pbmType = (__bridge CFStringRef)@"public.pbm";
    NSData *pbm = encodeImageAs(image, pbmType, nil);
    if (pbm) {
        results[@"pbm"] = pbm;
        NSLog(@"  %-12s → %lu bytes", "PBM", (unsigned long)[pbm length]);
    }

    // TGA — Targa
    CFStringRef tgaType = (__bridge CFStringRef)@"com.truevision.tga-image";
    NSData *tga = encodeImageAs(image, tgaType, nil);
    if (tga) {
        results[@"tga"] = tga;
        NSLog(@"  %-12s → %lu bytes", "TGA", (unsigned long)[tga length]);
    }

    // ASTC — Adaptive Scalable Texture Compression (Apple GPU format)
    CFStringRef astcType = (__bridge CFStringRef)@"org.khronos.astc";
    NSData *astc = encodeImageAs(image, astcType, nil);
    if (astc) {
        results[@"astc"] = astc;
        NSLog(@"  %-12s → %lu bytes", "ASTC", (unsigned long)[astc length]);
    }

    // KTX — Khronos Texture
    CFStringRef ktxType = (__bridge CFStringRef)@"org.khronos.ktx";
    NSData *ktx = encodeImageAs(image, ktxType, nil);
    if (ktx) {
        results[@"ktx"] = ktx;
        NSLog(@"  %-12s → %lu bytes", "KTX", (unsigned long)[ktx length]);
    }

    // ── Formats targeted at Preview / Notes / iMessage / Mail parsers ──

    // PDF — single-page image PDF (Preview, Mail inline, Notes, iMessage rich links)
    CFStringRef pdfType = (__bridge CFStringRef)@"com.adobe.pdf";
    NSData *pdf = encodeImageAs(image, pdfType, nil);
    if (pdf) {
        results[@"pdf"] = pdf;
        NSLog(@"  %-12s → %lu bytes", "PDF", (unsigned long)[pdf length]);
    }

    // ICNS — macOS icon format (Preview, Finder, QuickLook)
    CFStringRef icnsType = (__bridge CFStringRef)@"com.apple.icns";
    NSData *icns = encodeImageAs(image, icnsType, nil);
    if (icns) {
        results[@"icns"] = icns;
        NSLog(@"  %-12s → %lu bytes", "ICNS", (unsigned long)[icns length]);
    }

    // TIFF with PackBits compression (common in Mail attachments)
    NSDictionary *packBitsOpts = @{
        (__bridge NSString *)kCGImagePropertyTIFFDictionary: @{
            (__bridge NSString *)kCGImagePropertyTIFFCompression: @(32773) // PackBits
        }
    };
    NSData *tiffPB = encodeImageAs(image, (__bridge CFStringRef)UTTypeTIFF.identifier, packBitsOpts);
    if (tiffPB) {
        results[@"tiff-packbits.tiff"] = tiffPB;
        NSLog(@"  %-12s → %lu bytes", "TIFF-PackBits", (unsigned long)[tiffPB length]);
    }

    // TIFF with JPEG compression (Preview handles, exercises TIFF+JPEG decoder interplay)
    NSDictionary *tiffJpegOpts = @{
        (__bridge NSString *)kCGImagePropertyTIFFDictionary: @{
            (__bridge NSString *)kCGImagePropertyTIFFCompression: @7  // JPEG-in-TIFF
        }
    };
    NSData *tiffJpeg = encodeImageAs(image, (__bridge CFStringRef)UTTypeTIFF.identifier, tiffJpegOpts);
    if (tiffJpeg) {
        results[@"tiff-jpeg.tiff"] = tiffJpeg;
        NSLog(@"  %-12s → %lu bytes", "TIFF-JPEG", (unsigned long)[tiffJpeg length]);
    }

    // TIFF with Deflate/ZIP compression
    NSDictionary *tiffDeflateOpts = @{
        (__bridge NSString *)kCGImagePropertyTIFFDictionary: @{
            (__bridge NSString *)kCGImagePropertyTIFFCompression: @(32946) // Deflate
        }
    };
    NSData *tiffDeflate = encodeImageAs(image, (__bridge CFStringRef)UTTypeTIFF.identifier, tiffDeflateOpts);
    if (tiffDeflate) {
        results[@"tiff-deflate.tiff"] = tiffDeflate;
        NSLog(@"  %-12s → %lu bytes", "TIFF-Deflate", (unsigned long)[tiffDeflate length]);
    }

    // JPEG with EXIF-heavy properties (iMessage/Mail preview thumbnail path)
    NSDictionary *jpegExifOpts = @{
        (__bridge NSString *)kCGImageDestinationLossyCompressionQuality: @(0.5),
        (__bridge NSString *)kCGImagePropertyExifDictionary: @{
            (__bridge NSString *)kCGImagePropertyExifUserComment: @"fuzzed",
            (__bridge NSString *)kCGImagePropertyExifColorSpace: @(65535), // Uncalibrated
        },
        (__bridge NSString *)kCGImagePropertyTIFFDictionary: @{
            (__bridge NSString *)kCGImagePropertyTIFFSoftware: @"XNUImageFuzzer",
        }
    };
    NSData *jpegExif = encodeImageAs(image, (__bridge CFStringRef)UTTypeJPEG.identifier, jpegExifOpts);
    if (jpegExif) {
        results[@"jpeg-exif.jpg"] = jpegExif;
        NSLog(@"  %-12s → %lu bytes", "JPEG-EXIF", (unsigned long)[jpegExif length]);
    }

    // HEIC with max quality (iMessage default sending format on modern iOS)
    NSData *heicHQ = encodeImageAs(image, heicType, @{
        (__bridge NSString *)kCGImageDestinationLossyCompressionQuality: @(1.0)
    });
    if (heicHQ) {
        results[@"heic-hq.heic"] = heicHQ;
        NSLog(@"  %-12s → %lu bytes", "HEIC-HQ", (unsigned long)[heicHQ length]);
    }

    // HEIC with minimum quality (stresses decompressor edge cases)
    NSData *heicLQ = encodeImageAs(image, heicType, @{
        (__bridge NSString *)kCGImageDestinationLossyCompressionQuality: @(0.01)
    });
    if (heicLQ) {
        results[@"heic-lq.heic"] = heicLQ;
        NSLog(@"  %-12s → %lu bytes", "HEIC-LQ", (unsigned long)[heicLQ length]);
    }

    // ── ICC Profile Variant Encodings (for CFL fuzzer seed diversity) ──

    // TIFF with stripped color space (no ICC metadata)
    NSData *tiffNoICC = encodeImageStrippingColorSpace(image, (__bridge CFStringRef)UTTypeTIFF.identifier);
    if (tiffNoICC) {
        results[@"tiff-no-icc.tiff"] = tiffNoICC;
        NSLog(@"  %-12s → %lu bytes", "TIFF-noICC", (unsigned long)[tiffNoICC length]);
    }

    // PNG with stripped color space
    NSData *pngNoICC = encodeImageStrippingColorSpace(image, (__bridge CFStringRef)UTTypePNG.identifier);
    if (pngNoICC) {
        results[@"png-no-icc.png"] = pngNoICC;
        NSLog(@"  %-12s → %lu bytes", "PNG-noICC", (unsigned long)[pngNoICC length]);
    }

    // TIFF with mismatched ICC profile (exercises ICC parse error paths)
    NSData *tiffMismatch = encodeImageWithMismatchedProfile(image, (__bridge CFStringRef)UTTypeTIFF.identifier);
    if (tiffMismatch) {
        results[@"tiff-icc-mismatch.tiff"] = tiffMismatch;
        NSLog(@"  %-12s → %lu bytes", "TIFF-mismatch", (unsigned long)[tiffMismatch length]);
    }

    // PNG with mismatched ICC profile
    NSData *pngMismatch = encodeImageWithMismatchedProfile(image, (__bridge CFStringRef)UTTypePNG.identifier);
    if (pngMismatch) {
        results[@"png-icc-mismatch.png"] = pngMismatch;
        NSLog(@"  %-12s → %lu bytes", "PNG-mismatch", (unsigned long)[pngMismatch length]);
    }

    // TIFF with each of the 7 named color spaces
    for (int csIdx = 0; csIdx < 7; csIdx++) {
        CGColorSpaceRef namedCS = createNamedColorSpace(csIdx);
        if (!namedCS) continue;

        // Re-render through named color space
        size_t w = CGImageGetWidth(image);
        size_t h = CGImageGetHeight(image);
        size_t nComp = CGColorSpaceGetNumberOfComponents(namedCS);
        size_t bitsPerComp = 8;
        size_t bytesPerRow = w * (nComp + 1); // +1 for alpha
        CGBitmapInfo bitmapInfo = (CGBitmapInfo)kCGImageAlphaPremultipliedLast;

        // Only render for RGB-compatible color spaces (3 components)
        if (nComp == 3) {
            CGContextRef csCtx = CGBitmapContextCreate(NULL, w, h, bitsPerComp,
                bytesPerRow, namedCS, bitmapInfo);
            if (csCtx) {
                CGContextDrawImage(csCtx, CGRectMake(0, 0, w, h), image);
                CGImageRef csImage = CGBitmapContextCreateImage(csCtx);
                CGContextRelease(csCtx);
                if (csImage) {
                    NSData *csEncoded = encodeImageAs(csImage,
                        (__bridge CFStringRef)UTTypeTIFF.identifier, nil);
                    if (csEncoded) {
                        CFStringRef csName = CGColorSpaceCopyName(namedCS);
                        NSString *key = [NSString stringWithFormat:@"tiff-cs%d.tiff", csIdx];
                        results[key] = csEncoded;
                        NSLog(@"  TIFF-CS%-5d → %lu bytes (%@)", csIdx,
                              (unsigned long)[csEncoded length],
                              csName ? (__bridge NSString *)csName : @"unknown");
                        if (csName) CFRelease(csName);
                    }
                    CGImageRelease(csImage);
                }
            }
        }
        CGColorSpaceRelease(namedCS);
    }

    NSLog(@"Multi-format encoding: %lu formats produced", (unsigned long)[results count]);
    return results;
}

#pragma mark - ICC Profile Mutation

/*!
 * @brief Mutates ICC profile binary data to exercise parser error paths.
 * @details Applies targeted corruption strategies to ICC profile data:
 *   - Tag table offset/size corruption
 *   - Profile header field mutation (version, class, color space, PCS)
 *   - CLUT data corruption in rendering intent tags (A2B/B2A)
 *   - Random byte flips preserving the 'acsp' signature
 * @param profileData Original ICC profile data.
 * @return Mutated copy of the profile data.
 */
NSData* mutateICCProfile(NSData *profileData) {
    if (!profileData || [profileData length] < 132) return profileData;

    NSMutableData *mutated = [profileData mutableCopy];
    unsigned char *bytes = (unsigned char *)[mutated mutableBytes];
    NSUInteger len = [mutated length];

    uint32_t strategy = arc4random_uniform(6);

    switch (strategy) {
        case 0: {
            // Corrupt tag count and tag table entries (offset 128+)
            if (len > 132) {
                // Tag count at offset 128 (4 bytes, big-endian)
                uint32_t origCount = ((uint32_t)bytes[128] << 24) | ((uint32_t)bytes[129] << 16) |
                                     ((uint32_t)bytes[130] << 8) | bytes[131];
                uint32_t newCount = arc4random_uniform(2) == 0 ? origCount + arc4random_uniform(100) : 0xFFFF;
                bytes[128] = (newCount >> 24) & 0xFF;
                bytes[129] = (newCount >> 16) & 0xFF;
                bytes[130] = (newCount >>  8) & 0xFF;
                bytes[131] = newCount & 0xFF;
                NSLog(@"ICC mutation: tag count %u → %u", origCount, newCount);
            }
            break;
        }
        case 1: {
            // Corrupt tag offsets/sizes to trigger OOB reads
            // Each tag entry is 12 bytes starting at offset 132: sig(4) + offset(4) + size(4)
            if (len > 144) {
                uint32_t tagCount = ((uint32_t)bytes[128] << 24) | ((uint32_t)bytes[129] << 16) |
                                     ((uint32_t)bytes[130] << 8) | bytes[131];
                if (tagCount > 0 && tagCount < 200) {
                    uint32_t tagIdx = arc4random_uniform(tagCount > 10 ? 10 : tagCount);
                    size_t entryOff = 132 + tagIdx * 12;
                    if (entryOff + 12 <= len) {
                        // Set offset to near end of profile or beyond
                        uint32_t bigOffset = (uint32_t)(len - arc4random_uniform(16));
                        bytes[entryOff + 4] = (bigOffset >> 24) & 0xFF;
                        bytes[entryOff + 5] = (bigOffset >> 16) & 0xFF;
                        bytes[entryOff + 6] = (bigOffset >>  8) & 0xFF;
                        bytes[entryOff + 7] = bigOffset & 0xFF;
                        // Set size to very large
                        uint32_t bigSize = 0xFFFFFF00 | arc4random_uniform(256);
                        bytes[entryOff + 8]  = (bigSize >> 24) & 0xFF;
                        bytes[entryOff + 9]  = (bigSize >> 16) & 0xFF;
                        bytes[entryOff + 10] = (bigSize >>  8) & 0xFF;
                        bytes[entryOff + 11] = bigSize & 0xFF;
                        NSLog(@"ICC mutation: tag[%u] offset→0x%X size→0x%X", tagIdx, bigOffset, bigSize);
                    }
                }
            }
            break;
        }
        case 2: {
            // Mutate header fields: version(8-11), device class(12-15),
            // color space(16-19), PCS(20-23), rendering intent(64-67)
            size_t fields[] = {8, 12, 16, 20, 64};
            int fieldIdx = arc4random_uniform(5);
            size_t off = fields[fieldIdx];
            if (off + 4 <= len) {
                for (int j = 0; j < 4; j++) {
                    bytes[off + j] = arc4random_uniform(256);
                }
                NSLog(@"ICC mutation: header field at offset %zu randomized", off);
            }
            break;
        }
        case 3: {
            // Find A2B0/B2A0 tags and corrupt CLUT data
            // Walk tag table looking for 'A2B0' or 'B2A0' signatures
            uint32_t tagCount = ((uint32_t)bytes[128] << 24) | ((uint32_t)bytes[129] << 16) |
                                 ((uint32_t)bytes[130] << 8) | bytes[131];
            if (tagCount > 200) tagCount = 200;
            for (uint32_t t = 0; t < tagCount && 132 + t * 12 + 12 <= len; t++) {
                size_t entryOff = 132 + t * 12;
                char sig[5] = {bytes[entryOff], bytes[entryOff+1], bytes[entryOff+2], bytes[entryOff+3], 0};
                if (strcmp(sig, "A2B0") == 0 || strcmp(sig, "B2A0") == 0 ||
                    strcmp(sig, "A2B1") == 0 || strcmp(sig, "B2A1") == 0) {
                    uint32_t tagOff = ((uint32_t)bytes[entryOff+4] << 24) | ((uint32_t)bytes[entryOff+5] << 16) |
                                      ((uint32_t)bytes[entryOff+6] << 8) | bytes[entryOff+7];
                    uint32_t tagSize = ((uint32_t)bytes[entryOff+8] << 24) | ((uint32_t)bytes[entryOff+9] << 16) |
                                       ((uint32_t)bytes[entryOff+10] << 8) | bytes[entryOff+11];
                    if (tagOff < len && tagOff + tagSize <= len && tagSize > 32) {
                        // Corrupt CLUT grid points and data within the tag
                        size_t corruptStart = tagOff + 16;
                        size_t corruptCount = tagSize > 64 ? 32 : tagSize / 4;
                        for (size_t c = 0; c < corruptCount && corruptStart + c < len; c++) {
                            bytes[corruptStart + c] ^= arc4random_uniform(256);
                        }
                        NSLog(@"ICC mutation: corrupted %zu bytes in %s tag at offset %u", corruptCount, sig, tagOff);
                    }
                    break;
                }
            }
            break;
        }
        case 4: {
            // Set profile size field (bytes 0-3) to wrong value
            uint32_t wrongSize = arc4random_uniform(2) == 0 ? (uint32_t)len * 2 : 64;
            bytes[0] = (wrongSize >> 24) & 0xFF;
            bytes[1] = (wrongSize >> 16) & 0xFF;
            bytes[2] = (wrongSize >>  8) & 0xFF;
            bytes[3] = wrongSize & 0xFF;
            NSLog(@"ICC mutation: profile size header → %u (actual %lu)", wrongSize, (unsigned long)len);
            break;
        }
        case 5: {
            // Random byte flips (2%) preserving 'acsp' signature at 36-39
            size_t flipCount = len / 50;
            for (size_t i = 0; i < flipCount; i++) {
                size_t off = arc4random_uniform((uint32_t)len);
                if (off >= 36 && off <= 39) continue; // preserve 'acsp'
                bytes[off] ^= (1 << arc4random_uniform(8));
            }
            NSLog(@"ICC mutation: %zu random byte flips (acsp preserved)", flipCount);
            break;
        }
    }

    return mutated;
}

#pragma mark - embedICCProfileData

/*!
 * @brief Embeds ICC profile from raw NSData (not file path) into an image.
 * @param imageData Source image data.
 * @param iccData Raw ICC profile bytes.
 * @param format Image format identifier.
 * @return Image data with ICC profile embedded.
 */
NSData* embedICCProfileData(NSData *imageData, NSData *iccData, NSString *format) {
    if (!imageData || !iccData) return imageData;

    CGColorSpaceRef iccColorSpace = CGColorSpaceCreateWithICCData((CFDataRef)iccData);
    // Even if NULL (malformed), we still try to exercise the path

    CGImageSourceRef source = CGImageSourceCreateWithData((CFDataRef)imageData, NULL);
    if (!source) {
        if (iccColorSpace) CGColorSpaceRelease(iccColorSpace);
        return imageData;
    }

    CGImageRef cgImage = CGImageSourceCreateImageAtIndex(source, 0, NULL);
    CFRelease(source);
    if (!cgImage) {
        if (iccColorSpace) CGColorSpaceRelease(iccColorSpace);
        return imageData;
    }

    CGImageRef outputImage = cgImage;
    if (iccColorSpace) {
        size_t numComponents = CGColorSpaceGetNumberOfComponents(iccColorSpace);
        size_t width = CGImageGetWidth(cgImage);
        size_t height = CGImageGetHeight(cgImage);
        if (numComponents == 3) {
            CGContextRef ctx = CGBitmapContextCreate(NULL, width, height, 8, width * 4,
                iccColorSpace, (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
            if (ctx) {
                CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImage);
                CGImageRef rendered = CGBitmapContextCreateImage(ctx);
                if (rendered) {
                    CGImageRelease(cgImage);
                    outputImage = rendered;
                }
                CGContextRelease(ctx);
            }
        }
    }

    CFStringRef utType = (__bridge CFStringRef)UTTypePNG.identifier;
    if ([format containsString:@"tiff"]) utType = (__bridge CFStringRef)UTTypeTIFF.identifier;
    else if ([format containsString:@"jpg"] || [format containsString:@"jpeg"]) utType = (__bridge CFStringRef)UTTypeJPEG.identifier;

    NSMutableData *outputData = [NSMutableData data];
    CGImageDestinationRef dest = CGImageDestinationCreateWithData((CFMutableDataRef)outputData, utType, 1, NULL);
    if (!dest) {
        CGImageRelease(outputImage);
        if (iccColorSpace) CGColorSpaceRelease(iccColorSpace);
        return imageData;
    }

    CGImageDestinationAddImage(dest, outputImage, NULL);
    BOOL ok = CGImageDestinationFinalize(dest);
    CFRelease(dest);
    CGImageRelease(outputImage);
    if (iccColorSpace) CGColorSpaceRelease(iccColorSpace);

    return ok ? outputData : imageData;
}

#pragma mark - Pipeline Fuzzing

/*!
 * @brief Full pipeline: clean images → multi-format → fuzz → ICC embed → ICC+image fuzz → measure.
 * @details For each input image from xnuimagetools generators:
 *   Phase 1:   Save the clean image as-is (baseline)
 *   Phase 1.5: Re-encode into all supported formats (PNG, JPEG, TIFF, BMP, GIF,
 *              HEIC, WebP, JP2, EXR, DNG, TGA, ASTC, KTX, TIFF thumbnails)
 *   Phase 2:   Fuzz each format variant through bitmap permutations
 *   Phase 3:   Embed each clean ICC profile into the clean image
 *   Phase 4:   Embed mutated ICC profiles + fuzz the image (combined attack)
 *   Phase 5:   Chain iterations feeding fuzzed output back as input
 * All outputs get provenance names and metrics (SHA-256, entropy, JSON sidecar).
 * Mutated ICC profiles are saved alongside images for downstream CFL/iccDEV analysis.
 *
 * @param inputDir Directory of clean images (from xnuimagetools generators).
 * @param iterations Number of chained iterations for Phase 5.
 */
void performPipelineFuzzing(NSString *inputDir, int iterations) {
    NSArray<NSString *> *images = scanDirectoryForImages(inputDir);
    if ([images count] == 0) {
        NSLog(@"Pipeline: no images found in %@", inputDir);
        return;
    }

    NSArray<NSString *> *iccProfiles = loadICCProfilePaths();
    const char *envDir = getenv("FUZZ_OUTPUT_DIR");
    NSString *outputDir;
    if (envDir) {
        outputDir = [NSString stringWithUTF8String:envDir];
    } else {
        outputDir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    }

    // Create subdirectories for organized output
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *cleanDir   = [outputDir stringByAppendingPathComponent:@"pipeline-clean"];
    NSString *formatsDir = [outputDir stringByAppendingPathComponent:@"pipeline-formats"];
    NSString *fuzzedDir  = [outputDir stringByAppendingPathComponent:@"pipeline-fuzzed"];
    NSString *iccDir     = [outputDir stringByAppendingPathComponent:@"pipeline-icc"];
    NSString *comboDir   = [outputDir stringByAppendingPathComponent:@"pipeline-combo"];
    NSString *chainDir   = [outputDir stringByAppendingPathComponent:@"pipeline-chained"];
    NSString *profileDir = [outputDir stringByAppendingPathComponent:@"pipeline-profiles"];
    for (NSString *d in @[cleanDir, formatsDir, fuzzedDir, iccDir, comboDir, chainDir, profileDir]) {
        [fm createDirectoryAtPath:d withIntermediateDirectories:YES attributes:nil error:nil];
    }

    NSMutableArray<NSDictionary *> *allMetrics = [NSMutableArray array];
    int totalOutputs = 0;

    NSLog(@"=== Pipeline Fuzzing: %lu images, %lu ICC profiles, %d iterations ===",
          (unsigned long)[images count], (unsigned long)[iccProfiles count], iterations);

    for (NSUInteger imgIdx = 0; imgIdx < [images count]; imgIdx++) {
        NSString *imagePath = images[imgIdx];
        NSString *baseName = [[imagePath lastPathComponent] stringByDeletingPathExtension];
        NSString *ext = [[imagePath pathExtension] lowercaseString];
        if ([ext length] == 0) ext = @"png";

        NSData *cleanData = [NSData dataWithContentsOfFile:imagePath];
        if (!cleanData) {
            NSLog(@"Pipeline: failed to load %@", imagePath);
            continue;
        }

        NSLog(@"--- Pipeline image %lu/%lu: %@ (%lu bytes) ---",
              (unsigned long)(imgIdx + 1), (unsigned long)[images count], baseName,
              (unsigned long)[cleanData length]);

        // ── Phase 1: Save clean baseline ──
        NSString *cleanPath = [cleanDir stringByAppendingPathComponent:
            [NSString stringWithFormat:@"%@_clean.%@", baseName, ext]];
        [cleanData writeToFile:cleanPath atomically:YES];
        NSDictionary *cleanMetrics = measureOutput(nil, cleanData, cleanPath);
        NSMutableDictionary *cm = [cleanMetrics mutableCopy];
        cm[@"phase"] = @"clean";
        cm[@"source"] = baseName;
        [allMetrics addObject:cm];
        writeMetricsJSON(cm, cleanPath);
        totalOutputs++;

        // ── Phase 1.5: Multi-format re-encoding ──
        UIImage *cleanImage = [UIImage imageWithData:cleanData];
        CGImageRef cgClean = cleanImage ? cleanImage.CGImage : NULL;
        if (cgClean) {
            NSLog(@"Phase 1.5: encoding %@ into all supported formats", baseName);
            NSDictionary<NSString *, NSData *> *formatOutputs = encodeImageMultiFormat(cgClean);
            for (NSString *fmtExt in formatOutputs) {
                NSData *fmtData = formatOutputs[fmtExt];
                NSString *fmtName = [NSString stringWithFormat:@"%@.%@", baseName, fmtExt];
                NSString *fmtPath = [formatsDir stringByAppendingPathComponent:fmtName];
                [fmtData writeToFile:fmtPath atomically:YES];

                NSDictionary *fmtMetrics = measureOutput(cleanData, fmtData, fmtPath);
                NSMutableDictionary *fe = [fmtMetrics mutableCopy];
                fe[@"phase"] = @"format";
                fe[@"source"] = baseName;
                fe[@"format"] = fmtExt;
                [allMetrics addObject:fe];
                writeMetricsJSON(fe, fmtPath);
                totalOutputs++;
            }
        }

        // ── Phase 2: Fuzz through varied permutations (multi-format output) ──
        if (cleanImage) {
            int permutations[] = {1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15};
            int numPerms = sizeof(permutations) / sizeof(permutations[0]);
            for (int p = 0; p < numPerms; p++) {
                int perm = permutations[p];
                processImage(cleanImage, perm);
                CGImageRef fuzzedCG = cleanImage.CGImage;
                if (!fuzzedCG) continue;

                // Encode fuzzed image into multiple formats
                NSDictionary<NSString *, NSData *> *fuzzFormats = encodeImageMultiFormat(fuzzedCG);
                for (NSString *fmtExt in fuzzFormats) {
                    NSData *fuzzedData = fuzzFormats[fmtExt];
                    NSString *fuzzedName = [NSString stringWithFormat:@"%@_perm%d.%@", baseName, perm, fmtExt];
                    NSString *fuzzedPath = [fuzzedDir stringByAppendingPathComponent:fuzzedName];
                    [fuzzedData writeToFile:fuzzedPath atomically:YES];

                    NSDictionary *fm2 = measureOutput(cleanData, fuzzedData, fuzzedPath);
                    NSMutableDictionary *me = [fm2 mutableCopy];
                    me[@"phase"] = @"fuzzed";
                    me[@"source"] = baseName;
                    me[@"permutation"] = @(perm);
                    me[@"format"] = fmtExt;
                    [allMetrics addObject:me];
                    writeMetricsJSON(me, fuzzedPath);
                    totalOutputs++;
                }
            }
        }

        // ── Phase 3: Embed clean ICC profiles (PNG + TIFF) ──
        NSArray *iccFormats = @[@"png", @"tiff"];
        for (NSUInteger iccIdx = 0; iccIdx < [iccProfiles count]; iccIdx++) {
            NSString *iccPath = iccProfiles[iccIdx];
            NSString *iccName = [[iccPath lastPathComponent] stringByDeletingPathExtension];

            for (NSString *iccFmt in iccFormats) {
                NSData *iccEmbedded = embedICCProfile(cleanData, iccPath, iccFmt);
                NSString *iccOutName = [NSString stringWithFormat:@"%@_icc-%@.%@", baseName, iccName, iccFmt];
                NSString *iccOutPath = [iccDir stringByAppendingPathComponent:iccOutName];
                [iccEmbedded writeToFile:iccOutPath atomically:YES];

                NSDictionary *im = measureOutput(cleanData, iccEmbedded, iccOutPath);
                NSMutableDictionary *ie = [im mutableCopy];
                ie[@"phase"] = @"icc-clean";
                ie[@"source"] = baseName;
                ie[@"icc_profile"] = iccName;
                ie[@"format"] = iccFmt;
                [allMetrics addObject:ie];
                writeMetricsJSON(ie, iccOutPath);
                totalOutputs++;
            }
        }

        // ── Phase 4: Mutated ICC + fuzzed image (combined attack, multi-format) ──
        NSArray *comboFormats = @[@"png", @"tiff", @"jpeg"];
        for (NSUInteger iccIdx = 0; iccIdx < [iccProfiles count]; iccIdx++) {
            NSString *iccPath = iccProfiles[iccIdx];
            NSString *iccName = [[iccPath lastPathComponent] stringByDeletingPathExtension];
            NSData *originalICC = [NSData dataWithContentsOfFile:iccPath];
            if (!originalICC) continue;

            // Generate 3 mutations per profile
            for (int mut = 0; mut < 3; mut++) {
                NSData *mutatedICC = mutateICCProfile(originalICC);

                // Save the mutated profile for downstream iccDEV/CFL analysis
                NSString *mutProfileName = [NSString stringWithFormat:@"%@_mut%d_%@.icc",
                    baseName, mut + 1, iccName];
                NSString *mutProfilePath = [profileDir stringByAppendingPathComponent:mutProfileName];
                [mutatedICC writeToFile:mutProfilePath atomically:YES];

                // Fuzz the image first, then embed the mutated profile into each format
                NSData *imageToEmbed = cleanData;
                if (cleanImage) {
                    int perm = ((int)iccIdx * 3 + mut) % 14 + 1;
                    processImage(cleanImage, perm);
                    NSData *fuzzed = UIImagePNGRepresentation(cleanImage);
                    if (fuzzed) imageToEmbed = fuzzed;
                }

                for (NSString *comboFmt in comboFormats) {
                    NSData *comboData = embedICCProfileData(imageToEmbed, mutatedICC, comboFmt);
                    comboData = applyPostEncodingCorruption(comboData, comboFmt);

                    NSString *comboName = [NSString stringWithFormat:@"%@_combo-mut%d_%@.%@",
                        baseName, mut + 1, iccName, comboFmt];
                    NSString *comboPath = [comboDir stringByAppendingPathComponent:comboName];
                    [comboData writeToFile:comboPath atomically:YES];

                    NSDictionary *cm2 = measureOutput(cleanData, comboData, comboPath);
                    NSMutableDictionary *ce = [cm2 mutableCopy];
                    ce[@"phase"] = @"combo-mutated";
                    ce[@"source"] = baseName;
                    ce[@"icc_profile"] = iccName;
                    ce[@"mutation"] = @(mut + 1);
                    ce[@"format"] = comboFmt;
                    ce[@"mutated_profile_path"] = mutProfilePath;
                    [allMetrics addObject:ce];
                    writeMetricsJSON(ce, comboPath);
                    totalOutputs++;
                }
            }
        }

        // ── Phase 5: Chained iterations on the clean image ──
        if (iterations > 1) {
            // Save clean image to chain dir as iteration 0 input
            NSString *chainInput = [chainDir stringByAppendingPathComponent:
                [NSString stringWithFormat:@"%@_chain-input.%@", baseName, ext]];
            [cleanData writeToFile:chainInput atomically:YES];
            performChainedFuzzing(chainInput, iterations, NO);
        }
    }

    writeMetricsSummaryCSV(allMetrics, outputDir);
    NSLog(@"=== Pipeline Fuzzing complete: %d outputs from %lu images ===",
          totalOutputs, (unsigned long)[images count]);
}

/*!
 * @brief Entry point of the application, handling initialization, argument parsing, and image processing.
 *
 * @details Sets up the application environment, parses command-line arguments for image loading and processing,
 * and manages resources efficiently. Demonstrates a command-line utility pattern in Objective-C, integrating
 * C and Objective-C elements for image processing tasks.
 *
 * - **Environment Variables Setup**: Configures variables for detailed logging and debugging.
 * - **Command-Line Arguments**: Validates and parses arguments for image processing.
 * - **Image Processing**: Loads and processes the specified image.
 *
 * @param argc Count of command-line arguments.
 * @param argv Array of command-line arguments.
 * @return Returns 0 on success, 1 on failure.
 *
 * @note Utilizes `@autoreleasepool` for efficient memory management. The initial environment variable configurations
 * are for debugging and may need adjustment depending on deployment.
 */

#pragma mark - main
int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // Initial log with timestamp
        NSString *currentTime = formattedCurrentDateTime();
        NSLog(@"XNU Image Fuzzer starting %@", currentTime);

        // Set environment variables for detailed logging and debugging
        const char *envVars[] = {
            "CGBITMAP_CONTEXT_LOG_ERRORS", "CG_PDF_VERBOSE", "CG_CONTEXT_SHOW_BACKTRACE",
            "CG_CONTEXT_SHOW_BACKTRACE_ON_ERROR", "CG_IMAGE_SHOW_MALLOC", "CG_LAYER_SHOW_BACKTRACE",
            "CGBITMAP_CONTEXT_LOG", "CGCOLORDATAPROVIDER_VERBOSE", "CGPDF_LOG_PAGES",
            "MALLOC_CHECK_", "NSZombieEnabled", "NSAssertsEnabled", "NSShowAllViews",
            "IDELogRedirectionPolicy"
        };
        const char *envValues[] = {
            "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "YES", "YES", "YES", "oslogToStdio"
        };
        for (int i = 0; i < sizeof(envVars) / sizeof(char *); i++) {
            setenv(envVars[i], envValues[i], 1);
        }

        // Set LLVM coverage output path if env var is set but runtime hasn't picked it up
        // (happens with Mac Catalyst apps launched via 'open')
        const char *profFile = getenv("LLVM_PROFILE_FILE");
        llvm_profile_set_filename_fn set_fn = (llvm_profile_set_filename_fn)dlsym(RTLD_DEFAULT, "__llvm_profile_set_filename");
        if (profFile && set_fn) {
            NSLog(@"Setting LLVM profile file: %s", profFile);
            set_fn(profFile);
        }

        // Detect if launched with user-provided command-line arguments for image processing
        // New CLI modes: --input-dir <dir> [--iterations N]
        //                --chain <image> [--iterations N]
        //                <imagePath> <permutation>  (legacy)
        //                (no args) → performAllImagePermutations

        // Parse named arguments
        NSString *inputDir = nil;
        NSString *chainInput = nil;
        NSString *pipelineDir = nil;
        int iterations = 3; // default chained iterations

        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--input-dir") == 0 && i + 1 < argc) {
                inputDir = [NSString stringWithUTF8String:argv[++i]];
            } else if (strcmp(argv[i], "--chain") == 0 && i + 1 < argc) {
                chainInput = [NSString stringWithUTF8String:argv[++i]];
            } else if (strcmp(argv[i], "--pipeline") == 0 && i + 1 < argc) {
                pipelineDir = [NSString stringWithUTF8String:argv[++i]];
            } else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
                iterations = atoi(argv[++i]);
                if (iterations < 1) iterations = 1;
                if (iterations > MAX_ITERATIONS) iterations = MAX_ITERATIONS;
            }
        }

        if (pipelineDir) {
            // Pipeline fuzzing: clean → fuzz → ICC → combo → chain
            NSLog(@"Pipeline fuzzing mode: %@ (%d iterations)", pipelineDir, iterations);
            performPipelineFuzzing(pipelineDir, iterations);

            llvm_profile_write_file_fn write_fn = (llvm_profile_write_file_fn)dlsym(RTLD_DEFAULT, "__llvm_profile_write_file");
            if (write_fn) { write_fn(); }
            NSLog(@"XNU Image Fuzzer ✅ Pipeline complete %@", currentTime);
            return 0;

        } else if (inputDir) {
            // Batch fuzzing: process all images in directory
            NSLog(@"Batch fuzzing mode: %@ (%d iterations)", inputDir, iterations);
            performBatchFuzzing(inputDir, iterations);

            llvm_profile_write_file_fn write_fn = (llvm_profile_write_file_fn)dlsym(RTLD_DEFAULT, "__llvm_profile_write_file");
            if (write_fn) { write_fn(); }
            NSLog(@"XNU Image Fuzzer ✅ Batch complete %@", currentTime);
            return 0;

        } else if (chainInput) {
            // Chained fuzzing: multi-pass on single image
            NSLog(@"Chained fuzzing mode: %@ (%d iterations)", chainInput, iterations);
            performChainedFuzzing(chainInput, iterations, NO);

            llvm_profile_write_file_fn write_fn = (llvm_profile_write_file_fn)dlsym(RTLD_DEFAULT, "__llvm_profile_write_file");
            if (write_fn) { write_fn(); }
            NSLog(@"XNU Image Fuzzer ✅ Chain complete %@", currentTime);
            return 0;

        } else if (argc > 2 && argv[1][0] != '-') {
            NSString *imageName = [NSString stringWithUTF8String:argv[1]];
            int permutation = atoi(argv[2]);

            NSLog(@"Loading file: %@", imageName);
            UIImage *image = loadImageFromFile(imageName);
            if (!image) {
                NSLog(@"Failed to find path for image: %@", imageName);
                NSLog(@"Failed to load image: %@", imageName);
                return 1; // Error due to failed image loading
            }

            processImage(image, permutation);
            dump_comm_page();
            dumpDeviceInfo();
            dumpMacDeviceInfo();

            NSLog(@"XNU Image Fuzzer ✅ %@", currentTime);

            // Flush LLVM coverage data before exit
            llvm_profile_write_file_fn write_fn = (llvm_profile_write_file_fn)dlsym(RTLD_DEFAULT, "__llvm_profile_write_file");
            if (write_fn) {
                write_fn();
            }

            return 0; // Successful completion of command-line image processing
        } else if (argc == 1 || (argc > 2 && argv[1][0] == '-')) {
            // Perform all image permutations if no valid user-provided arguments are present
            performAllImagePermutations();

            // Flush LLVM coverage data before exit (dlsym, no-op without instrumentation)
            llvm_profile_write_file_fn write_fn2 = (llvm_profile_write_file_fn)dlsym(RTLD_DEFAULT, "__llvm_profile_write_file");
            if (write_fn2) {
                NSLog(@"Flushing LLVM coverage data...");
                write_fn2();
            }

            return 0; // Successful completion of image permutation fuzzing
        } else {
            NSLog(@"Incorrect usage. Expected valid arguments, got %d", argc - 1);
            NSLog(@"Usage: %s <imagePath> <permutation>", argv[0]);
            NSLog(@"       %s --pipeline <directory> [--iterations N]", argv[0]);
            NSLog(@"       %s --chain <imagePath> [--iterations N]", argv[0]);
            NSLog(@"       %s --input-dir <directory> [--iterations N]", argv[0]);
            NSLog(@"       %s  (no args = generate all permutations)", argv[0]);
            NSLog(@"Environment: FUZZ_OUTPUT_DIR, FUZZ_ICC_DIR, LLVM_PROFILE_FILE");
            return 1; // Error due to incorrect usage
        }
    }
}

#pragma mark - isImagePathValid

/*!
 * @brief Validates the existence of a file at a specified path.
 * @details Checks if an image file exists at a given path, essential for applications that require the presence of a file before performing further operations. Utilizes `NSFileManager`'s `fileExistsAtPath:` to assess file presence, ensuring the path's validity for subsequent processing or operations. This function is crucial in contexts where the accuracy of file paths directly impacts application behavior or user experience.
 *
 * @param path NSString representing the file path to validate.
 *
 * @return Returns YES if the file exists at the specified path; otherwise, returns NO.
 *
 * @note
 * - **Implementation**: Leverages `NSFileManager` for reliable file existence checks. Logs the outcome to provide clear feedback on path validity.
 * - **Versatility**: While demonstrated for image files, this method can be adapted for any file type, enhancing its utility across various application needs.
 *
 * ### Example Usage:
 * @code
 * BOOL valid = isImagePathValid(@"/path/to/image.png");
 * if (valid) {
 *     NSLog(@"The image path is valid. Proceed with loading or processing.");
 * } else {
 *     NSLog(@"The image path is invalid. Check the path or notify the user.");
 * }
 * @endcode
 */
BOOL isValidImagePath(NSString *path) {
    BOOL fileExists = [[NSFileManager defaultManager] fileExistsAtPath:path];
    NSLog(fileExists ? @"Valid image path: %@" : @"Invalid image path: %@", path);
    return fileExists;
}

#pragma mark - loadImageFromFile

/*!
 * @brief Loads an image from the application bundle into a UIImage object.
 * @details Essential for iOS applications, this function loads images stored within the app's resources, facilitating the display or processing of those images. It abstracts filesystem complexities, allowing developers to concentrate on resource utilization.
 *
 * @param imageName NSString representing the file name (including its extension) of the image to load.
 *
 * @return A `UIImage` object initialized with the specified image file's contents or nil if the image could not be loaded.
 *
 * @note
 * - **Path Retrieval**: Uses `NSBundle`'s `pathForResource:ofType:` to locate the image file, simplifying access to app resources.
 * - **Data Conversion**: Converts the file content into `NSData`, a format compatible with `UIImage`'s `imageWithData:` initializer.
 * - **UIImage Initialization**: Creates a `UIImage` from `NSData`. On success, logs image details like dimensions and scale for debugging or information.
 *
 * ### Example Usage:
 * @code
 * UIImage *loadedImage = loadImageFromFile(@"exampleImage.png");
 * if (loadedImage) {
 *     NSLog(@"Image loaded successfully with dimensions: %f x %f", loadedImage.size.width, loadedImage.size.height);
 * } else {
 *     NSLog(@"Failed to load image.");
 * }
 * @endcode
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

/*!
 * @brief Processes an image using various bitmap context configurations.
 * @details Central to testing different bitmap context configurations, this function allows for the exploration and application of a wide range of image processing techniques. Configurations vary by color space, alpha settings, bit depth, and pixel format, enabling comprehensive testing across different image processing scenarios.
 *
 * @param image The `UIImage` object to be processed, which must contain a valid `CGImage`.
 * @param permutation An integer specifying the bitmap context configuration to apply. A value of -1 applies all configurations in a loop, while any other value selects a specific configuration.
 *
 * @note
 * - **CGImage Retrieval**: Begins by extracting the `CGImage` from the `UIImage`. Logs an error and exits if this step fails.
 * - **Configuration Application**: Iterates through or selects a specific bitmap context configuration to apply. Logs each action and utilizes corresponding functions for creating and processing the bitmap context.
 * - **Modular Processing Logic**: Processing for each configuration is handled in separate functions, facilitating easy adjustments or expansions to processing capabilities.
 *
 * ### Usage Example:
 * @code
 * // Process with all configurations
 * processImage(myImage, -1);
 *
 * // Process with a specific configuration
 * processImage(myImage, 3); // Example: Applies Non-Premultiplied Alpha settings
 * @endcode
 */
void processImage(UIImage *image, int permutation) {
    CGImageRef cgImg = [image CGImage];
    if (!cgImg) {
        NSLog(@"Failed to get CGImage from UIImage.");
        return;
    }
    NSLog(@"CGImage created from UIImage. Dimensions: %zu x %zu", CGImageGetWidth(cgImg), CGImageGetHeight(cgImg));

    if (permutation == -1) {
        for (int i = 1; i <= 15; i++) {
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
                    NSLog(@"Case: Creating bitmap context with Grayscale settings");
                    createBitmapContextGrayscale(cgImg);
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
                case 13:
                    NSLog(@"Case: Creating bitmap context with CMYK color space settings");
                    createBitmapContextCMYK(cgImg);
                    break;
                case 14:
                    NSLog(@"Case: Creating bitmap context with HDR Float16 settings");
                    createBitmapContextHDRFloat16(cgImg);
                    break;
                case 15:
                    NSLog(@"Case: Creating bitmap context with Indexed Color settings");
                    createBitmapContextIndexedColor(cgImg);
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
                NSLog(@"Case: Creating bitmap context with Grayscale settings");
                createBitmapContextGrayscale(cgImg);
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
            case 13:
                NSLog(@"Case: Creating bitmap context with CMYK color space settings");
                createBitmapContextCMYK(cgImg);
                break;
            case 14:
                NSLog(@"Case: Creating bitmap context with HDR Float16 settings");
                createBitmapContextHDRFloat16(cgImg);
                break;
            case 15:
                NSLog(@"Case: Creating bitmap context with Indexed Color settings");
                createBitmapContextIndexedColor(cgImg);
                break;
            default:
                NSLog(@"Case: Invalid permutation number %d", permutation);
                break;        }
        NSLog(@"Completed image processing for permutation %d", permutation);
    }
}

#pragma mark - createBitmapContextStandardRBG

/*!
 * @brief Creates a bitmap context with standard RGB settings, applies a fuzzing process to alter the image, and saves the fuzzed image. Useful for testing image processing functionalities or creating varied visual effects.
 *
 * @details This function demonstrates how to create a bitmap context, manipulate image pixel data through a fuzzing process, and save the modified image. It covers validating input images, creating bitmap contexts with specific configurations, and applying image processing algorithms to explore and enhance image processing techniques.
 *
 * @param cgImg The source image from which to create the bitmap context, represented as a `CGImageRef`.
 * @param permutation An integer representing the type or level of fuzzing to apply. Though not utilized in this simplified example, it is designed to dictate different fuzzing algorithms or intensities.
 *
 * @note
 * - **Memory Management**: Demonstrates careful release of resources, including color space and bitmap context, and freeing of dynamically allocated memory.
 * - **Debugging**: Includes commented-out calls to `debugMemoryHandling` to illustrate potential insertion points for memory diagnostics.
 * - **Extensibility**: The `permutation` parameter demonstrates the function's potential to apply various fuzzing types based on input parameters, enhancing modularity and maintainability.
 * - **Logging**: Utilizes `NSLog` for debugging purposes. A more sophisticated logging framework is recommended for production code.
 * - **Separation of Concerns**: Abstracts the actual fuzzing logic into the `applyEnhancedFuzzingToBitmapContext` function, promoting code modularity and maintainability.
 *
 * ### Process Overview:
 * 1. Validates the `CGImageRef` input to ensure a source image is provided.
 * 2. Retrieves source image dimensions and calculates bytes per row for an RGBA pixel format.
 * 3. Allocates memory for raw pixel data.
 * 4. Creates a `CGColorSpaceRef` in the device RGB color space.
 * 5. Specifies bitmap information for alpha channel handling and byte order.
 * 6. Creates the bitmap context with allocated memory, color space, and specified bitmap info.
 * 7. Draws the source image into the bitmap context.
 * 8. Applies a fuzzing algorithm to manipulate the pixel data directly.
 * 9. Generates a new `CGImageRef` from the bitmap context, converts it to `UIImage`, and saves the result.
 * 10. Releases allocated resources, including the bitmap context and pixel data memory.
 *
 * ### Usage Example:
 * @code
 * // Process with all configurations
 * processImage(myImage, -1);
 *
 * // Process with a specific configuration
 * processImage(myImage, 3); // Example: Applies Non-Premultiplied Alpha settings
 * @endcode
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

    // Initialize memory with 0x41 pattern for post-operation change detection
    memset(rawData, 0x41, height * bytesPerRow);

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
    // Initialize a variable to keep track of unchanged and changed bytes
    size_t unchangedCount = 0;
    size_t changedCount = 0;

    // Check for 0x41 pattern after operations and detect changes
    for (size_t i = 0; i < height * bytesPerRow; i++) {
        if (rawData[i] == 0x41) {
            unchangedCount++;
        } else {
            // Log the first few changes to avoid flooding the log
            if (changedCount < 10) { // Limiting to the first 10 changes for brevity
                NSLog(@"Detected change from 0x41 at byte offset %zu, new value: 0x%X", i, rawData[i]);
            }
            changedCount++;
        }
    }
 
    // Summarize findings
    if (unchangedCount > 0) {
        NSLog(@"Detected unchanged 0x41 pattern in %zu places.", unchangedCount);
    }
    NSLog(@"Detected changes in %zu places.", changedCount);

    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg);

        saveFuzzedImage(newImage, @"standard_rgb_png");
        saveFuzzedImage(newImage, @"standard_rgb_jpeg");
        saveFuzzedImage(newImage, @"standard_rgb_gif");
        saveFuzzedImage(newImage, @"standard_rgb_tiff");
        
        NSLog(@"Modified UIImage created and saved successfully.");
    }

    CGContextRelease(ctx);
    free(rawData);
//    debugMemoryHandling();
}

#pragma mark - createBitmapContextPremultipliedFirstAlpha

/*!
 * @brief Creates a bitmap context with Premultiplied First Alpha settings and applies image processing.
 *
 * This function initializes a bitmap context optimized for image processing with premultiplied first alpha settings, drawing a provided CGImage into this context. It fills the allocated memory with a 0x41 pattern to facilitate debugging and security analysis by identifying unused or inefficiently managed memory regions. After processing the image, it checks for any unchanged memory areas and logs their locations, offering insights into memory utilization.
 *
 * @param cgImg A `CGImageRef` representing the source image to be transformed. Must not be NULL.
 *
 * Utilizing a 0x41 pattern fill and subsequent check, this function aids in debugging memory handling and potentially identifying security vulnerabilities related to buffer overflow or improper memory management. It's designed for enhanced debugging and should be used with consideration for its performance impact in production environments.
 *
 * ### Example Usage:
 * @code
 * CGImageRef sourceImage = CGImageCreate(...); // Create or obtain a CGImageRef
 * createBitmapContextPremultipliedFirstAlpha(sourceImage);
 * CGImageRelease(sourceImage); // Clean up the source image if it's no longer needed
 * @endcode
 *
 * @note Ensure that the `CGImageRef` provided to this function is valid. The function logs detailed information about its operation, especially detecting unchanged memory areas after processing, which can be instrumental in identifying inefficiencies or vulnerabilities.
 */
void createBitmapContextPremultipliedFirstAlpha(CGImageRef cgImg) {
    NSLog(@"Creating bitmap context with Premultiplied First Alpha settings");

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
        return;
    }

    // Initialize memory with 0x41 pattern
    memset(rawData, 0x41, height * bytesPerRow);

    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    if (!colorSpace) {
        NSLog(@"Failed to create color space");
        free(rawData);
        return;
    }

    CGBitmapInfo bitmapInfo = kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Big;
    CGContextRef ctx = CGBitmapContextCreate(rawData, width, height, 8, bytesPerRow, colorSpace, bitmapInfo);
    CGColorSpaceRelease(colorSpace);

    if (!ctx) {
        NSLog(@"Failed to create bitmap context");
        free(rawData);
        return;
    }

    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImg);

    NSLog(@"Applying enhanced fuzzing logic to the bitmap context");
    applyEnhancedFuzzingToBitmapContext(rawData, width, height, YES);

    // Initialize a variable to keep track of unchanged and changed bytes
    size_t unchangedCount = 0;
    size_t changedCount = 0;

    // Check for 0x41 pattern after operations and detect changes
    for (size_t i = 0; i < height * bytesPerRow; i++) {
        if (rawData[i] == 0x41) {
            unchangedCount++;
        } else {
            // Log the first few changes to avoid flooding the log
            if (changedCount < 10) { // Limiting to the first 10 changes for brevity
                NSLog(@"Detected change from 0x41 at byte offset %zu, new value: 0x%X", i, rawData[i]);
            }
            changedCount++;
        }
    }

    // Summarize findings
    if (unchangedCount > 0) {
        NSLog(@"Detected unchanged 0x41 pattern in %zu places.", unchangedCount);
    }
    NSLog(@"Detected changes in %zu places.", changedCount);

    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg);

        // Save the image in both PNG and JPEG formats
        // The contextDescription now should indicate the desired format
        saveFuzzedImage(newImage, @"premultiplied_first_alpha_png");
        saveFuzzedImage(newImage, @"premultiplied_first_alpha_jpeg");
        saveFuzzedImage(newImage, @"premultiplied_first_alpha_gif");
        saveFuzzedImage(newImage, @"premultiplied_first_alpha_tiff");
        
        NSLog(@"Modified UIImage created and saved successfully in both PNG and JPEG formats.");
    }
    
    CGContextRelease(ctx);
    free(rawData);
}

#pragma mark - createBitmapContextNonPremultipliedAlpha

/*!
 * @brief Creates a bitmap graphics context with Non-Premultiplied Alpha settings for processing a CGImage.
 * @details Tailored for scenarios where non-premultiplied alpha handling is crucial, this function facilitates precise control over the alpha channel during image processing. It's particularly useful where premultiplication could obscure details or degrade quality. The function outlines a structured approach to creating a bitmap context that maintains the integrity of the alpha channel, applying modifications through an "enhanced fuzzing" process, and concluding with the saving of the altered image.
 *
 * The procedure includes validating the CGImageRef, memory allocation for pixel data, setting up a Device RGB color space, configuring bitmap context parameters for non-premultiplied alpha, image rendering, applying custom processing logic, and resource cleanup.
 *
 * @param cgImg The `CGImageRef` representing the image to be processed, used as the source for the bitmap context.
 *
 * @note
 * - Emphasizes meticulous memory management to prevent leaks, including the release of the bitmap context and allocated pixel data.
 * - Incorporates diagnostic logging at various stages to support debugging and ensure processing accuracy.
 *
 * ### Process:
 * 1. **Validation**: Ensures the `CGImageRef` is non-null and valid for processing.
 * 2. **Memory Allocation**: Determines the required dimensions and allocates memory for storing the image's pixel data.
 * 3. **Color Space Setup**: Creates a Device RGB color space for the bitmap context, essential for accurate color reproduction.
 * 4. **Bitmap Context Configuration**: Establishes a bitmap context tailored for non-premultiplied alpha, specifying relevant bitmap info flags.
 * 5. **Image Rendering**: Draws the source CGImage into the bitmap context, preserving raw pixel data integrity.
 * 6. **Custom Processing**: Applies an "enhanced fuzzing" algorithm to the pixel data, modifying the image's appearance or characteristics.
 * 7. **Image Generation and Saving**: Converts the processed bitmap context into a new CGImage and a UIImage, saving the result with a distinctive identifier.
 * 8. **Resource Cleanup**: Carefully releases the bitmap context and frees the memory allocated for pixel data, ensuring no memory leaks occur.
 *
 * ### Usage Example:
 * @code
 * // Assuming cgImg is a valid CGImageRef
 * createBitmapContextNonPremultipliedAlpha(cgImg);
 * @endcode
 */
void createBitmapContextNonPremultipliedAlpha(CGImageRef cgImg) {
    NSLog(@"Creating bitmap context with Non-Premultiplied Alpha settings");

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
        return;
    }

    // Initialize memory with 0x41 pattern for post-operation change detection
    memset(rawData, 0x41, height * bytesPerRow);

    // Create a color space for the bitmap context
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    if (!colorSpace) {
        NSLog(@"Failed to create color space");
        free(rawData);
        return;
    }

    // Define bitmap info with non-premultiplied alpha
    CGBitmapInfo bitmapInfo = kCGImageAlphaNoneSkipLast | kCGBitmapByteOrder32Big;
    CGContextRef ctx = CGBitmapContextCreate(rawData, width, height, 8, bytesPerRow, colorSpace, bitmapInfo);
    CGColorSpaceRelease(colorSpace);

    if (!ctx) {
        NSLog(@"Failed to create bitmap context");
        free(rawData);
        return;
    }

    // Draw the CGImage into the bitmap context
    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImg);

    // Apply fuzzing logic directly to the bitmap's raw data
    NSLog(@"Applying enhanced fuzzing logic to the bitmap context with non-premultiplied alpha");
    applyEnhancedFuzzingToBitmapContext(rawData, width, height, YES); // Assuming verbose logging is desired
    // Initialize a variable to keep track of unchanged and changed bytes
        size_t unchangedCount = 0;
        size_t changedCount = 0;

        // Check for 0x41 pattern after operations and detect changes
        for (size_t i = 0; i < height * bytesPerRow; i++) {
            if (rawData[i] == 0x41) {
                unchangedCount++;
            } else {
                // Log the first few changes to avoid flooding the log
                if (changedCount < 10) { // Limiting to the first 10 changes for brevity
                    NSLog(@"Detected change from 0x41 at byte offset %zu, new value: 0x%X", i, rawData[i]);
                }
                changedCount++;
            }
        }
     
        // Summarize findings
        if (unchangedCount > 0) {
            NSLog(@"Detected unchanged 0x41 pattern in %zu places.", unchangedCount);
        }
        NSLog(@"Detected changes in %zu places.", changedCount);
    
    // Create a new image from the modified context
    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg);

        // Save the fuzzed image with a context-specific identifier
        saveFuzzedImage(newImage, @"non_premultiplied_alpha_png");
        saveFuzzedImage(newImage, @"non_premultiplied_alpha_jpeg");
        saveFuzzedImage(newImage, @"non_premultiplied_alpha_gif");
        saveFuzzedImage(newImage, @"non_premultiplied_alpha_tiff");

        NSLog(@"Modified UIImage created and saved successfully for non-premultiplied alpha in both PNG, JPEG and GIF formats.");
    }

    // Cleanup
    CGContextRelease(ctx);
    free(rawData);
}

#pragma mark - createBitmapContext16BitDepth

/*!
 * @brief Creates a bitmap graphics context for 16-bit depth per channel processing.
 * @details This function is tailored for scenarios requiring high color fidelity, utilizing 16-bit depth per channel to enhance color range and reduce artifacts. It's ideal for high-quality image processing and editing, ensuring the highest fidelity in color information. The process involves validating the source image, allocating a memory buffer with adequate depth, setting up a suitable color space, configuring and rendering into the bitmap context, applying custom image processing, and managing resources efficiently.
 *
 * @param cgImg The `CGImageRef` representing the source image for processing in the 16-bit depth bitmap context.
 *
 * @note
 * - Prioritizes detailed logging for debugging and error tracking, particularly useful given the function's complexity and higher memory demands.
 * - Includes commented-out sections for memory diagnostics, indicating a considered approach to monitoring and managing memory usage in high-depth processing scenarios.
 *
 * ### Process:
 * 1. **Input Validation**: Checks the `CGImageRef` for nullity, logging any errors encountered.
 * 2. **Dimension Calculation**: Determines the necessary dimensions for the bitmap context and pixel data buffer based on the source image's size.
 * 3. **Memory Allocation**: Allocates memory for the raw pixel data, factoring in the increased requirements for 16-bit depth per channel.
 * 4. **Color Space Creation**: Establishes a Device RGB color space to ensure accurate color reproduction within the context.
 * 5. **Bitmap Context Configuration**: Sets up the bitmap context to support 16-bit depth per color channel, including considerations for premultiplied alpha.
 * 6. **Image Rendering**: Captures the source CGImage within the bitmap context, maintaining high color depth.
 * 7. **Custom Processing**: Applies an "enhanced fuzzing" algorithm to the high-depth pixel data, with an emphasis on thorough diagnostic logging.
 * 8. **Image Generation and Saving**: Creates a new CGImage from the context, encapsulates it in a UIImage, and saves the result, denoting its 16-bit depth processing.
 * 9. **Resource Cleanup**: Ensures the release of all allocated resources, including the bitmap context and pixel data buffer, to maintain operational cleanliness.
 *
 * ### Usage Example:
 * @code
 * // Assuming cgImg is a valid CGImageRef
 * createBitmapContext16BitDepth(cgImg);
 * @endcode
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

    // Apply fuzzing logic with proper 16-bit handler
    NSLog(@"Applying enhanced 16-bit fuzzing logic to the bitmap context");
    applyEnhancedFuzzingToBitmapContext16Bit(rawData, width, height, YES);
    // Initialize a variable to keep track of unchanged and changed bytes
    size_t unchangedCount = 0;
    size_t changedCount = 0;
 
 
    // Check for 0x41 pattern after operations and detect changes
    for (size_t i = 0; i < height * bytesPerRow; i++) {
        if (rawData[i] == 0x41) {
            unchangedCount++;
        } else {
            // Log the first few changes to avoid flooding the log
            if (changedCount < 10) { // Limiting to the first 10 changes for brevity
                NSLog(@"Detected change from 0x41 at byte offset %zu, new value: 0x%X", i, rawData[i]);
            }
            changedCount++;
        }
    }

    // Summarize findings
    if (unchangedCount > 0) {
        NSLog(@"Detected unchanged 0x41 pattern in %zu places.", unchangedCount);
    }
    NSLog(@"Detected changes in %zu places.", changedCount);
    
    // Create a new image from the modified context
    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg);

        // Save the fuzzed image with a context-specific identifier
        saveFuzzedImage(newImage, @"16bit_depth_png");
        saveFuzzedImage(newImage, @"16bit_depth_jpeg");
        saveFuzzedImage(newImage, @"16bit_depth_gif");
        saveFuzzedImage(newImage, @"16bit_depth_tiff");
        
        NSLog(@"Modified UIImage created and saved successfully in both PNG and JPEG formats.");
    }

    // Cleanup
    CGContextRelease(ctx);
    free(rawData);
//    debugMemoryHandling(); // Post-operation diagnostic
}

#pragma mark - createBitmapContextGrayscale

void createBitmapContextGrayscale(CGImageRef cgImg) {
    if (!cgImg) {
        NSLog(@"Invalid CGImageRef provided.");
        return;
    }

    NSLog(@"Creating bitmap context with Grayscale settings");

    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    size_t bytesPerRow = width * 2; // 1 byte gray + 1 byte alpha per pixel

    unsigned char *rawData = (unsigned char *)calloc(height * bytesPerRow, sizeof(unsigned char));
    if (!rawData) {
        NSLog(@"Failed to allocate memory for grayscale processing");
        return;
    }

    memset(rawData, 0x41, height * bytesPerRow);

    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceGray();
    if (!colorSpace) {
        NSLog(@"Failed to create grayscale color space");
        free(rawData);
        return;
    }

    CGContextRef ctx = CGBitmapContextCreate(rawData, width, height, 8, bytesPerRow, colorSpace, (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
    CGColorSpaceRelease(colorSpace);

    if (!ctx) {
        NSLog(@"Failed to create grayscale bitmap context");
        free(rawData);
        return;
    }

    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImg);

    // Apply grayscale-specific fuzzing: random noise, inversion, extreme values
    for (size_t y = 0; y < height; y++) {
        for (size_t x = 0; x < width; x++) {
            size_t idx = y * bytesPerRow + x * 2;
            switch (arc4random_uniform(5)) {
                case 0: // Invert gray
                    rawData[idx] = 255 - rawData[idx];
                    break;
                case 1: // Random noise
                    {
                        int noise = (int)arc4random_uniform(101) - 50;
                        int newVal = (int)rawData[idx] + noise;
                        rawData[idx] = (unsigned char)fmax(0, fmin(255, newVal));
                    }
                    break;
                case 2: // Extreme value
                    rawData[idx] = (arc4random_uniform(2) == 0) ? 0 : 255;
                    break;
                case 3: // Bit flip
                    rawData[idx] ^= (1 << arc4random_uniform(8));
                    break;
                case 4: // Alpha mutation
                    rawData[idx + 1] = arc4random_uniform(256);
                    break;
            }
        }
    }

    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from grayscale context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg);

        saveFuzzedImage(newImage, @"grayscale_png");
        saveFuzzedImage(newImage, @"grayscale_jpeg");
        saveFuzzedImage(newImage, @"grayscale_gif");
        saveFuzzedImage(newImage, @"grayscale_tiff");
        NSLog(@"Grayscale fuzzed image saved successfully.");
    }

    CGContextRelease(ctx);
    free(rawData);
}

#pragma mark - createBitmapContextHDRFloatComponents

/*!
 * @brief Initializes a bitmap context for HDR content with floating-point components.
 * @details This function is pivotal for handling High Dynamic Range (HDR) images, enabling the precise manipulation of extended color and brightness ranges. By employing floating-point components and an HDR-compatible color space, it facilitates the processing of images with significantly broader luminance and color gamut than traditional 8-bit or 16-bit formats allow. The function outlines steps for validating the source image, allocating memory for HDR data, setting up an HDR-compatible color space and bitmap context, and applying custom image processing.
 *
 * @param cgImg The `CGImageRef` representing the source image for processing in the HDR bitmap context.
 *
 * @note
 * - The function's design caters to advanced image processing experiments, including dynamic manipulation and fuzzing based on varying data inputs.
 * - Assumes the use of a mechanism to cycle through predefined strings for the fuzzing process, illustrating the method's adaptability to different parameters or data influences.
 *
 * ### Process:
 * 1. **Input Validation**: Confirms the `CGImageRef` is valid and not null.
 * 2. **Memory Allocation**: Allocates a buffer for floating-point raw data, accounting for HDR's extensive data size requirements.
 * 3. **Color Space Creation**: Initiates an HDR-compatible color space (`kCGColorSpaceExtendedLinearSRGB`) to accurately handle HDR images' expanded gamut and luminance.
 * 4. **Bitmap Context Setup**: Configures the bitmap context with 32 bits per component in floating-point format, suitable for HDR content's nuanced representation.
 * 5. **Image Rendering**: Draws the source CGImage into the context, ensuring it captures the high precision of HDR.
 * 6. **Custom Processing**: Applies a custom fuzzing process to the bitmap data, using predefined strings to demonstrate or test specific effects.
 * 7. **Image Generation and Saving**: Creates a new CGImage from the modified context, then a UIImage, facilitating its use within UIKit applications. Saves the processed image with a relevant identifier.
 * 8. **Resource Cleanup**: Releases all allocated resources, including the color space, bitmap context, and memory buffer, to prevent memory leaks.
 *
 * ### Usage Example:
 * @code
 * // Assuming cgImg is a valid CGImageRef
 * createBitmapContextHDRFloatComponents(cgImg);
 * @endcode
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
    float *rawData = (float *)calloc(height * width * 4, sizeof(float));
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
    applyEnhancedFuzzingToBitmapContextWithFloats(rawData, width, height, YES);
    currentStringIndex = (currentStringIndex + 1) % NUMBER_OF_STRINGS; // Move to the next string for the next call

    // Initialize a variable to keep track of unchanged and changed floats
    size_t unchangedCount = 0;
    size_t changedCount = 0;
    size_t totalFloats = height * width * 4;

    // Check for changes in float data after operations
    for (size_t i = 0; i < totalFloats; i++) {
        if (rawData[i] == 0.0f) {
            unchangedCount++;
        } else {
            // Log the first few changes to avoid flooding the log
            if (changedCount < 10) {
                union {
                    float f;
                    unsigned int u;
                } floatToHex;

                floatToHex.f = rawData[i];
                NSLog(@"Detected change at float offset %zu, value: %f (0x%X)", i, rawData[i], floatToHex.u);
            }
            changedCount++;
        }
    }

    // Summarize findings
    if (unchangedCount > 0) {
        NSLog(@"Detected unchanged 0x41 pattern in %zu places.", unchangedCount);
    }
    NSLog(@"Detected changes in %zu places.", changedCount);

    // Normalize float values to [0.0, 1.0] so saved images have visible variation.
    // Without this, NaN/Infinity/FLT_MAX from fuzzing clamp to uniform black.
    for (size_t i = 0; i < totalFloats; i++) {
        float v = rawData[i];
        if (isnan(v) || isinf(v)) {
            rawData[i] = (float)arc4random() / UINT32_MAX;
        } else {
            v = fmodf(fabsf(v), 1.0f);
            rawData[i] = v;
        }
    }
    NSLog(@"Normalized %zu float values to [0.0, 1.0] for visible output", totalFloats);

    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from HDR context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg);

        saveFuzzedImage(newImage, @"hdr_float_png");
        saveFuzzedImage(newImage, @"hdr_float_jpeg");
        saveFuzzedImage(newImage, @"hdr_float_gif");
        saveFuzzedImage(newImage, @"hdr_float_tiff");
        NSLog(@"Modified UIImage with HDR and floating-point components created and saved successfully in both PNG, JPEG and GIF formats.");
    }

    CGContextRelease(ctx);
    free(rawData);
}

#pragma mark - createBitmapContextAlphaOnly

/*!
 * @brief Creates a bitmap context for alpha channel manipulation of a CGImageRef.
 * @details This function is specifically designed for scenarios requiring isolated handling of image transparency, excluding color data. It supports applications in graphics editing, custom rendering, and transparency management by focusing exclusively on the alpha channel. The function validates the source image, configures a dedicated bitmap context for alpha data, applies custom modifications to transparency levels, and manages resource cleanup effectively.
 *
 * @param cgImg The `CGImageRef` representing the source image from which the alpha channel will be extracted and processed.
 *
 * Implementation Notes:
 * - Assumes the presence of an alpha channel in the input image. In the absence of transparency in the source image, extracted alpha data may lack significance.
 * - References the `applyEnhancedFuzzingToBitmapContextAlphaOnly` function for specific alpha data manipulation, aimed at testing or enhancing transparency effects.
 * - Highlighting the challenge of utilizing processed alpha data for image reconstruction, as this operation concentrates on transparency without color components.
 * - Includes indications for `debugMemoryHandling` to facilitate memory management diagnostics, crucial for optimizing resource use in constrained environments.
 *
 * ### Process:
 * 1. **Input Validation**: Ensures the `CGImageRef` is suitable for transparency extraction and processing.
 * 2. **Dimension Retrieval**: Accurately configures the bitmap context based on the source image's dimensions.
 * 3. **Memory Allocation**: Dedicates a memory buffer for storing alpha data, reflecting opacity with one byte per pixel.
 * 4. **Bitmap Context Creation**: Establishes a context focused on alpha channel information, omitting color space configuration.
 * 5. **Alpha Extraction**: Draws the source image into the context, isolating the alpha channel data.
 * 6. **Transparency Manipulation**: Applies custom fuzzing to the alpha data, adjusting transparency for specific effects or testing.
 * 7. **Resource Cleanup**: Releases the bitmap context and alpha data array, ensuring no memory leaks.
 *
 * ### Usage Example:
 * @code
 * // Assuming cgImg is a valid CGImageRef with an alpha channel
 * createBitmapContextAlphaOnly(cgImg);
 * @endcode
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
    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg);
        
        saveFuzzedImage(newImage, @"alpha_channel_png");
        saveFuzzedImage(newImage, @"alpha_channel_jpeg");
        saveFuzzedImage(newImage, @"alpha_channel_gif");
        saveFuzzedImage(newImage, @"alpha_channel_tiff");
        
        NSLog(@"Modified UIImage created and saved successfully.");
    }
    // Cleanup and resource management
    CGContextRelease(ctx);
    free(alphaData);
//    debugMemoryHandling(); // Post-operation diagnostic

    NSLog(@"Alpha-only bitmap context processing completed.");
}

#pragma mark - createBitmapContext1BitMonochrome

/*!
 * @brief Creates a bitmap context for 1-bit monochrome image processing.
 * @details This function is crafted for applications that convert color or grayscale images to monochrome using a 1-bit per pixel format. It's particularly suited for environments where reducing data size is crucial, such as in low-bandwidth or memory-constrained situations, or to achieve a certain aesthetic. The function covers the process from validating the input image, through creating a monochrome bitmap context, to finalizing and releasing resources.
 *
 * @param cgImg The `CGImageRef` representing the source image to be converted to 1-bit monochrome.
 *
 * @note The conversion might incorporate techniques like dithering, contrast adjustments, or edge enhancement to optimize the monochrome output. This description assumes a basic approach but acknowledges the potential for more complex processing strategies tailored to specific requirements.
 *
 * ### Process:
 * 1. **Input Validation**: Confirms the `CGImageRef` is valid and non-null.
 * 2. **Dimension and Byte Calculation**: Sets up the bitmap context based on the source image's dimensions and calculates the minimum bytes per row for 1-bit data.
 * 3. **Bitmap Context Creation**: Establishes a monochrome bitmap context without a color space or alpha channel.
 * 4. **Background Initialization**: Prepares the bitmap with a white background for consistent monochrome conversion.
 * 5. **Image Drawing**: Renders the input image into the context, initiating the conversion to 1-bit color depth.
 * 6. **Bitmap Manipulation**: Directly adjusts the bitmap data to refine the monochrome output as needed.
 * 7. **CGImage Generation**: Produces a new CGImage reflecting the monochrome conversion.
 * 8. **UIImage Creation**: Converts the new CGImage into a UIImage for UIKit compatibility or additional processing.
 * 9. **Optional Saving**: Tags and saves the monochrome image for easy storage or retrieval.
 * 10. **Resource Cleanup**: Ensures the release of the bitmap context and any other allocated resources.
 *
 * ### Usage Example:
 * @code
 * // Assuming cgImg is a valid CGImageRef
 * createBitmapContext1BitMonochrome(cgImg);
 * @endcode
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

    // Use device gray colorspace for 1-bit monochrome (NULL colorspace may fail on some systems)
    CGColorSpaceRef graySpace = CGColorSpaceCreateDeviceGray();
    CGContextRef ctx = CGBitmapContextCreate(NULL, width, height, 1, bytesPerRow, graySpace, (CGBitmapInfo)kCGImageAlphaNone);
    CGColorSpaceRelease(graySpace);
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

/*!
* @brief Creates a bitmap context with Big Endian byte ordering for image data processing.
* @details This function is designed for scenarios where Big Endian representation is crucial for the consistency of pixel color data in memory, particularly in systems or applications expecting
* this byte order. It validates the input image, establishes an appropriate RGB color space, configures a bitmap context for Big Endian processing, applies an "enhanced fuzzing logic" to the
* pixel data for testing or artistic purposes, and finalizes the process by releasing resources and saving the modified image.
*
* @param cgImg The `CGImageRef` representing the original image for processing. It is essential that this image is not null to proceed with the transformation.
*
* ### Process:
* 1. **Input Validation**: Ensures the `CGImageRef` provided is valid and not null.
* 2. **Color Space Creation**: Sets up a color space suitable for RGB data manipulation.
* 3. **Bitmap Context Configuration**: Initiates a bitmap context with Big Endian byte ordering to prioritize the most significant byte in pixel color data.
* 4. **Image Rendering**: Draws the original image into the configured bitmap context, preparing for data manipulation.
* 5. **Pixel Data Fuzzing**: Applies an "enhanced fuzzing logic" directly to the raw pixel data, aiming to test algorithm resilience, simulate effects, or introduce noise.
* 6. **CGImage Generation**: Creates a new CGImage from the context to encapsulate the modifications.
* 7. **Resource Cleanup**: Releases the color space, bitmap context, and any other allocated resources to ensure efficient memory management.
* 8. **Image Saving**: Marks the transformation's completion by saving the modified image with a unique identifier.
*
* ### Example Usage:
*  @code
* // Assuming cgImg is a valid CGImageRef
* createBitmapContextBigEndian(cgImg);
* @endcode
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
        saveFuzzedImage(newImage, @"Big_Endian_png");
        saveFuzzedImage(newImage, @"Big_Endian_jpeg");
        saveFuzzedImage(newImage, @"Big_Endian_gif");
        saveFuzzedImage(newImage, @"Big_Endian_tiff");
        NSLog(@"Modified UIImage with Big Endian settings created and saved successfully in PNG, JPEG and GIF.");
    }

    NSLog(@"Bitmap context with Big Endian settings created and handled successfully for PNG, JPG and GIF");
    CGContextRelease(ctx); // Release the bitmap context
}

#pragma mark - createBitmapContextLittleEndian

/*!
* @brief Initializes a bitmap context with Little Endian settings for image data processing.
* @details This function focuses on preparing and manipulating a bitmap graphics context optimized for Little Endian byte ordering, suitable for systems and applications that require the least
* significant byte to be stored first. It involves creating an RGB color space, setting up the bitmap context for Little Endian processing, applying predefined fuzzing algorithms to pixel data, and
* finalizing the modified image. The process is aimed at testing image processing capabilities, creating visual effects, or introducing distortions through direct pixel manipulation.
*
* @param cgImg The `CGImageRef` representing the image to be processed, which must not be null to ensure successful transformation.
*
* ### Process:
* 1. **Input Validation**: Confirms that the provided `CGImageRef` is valid and non-null.
* 2. **Color Space and Context Setup**: Establishes an RGB color space and creates a bitmap context tailored for Little Endian byte ordering.
* 3. **Image Drawing and Pixel Manipulation**: Renders the original image into the context, then employs "enhanced fuzzing logic" for direct pixel data alteration.
* 4. **CGImage Creation**: Generates a new CGImage from the modified bitmap context, capturing the changes.
* 5. **Resource Management**: Releases the color space and bitmap context to manage memory usage effectively.
* 6. **Image Saving**: Completes the modification process by saving the altered image with a specific identifier, integrating external routines for saving and potentially additional processing.
*
* ### Example Usage:
*  @code
* // Assuming cgImg is a valid CGImageRef
*  createBitmapContextLittleEndian(cgImg);
* @endcode
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
        saveFuzzedImage(newImage, @"Little_Endian_png");
        saveFuzzedImage(newImage, @"Little_Endian_jpeg");
        saveFuzzedImage(newImage, @"Little_Endian_gif");
        saveFuzzedImage(newImage, @"Little_Endian_tiff");
        NSLog(@"Modified UIImage with Little Endian settings created and saved successfully for PNG, JPG and GIF.");
    }

    NSLog(@"Bitmap context with Little Endian settings created successfully");
    CGContextRelease(ctx); // Release the bitmap context
}

#pragma mark - createBitmapContext8BitInvertedColors

/*!
 * @brief Transforms the color representation of an image by inverting its colors and applying an 8-bit color depth.
 *
 * This function is designed for manipulating a bitmap graphics context to invert the RGB values of each pixel in a given CGImageRef,
 * while keeping the alpha channel unchanged. It applies an "enhanced fuzzing logic" to the modified pixel data, making it suitable for creating visual negatives,
 * enhancing image contrast, or evaluating the robustness of image processing algorithms. The color inversion process creates complementary colors for each pixel,
 * offering a straightforward method for achieving visual effects or testing.
 *
 * The setup includes configuring a bitmap context optimized for color inversion and specifying byte order and alpha channel handling. It involves iterating over raw pixel data
 * for manual color inversion and integrating enhanced fuzzing routines for further pixel manipulation. The function concludes by generating a new CGImage that encapsulates all modifications,
 * which is then saved with a unique identifier.
 *
 * Resource management is a key aspect, ensuring efficient memory use and necessitating the implementation of fuzzing and saving routines elsewhere within the application's codebase.
 *
 * @param cgImg The CGImageRef representing the source image to be transformed. This parameter must not be NULL to ensure proper function execution.
 *
 * @note Utilizing this function requires careful consideration of the source image's format and the intended outcome, particularly in terms of color depth and the specific effects of the enhanced fuzzing logic.
 * The reliance on external methods for the fuzzing process and saving the modified image highlights the need for a comprehensive approach to image processing within the application.
 *
 * ### Example Usage:
 * @code
 * CGImageRef sourceImage = ...; // Assume this is a valid CGImageRef
 * createBitmapContextForColorInversionAndFuzzing(sourceImage);
 * @endcode
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
        saveFuzzedImage(newImage, @"8Bit_InvertedColors_png");
        saveFuzzedImage(newImage, @"8Bit_InvertedColors_jpeg");
        saveFuzzedImage(newImage, @"8Bit_InvertedColors_gif");
        saveFuzzedImage(newImage, @"8Bit_InvertedColors_tiff");
        NSLog(@"Modified UIImage with createBitmapContext8BitInvertedColors settings created and saved successfully for PNG, JPG and GIF.");
    }

    CGContextRelease(ctx); // Release the bitmap context
}

#pragma mark - createBitmapContext32BitFloat4Component

/*!
 * @brief Creates a bitmap context with standard RGB settings, applies a fuzzing process to alter the image, and saves the fuzzed image.
 * Useful for testing image processing functionalities or creating varied visual effects.
 *
 * @details This function demonstrates how to create a bitmap context, manipulate image pixel data through a fuzzing process, and save the modified image. It covers validating input images, creating bitmap contexts with specific configurations, and applying image processing algorithms to explore and enhance image processing techniques.
 *
 * @param cgImg The source image from which to create the bitmap context, represented as a `CGImageRef`.
 *
 * @note
 * - **Memory Management**: Demonstrates careful release of resources, including color space and bitmap context, and freeing of dynamically allocated memory.
 * - **Debugging**: Includes commented-out calls to `debugMemoryHandling` to illustrate potential insertion points for memory diagnostics.
 * - **Extensibility**: The `permutation` parameter demonstrates the function's potential to apply various fuzzing types based on input parameters, enhancing modularity and maintainability.
 * - **Logging**: Utilizes `NSLog` for debugging purposes. A more sophisticated logging framework is recommended for production code.
 * - **Separation of Concerns**: Abstracts the actual fuzzing logic into the `applyEnhancedFuzzingToBitmapContext` function, promoting code modularity and maintainability.
 *
 * ### Process Overview:
 * 1. Validates the `CGImageRef` input to ensure a source image is provided.
 * 2. Retrieves source image dimensions and calculates bytes per row for an RGBA pixel format.
 * 3. Allocates memory for raw pixel data.
 * 4. Creates a `CGColorSpaceRef` in the device RGB color space.
 * 5. Specifies bitmap information for alpha channel handling and byte order.
 * 6. Creates the bitmap context with allocated memory, color space, and specified bitmap info.
 * 7. Draws the source image into the bitmap context.
 * 8. Applies a fuzzing algorithm to manipulate the pixel data directly.
 * 9. Generates a new `CGImageRef` from the bitmap context, converts it to `UIImage`, and saves the result.
 * 10. Releases allocated resources, including the bitmap context and pixel data memory.
 *
 * ### Usage Example:
 * @code
 * // Process with all configurations
 * processImage(myImage, -1);
 *
 * // Process with a specific configuration
 * processImage(myImage, 3); // Example: Applies Non-Premultiplied Alpha settings
 * @endcode
 */
void createBitmapContext32BitFloat4Component(CGImageRef cgImg) {
    static dispatch_once_t onceToken;
    static os_log_t createBitmapContextLog;
    dispatch_once(&onceToken, ^{
        createBitmapContextLog = os_log_create("cx.srd.xnuimagefuzzer", "CreateBitmapContext");
    });

    os_signpost_id_t spid = os_signpost_id_generate(createBitmapContextLog);
    os_signpost_event_emit(createBitmapContextLog, spid, "Start creating createBitmapContext32BitFloat4Component context");

    if (!cgImg) {
        NSLog(@"Invalid CGImageRef provided.");
        return;
    }

    NSLog(@"Creating bitmap context with 32-bit float, 4-component settings");

    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    size_t bytesPerRow = width * 4 * sizeof(float);

    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    if (!colorSpace) {
        NSLog(@"Failed to create color space");
        return;
    }

    CGBitmapInfo bitmapInfo = kCGImageAlphaPremultipliedLast | kCGBitmapFloatComponents;
    CGContextRef ctx = CGBitmapContextCreate(NULL, width, height, 32, bytesPerRow, colorSpace, bitmapInfo);
    CGColorSpaceRelease(colorSpace);

    if (!ctx) {
        NSLog(@"Failed to create bitmap context with 32-bit float, 4-component settings");
        return;
    }

    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImg);

    NSLog(@"Applying enhanced fuzzing logic to the bitmap context");
    float *floatData = (float*)CGBitmapContextGetData(ctx);
    applyEnhancedFuzzingToBitmapContextWithFloats(floatData, width, height, YES);

    // Normalize float values to [0.0, 1.0] so saved images have visible variation
    size_t totalFloats = height * width * 4;
    for (size_t i = 0; i < totalFloats; i++) {
        float v = floatData[i];
        if (isnan(v) || isinf(v)) {
            floatData[i] = (float)arc4random() / UINT32_MAX;
        } else {
            floatData[i] = fmodf(fabsf(v), 1.0f);
        }
    }
    NSLog(@"Normalized %zu float values to [0.0, 1.0] for visible output", totalFloats);

    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg);
        // Placeholder for saving the fuzzed image. Implement this function to save your image as needed.
        saveFuzzedImage(newImage, @"32bit_float4_png");
        saveFuzzedImage(newImage, @"32bit_float4_jpeg");
        saveFuzzedImage(newImage, @"32bit_float4_gif");
        saveFuzzedImage(newImage, @"32bit_float4_tiff");
        NSLog(@"Modified UIImage with 32-bit float, 4-component settings created and saved successfully for PNG, JPG and GIF.");
    }

    CGContextRelease(ctx);

    os_signpost_event_emit(createBitmapContextLog, spid, "Finished creating bitmap context for 32bit_float4");
}

#pragma mark - createBitmapContextCMYK

void createBitmapContextCMYK(CGImageRef cgImg) {
    NSLog(@"Creating bitmap context with CMYK color space settings");

    if (!cgImg) {
        NSLog(@"Invalid CGImageRef provided.");
        return;
    }

    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    size_t bytesPerPixel = 5; // CMYK + Alpha
    size_t bytesPerRow = width * bytesPerPixel;

    unsigned char *rawData = (unsigned char *)calloc(height * bytesPerRow, sizeof(unsigned char));
    if (!rawData) {
        NSLog(@"Failed to allocate memory for CMYK image processing");
        return;
    }

    // Fill with fuzzed CMYK data
    for (size_t i = 0; i < height * bytesPerRow; i++) {
        rawData[i] = arc4random_uniform(256);
    }

    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceCMYK();
    if (!colorSpace) {
        NSLog(@"Failed to create CMYK color space");
        free(rawData);
        return;
    }

    CGBitmapInfo bitmapInfo = (CGBitmapInfo)kCGImageAlphaNone;
    // CMYK contexts: 4 components, no alpha, 4 bytes per pixel
    size_t cmykBytesPerRow = width * 4;
    unsigned char *cmykData = (unsigned char *)calloc(height * cmykBytesPerRow, sizeof(unsigned char));
    if (!cmykData) {
        NSLog(@"Failed to allocate CMYK buffer");
        CGColorSpaceRelease(colorSpace);
        free(rawData);
        return;
    }

    for (size_t i = 0; i < height * cmykBytesPerRow; i++) {
        cmykData[i] = arc4random_uniform(256);
    }

    CGContextRef ctx = CGBitmapContextCreate(cmykData, width, height, 8, cmykBytesPerRow, colorSpace, bitmapInfo);
    CGColorSpaceRelease(colorSpace);

    if (!ctx) {
        NSLog(@"Failed to create CMYK bitmap context — falling back to RGB conversion");
        // Fallback: create an RGB context and convert CMYK data manually
        CGColorSpaceRef rgbSpace = CGColorSpaceCreateDeviceRGB();
        size_t rgbBytesPerRow = width * 4;
        unsigned char *rgbData = (unsigned char *)calloc(height * rgbBytesPerRow, sizeof(unsigned char));
        if (!rgbData) {
            CGColorSpaceRelease(rgbSpace);
            free(rawData);
            free(cmykData);
            return;
        }

        // Convert CMYK to RGB with fuzzed values
        for (size_t y = 0; y < height; y++) {
            for (size_t x = 0; x < width; x++) {
                size_t cmykIdx = y * cmykBytesPerRow + x * 4;
                size_t rgbIdx = y * rgbBytesPerRow + x * 4;
                float c = cmykData[cmykIdx] / 255.0f;
                float m = cmykData[cmykIdx + 1] / 255.0f;
                float yy = cmykData[cmykIdx + 2] / 255.0f;
                float k = cmykData[cmykIdx + 3] / 255.0f;
                rgbData[rgbIdx]     = (unsigned char)((1.0f - c) * (1.0f - k) * 255.0f);
                rgbData[rgbIdx + 1] = (unsigned char)((1.0f - m) * (1.0f - k) * 255.0f);
                rgbData[rgbIdx + 2] = (unsigned char)((1.0f - yy) * (1.0f - k) * 255.0f);
                rgbData[rgbIdx + 3] = 255;
            }
        }

        CGContextRef rgbCtx = CGBitmapContextCreate(rgbData, width, height, 8, rgbBytesPerRow,
                                                     rgbSpace, (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
        CGColorSpaceRelease(rgbSpace);
        if (rgbCtx) {
            applyEnhancedFuzzingToBitmapContext(rgbData, width, height, verboseLogging);
            CGImageRef newCgImg = CGBitmapContextCreateImage(rgbCtx);
            if (newCgImg) {
                UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
                CGImageRelease(newCgImg);
                saveFuzzedImage(newImage, @"cmyk_png");
                saveFuzzedImage(newImage, @"cmyk_jpeg");
                saveFuzzedImage(newImage, @"cmyk_tiff");
                NSLog(@"CMYK (RGB fallback) fuzzed images saved successfully.");
            }
            CGContextRelease(rgbCtx);
        }
        free(rgbData);
        free(rawData);
        free(cmykData);
        return;
    }

    // Draw source image into CMYK context (CoreGraphics handles color space conversion)
    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImg);

    // Apply fuzzing to CMYK pixel data
    size_t totalBytes = height * cmykBytesPerRow;
    size_t flipCount = totalBytes / 25; // 4% mutation rate for CMYK
    for (size_t i = 0; i < flipCount; i++) {
        size_t offset = arc4random_uniform((uint32_t)totalBytes);
        cmykData[offset] ^= (1 << arc4random_uniform(8));
    }
    NSLog(@"Applied %zu bit flips to CMYK pixel data", flipCount);

    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from CMYK context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg);
        saveFuzzedImage(newImage, @"cmyk_png");
        saveFuzzedImage(newImage, @"cmyk_jpeg");
        saveFuzzedImage(newImage, @"cmyk_tiff");
        NSLog(@"CMYK fuzzed images saved successfully.");
    }

    CGContextRelease(ctx);
    free(rawData);
    free(cmykData);
}

#pragma mark - createBitmapContextHDRFloat16

void createBitmapContextHDRFloat16(CGImageRef cgImg) {
    NSLog(@"Creating bitmap context with HDR Float16 settings");

    if (!cgImg) {
        NSLog(@"Invalid CGImageRef provided.");
        return;
    }

    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);
    // Use 16-bit float components: 4 components × 2 bytes = 8 bytes per pixel
    // (bytesPerRow used for float16 data sizing, float32 context uses floatBytesPerRow)

    uint16_t *float16Data = (uint16_t *)calloc(height * width * 4, sizeof(uint16_t));
    if (!float16Data) {
        NSLog(@"Failed to allocate memory for HDR Float16 image processing");
        return;
    }

    // Fill with random IEEE 754 half-precision values including edge cases
    for (size_t i = 0; i < height * width * 4; i++) {
        uint32_t r = arc4random_uniform(10);
        switch (r) {
            case 0: float16Data[i] = 0x0000; break; // +0.0
            case 1: float16Data[i] = 0x8000; break; // -0.0
            case 2: float16Data[i] = 0x7C00; break; // +Inf
            case 3: float16Data[i] = 0xFC00; break; // -Inf
            case 4: float16Data[i] = 0x7E00; break; // NaN
            case 5: float16Data[i] = 0x0001; break; // Smallest denorm
            case 6: float16Data[i] = 0x7BFF; break; // Largest finite (65504)
            default: float16Data[i] = (uint16_t)arc4random_uniform(0x10000); break;
        }
    }

    // Use 32-bit float context and convert — CoreGraphics doesn't directly support float16 contexts
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    if (!colorSpace) {
        NSLog(@"Failed to create color space for HDR Float16");
        free(float16Data);
        return;
    }

    size_t floatBytesPerRow = width * 4 * sizeof(float);
    float *floatData = (float *)calloc(height * width * 4, sizeof(float));
    if (!floatData) {
        NSLog(@"Failed to allocate float32 conversion buffer");
        CGColorSpaceRelease(colorSpace);
        free(float16Data);
        return;
    }

    // Convert float16 → float32 for the bitmap context
    for (size_t i = 0; i < height * width * 4; i++) {
        uint16_t h = float16Data[i];
        uint32_t sign = (h >> 15) & 1;
        uint32_t exp = (h >> 10) & 0x1F;
        uint32_t mant = h & 0x3FF;
        uint32_t f;
        if (exp == 0) {
            if (mant == 0) {
                f = sign << 31;
            } else {
                // Denormalized
                exp = 1;
                while (!(mant & 0x400)) { mant <<= 1; exp--; }
                mant &= 0x3FF;
                f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
            }
        } else if (exp == 0x1F) {
            f = (sign << 31) | 0x7F800000 | (mant << 13);
        } else {
            f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
        }
        memcpy(&floatData[i], &f, sizeof(float));
    }

    CGBitmapInfo bitmapInfo = kCGImageAlphaPremultipliedLast | kCGBitmapFloatComponents | kCGBitmapByteOrder32Host;
    CGContextRef ctx = CGBitmapContextCreate(floatData, width, height, 32, floatBytesPerRow, colorSpace, bitmapInfo);
    CGColorSpaceRelease(colorSpace);

    if (!ctx) {
        NSLog(@"Failed to create HDR Float16 bitmap context");
        free(float16Data);
        free(floatData);
        return;
    }

    // Apply additional fuzzing to float data
    applyEnhancedFuzzingToBitmapContextWithFloats(floatData, width, height, YES);

    // Normalize for visible output
    size_t totalFloats = height * width * 4;
    for (size_t i = 0; i < totalFloats; i++) {
        float v = floatData[i];
        if (isnan(v) || isinf(v)) {
            floatData[i] = (float)arc4random() / UINT32_MAX;
        } else {
            floatData[i] = fmodf(fabsf(v), 1.0f);
        }
    }
    NSLog(@"Normalized %zu HDR Float16 values to [0.0, 1.0]", totalFloats);

    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from HDR Float16 context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg);
        saveFuzzedImage(newImage, @"hdr_float16_png");
        saveFuzzedImage(newImage, @"hdr_float16_jpeg");
        saveFuzzedImage(newImage, @"hdr_float16_tiff");
        NSLog(@"HDR Float16 fuzzed images saved successfully.");
    }

    CGContextRelease(ctx);
    free(float16Data);
    free(floatData);
}

#pragma mark - createBitmapContextIndexedColor

void createBitmapContextIndexedColor(CGImageRef cgImg) {
    NSLog(@"Creating bitmap context with Indexed Color (palette-based) settings");

    if (!cgImg) {
        NSLog(@"Invalid CGImageRef provided.");
        return;
    }

    size_t width = CGImageGetWidth(cgImg);
    size_t height = CGImageGetHeight(cgImg);

    // Create a palette with deliberate corruption variants
    uint32_t paletteVariant = arc4random_uniform(5);
    size_t numColors;
    unsigned char palette[256 * 3]; // RGB palette, max 256 entries

    switch (paletteVariant) {
        case 0:
            // Standard 256-color palette with random corruption
            numColors = 256;
            for (size_t i = 0; i < numColors * 3; i++) {
                palette[i] = arc4random_uniform(256);
            }
            // Corrupt: duplicate several palette entries
            for (int c = 0; c < 16; c++) {
                size_t src = arc4random_uniform((uint32_t)numColors) * 3;
                size_t dst = arc4random_uniform((uint32_t)numColors) * 3;
                memcpy(&palette[dst], &palette[src], 3);
            }
            NSLog(@"IndexedColor: 256-color palette with %d duplicate entries", 16);
            break;
        case 1:
            // Minimal 2-color palette (1-bit indexed)
            numColors = 2;
            palette[0] = 0; palette[1] = 0; palette[2] = 0;       // Black
            palette[3] = 255; palette[4] = 255; palette[5] = 255; // White
            NSLog(@"IndexedColor: Minimal 2-color palette");
            break;
        case 2:
            // Corrupt palette with all-zero entries (invisible)
            numColors = 64;
            memset(palette, 0, numColors * 3);
            // Inject a few visible colors
            for (int c = 0; c < 4; c++) {
                size_t idx = arc4random_uniform((uint32_t)numColors) * 3;
                palette[idx] = 255;
                palette[idx + 1] = arc4random_uniform(256);
                palette[idx + 2] = arc4random_uniform(256);
            }
            NSLog(@"IndexedColor: Mostly-zero palette with 4 visible entries");
            break;
        case 3:
            // Gradient palette
            numColors = 256;
            for (size_t i = 0; i < numColors; i++) {
                palette[i * 3]     = (unsigned char)i;
                palette[i * 3 + 1] = (unsigned char)(255 - i);
                palette[i * 3 + 2] = (unsigned char)((i * 7) & 0xFF);
            }
            NSLog(@"IndexedColor: Gradient palette");
            break;
        default:
            // Extreme: single-color palette
            numColors = 1;
            palette[0] = arc4random_uniform(256);
            palette[1] = arc4random_uniform(256);
            palette[2] = arc4random_uniform(256);
            NSLog(@"IndexedColor: Single-color palette (%u, %u, %u)", palette[0], palette[1], palette[2]);
            break;
    }

    // Create indexed pixel data (each pixel is an index into the palette)
    unsigned char *indexData = (unsigned char *)calloc(height * width, sizeof(unsigned char));
    if (!indexData) {
        NSLog(@"Failed to allocate indexed pixel data");
        return;
    }

    // Fill with random indices, some deliberately out of range
    for (size_t i = 0; i < height * width; i++) {
        if (arc4random_uniform(20) == 0) {
            indexData[i] = arc4random_uniform(256); // May exceed numColors — corrupt index
        } else {
            indexData[i] = arc4random_uniform((uint32_t)numColors);
        }
    }

    // Convert indexed data to RGBA for bitmap context
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    if (!colorSpace) {
        free(indexData);
        return;
    }

    size_t bytesPerRow = width * 4;
    unsigned char *rgbaData = (unsigned char *)calloc(height * bytesPerRow, sizeof(unsigned char));
    if (!rgbaData) {
        CGColorSpaceRelease(colorSpace);
        free(indexData);
        return;
    }

    // Map indexed colors to RGBA, with out-of-range indices wrapping
    for (size_t y = 0; y < height; y++) {
        for (size_t x = 0; x < width; x++) {
            unsigned char idx = indexData[y * width + x];
            size_t palIdx = (idx % numColors) * 3;
            size_t pixIdx = (y * bytesPerRow) + (x * 4);
            rgbaData[pixIdx]     = palette[palIdx];
            rgbaData[pixIdx + 1] = palette[palIdx + 1];
            rgbaData[pixIdx + 2] = palette[palIdx + 2];
            rgbaData[pixIdx + 3] = (arc4random_uniform(10) == 0) ? arc4random_uniform(256) : 255;
        }
    }

    CGBitmapInfo bitmapInfo = kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big;
    CGContextRef ctx = CGBitmapContextCreate(rgbaData, width, height, 8, bytesPerRow, colorSpace, bitmapInfo);
    CGColorSpaceRelease(colorSpace);

    if (!ctx) {
        NSLog(@"Failed to create indexed color bitmap context");
        free(indexData);
        free(rgbaData);
        return;
    }

    // Draw source image first, then overlay indexed corruption
    CGContextDrawImage(ctx, CGRectMake(0, 0, width, height), cgImg);

    // Apply additional fuzzing
    applyEnhancedFuzzingToBitmapContext(rgbaData, width, height, verboseLogging);

    CGImageRef newCgImg = CGBitmapContextCreateImage(ctx);
    if (!newCgImg) {
        NSLog(@"Failed to create CGImage from indexed color context");
    } else {
        UIImage *newImage = [UIImage imageWithCGImage:newCgImg];
        CGImageRelease(newCgImg);
        saveFuzzedImage(newImage, @"indexed_color_png");
        saveFuzzedImage(newImage, @"indexed_color_jpeg");
        saveFuzzedImage(newImage, @"indexed_color_gif");
        saveFuzzedImage(newImage, @"indexed_color_tiff");
        NSLog(@"Indexed color fuzzed images saved successfully (palette variant %u, %zu colors).",
              paletteVariant, numColors);
    }

    CGContextRelease(ctx);
    free(indexData);
    free(rgbaData);
}
