# Memory.h

## Overview

Memory.h is a C++ header file that provides a collection of functions and utilities for memory management and manipulation in a Windows environment. It includes functions for reading and writing to process memory, obtaining process information, and scanning memory regions for specific patterns.

## Features

- **Process Information Retrieval**: Functions to get process ID by name and main module of a process.
- **Memory Reading and Writing**: Templates for reading from and writing to process memory.
- **Memory Scanning**: Functions for pattern scanning in memory regions (synchronous and asynchronous).
- **Multi-Level Pointer Handling**: Function to follow multi-level pointers.
- **Function Detouring**: Functions for detouring functions in process memory (5-byte jmp near, 14-byte jmp far).

## Dependencies

This header file relies on the following Windows-specific libraries:

- Windows.h
- Psapi.h
- TlHelp32.h

## Usage

Here are some examples of how you might use the functions provided in this header file:

```cpp
#include "Memory.h"

// Get process ID by name
std::int32_t process_id = memory::get_process_id_by_name("process_name.exe");

// Open the process
bool success = memory::open_process(process_id);

// Read from a specific memory address
std::uint64_t value = memory::read<std::uint64_t>(0x12345678);

// Write to a specific memory address
bool result = memory::write<float>(0x12345678, 43.5);

// Scan for a pattern in memory
std::string pattern = "AA BB CC ?? DD";
std::uint64_t found_address = memory::aob_scan(0x10000000, 0x20000000, pattern);

// Asynchronously scan for a pattern in memory
memory::aob_scan_async(pattern, [](std::uint64_t result) {
    // Callback function to handle the result
});
```

## Examples

### Asynchronously pattern scanning and detouring a function

```cpp
#include "Memory.h"
#include <iostream>

int main()
{
    const auto pid = memory::get_process_id_by_name("Tutorial-i386.exe");
    if (pid == -1) 
    {
        std::cerr << "Process not found!" << '\n';
        return 1;
    }
    
    if (!memory::open_process(pid))
    {
        std::cerr << "Failed at open_process\n";
        return 1;
    }

    memory::aob_scan_async("83 C0 01 29 83 B0 04 00 00", [](const std::uint64_t& result)
    {
        if (result == 0)
        {
            std::cerr << "Pattern not found\n";
            return;
        }
        
        std::cout << "Pattern scan result:" << std::hex << result << '\n';
        const auto detour_addr = memory::create_detour(result, { 0x83, 0xC0, 0x01, 0x29, 0x83, 0xB0, 0x04, 0x00, 0x00 }, 9);
        std::cout << "Detour address:" << std::hex << detour_addr;
    });

    std::cin.get();
    return 0;
}
```

## License

This project is licensed under the GPL-3.0 License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This code is provided as-is for educational purposes and should not be used maliciously. The author is not responsible for any misuse of this code.

## Contributing

Contributions are welcome. Please open an issue or submit a pull request.

## Support

If you encounter any problems or have any questions, please open an issue on GitHub.
