#pragma once

#include <future>
#include <Windows.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <sstream>

#include <string>
#include <vector>

struct memory_region_result
{
    std::uint64_t current_base_address;
    std::uint64_t region_size;
    std::uint64_t region_base;
};

namespace memory_utilities
{
    inline std::vector<std::string> split(const std::string &string, const char delimiter)
    {
        std::vector<std::string> tokens;
        std::string token;
        std::istringstream token_stream(string);

        while (std::getline(token_stream, token, delimiter))
        {
            tokens.push_back(token);
        }

        return tokens;
    }
    
    inline void get_main_module(const HANDLE& process_handle, MODULEINFO& module_info)
    {
        HMODULE module_entry = {};
        DWORD cb_needed;
        if (EnumProcessModules(process_handle, &module_entry, sizeof(module_entry), &cb_needed) == 0)
        {
            return;
        }
        
        GetModuleInformation(process_handle, module_entry, &module_info, sizeof(MODULEINFO));
    }
}

namespace memory
{
    static std::int32_t process_id;
    static HANDLE proc_handle;
    static MODULEINFO main_module;

    inline std::int32_t get_process_id_by_name(const std::string& process_name)
    {
        const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            return -1;
        }
        
        PROCESSENTRY32 entry{};
        entry.dwSize = sizeof(PROCESSENTRY32);

        int32_t proc_id = -1;
        BOOL h_result = Process32First(snapshot, &entry);
        while (h_result)
        {
            char ch[260];
            WideCharToMultiByte(CP_ACP, 0, entry.szExeFile, -1, ch, 260, nullptr, nullptr);
            std::string curr_process_name(ch);
            
            if (process_name == curr_process_name)
            {
                proc_id = static_cast<std::int32_t>(entry.th32ProcessID);
                break;
            }
            
            h_result = Process32Next(snapshot, &entry);
        }

        CloseHandle(snapshot);
        return proc_id;
    }

    inline bool open_process(const std::int32_t& proc_id)
    {
        if (proc_id <= 0)
        {
            return false;
        }
        
        const HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc_id);
        if (h_process != nullptr)
        {
            process_id = proc_id;
            proc_handle = h_process;
            memory_utilities::get_main_module(proc_handle, main_module);
        }
        return h_process;
    }
    
    template <typename T>
    T read(const std::uint64_t& address)
    {
        T value;
        ReadProcessMemory(proc_handle, reinterpret_cast<LPCVOID>(address), &value, sizeof(T), nullptr);
        return value;
    }

    template <typename T>
    bool write(const std::uint64_t& address, T write, const bool& remove_write_protection = true)
    {
        DWORD protect;
        if (remove_write_protection)
        {
            VirtualProtectEx(proc_handle, reinterpret_cast<LPVOID>(address), sizeof(T), PAGE_EXECUTE_READWRITE, &protect);
        }
        const auto result = WriteProcessMemory(proc_handle, reinterpret_cast<LPVOID>(address), &write, sizeof(T), nullptr);
        if (remove_write_protection)
        {
            VirtualProtectEx(proc_handle, reinterpret_cast<LPVOID>(address), sizeof(T), protect, nullptr);
        }
        return result;
    }

    template <typename T>
    bool write_vector(const std::uint64_t& address, std::vector<T> write, const bool& remove_write_protection = true)
    {
        const auto size = static_cast<std::int32_t>(write.size());
        DWORD protect;
        if (remove_write_protection)
        {
            VirtualProtectEx(proc_handle, reinterpret_cast<LPVOID>(address), size, PAGE_EXECUTE_READWRITE, &protect);
        }
        const auto result = WriteProcessMemory(proc_handle, reinterpret_cast<LPVOID>(address), write.data(), size, nullptr);
        if (remove_write_protection)
        {
            VirtualProtectEx(proc_handle, reinterpret_cast<LPVOID>(address), size, protect, nullptr);
        }
        return result;
    }
    
    inline std::int32_t find_pattern(
        const std::uint8_t* body,
        const size_t& body_length,
        const std::vector<std::uint8_t>& aob_pattern,
        const std::vector<std::uint8_t>& mask,
        const size_t& start
    )
    {
        std::int32_t found_index = -1;
        const auto pattern_size = aob_pattern.size();
        
        if (body_length <= 0 || start > body_length - pattern_size || pattern_size > body_length)
        {
            return found_index;
        }

        for (size_t i = start; i <= body_length - pattern_size; i++)
        {
            if ((body[i] & mask[0]) == (aob_pattern[0] & mask[0]))
            {
                auto match = true;

                for (size_t j = pattern_size - 1; j >= 1; j--)
                {
                    if ((body[i + j] & mask[j]) == (aob_pattern[j] & mask[j]))
                    {
                        continue;
                    }

                    match = false;
                    break;
                }

                if (!match)
                {
                    continue;   
                }

                found_index = static_cast<std::int32_t>(i);
                break;
            }
        }
        
        return found_index;
    }

    inline std::uint64_t compare_scan(
        const memory_region_result& item,
        const std::vector<std::uint8_t>& aob_pattern,
        const std::vector<std::uint8_t>& mask
    )
    {
        if (aob_pattern.size() != mask.size())
        {
            throw std::bad_array_new_length();
        }

        SIZE_T bytes_read;
        const auto buffer = new std::uint8_t[item.region_size];
        ReadProcessMemory(proc_handle, reinterpret_cast<LPCVOID>(item.current_base_address), buffer, item.region_size, &bytes_read);

        const int32_t found_index = find_pattern(buffer, bytes_read, aob_pattern, mask, 0);
        
        delete[] buffer;
        return found_index == -1 ? 0 : item.current_base_address + found_index;
    }

    inline std::uint64_t aob_scan(
        std::uint64_t start,
        std::uint64_t end,
        const std::string& sig,
        const bool& writable = false,
        const bool& executable = true
    )
    {
        SYSTEM_INFO system_info{};
        GetSystemInfo(&system_info);

        if (start < reinterpret_cast<std::uint64_t>(system_info.lpMinimumApplicationAddress))
        {
            start = reinterpret_cast<std::uint64_t>(system_info.lpMinimumApplicationAddress);
        }

        if (end > reinterpret_cast<std::uint64_t>(system_info.lpMaximumApplicationAddress))
        {
            end = reinterpret_cast<std::uint64_t>(system_info.lpMaximumApplicationAddress);
        }

        std::vector<memory_region_result> memory_region_results{};
        MEMORY_BASIC_INFORMATION basic_information{};
        std::uint64_t current_base_address = start;
        SIZE_T size{};
        
        #if _M_X64
            size = sizeof(MEMORY_BASIC_INFORMATION64);
        #else
            size = sizeof(MEMORY_BASIC_INFORMATION32);
        #endif
        
        while (VirtualQueryEx(proc_handle, reinterpret_cast<LPCVOID>(current_base_address), &basic_information, size) &&
                current_base_address < end &&
                current_base_address + basic_information.RegionSize > current_base_address)
        {
            bool is_valid = basic_information.State == MEM_COMMIT;
            is_valid &= basic_information.BaseAddress < system_info.lpMaximumApplicationAddress;
            is_valid &= (basic_information.Protect & PAGE_GUARD) == 0;
            is_valid &= (basic_information.Protect & PAGE_NOACCESS) == 0;
            is_valid &= basic_information.Type == MEM_PRIVATE || basic_information.Type == MEM_IMAGE;

            if (is_valid)
            {
                const bool is_readable = (basic_information.Protect & PAGE_READONLY) > 0;

                bool is_writable = (basic_information.Protect & PAGE_READWRITE) > 0 ||
                                   (basic_information.Protect & PAGE_WRITECOPY) > 0 ||
                                   (basic_information.Protect & PAGE_EXECUTE_READWRITE) > 0 ||
                                   (basic_information.Protect & PAGE_EXECUTE_WRITECOPY) > 0;

                bool is_executable = (basic_information.Protect & PAGE_EXECUTE) > 0 ||
                                     (basic_information.Protect & PAGE_EXECUTE_READ) > 0 ||
                                     (basic_information.Protect & PAGE_EXECUTE_READWRITE) > 0 ||
                                     (basic_information.Protect & PAGE_EXECUTE_WRITECOPY) > 0;

                is_writable &= writable;
                is_executable &= executable;
                
                is_valid &= is_readable || is_writable || is_executable;
            }

            if (!is_valid)
            {
                current_base_address =
                    reinterpret_cast<std::uint64_t>(basic_information.BaseAddress) + basic_information.RegionSize;
                continue;
            }
            
            memory_region_result mem_region
            {
                current_base_address,
                basic_information.RegionSize,
                reinterpret_cast<std::uint64_t>(basic_information.BaseAddress)
            };

            current_base_address = 
                reinterpret_cast<std::uint64_t>(basic_information.BaseAddress) + basic_information.RegionSize;

            if (!memory_region_results.empty())
            {
                const memory_region_result previous_region = memory_region_results[memory_region_results.size() - 1];
                if (previous_region.region_base + previous_region.region_size ==
                        reinterpret_cast<std::uint64_t>(basic_information.BaseAddress))
                {
                    memory_region_results[memory_region_results.size() - 1] = memory_region_result
                    {
                        previous_region.current_base_address,
                        previous_region.region_base,
                        previous_region.region_size + basic_information.RegionSize
                    };

                    continue;
                }
            }

            memory_region_results.emplace_back(mem_region);
        }

        std::vector<std::string> string_byte_array = memory_utilities::split(sig, ' ');
        std::vector<std::uint8_t> aob_pattern(string_byte_array.size());
        std::vector<std::uint8_t> mask(string_byte_array.size());
        
        for (size_t i = 0; i < string_byte_array.size(); i++)
        {
            const std::string ba = string_byte_array[i];

            if (ba == "??" || (ba.length() == 1 && ba == "?"))
            {
                mask[i] = 0x00;
                string_byte_array[i] = "0x00";
            }
            else if (std::isalnum(ba[0]) && ba[1] == '?')
            {
                mask[i] = 0xF0;
                string_byte_array[i] = std::string(1, ba[0]) + "0";
            }
            else if (std::isalnum(ba[1]) && ba[0] == '?')
            {
                mask[i] = 0x0F;
                string_byte_array[i] = "0" + std::string(1, ba[1]);
            }
            else
            {
                mask[i] = 0xFF;
            }
        }

        for (size_t i = 0; i < string_byte_array.size(); i++)
        {
            aob_pattern[i] = static_cast<std::uint8_t>(std::stoi(string_byte_array[i], nullptr, 16) & mask[i]);
        }
        
        for (memory_region_result result : memory_region_results)
        {
            const auto compare_scan_result = compare_scan(result, aob_pattern, mask);
            if (compare_scan_result)
            {
                return compare_scan_result;
            }
        }
        
        return reinterpret_cast<std::uint64_t>(nullptr);
    }
    
    inline void aob_scan_async(
        std::uint64_t start,
        std::uint64_t end,
        const std::string& sig,       
        const std::function<void(std::uint64_t)>& callback,
        const bool& writable = false,
        const bool& executable = true
    )
    {
        std::thread([start, end, sig, writable, executable, callback]
        {
            const std::uint64_t result = aob_scan(start, end, sig, writable, executable);
            callback(result);
        }).detach();
    }

    inline std::uint64_t aob_scan(const std::string& sig, const bool& writable = false, const bool& executable = true)
    {
        const std::uint64_t start = reinterpret_cast<std::uint64_t>(main_module.lpBaseOfDll);
        const std::uint64_t end = start + main_module.SizeOfImage;
        return aob_scan(start, end, sig, writable, executable);
    }

    inline void aob_scan_async(
        const std::string& sig,
        const std::function<void(std::uint64_t)>& callback,
        const bool& writable = false,
        const bool& executable = true
    )
    {
        const std::uint64_t start = reinterpret_cast<std::uint64_t>(main_module.lpBaseOfDll);
        const std::uint64_t end = start + main_module.SizeOfImage;
        std::thread([start, end, sig, writable, executable, callback]
        {
            const std::uint64_t result = aob_scan(start, end, sig, writable, executable);
            callback(result);
        }).detach();
    }

    inline std::uint64_t follow_multi_level_pointer(const std::uint64_t& address, const std::vector<uint32_t>& offsets)
    {
        std::uint64_t result = address;
        for (const unsigned int offset : offsets)
        {
            result = read<std::uint64_t>(result);
            result += offset;
        }
        return result;
    }

    inline bool check_if_free(std::uint64_t& base_addr, const std::uint32_t& size, const bool& inc_duration)
    {
        std::uint32_t needed_size = size;

        if ((needed_size & 0xFFF) > 0)
        {
            needed_size = needed_size + 0x1000 & ~0xFFF;
        }
        
        MEMORY_BASIC_INFORMATION mbi{};
        const ULONGLONG start_time = GetTickCount64();
        std::uint32_t tries = 0;
        std::uint64_t new_base;
        SIZE_T info_size{};
        
        #if _M_X64
            info_size = sizeof(MEMORY_BASIC_INFORMATION64);
        #else
            info_size = sizeof(MEMORY_BASIC_INFORMATION32);
        #endif
        
        while (VirtualQueryEx(proc_handle, reinterpret_cast<LPCVOID>(base_addr), &mbi, info_size))
        {
            if (mbi.RegionSize == 0)
            {
                return false;
            }

            if (mbi.State == MEM_FREE && mbi.RegionSize >= needed_size)
            {
                if (tries == 0)
                {
                    base_addr = reinterpret_cast<std::uint64_t>(mbi.BaseAddress);
                }
                else
                {
                    if (inc_duration)
                    {
                        base_addr = reinterpret_cast<std::uint64_t>(mbi.BaseAddress);
                    }
                    else
                    {
                        base_addr = reinterpret_cast<std::uint64_t>(mbi.AllocationBase) + mbi.RegionSize - size;
                    }
                }

                return true;
            }

            if (inc_duration)
            {
                new_base = reinterpret_cast<std::uint64_t>(mbi.AllocationBase) + mbi.RegionSize;
                if (new_base < base_addr)
                {
                    return false;
                }
            }
            else
            {
                SYSTEM_INFO sys_info{};
                GetSystemInfo(&sys_info);
                
                new_base = reinterpret_cast<std::uint64_t>(mbi.AllocationBase) - sys_info.dwAllocationGranularity;
                if (new_base > base_addr)
                {
                    return false;
                }
            }

            if (new_base == base_addr)
            {
                return false;
            }

            base_addr = new_base;
            if (tries > 50 && GetTickCount64() > start_time + 2000)
            {
                return false;
            }
            
            ++tries;
        }
        
        return false;
    }

    inline std::uint64_t find_free_block_for_region(const std::uint64_t& base_addr, const std::uint32_t& size)
    {
        if (base_addr == 0)
        {
            return 0;
        }

       std::uint64_t min_address = base_addr - 0x70000000;
       std::uint64_t max_address = base_addr + 0x70000000;

        SYSTEM_INFO sys_info{};
        GetSystemInfo(&sys_info);
        
        BOOL is_64_bit_process;
        if (IsWow64Process(proc_handle, &is_64_bit_process) && is_64_bit_process)
        {
            if (min_address > reinterpret_cast<uint64_t>(sys_info.lpMaximumApplicationAddress) ||
                min_address < reinterpret_cast<uint64_t>(sys_info.lpMinimumApplicationAddress))
            {
                min_address = reinterpret_cast<uint64_t>(sys_info.lpMinimumApplicationAddress);
            }
            
            if (max_address < reinterpret_cast<uintptr_t>(sys_info.lpMinimumApplicationAddress) ||
                max_address > reinterpret_cast<uintptr_t>(sys_info.lpMaximumApplicationAddress))
            {
                max_address = reinterpret_cast<uintptr_t>(sys_info.lpMaximumApplicationAddress);
            }
        }
        else
        {
            min_address = 0x10000;
            max_address = 0xfffffffff;
        }

        if (sys_info.dwAllocationGranularity == 0)
        {
            sys_info.dwAllocationGranularity = 4096;
        }

        std::uint64_t right = base_addr & ~0xfff;
        std::uint64_t left = right - 0x1000;

        bool right_tok = check_if_free(right, size, true);
        if (right_tok && right > max_address)
        {
            right_tok = false;
        }

        bool left_tok = check_if_free(left, size, false);
        if (left_tok && left < min_address)
        {
            left_tok = false;
        }

        if (right_tok && left_tok)
        {
            if (right - base_addr < base_addr - left)
            {
                return right;
            }

            return left;
        }

        if (right_tok)
        {
            return right;
        }

        if (left_tok)
        {
            return left;
        }

        return base_addr;
    }
    
    inline std::uint64_t create_detour(
        const std::uint64_t& address,
        const std::vector<std::uint8_t>& new_bytes,
        const std::int32_t& replace_count,
        const std::size_t& size = 0x1000,
        const std::vector<std::uint8_t>& var_bytes = {},
        const std::int32_t& var_offset = 0,
        const bool& make_detour = true
    )
    {
        if (replace_count < 5)
        {
            throw std::invalid_argument("Replace count is less than 5");
        }

        std::uint64_t preferred = address;
        std::uint64_t cave_address = 0;

        while (cave_address == 0)
        {
            cave_address = reinterpret_cast<std::uint64_t>(
                VirtualAllocEx(
                    proc_handle,
                    reinterpret_cast<LPVOID>(find_free_block_for_region(preferred, static_cast<uint32_t>(size))),
                    size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE
                )
            );

            if (cave_address != 0)
            {
                break;
            }

            preferred += 0x10000;
        }

        const auto offset1 = static_cast<std::uint32_t>(cave_address - address - 5);
        std::vector<std::uint8_t> jmp_bytes(replace_count, 0);
        jmp_bytes[0] = 0xE9;
        std::copy_n(reinterpret_cast<const std::uint8_t*>(&offset1), sizeof(offset1), jmp_bytes.begin() + 1);

        const auto jmp_bytes_size = static_cast<std::int32_t>(jmp_bytes.size());
        for (std::int32_t i = 5; i < jmp_bytes_size; ++i)
        {
            jmp_bytes[i] = 0x90;
        }

        const auto new_bytes_size = static_cast<std::int32_t>(new_bytes.size());
        std::vector<std::uint8_t> detour_bytes(new_bytes_size + 5, 0);
        std::copy(new_bytes.begin(), new_bytes.end(), detour_bytes.begin());
        
        const auto offset2 = static_cast<std::uint32_t>(address + jmp_bytes_size - (cave_address + new_bytes_size) - 5);
        detour_bytes[new_bytes_size] = 0xE9;
        std::copy_n(
            reinterpret_cast<const std::uint8_t*>(&offset2),
            sizeof(offset2),
            detour_bytes.begin() + new_bytes_size + 1
        );
        write_vector(cave_address, detour_bytes);

        if (!var_bytes.empty())
        {
            write_vector(cave_address + detour_bytes.size() + var_offset, var_bytes);
        }

        if (make_detour)
        {
            write_vector(address, jmp_bytes);
        }
        
        return cave_address;
    }

    inline std::uint64_t create_far_detour(
        const std::uint64_t& address,
        const std::vector<std::uint8_t>& new_bytes,
        const std::int32_t& replace_count,
        const std::size_t& detour_size = 0x1000,
        const std::vector<std::uint8_t>& var_bytes = {},
        const std::int32_t& var_offset = 0,
        const bool& make_detour = true
    )
    {
        if (replace_count < 14)
        {
            throw std::invalid_argument("Replace count is less than 14");
        }

        const std::uint64_t cave_address =
            reinterpret_cast<std::uint64_t>(VirtualAllocEx(
                proc_handle,
                nullptr,
                detour_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            ));

        std::vector<std::uint8_t> jmp_bytes(replace_count, 0);
        jmp_bytes[0] = 0xFF;
        jmp_bytes[1] = 0x25;
        std::copy_n(reinterpret_cast<const std::uint8_t*>(&cave_address), sizeof(cave_address), jmp_bytes.begin() + 6);

        const std::int32_t jmp_bytes_size = static_cast<std::int32_t>(jmp_bytes.size());
        for (std::int32_t i = 14; i < jmp_bytes_size; ++i)
        {
            jmp_bytes[i] = 0x90;
        }

        const std::int32_t new_bytes_size = static_cast<std::int32_t>(new_bytes.size());
        std::vector<std::uint8_t> detour_bytes(new_bytes_size + 14, 0);
        std::copy(new_bytes.begin(), new_bytes.end(), detour_bytes.begin());
        
        detour_bytes[new_bytes_size] = 0xFF;
        detour_bytes[new_bytes_size + 1] = 0x25;
        std::copy_n(
            reinterpret_cast<const std::uint8_t*>(address + jmp_bytes_size),
            sizeof(address),
            detour_bytes.begin() + new_bytes_size + 6
        );
        write_vector(cave_address, detour_bytes);

        if (!var_bytes.empty())
        {
            write_vector(cave_address + detour_bytes.size() + var_offset, var_bytes);
        }

        if (make_detour)
        {
            write_vector(address, jmp_bytes);
        }
        
        return cave_address;
    }
}
