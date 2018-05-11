#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <Windows.h>
#include <winnt.h>

namespace sysidx
{
	struct export_entry_t
	{
		std::string m_name;
		std::uint32_t m_syscall_index;
	};

	auto get_syscall_index(std::uint32_t address) -> std::uint32_t
	{
		return *reinterpret_cast<std::uint32_t*>(address + 1);
	}

	auto get_exports(std::uintptr_t module_base, std::vector<export_entry_t>& out_exports) -> void
	{
		if (!module_base)
			return;

		auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module_base);
		auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(module_base + dos->e_lfanew);

		auto export_base = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (export_base)
		{
			auto export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(module_base + export_base);

			for (auto i = 0U; i < export_dir->NumberOfFunctions; i++)
			{
				auto entry_name_rva = *reinterpret_cast<std::ptrdiff_t*>(module_base + export_dir->AddressOfNames + i * sizeof(DWORD));
				auto entry_ordinal = *reinterpret_cast<std::uint16_t*>(module_base + export_dir->AddressOfNameOrdinals + i * sizeof(USHORT));
				auto entry_address = *reinterpret_cast<std::uintptr_t*>(module_base + export_dir->AddressOfFunctions + entry_ordinal * sizeof(DWORD));
				auto entry_name = reinterpret_cast<char*>(module_base + entry_name_rva);

				// make sure we're dumping Nt syscall wrappers only
				// search for a 'ret' instruction byte and an alignment at the end
				// this works for the changed Win10 switch-to-long-mode method in ntdll and most likely has to be changed in order to support previous Win versions
				auto function_address = module_base + entry_address;
				auto ret_check = *reinterpret_cast<std::uint8_t*>(function_address + 12) == 0xC2;
				auto align_check = *reinterpret_cast<std::uint8_t*>(function_address + 15) == 0x90;
				if (ret_check && align_check)
				{
					auto syscall_index = get_syscall_index(function_address);
					if (std::find_if(out_exports.begin(), out_exports.end(), [&](const export_entry_t& e) -> bool
					{
						return e.m_syscall_index == syscall_index;
					}) == out_exports.end())
						out_exports.push_back({ entry_name, syscall_index });
				}
			}
		}
	}
}