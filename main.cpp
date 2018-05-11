#include "syscall_indices.hpp"

int main(void)
{
	std::ios::sync_with_stdio(false);

	// Not calling USER32 functions directly so we have to load the library manually
	LoadLibraryA("user32.dll");

	using RtlGetVersionFn = NTSTATUS(NTAPI*)(PRTL_OSVERSIONINFOEXW);
	auto rtl_get_version = reinterpret_cast<RtlGetVersionFn>(GetProcAddress(GetModuleHandleA("NTDLL"), "RtlGetVersion"));
	auto version = RTL_OSVERSIONINFOEXW{ 0 };
	rtl_get_version(&version);

	auto file = std::ofstream("dump.txt");
	if (file.is_open())
	{
		auto win_ver = (version.dwMajorVersion << 8) | version.dwMinorVersion;
		if (win_ver != _WIN32_WINNT_WIN10)
		{
			file << "Error: Your current OS isn't Win10";
			file.close();
			return 0;
		}

		auto exports = std::vector<sysidx::export_entry_t>();
		sysidx::get_exports(reinterpret_cast<std::uintptr_t>(GetModuleHandleA("ntdll.dll")), exports);
		sysidx::get_exports(reinterpret_cast<std::uintptr_t>(GetModuleHandleA("win32u.dll")), exports);
		std::sort(exports.begin(), exports.end(), [](const sysidx::export_entry_t& a, const sysidx::export_entry_t& b)
		{
			return b.m_syscall_index > a.m_syscall_index;
		});

		auto out = std::stringstream("");
		for (auto& entry : exports)
			out << std::hex << std::uppercase << "0x" << entry.m_syscall_index << " - " << entry.m_name << '\n';

		file << out.str();
		file.close();
	}

	return 0;
}