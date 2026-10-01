#include "Console.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <iostream>
#endif

#include <string>

namespace delprofils {

void Console::out(std::wstring_view text) const { write(false, text); }
void Console::err(std::wstring_view text) const { write(true, text); }

void Console::write(bool error, std::wstring_view text) const {
    if (quiet_ || text.empty()) return;
#ifdef _WIN32
    HANDLE h = GetStdHandle(error ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE);
    if (!h || h == INVALID_HANDLE_VALUE) return;
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode)) {
        DWORD written = 0;
        WriteConsoleW(h, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
        return;
    }
    const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                                          static_cast<int>(text.size()), nullptr, 0,
                                          nullptr, nullptr);
    if (bytes <= 0) return;
    std::string utf8(static_cast<std::size_t>(bytes), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                        static_cast<int>(text.size()), utf8.data(), bytes,
                        nullptr, nullptr);
    DWORD written = 0;
    WriteFile(h, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
#else
    std::wostream& os = error ? std::wcerr : std::wcout;
    os << text;
#endif
}

} // namespace delprofils
