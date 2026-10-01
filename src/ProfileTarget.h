#pragma once

#include <string>
#include <string_view>

namespace delprofils {

namespace profile_target_detail {

inline std::wstring asciiLower(std::wstring_view value) {
    std::wstring result(value);
    for (wchar_t& character : result) {
        if (character >= L'A' && character <= L'Z') {
            character = static_cast<wchar_t>(character - L'A' + L'a');
        }
    }
    return result;
}

inline bool validComputerName(std::wstring_view value) {
    if (value.empty() || value.size() > 253) return false;
    for (const wchar_t character : value) {
        const bool alphanumeric = (character >= L'a' && character <= L'z') ||
            (character >= L'A' && character <= L'Z') ||
            (character >= L'0' && character <= L'9');
        if (!alphanumeric && character != L'-' && character != L'.') return false;
    }
    return true;
}

} // namespace profile_target_detail

class ProfileTarget {
public:
    static ProfileTarget local() {
        ProfileTarget result;
        result.valid_ = true;
        result.local_ = true;
        return result;
    }

    static ProfileTarget fromComputer(std::wstring_view computer) {
        return fromComputer(computer, {});
    }

    static ProfileTarget fromComputer(std::wstring_view computer,
                                      std::wstring_view localComputerName) {
        if (computer.rfind(L"\\\\", 0) == 0) computer.remove_prefix(2);
        if (!profile_target_detail::validComputerName(computer)) return {};

        const std::wstring lower = profile_target_detail::asciiLower(computer);
        const std::wstring localLower = profile_target_detail::asciiLower(localComputerName);
        if (lower == L"." || lower == L"localhost" ||
            (!localLower.empty() && lower == localLower)) {
            return local();
        }

        ProfileTarget result;
        result.valid_ = true;
        result.local_ = false;
        result.computer_ = std::wstring(computer);
        return result;
    }

    bool valid() const { return valid_; }
    bool isLocal() const { return local_; }
    const std::wstring& computer() const { return computer_; }
    std::wstring wmiNamespace() const {
        if (!valid_) return {};
        if (local_) return L"ROOT\\CIMV2";
        return L"\\\\" + computer_ + L"\\ROOT\\CIMV2";
    }

private:
    bool valid_ = false;
    bool local_ = true;
    std::wstring computer_;
};

} // namespace delprofils
