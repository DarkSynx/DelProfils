#include "ProfileRoot.h"

#include <string_view>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <userenv.h>
#endif

namespace delprofils {
namespace {

std::wstring normalizedPath(std::wstring value) {
    while (value.size() > 3 && (value.back() == L'\\' || value.back() == L'/')) value.pop_back();
    for (wchar_t& character : value) {
        if (character >= L'A' && character <= L'Z') {
            character = static_cast<wchar_t>(character - L'A' + L'a');
        }
        if (character == L'/') character = L'\\';
    }
    return value;
}

bool localDriveRoot(std::wstring_view path) {
    return path.size() >= 3 &&
           ((path[0] >= L'a' && path[0] <= L'z') || (path[0] >= L'A' && path[0] <= L'Z')) &&
           path[1] == L':' && path[2] == L'\\';
}

} // namespace

bool isDirectChildOfProfilesRoot(const std::wstring& profilePath,
                                 const std::wstring& profilesRoot) {
    const std::wstring root = normalizedPath(profilesRoot);
    const std::wstring path = normalizedPath(profilePath);
    if (!localDriveRoot(root) || path.size() <= root.size() + 1 ||
        path.compare(0, root.size(), root) != 0 || path[root.size()] != L'\\') {
        return false;
    }
    const std::wstring_view leaf(path.c_str() + root.size() + 1,
                                 path.size() - root.size() - 1);
    return !leaf.empty() && leaf.find(L'\\') == std::wstring_view::npos;
}

ProfilesRootResult queryProfilesRoot() {
#ifndef _WIN32
    return {};
#else
    DWORD characters = 0;
    if (GetProfilesDirectoryW(nullptr, &characters) || characters == 0) {
        return {false, {}, GetLastError()};
    }
    const DWORD firstError = GetLastError();
    if (firstError != ERROR_INSUFFICIENT_BUFFER) return {false, {}, firstError};

    std::vector<wchar_t> buffer(characters, L'\0');
    DWORD capacity = characters;
    if (!GetProfilesDirectoryW(buffer.data(), &capacity)) {
        return {false, {}, GetLastError()};
    }
    std::wstring path(buffer.data());
    if (path.empty() || !localDriveRoot(path)) return {false, {}, ERROR_INVALID_DATA};
    return {true, std::move(path), ERROR_SUCCESS};
#endif
}

} // namespace delprofils
