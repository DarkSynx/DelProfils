#include "SystemProfilePaths.h"

#ifdef _WIN32
#include <windows.h>
#include <knownfolders.h>
#include <shlobj.h>
#include <userenv.h>
#endif

#include <vector>

namespace delprofils {
namespace {

#ifdef _WIN32
std::wstring message(const wchar_t* step, DWORD error) {
    return std::wstring(step) + L" (WIN32=" + std::to_wstring(error) + L")";
}

bool getProfilesDirectory(std::wstring& result, DWORD& error) {
    DWORD count = 0;
    if (GetProfilesDirectoryW(nullptr, &count) || count == 0) {
        error = GetLastError();
        return false;
    }
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        error = GetLastError();
        return false;
    }
    std::vector<wchar_t> buffer(count, L'\0');
    if (!GetProfilesDirectoryW(buffer.data(), &count)) {
        error = GetLastError();
        return false;
    }
    result.assign(buffer.data());
    return !result.empty();
}

bool getDefaultProfileDirectory(std::wstring& result, DWORD& error) {
    DWORD count = 0;
    if (GetDefaultUserProfileDirectoryW(nullptr, &count) || count == 0) {
        error = GetLastError();
        return false;
    }
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        error = GetLastError();
        return false;
    }
    std::vector<wchar_t> buffer(count, L'\0');
    if (!GetDefaultUserProfileDirectoryW(buffer.data(), &count)) {
        error = GetLastError();
        return false;
    }
    result.assign(buffer.data());
    return !result.empty();
}

bool getCommonDataDirectory(std::wstring& result, DWORD& error) {
    DWORD count = 0;
    if (GetAllUsersProfileDirectoryW(nullptr, &count) || count == 0) {
        error = GetLastError();
        return false;
    }
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        error = GetLastError();
        return false;
    }
    std::vector<wchar_t> buffer(count, L'\0');
    if (!GetAllUsersProfileDirectoryW(buffer.data(), &count)) {
        error = GetLastError();
        return false;
    }
    result.assign(buffer.data());
    return !result.empty();
}

bool readRegistryString(HKEY key, const wchar_t* valueName, std::wstring& result, DWORD& error) {
    DWORD type = 0;
    DWORD bytes = 0;
    const LSTATUS first = RegGetValueW(key, nullptr, valueName,
                                       RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
                                       &type, nullptr, &bytes);
    if (first != ERROR_SUCCESS || bytes < sizeof(wchar_t) || bytes > 32768U * sizeof(wchar_t)) {
        error = static_cast<DWORD>(first);
        return false;
    }
    std::vector<wchar_t> buffer(bytes / sizeof(wchar_t) + 1U, L'\0');
    const LSTATUS second = RegGetValueW(key, nullptr, valueName,
                                        RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
                                        &type, buffer.data(), &bytes);
    if (second != ERROR_SUCCESS) {
        error = static_cast<DWORD>(second);
        return false;
    }
    result.assign(buffer.data());
    return !result.empty();
}

std::wstring lower(std::wstring value) {
    for (wchar_t& character : value) {
        if (character >= L'A' && character <= L'Z') {
            character = static_cast<wchar_t>(character - L'A' + L'a');
        }
    }
    return value;
}

bool expandRemoteSystemDrive(std::wstring& value, const std::wstring& systemDrive) {
    const std::wstring marker = L"%systemdrive%";
    std::wstring output;
    std::wstring remainder = value;
    for (;;) {
        const std::wstring lowered = lower(remainder);
        const std::size_t position = lowered.find(marker);
        if (position == std::wstring::npos) break;
        output += remainder.substr(0, position);
        output += systemDrive;
        remainder.erase(0, position + marker.size());
    }
    output += remainder;
    if (output.find(L'%') != std::wstring::npos) return false;
    value = std::move(output);
    return !value.empty();
}

#endif

} // namespace

SystemProfilePaths querySystemProfilePaths() {
    return querySystemProfilePaths(ProfileTarget::local());
}

SystemProfilePaths querySystemProfilePaths(const ProfileTarget& target) {
    SystemProfilePaths result;
#ifndef _WIN32
    (void)target;
    result.diagnostic = L"chemins de profils système disponibles uniquement sous Windows";
    result.win32Error = 50U; // ERROR_NOT_SUPPORTED
    return result;
#else
    if (!target.valid()) {
        result.diagnostic = L"cible chemins profils invalide";
        result.win32Error = ERROR_INVALID_COMPUTERNAME;
        return result;
    }
    if (!target.isLocal()) {
        HKEY remoteMachine = nullptr;
        const LSTATUS connect = RegConnectRegistryW(target.computer().c_str(), HKEY_LOCAL_MACHINE,
                                                    &remoteMachine);
        if (connect != ERROR_SUCCESS) {
            result.diagnostic = message(L"RegConnectRegistryW distant impossible", static_cast<DWORD>(connect));
            result.win32Error = static_cast<unsigned long>(connect);
            return result;
        }
        HKEY profileList = nullptr;
        constexpr wchar_t kProfileList[] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
        LSTATUS status = RegOpenKeyExW(remoteMachine, kProfileList, 0,
                                       KEY_READ | KEY_WOW64_64KEY, &profileList);
        if (status != ERROR_SUCCESS) {
            RegCloseKey(remoteMachine);
            result.diagnostic = message(L"ouverture ProfileList distant impossible", static_cast<DWORD>(status));
            result.win32Error = static_cast<unsigned long>(status);
            return result;
        }
        HKEY environment = nullptr;
        constexpr wchar_t kEnvironment[] =
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
        status = RegOpenKeyExW(remoteMachine, kEnvironment, 0,
                               KEY_READ | KEY_WOW64_64KEY, &environment);
        if (status != ERROR_SUCCESS) {
            RegCloseKey(profileList);
            RegCloseKey(remoteMachine);
            result.diagnostic = message(L"environnement distant inaccessible", static_cast<DWORD>(status));
            result.win32Error = static_cast<unsigned long>(status);
            return result;
        }

        DWORD error = ERROR_SUCCESS;
        std::wstring systemDrive;
        std::wstring programData;
        if (!readRegistryString(profileList, L"ProfilesDirectory", result.profilesRoot, error) ||
            !readRegistryString(environment, L"SystemDrive", systemDrive, error) ||
            !readRegistryString(environment, L"ProgramData", programData, error) ||
            !expandRemoteSystemDrive(result.profilesRoot, systemDrive) ||
            !expandRemoteSystemDrive(programData, systemDrive)) {
            RegCloseKey(environment);
            RegCloseKey(profileList);
            RegCloseKey(remoteMachine);
            result.diagnostic = message(L"valeurs de profils distants incomplètes", error);
            result.win32Error = error;
            return result;
        }
        RegCloseKey(environment);
        RegCloseKey(profileList);
        RegCloseKey(remoteMachine);
        result.defaultPath = result.profilesRoot + L"\\Default";
        result.publicPath = result.profilesRoot + L"\\Public";
        result.commonDataPath = std::move(programData);
        result.complete = true;
        return result;
    }
    DWORD error = ERROR_SUCCESS;
    if (!getProfilesDirectory(result.profilesRoot, error)) {
        result.diagnostic = message(L"GetProfilesDirectoryW impossible", error);
        result.win32Error = error;
        return result;
    }
    if (!getDefaultProfileDirectory(result.defaultPath, error)) {
        result.diagnostic = message(L"GetDefaultUserProfileDirectoryW impossible", error);
        result.win32Error = error;
        return result;
    }
    PWSTR publicPath = nullptr;
    const HRESULT publicResult = SHGetKnownFolderPath(FOLDERID_Public, 0, nullptr, &publicPath);
    if (FAILED(publicResult) || publicPath == nullptr || publicPath[0] == L'\0') {
        if (publicPath != nullptr) CoTaskMemFree(publicPath);
        result.diagnostic = message(L"SHGetKnownFolderPath(FOLDERID_Public) impossible", static_cast<DWORD>(publicResult));
        result.win32Error = static_cast<DWORD>(publicResult);
        return result;
    }
    result.publicPath.assign(publicPath);
    CoTaskMemFree(publicPath);
    if (!getCommonDataDirectory(result.commonDataPath, error)) {
        result.diagnostic = message(L"GetAllUsersProfileDirectoryW impossible", error);
        result.win32Error = error;
        return result;
    }
    result.complete = true;
    return result;
#endif
}

} // namespace delprofils
