#include "ProfileScanner.h"
#include "ProfileLoadProbe.h"
#include "ProfileAge.h"
#include "ProfileReconciler.h"
#include "SecurityContext.h"
#include "WmiProfileQuery.h"

#include <algorithm>
#include <cstddef>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace delprofils {
namespace {

#ifdef _WIN32
std::wstring basenameOf(std::wstring path) {
    while (!path.empty() && (path.back() == L'\\' || path.back() == L'/')) path.pop_back();
    const auto pos = path.find_last_of(L"\\/");
    return pos == std::wstring::npos ? path : path.substr(pos + 1);
}

bool endsWithBak(const std::wstring& s) {
    if (s.size() < 4) return false;
    std::wstring tail = s.substr(s.size() - 4);
    for (auto& ch : tail) {
        if (ch >= L'A' && ch <= L'Z') ch = static_cast<wchar_t>(ch - L'A' + L'a');
    }
    return tail == L".bak";
}

struct RegKey {
    HKEY h = nullptr;
    ~RegKey() { if (h) RegCloseKey(h); }
    RegKey() = default;
    RegKey(const RegKey&) = delete;
    RegKey& operator=(const RegKey&) = delete;
};

bool readProfilePath(HKEY key, std::wstring& out, std::wstring& diagnostic) {
    DWORD type = 0;
    DWORD bytes = 0;
    const DWORD flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND;
    LSTATUS rc = RegGetValueW(key, nullptr, L"ProfileImagePath", flags, &type, nullptr, &bytes);
    if (rc != ERROR_SUCCESS) {
        diagnostic = L"ProfileImagePath absent/inaccessible (" + std::to_wstring(rc) + L")";
        return false;
    }
    if (bytes < sizeof(wchar_t) || bytes > 32768UL * sizeof(wchar_t)) {
        diagnostic = L"ProfileImagePath taille invalide";
        return false;
    }
    std::vector<wchar_t> buf(bytes / sizeof(wchar_t) + 2, L'\0');
    rc = RegGetValueW(key, nullptr, L"ProfileImagePath", flags, &type, buf.data(), &bytes);
    if (rc != ERROR_SUCCESS) {
        diagnostic = L"ProfileImagePath lecture échouée (" + std::to_wstring(rc) + L")";
        return false;
    }
    std::wstring raw(buf.data());
    if (type == REG_EXPAND_SZ) {
        DWORD needed = ExpandEnvironmentStringsW(raw.c_str(), nullptr, 0);
        if (needed == 0 || needed > 32768) {
            diagnostic = L"ProfileImagePath expansion impossible";
            return false;
        }
        std::vector<wchar_t> expanded(needed, L'\0');
        const DWORD written = ExpandEnvironmentStringsW(raw.c_str(), expanded.data(), needed);
        if (written == 0 || written > needed) {
            diagnostic = L"ProfileImagePath expansion échouée";
            return false;
        }
        out.assign(expanded.data());
        if (out.find(L'%') != std::wstring::npos) {
            diagnostic = L"ProfileImagePath contient une variable non résolue";
            return false;
        }
    } else {
        out = std::move(raw);
    }
    return !out.empty();
}

std::optional<std::uint32_t> readDwordValue(HKEY key, const wchar_t* name) {
    DWORD type = 0;
    DWORD bytes = sizeof(DWORD);
    DWORD value = 0;
    const LSTATUS rc = RegGetValueW(key, nullptr, name, RRF_RT_REG_DWORD,
                                    &type, &value, &bytes);
    if (rc != ERROR_SUCCESS || type != REG_DWORD || bytes != sizeof(DWORD)) return std::nullopt;
    return static_cast<std::uint32_t>(value);
}

std::optional<FileTimeTicks> readStableProfileFileTime(HKEY key, const wchar_t* lowName,
                                                       const wchar_t* highName,
                                                       std::wstring& diagnostic) {
    const auto lowFirst = readDwordValue(key, lowName);
    const auto highFirst = readDwordValue(key, highName);
    const auto lowSecond = readDwordValue(key, lowName);
    const auto highSecond = readDwordValue(key, highName);
    if (!lowFirst.has_value() || !highFirst.has_value() ||
        !lowSecond.has_value() || !highSecond.has_value()) {
        diagnostic = std::wstring(L"horodatage registre absent/invalide: ") + lowName + L"/" + highName;
        return std::nullopt;
    }
    if (*lowFirst != *lowSecond || *highFirst != *highSecond) {
        diagnostic = std::wstring(L"horodatage registre instable: ") + lowName + L"/" + highName;
        return std::nullopt;
    }
    const auto combined = combineFileTimeDwords(lowFirst, highFirst);
    if (!combined.has_value()) {
        diagnostic = std::wstring(L"horodatage registre nul: ") + lowName + L"/" + highName;
    }
    return combined;
}

std::optional<FileTimeTicks> readProfileFileLastWriteTime(const std::wstring& profilePath,
                                                           const wchar_t* fileName,
                                                           std::wstring& diagnostic,
                                                           bool* accessDenied = nullptr) {
    if (accessDenied != nullptr) *accessDenied = false;
    const std::wstring filePath = profilePath + L"\\" + fileName;
    WIN32_FILE_ATTRIBUTE_DATA attributes{};
    if (!GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &attributes)) {
        const DWORD error = GetLastError();
        if (accessDenied != nullptr && error == ERROR_ACCESS_DENIED) *accessDenied = true;
        diagnostic = std::wstring(fileName) + L" absent ou inaccessible (" +
            std::to_wstring(error) + L")";
        return std::nullopt;
    }
    if ((attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
        (attributes.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        diagnostic = std::wstring(fileName) + L" n'est pas un fichier ordinaire";
        return std::nullopt;
    }
    const auto result = combineFileTimeDwords(attributes.ftLastWriteTime.dwLowDateTime,
                                               attributes.ftLastWriteTime.dwHighDateTime);
    if (!result.has_value()) diagnostic = std::wstring(fileName) + L" LastWriteTime invalide";
    return result;
}
#endif

#ifdef _WIN32
bool sidEquals(const std::wstring& a, const std::wstring& b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        wchar_t ca = a[i], cb = b[i];
        if (ca >= L'A' && ca <= L'Z') ca = static_cast<wchar_t>(ca - L'A' + L'a');
        if (cb >= L'A' && cb <= L'Z') cb = static_cast<wchar_t>(cb - L'A' + L'a');
        if (ca != cb) return false;
    }
    return true;
}

bool isAbsoluteSystemSid(const std::wstring& sid) {
    return sidEquals(sid, L"S-1-5-18") || sidEquals(sid, L"S-1-5-19") || sidEquals(sid, L"S-1-5-20");
}
#endif

} // namespace

ScanResult enumerateLocalProfileList(bool collectNtUserIni) {
    return enumerateProfileList(ProfileTarget::local(), collectNtUserIni);
}

ScanResult enumerateProfileList(const ProfileTarget& target, bool collectNtUserIni) {
#ifndef _WIN32
    (void)target;
    (void)collectNtUserIni;
    ScanResult r;
    r.complete = false;
    r.diagnostic = L"scanner ProfileList disponible uniquement sous Windows";
    return r;
#else
    constexpr wchar_t kProfileList[] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
    ScanResult result;
    if (!target.valid()) {
        result.systemError = ERROR_INVALID_COMPUTERNAME;
        result.diagnostic = L"cible ProfileList invalide";
        return result;
    }
    RegKey remoteMachine;
    HKEY machine = HKEY_LOCAL_MACHINE;
    if (!target.isLocal()) {
        const LSTATUS connect = RegConnectRegistryW(target.computer().c_str(), HKEY_LOCAL_MACHINE,
                                                    &remoteMachine.h);
        if (connect != ERROR_SUCCESS) {
            result.systemError = static_cast<unsigned long>(connect);
            result.diagnostic = L"connexion au registre distant impossible";
            return result;
        }
        machine = remoteMachine.h;
    }
    RegKey root;
    LSTATUS rc = RegOpenKeyExW(machine, kProfileList, 0,
                               KEY_READ | KEY_WOW64_64KEY, &root.h);
    if (rc != ERROR_SUCCESS) {
        result.systemError = static_cast<unsigned long>(rc);
        result.diagnostic = L"ouverture ProfileList impossible";
        return result;
    }

    DWORD subkeys = 0;
    DWORD maxName = 0;
    rc = RegQueryInfoKeyW(root.h, nullptr, nullptr, nullptr, &subkeys, &maxName,
                          nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (rc != ERROR_SUCCESS) {
        result.systemError = static_cast<unsigned long>(rc);
        result.diagnostic = L"RegQueryInfoKeyW a échoué";
        return result;
    }

    std::vector<wchar_t> name(static_cast<std::size_t>(maxName) + 2, L'\0');
    for (DWORD i = 0; i < subkeys; ++i) {
        DWORD len = static_cast<DWORD>(name.size());
        FILETIME ft{};
        rc = RegEnumKeyExW(root.h, i, name.data(), &len, nullptr, nullptr, nullptr, &ft);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) {
            result.systemError = static_cast<unsigned long>(rc);
            result.diagnostic = L"énumération ProfileList incomplète";
            return result;
        }

        ProfileInfo p;
        p.sidKey.assign(name.data(), len);
        p.bakEntry = endsWithBak(p.sidKey);

        RegKey child;
        rc = RegOpenKeyExW(root.h, p.sidKey.c_str(), 0,
                           KEY_READ | KEY_WOW64_64KEY, &child.h);
        if (rc != ERROR_SUCCESS) {
            p.diagnostics.push_back(L"clé profil inaccessible (" + std::to_wstring(rc) + L")");
        } else {
            std::wstring diag;
            if (readProfilePath(child.h, p.profilePath, diag)) {
                p.pathKnown = true;
                p.baseName = basenameOf(p.profilePath);
            } else {
                p.diagnostics.push_back(std::move(diag));
            }
            if (!p.bakEntry) {
                std::wstring loadDiagnostic;
                p.ageEvidence.loadTime = readStableProfileFileTime(
                    child.h, L"LocalProfileLoadTimeLow", L"LocalProfileLoadTimeHigh", loadDiagnostic);
                if (!loadDiagnostic.empty()) p.diagnostics.push_back(std::move(loadDiagnostic));

                std::wstring unloadDiagnostic;
                p.ageEvidence.unloadTime = readStableProfileFileTime(
                    child.h, L"LocalProfileUnLoadTimeLow", L"LocalProfileUnLoadTimeHigh", unloadDiagnostic);
                if (!unloadDiagnostic.empty()) p.diagnostics.push_back(std::move(unloadDiagnostic));

                if (!p.pathKnown) {
                    p.diagnostics.push_back(L"NTUSER.DAT non lu: ProfileImagePath inconnu");
                } else if (!target.isLocal()) {
                    p.diagnostics.push_back(L"NTUSER.DAT non lu: cible distante (WMI reste l'autorité runtime)");
                } else {
                    std::wstring datDiagnostic;
                    p.ageEvidence.ntUserDatLastWriteTime =
                        readProfileFileLastWriteTime(p.profilePath, L"NTUSER.DAT", datDiagnostic,
                                                     &p.profileDataAccessDenied);
                    if (!datDiagnostic.empty()) p.diagnostics.push_back(std::move(datDiagnostic));
                }

                if (collectNtUserIni) {
                    p.ageEvidence.useNtUserIni = true;
                    if (!p.pathKnown) {
                        p.diagnostics.push_back(L"NTUSER.INI non lu: ProfileImagePath inconnu");
                    } else if (!target.isLocal()) {
                        p.diagnostics.push_back(L"NTUSER.INI non lu: cible distante");
                    } else {
                        std::wstring iniDiagnostic;
                        p.ageEvidence.ntUserIniLastWriteTime =
                            readProfileFileLastWriteTime(p.profilePath, L"NTUSER.INI", iniDiagnostic);
                        if (!iniDiagnostic.empty()) p.diagnostics.push_back(std::move(iniDiagnostic));
                    }
                }
            }
        }
        p.signals.bakEntry = p.bakEntry;
        p.signals.systemSid = !p.bakEntry && isAbsoluteSystemSid(p.sidKey);
        if (p.bakEntry) p.diagnostics.push_back(L"entrée SID.bak: diagnostic uniquement");
        p.guard = evaluateProfileGuard(p.signals);
        result.profiles.push_back(std::move(p));
    }

    // A canonical SID beside SID.bak is an ambiguity, not a deletion target.
    // Mark both sides as a protected group before any plan can be constructed.
    std::vector<std::wstring> bakBaseSids;
    for (const auto& profile : result.profiles) {
        if (profile.bakEntry && profile.sidKey.size() > 4) {
            bakBaseSids.push_back(profile.sidKey.substr(0, profile.sidKey.size() - 4));
        }
    }
    for (auto& profile : result.profiles) {
        if (profile.bakEntry) continue;
        for (const auto& baseSid : bakBaseSids) {
            if (!sidEquals(profile.sidKey, baseSid)) continue;
            profile.signals.bakEntry = true;
            profile.diagnostics.push_back(L"entrée SID.bak associée: groupe protégé");
            profile.guard = evaluateProfileGuard(profile.signals);
            break;
        }
    }

    result.complete = true;
    return result;
#endif
}

bool enrichRuntimeSignals(ScanResult& result, const std::vector<std::size_t>& candidateIndexes,
                          std::wstring& diagnostic) {
    return enrichRuntimeSignals(result, ProfileTarget::local(), candidateIndexes, diagnostic);
}

bool enrichRuntimeSignals(ScanResult& result, const ProfileTarget& target,
                          const std::vector<std::size_t>& candidateIndexes,
                          std::wstring& diagnostic) {
    diagnostic.clear();
#ifndef _WIN32
    (void)result;
    (void)target;
    (void)candidateIndexes;
    diagnostic = L"enrichissement runtime disponible uniquement sous Windows";
    return false;
#else
    if (!result.complete) {
        diagnostic = L"catalogue ProfileList incomplet";
        return false;
    }
    std::vector<std::size_t> indexes;
    std::vector<bool> seen(result.profiles.size(), false);
    for (const std::size_t index : candidateIndexes) {
        if (index >= result.profiles.size()) {
            diagnostic = L"index candidat hors catalogue";
            return false;
        }
        if (!seen[index]) {
            seen[index] = true;
            indexes.push_back(index);
        }
    }

    std::vector<std::wstring> wmiSids;
    for (const std::size_t index : indexes) {
        const ProfileInfo& profile = result.profiles[index];
        if (!profile.bakEntry && !profile.signals.bakEntry) wmiSids.push_back(profile.sidKey);
    }

    std::vector<WmiProfileRecord> wmiProfiles;
    for (std::size_t begin = 0; begin < wmiSids.size(); begin += 32) {
        const std::size_t end = std::min(begin + 32, wmiSids.size());
        const std::vector<std::wstring> batch(wmiSids.begin() + static_cast<std::ptrdiff_t>(begin),
                                              wmiSids.begin() + static_cast<std::ptrdiff_t>(end));
        const WmiProfileQueryResult wmi = queryWmiProfilesForSids(target, batch);
        if (!wmi.complete) {
            result.systemError = wmi.systemError;
            diagnostic = L"inventaire WMI sélectionné incomplet: " + wmi.diagnostic;
            return false;
        }
        wmiProfiles.insert(wmiProfiles.end(), wmi.profiles.begin(), wmi.profiles.end());
    }

    const CurrentSidResult currentSid = target.isLocal() ? queryCurrentProcessSid() : CurrentSidResult{};
    for (const std::size_t index : indexes) {
        ProfileInfo& profile = result.profiles[index];
        profile.signals.currentSidCheckKnown = currentSid.known;
        profile.signals.currentProcessSid = currentSid.known && !profile.bakEntry &&
            sidEquals(currentSid.sid, profile.sidKey);
        if (!profile.bakEntry && !profile.signals.bakEntry) {
            if (target.isLocal()) {
                const ProfileLoadProbeResult load = probeProfileLoadedHives(profile.sidKey);
                profile.signals.userHive = load.userHive;
                profile.signals.classesHive = load.classesHive;
                profile.diagnostics.insert(profile.diagnostics.end(), load.diagnostics.begin(), load.diagnostics.end());
            } else {
                profile.signals.userHive = LoadSignal::Unknown;
                profile.signals.classesHive = LoadSignal::Unknown;
                profile.diagnostics.push_back(L"HKU local non utilisé pour une cible distante");
            }

            const WmiReconcileResult reconciled = reconcileWmiProfile(profile.signals, profile.sidKey, wmiProfiles);
            profile.wmiMatch = reconciled.status;
            profile.wmiLocalPath = reconciled.localPath;
            profile.roamingConfigured = reconciled.roamingConfigured;
            profile.roamingPreference = reconciled.roamingPreference;
            profile.roamingPath = reconciled.roamingPath;
            profile.signals = reconciled.signals;
            if (reconciled.lastUseTimeCim.has_value()) {
                profile.ageEvidence.wmiLastUseTime = parseCimDateTimeUtc(*reconciled.lastUseTimeCim);
                if (!profile.ageEvidence.wmiLastUseTime.has_value()) {
                    profile.diagnostics.push_back(L"WMI LastUseTime invalide ou non convertible UTC");
                }
            }
            profile.diagnostics.insert(profile.diagnostics.end(), reconciled.diagnostics.begin(),
                                       reconciled.diagnostics.end());
        }
        if (!currentSid.known && !currentSid.diagnostic.empty()) {
            profile.diagnostics.push_back(L"SID processus inconnu: " + currentSid.diagnostic);
        }
        profile.guard = evaluateProfileGuard(profile.signals);
    }
    return true;
#endif
}

ScanResult scanLocalProfiles(bool collectNtUserIni) {
    return scanProfiles(ProfileTarget::local(), collectNtUserIni);
}

ScanResult scanProfiles(const ProfileTarget& target, bool collectNtUserIni) {
    ScanResult result = enumerateProfileList(target, collectNtUserIni);
    if (!result.complete) return result;
    std::vector<std::size_t> allNonBak;
    for (std::size_t index = 0; index < result.profiles.size(); ++index) {
        if (!result.profiles[index].bakEntry && !result.profiles[index].signals.bakEntry) {
            allNonBak.push_back(index);
        }
    }
    std::wstring diagnostic;
    if (!enrichRuntimeSignals(result, target, allNonBak, diagnostic)) {
        result.complete = false;
        result.diagnostic = std::move(diagnostic);
    }
    return result;
}

} // namespace delprofils
