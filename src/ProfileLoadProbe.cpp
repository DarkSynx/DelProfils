#include "ProfileLoadProbe.h"

#ifdef _WIN32
#include <windows.h>
#endif

namespace delprofils {
namespace {
#ifdef _WIN32
LoadSignal probeOne(const std::wstring& subkey, std::vector<std::wstring>& diagnostics) {
    HKEY h = nullptr;
    const LSTATUS rc = RegOpenKeyExW(HKEY_USERS, subkey.c_str(), 0, KEY_READ, &h);
    if (rc == ERROR_SUCCESS) {
        RegCloseKey(h);
        return LoadSignal::Present;
    }
    if (rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND) return LoadSignal::Absent;
    diagnostics.push_back(L"HKU probe failed for " + subkey + L" (" + std::to_wstring(rc) + L")");
    return LoadSignal::Unknown;
}
#endif
}

ProfileLoadProbeResult probeProfileLoadedHives(const std::wstring& sid) {
    ProfileLoadProbeResult r;
#ifndef _WIN32
    (void)sid;
    r.diagnostics.push_back(L"HKU load probe unavailable outside Windows");
    return r;
#else
    if (sid.empty()) {
        r.diagnostics.push_back(L"HKU load probe skipped: empty SID");
        return r;
    }
    r.userHive = probeOne(sid, r.diagnostics);
    r.classesHive = probeOne(sid + L"_Classes", r.diagnostics);
    return r;
#endif
}

} // namespace delprofils
