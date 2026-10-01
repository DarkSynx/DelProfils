#include "ProfileReconciler.h"

namespace delprofils {
namespace {

bool sidEqualsAscii(const std::wstring& a, const std::wstring& b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        wchar_t ca = a[i];
        wchar_t cb = b[i];
        if (ca >= L'A' && ca <= L'Z') ca = static_cast<wchar_t>(ca - L'A' + L'a');
        if (cb >= L'A' && cb <= L'Z') cb = static_cast<wchar_t>(cb - L'A' + L'a');
        if (ca != cb) return false;
    }
    return true;
}

LoadSignal fromOptionalBool(const std::optional<bool>& value) {
    if (!value.has_value()) return LoadSignal::Unknown;
    return *value ? LoadSignal::Present : LoadSignal::Absent;
}

}

WmiReconcileResult reconcileWmiProfile(const ProfileSignals& base,
                                       const std::wstring& registrySid,
                                       const std::vector<WmiProfileRecord>& records) {
    WmiReconcileResult result;
    result.signals = base;
    result.signals.wmiLoaded = LoadSignal::Unknown;
    result.signals.wmiRefCountKnown = false;
    result.signals.wmiRefCount = 0;
    result.signals.wmiSpecial = LoadSignal::Unknown;

    const WmiProfileRecord* match = nullptr;
    for (const auto& record : records) {
        if (!sidEqualsAscii(record.sid, registrySid)) continue;
        if (match != nullptr) {
            result.status = WmiMatchStatus::Duplicate;
            result.diagnostics.push_back(L"plusieurs instances Win32_UserProfile pour le même SID");
            return result;
        }
        match = &record;
    }

    if (match == nullptr) {
        result.status = WmiMatchStatus::Missing;
        result.diagnostics.push_back(L"aucune instance Win32_UserProfile correspondante");
        return result;
    }

    result.status = WmiMatchStatus::Matched;
    result.localPath = match->localPath;
    result.roamingConfigured = match->roamingConfigured.value_or(false);
    result.roamingPreference = match->roamingPreference.value_or(false);
    if (match->roamingPath.has_value()) result.roamingPath = *match->roamingPath;
    result.lastUseTimeCim = match->lastUseTimeCim;
    result.signals.wmiLoaded = fromOptionalBool(match->loaded);
    result.signals.wmiSpecial = fromOptionalBool(match->special);
    if (match->refCount.has_value()) {
        result.signals.wmiRefCountKnown = true;
        result.signals.wmiRefCount = static_cast<unsigned long>(*match->refCount);
    }
    result.diagnostics = match->diagnostics;
    return result;
}

}
