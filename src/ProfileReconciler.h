#pragma once

#include "ProfileGuard.h"
#include "WmiProfileData.h"

#include <optional>
#include <string>
#include <vector>

namespace delprofils {

struct WmiReconcileResult {
    WmiMatchStatus status = WmiMatchStatus::Missing;
    ProfileSignals signals;
    std::wstring localPath;
    bool roamingConfigured = false;
    bool roamingPreference = false;
    std::wstring roamingPath;
    std::optional<std::wstring> lastUseTimeCim;
    std::vector<std::wstring> diagnostics;

    bool isRoamingProfile() const { return roamingConfigured && roamingPreference; }
};

WmiReconcileResult reconcileWmiProfile(const ProfileSignals& base,
                                       const std::wstring& registrySid,
                                       const std::vector<WmiProfileRecord>& records);

}
