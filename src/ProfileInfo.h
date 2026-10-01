#pragma once
#include "ProfileAge.h"
#include "ProfileGuard.h"
#include "WmiProfileData.h"
#include <string>
#include <vector>

namespace delprofils {
struct ProfileInfo {
    std::wstring sidKey;
    std::wstring profilePath;
    std::wstring baseName;
    bool pathKnown = false;
    // True only when Windows explicitly denied access to NTUSER.DAT.
    // An unreadable profile must not be mistaken for a safe deletion target.
    bool profileDataAccessDenied = false;
    bool bakEntry = false;
    WmiMatchStatus wmiMatch = WmiMatchStatus::NotApplicable;
    std::wstring wmiLocalPath;
    bool roamingConfigured = false;
    bool roamingPreference = false;
    std::wstring roamingPath;
    ProfileAgeEvidence ageEvidence;
    ProfileSignals signals;
    GuardDecision guard;
    std::vector<std::wstring> diagnostics;
};
}
