#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace delprofils {

enum class WmiMatchStatus {
    NotApplicable,
    Missing,
    Matched,
    Duplicate
};

struct WmiProfileRecord {
    std::wstring sid;
    std::wstring localPath;
    std::optional<bool> loaded;
    std::optional<std::uint32_t> refCount;
    std::optional<bool> special;
    std::optional<bool> roamingConfigured;
    std::optional<bool> roamingPreference;
    std::optional<std::wstring> roamingPath;
    std::optional<std::wstring> lastUseTimeCim;
    std::vector<std::wstring> diagnostics;
};

struct WmiProfileQueryResult {
    bool complete = false;
    unsigned long systemError = 0;
    std::wstring diagnostic;
    std::vector<WmiProfileRecord> profiles;
};

}
