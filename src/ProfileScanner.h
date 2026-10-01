#pragma once
#include "ProfileInfo.h"
#include "ProfileTarget.h"
#include <cstddef>
#include <string>
#include <vector>

namespace delprofils {
struct ScanResult {
    bool complete = false;
    unsigned long systemError = 0;
    std::wstring diagnostic;
    std::vector<ProfileInfo> profiles;
};
ScanResult scanLocalProfiles(bool collectNtUserIni = false);
ScanResult enumerateLocalProfileList(bool collectNtUserIni = false);
ScanResult scanProfiles(const ProfileTarget& target, bool collectNtUserIni = false);
ScanResult enumerateProfileList(const ProfileTarget& target, bool collectNtUserIni = false);
bool enrichRuntimeSignals(ScanResult& result, const std::vector<std::size_t>& candidateIndexes,
                          std::wstring& diagnostic);
bool enrichRuntimeSignals(ScanResult& result, const ProfileTarget& target,
                          const std::vector<std::size_t>& candidateIndexes,
                          std::wstring& diagnostic);
}
