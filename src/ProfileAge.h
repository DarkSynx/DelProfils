#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace delprofils {

using FileTimeTicks = std::uint64_t;

enum class AgeDisposition {
    Unknown,
    Recent,
    Old
};

struct ProfileAgeEvidence {
    std::optional<FileTimeTicks> loadTime;
    std::optional<FileTimeTicks> unloadTime;
    std::optional<FileTimeTicks> wmiLastUseTime;
    std::optional<FileTimeTicks> ntUserDatLastWriteTime;
    std::optional<FileTimeTicks> ntUserIniLastWriteTime;
    bool useNtUserIni = false;
};

struct AgeDecision {
    AgeDisposition disposition = AgeDisposition::Unknown;
    std::optional<FileTimeTicks> newestEvidence;
    std::wstring reason;
};

AgeDecision evaluateProfileAge(const ProfileAgeEvidence& evidence, FileTimeTicks t0,
                               unsigned long days);

// DelProf2-compatible age selection for the historical /d switch.
// /ntuserini changes the sole source from NTUSER.DAT to NTUSER.INI.
AgeDecision evaluateLegacyFileAge(const ProfileAgeEvidence& evidence, FileTimeTicks t0,
                                  unsigned long days);

const wchar_t* ageDispositionLabel(AgeDisposition disposition);

bool passesAgeFilter(AgeDisposition disposition);

std::optional<FileTimeTicks> parseCimDateTimeUtc(std::wstring_view value);

std::optional<FileTimeTicks> combineFileTimeDwords(std::optional<std::uint32_t> low,
                                                    std::optional<std::uint32_t> high);

} // namespace delprofils
