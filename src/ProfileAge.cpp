#include "ProfileAge.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace delprofils {
namespace {

constexpr FileTimeTicks kTicksPerSecond = 10'000'000ULL;
constexpr FileTimeTicks kTicksPerDay = 86'400ULL * kTicksPerSecond;
constexpr std::int64_t kUnixEpochInFileTimeSeconds = 11'644'473'600LL;

AgeDecision unknown(std::wstring reason) {
    AgeDecision result;
    result.reason = std::move(reason);
    return result;
}

bool usable(FileTimeTicks value, FileTimeTicks t0) {
    return value != 0 && value <= t0;
}

bool isLeapYear(int year) {
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

unsigned daysInMonth(int year, unsigned month) {
    static constexpr unsigned kDays[] = {31, 28, 31, 30, 31, 30,
                                         31, 31, 30, 31, 30, 31};
    if (month == 2 && isLeapYear(year)) return 29;
    return kDays[month - 1];
}

int digitAt(std::wstring_view value, std::size_t first, std::size_t count) {
    int result = 0;
    for (std::size_t i = 0; i < count; ++i) {
        const wchar_t ch = value[first + i];
        if (ch < L'0' || ch > L'9') return -1;
        result = result * 10 + static_cast<int>(ch - L'0');
    }
    return result;
}

// Nombre de jours depuis le 1er janvier 1970, calendrier grégorien proleptique.
std::int64_t daysSinceUnixEpoch(int year, unsigned month, unsigned day) {
    year -= month <= 2 ? 1 : 0;
    const int era = (year >= 0 ? year : year - 399) / 400;
    const unsigned yearOfEra = static_cast<unsigned>(year - era * 400);
    const unsigned monthPrime = month > 2 ? month - 3 : month + 9;
    const unsigned dayOfYear = (153 * monthPrime + 2) / 5 + day - 1;
    const unsigned dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear;
    return static_cast<std::int64_t>(era) * 146097 + static_cast<std::int64_t>(dayOfEra) - 719468;
}

} // namespace

AgeDecision evaluateProfileAge(const ProfileAgeEvidence& evidence, FileTimeTicks t0,
                               unsigned long days) {
    if (t0 == 0 || days == 0) return unknown(L"AGE_INVALID_REFERENCE_OR_DAYS");
    if (!evidence.loadTime.has_value() || !evidence.unloadTime.has_value() ||
        !evidence.wmiLastUseTime.has_value()) {
        return unknown(L"AGE_REQUIRED_EVIDENCE_MISSING");
    }

    const FileTimeTicks load = *evidence.loadTime;
    const FileTimeTicks unload = *evidence.unloadTime;
    const FileTimeTicks wmi = *evidence.wmiLastUseTime;
    if (!usable(load, t0) || !usable(unload, t0) || !usable(wmi, t0)) {
        return unknown(L"AGE_REQUIRED_EVIDENCE_INVALID");
    }
    if (load > unload) return unknown(L"AGE_LOAD_AFTER_UNLOAD");

    FileTimeTicks newest = std::max({load, unload, wmi});
    if (evidence.useNtUserIni) {
        if (!evidence.ntUserIniLastWriteTime.has_value() ||
            !usable(*evidence.ntUserIniLastWriteTime, t0)) {
            return unknown(L"AGE_NTUSERINI_EVIDENCE_INVALID");
        }
        newest = std::max(newest, *evidence.ntUserIniLastWriteTime);
    }

    if (static_cast<FileTimeTicks>(days) > std::numeric_limits<FileTimeTicks>::max() / kTicksPerDay) {
        return unknown(L"AGE_THRESHOLD_OVERFLOW");
    }
    const FileTimeTicks threshold = static_cast<FileTimeTicks>(days) * kTicksPerDay;
    AgeDecision result;
    result.newestEvidence = newest;
    result.disposition = (t0 - newest >= threshold) ? AgeDisposition::Old : AgeDisposition::Recent;
    result.reason = result.disposition == AgeDisposition::Old ? L"AGE_THRESHOLD_MET" : L"AGE_TOO_RECENT";
    return result;
}

AgeDecision evaluateLegacyFileAge(const ProfileAgeEvidence& evidence, FileTimeTicks t0,
                                  unsigned long days) {
    if (t0 == 0 || days == 0) return unknown(L"LEGACY_AGE_INVALID_REFERENCE_OR_DAYS");

    const std::optional<FileTimeTicks>& selected = evidence.useNtUserIni
        ? evidence.ntUserIniLastWriteTime : evidence.ntUserDatLastWriteTime;
    const wchar_t* source = evidence.useNtUserIni ? L"NTUSERINI" : L"NTUSERDAT";
    if (!selected.has_value() || !usable(*selected, t0)) {
        return unknown(std::wstring(L"LEGACY_") + source + L"_EVIDENCE_INVALID");
    }
    if (static_cast<FileTimeTicks>(days) > std::numeric_limits<FileTimeTicks>::max() / kTicksPerDay) {
        return unknown(L"LEGACY_AGE_THRESHOLD_OVERFLOW");
    }

    const FileTimeTicks threshold = static_cast<FileTimeTicks>(days) * kTicksPerDay;
    AgeDecision result;
    result.newestEvidence = *selected;
    result.disposition = (t0 - *selected >= threshold) ? AgeDisposition::Old
                                                         : AgeDisposition::Recent;
    result.reason = std::wstring(L"LEGACY_") + source +
        (result.disposition == AgeDisposition::Old ? L"_THRESHOLD_MET" : L"_TOO_RECENT");
    return result;
}

const wchar_t* ageDispositionLabel(AgeDisposition disposition) {
    switch (disposition) {
    case AgeDisposition::Old: return L"OLD";
    case AgeDisposition::Recent: return L"RECENT";
    case AgeDisposition::Unknown: return L"UNKNOWN";
    }
    return L"UNKNOWN";
}

bool passesAgeFilter(AgeDisposition disposition) {
    return disposition == AgeDisposition::Old;
}

std::optional<FileTimeTicks> parseCimDateTimeUtc(std::wstring_view value) {
    if (value.size() != 25 || value[14] != L'.' ||
        (value[21] != L'+' && value[21] != L'-')) {
        return std::nullopt;
    }

    const int year = digitAt(value, 0, 4);
    const int month = digitAt(value, 4, 2);
    const int day = digitAt(value, 6, 2);
    const int hour = digitAt(value, 8, 2);
    const int minute = digitAt(value, 10, 2);
    const int second = digitAt(value, 12, 2);
    const int microseconds = digitAt(value, 15, 6);
    const int offsetMinutes = digitAt(value, 22, 3);
    if (year < 1 || month < 1 || month > 12 || day < 1 ||
        day > static_cast<int>(daysInMonth(year, static_cast<unsigned>(month))) ||
        hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59 ||
        microseconds < 0 || offsetMinutes < 0 || offsetMinutes > 840) {
        return std::nullopt;
    }

    const std::int64_t localSeconds = daysSinceUnixEpoch(year, static_cast<unsigned>(month),
                                                           static_cast<unsigned>(day)) * 86400LL +
                                      static_cast<std::int64_t>(hour) * 3600LL +
                                      static_cast<std::int64_t>(minute) * 60LL + second;
    const std::int64_t signedOffset = static_cast<std::int64_t>(offsetMinutes) * 60LL;
    const std::int64_t utcSeconds = value[21] == L'+' ? localSeconds - signedOffset
                                                       : localSeconds + signedOffset;
    const std::int64_t fileTimeSeconds = utcSeconds + kUnixEpochInFileTimeSeconds;
    if (fileTimeSeconds <= 0 ||
        fileTimeSeconds > static_cast<std::int64_t>(std::numeric_limits<FileTimeTicks>::max() / kTicksPerSecond)) {
        return std::nullopt;
    }

    const FileTimeTicks secondsTicks = static_cast<FileTimeTicks>(fileTimeSeconds) * kTicksPerSecond;
    const FileTimeTicks microsecondTicks = static_cast<FileTimeTicks>(microseconds) * 10ULL;
    if (secondsTicks > std::numeric_limits<FileTimeTicks>::max() - microsecondTicks) return std::nullopt;
    return secondsTicks + microsecondTicks;
}

std::optional<FileTimeTicks> combineFileTimeDwords(std::optional<std::uint32_t> low,
                                                    std::optional<std::uint32_t> high) {
    if (!low.has_value() || !high.has_value()) return std::nullopt;
    const FileTimeTicks result = (static_cast<FileTimeTicks>(*high) << 32U) |
                                 static_cast<FileTimeTicks>(*low);
    return result == 0 ? std::nullopt : std::optional<FileTimeTicks>(result);
}

} // namespace delprofils
