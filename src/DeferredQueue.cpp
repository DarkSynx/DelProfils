#include "DeferredQueue.h"

#include <algorithm>
#include <limits>
#include <set>

namespace delprofils {
namespace {
constexpr std::size_t kMaximumRecords = 4096;

std::wstring asciiLower(std::wstring_view value) {
    std::wstring result(value);
    for (wchar_t& ch : result) {
        if (ch >= L'A' && ch <= L'Z') ch = static_cast<wchar_t>(ch - L'A' + L'a');
    }
    return result;
}

std::wstring normalizedPath(std::wstring_view value) {
    std::wstring result(value);
    while (result.size() > 3 && (result.back() == L'\\' || result.back() == L'/')) result.pop_back();
    return asciiLower(result);
}

bool validSid(std::wstring_view value) {
    if (value.size() < 5 || value.size() > 184 || asciiLower(value).rfind(L"s-1-", 0) != 0) return false;
    for (wchar_t ch : value) {
        if ((ch < L'0' || ch > L'9') && ch != L'S' && ch != L's' && ch != L'-') return false;
    }
    return true;
}

bool validPolicyName(std::wstring_view value) {
    if (value.empty() || value.size() > 64) return false;
    for (wchar_t ch : value) {
        const bool alpha = (ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z');
        const bool digit = ch >= L'0' && ch <= L'9';
        if (!alpha && !digit && ch != L'_' && ch != L'-') return false;
    }
    return true;
}

bool validSha256(std::wstring_view value) {
    if (value.size() != 64) return false;
    for (wchar_t ch : value) {
        if (!((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f'))) return false;
    }
    return true;
}

bool validRecord(const DeferredRecord& record) {
    return validSid(record.sid) && !record.profilePath.empty() && record.profilePath.size() <= 32767 &&
        validPolicyName(record.policyName) && validSha256(record.policySha256) &&
        record.firstObservedUtcTicks != 0 && record.lastObservedUtcTicks >= record.firstObservedUtcTicks &&
        record.observedLoadedCount != 0;
}

void appendHex(std::wstring& output, std::uint32_t value) {
    constexpr wchar_t alphabet[] = L"0123456789abcdef";
    for (int shift = 28; shift >= 0; shift -= 4) output.push_back(alphabet[(value >> shift) & 0x0f]);
}

bool readHex(std::wstring_view input, std::uint32_t& value) {
    if (input.size() != 8) return false;
    value = 0;
    for (wchar_t ch : input) {
        std::uint32_t digit = 0;
        if (ch >= L'0' && ch <= L'9') digit = static_cast<std::uint32_t>(ch - L'0');
        else if (ch >= L'a' && ch <= L'f') digit = static_cast<std::uint32_t>(ch - L'a' + 10);
        else return false;
        value = (value << 4) | digit;
    }
    return true;
}

std::wstring encodeField(std::wstring_view field) {
    std::wstring output;
    output.reserve(field.size() * 9);
    for (wchar_t ch : field) {
        output.push_back(L'%');
        appendHex(output, static_cast<std::uint32_t>(ch));
    }
    return output;
}

bool decodeField(std::wstring_view field, std::wstring& output) {
    if (field.size() % 9 != 0) return false;
    output.clear();
    output.reserve(field.size() / 9);
    for (std::size_t index = 0; index < field.size(); index += 9) {
        if (field[index] != L'%') return false;
        std::uint32_t code = 0;
        if (!readHex(field.substr(index + 1, 8), code) || code > static_cast<std::uint32_t>(std::numeric_limits<wchar_t>::max())) {
            return false;
        }
        output.push_back(static_cast<wchar_t>(code));
    }
    return true;
}

bool parseUnsigned(std::wstring_view text, std::uint64_t maximum, std::uint64_t& value) {
    if (text.empty()) return false;
    value = 0;
    for (wchar_t ch : text) {
        if (ch < L'0' || ch > L'9') return false;
        const std::uint64_t digit = static_cast<std::uint64_t>(ch - L'0');
        if (value > (maximum - digit) / 10U) return false;
        value = value * 10U + digit;
    }
    return true;
}

std::vector<std::wstring_view> splitTabs(std::wstring_view line) {
    std::vector<std::wstring_view> fields;
    std::size_t begin = 0;
    while (begin <= line.size()) {
        const std::size_t end = line.find(L'\t', begin);
        fields.push_back(line.substr(begin, end == std::wstring_view::npos ? std::wstring_view::npos : end - begin));
        if (end == std::wstring_view::npos) break;
        begin = end + 1;
    }
    return fields;
}

} // namespace

QueueRecordDecision validateDeferredRecord(const DeferredRecord& record, std::wstring_view sid,
    std::wstring_view path, std::wstring_view policyName, std::wstring_view policySha256,
    bool protectedNow) {
    if (asciiLower(record.sid) != asciiLower(sid)) return QueueRecordDecision::RemoveChangedSid;
    if (normalizedPath(record.profilePath) != normalizedPath(path)) return QueueRecordDecision::RemoveChangedPath;
    if (asciiLower(record.policyName) != asciiLower(policyName) || record.policySha256 != policySha256) {
        return QueueRecordDecision::RemoveChangedPolicy;
    }
    if (protectedNow) return QueueRecordDecision::RemoveProtected;
    return QueueRecordDecision::Keep;
}

std::wstring encodeDeferredQueue(const std::vector<DeferredRecord>& records) {
    if (records.size() > kMaximumRecords) return {};
    std::set<std::wstring> seenSids;
    std::wstring output = L"DLPQ1\n";
    for (const auto& record : records) {
        const std::wstring normalizedSid = asciiLower(record.sid);
        if (!validRecord(record) || !seenSids.insert(normalizedSid).second) return {};
        output += record.sid + L"\t" + encodeField(record.profilePath) + L"\t" + record.policyName + L"\t" +
            record.policySha256 + L"\t" + std::to_wstring(record.firstObservedUtcTicks) + L"\t" +
            std::to_wstring(record.lastObservedUtcTicks) + L"\t" + std::to_wstring(record.observedLoadedCount) + L"\n";
    }
    return output;
}

bool decodeDeferredQueue(std::wstring_view text, std::vector<DeferredRecord>& records,
                         std::wstring& diagnostic) {
    records.clear();
    diagnostic.clear();
    constexpr std::wstring_view header = L"DLPQ1\n";
    if (text.rfind(header, 0) != 0) {
        diagnostic = L"version de file inconnue";
        return false;
    }
    std::set<std::wstring> seenSids;
    std::size_t offset = header.size();
    while (offset < text.size()) {
        const std::size_t end = text.find(L'\n', offset);
        if (end == std::wstring_view::npos) {
            diagnostic = L"ligne de file non terminée";
            return false;
        }
        const auto fields = splitTabs(text.substr(offset, end - offset));
        if (fields.size() != 7) {
            diagnostic = L"nombre de champs invalide";
            return false;
        }
        DeferredRecord record;
        record.sid = std::wstring(fields[0]);
        record.policyName = std::wstring(fields[2]);
        record.policySha256 = std::wstring(fields[3]);
        std::uint64_t count = 0;
        if (!decodeField(fields[1], record.profilePath) ||
            !parseUnsigned(fields[4], std::numeric_limits<std::uint64_t>::max(), record.firstObservedUtcTicks) ||
            !parseUnsigned(fields[5], std::numeric_limits<std::uint64_t>::max(), record.lastObservedUtcTicks) ||
            !parseUnsigned(fields[6], std::numeric_limits<std::uint32_t>::max(), count)) {
            diagnostic = L"champ de file invalide";
            return false;
        }
        record.observedLoadedCount = static_cast<std::uint32_t>(count);
        if (!validRecord(record) || !seenSids.insert(asciiLower(record.sid)).second ||
            records.size() >= kMaximumRecords) {
            diagnostic = L"enregistrement de file invalide ou dupliqué";
            return false;
        }
        records.push_back(std::move(record));
        offset = end + 1;
    }
    return true;
}

} // namespace delprofils
