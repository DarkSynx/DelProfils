#include "ProfileDeletionPlan.h"

#include <string_view>

namespace delprofils {
namespace {

std::wstring asciiLower(std::wstring_view value) {
    std::wstring result(value);
    for (wchar_t& character : result) {
        if (character >= L'A' && character <= L'Z') {
            character = static_cast<wchar_t>(character - L'A' + L'a');
        }
    }
    return result;
}

std::wstring normalizedPath(std::wstring value) {
    while (value.size() > 3 && (value.back() == L'\\' || value.back() == L'/')) value.pop_back();
    return asciiLower(value);
}

bool samePath(const std::wstring& first, const std::wstring& second) {
    return normalizedPath(first) == normalizedPath(second);
}

bool pathsOverlap(const std::wstring& first, const std::wstring& second) {
    const std::wstring a = normalizedPath(first);
    const std::wstring b = normalizedPath(second);
    if (a == b) return true;
    const auto descendant = [](const std::wstring& child, const std::wstring& parent) {
        return child.size() > parent.size() && child.compare(0, parent.size(), parent) == 0 &&
               child[parent.size()] == L'\\';
    };
    return descendant(a, b) || descendant(b, a);
}

bool sameAsciiInsensitive(const std::wstring& first, const std::wstring& second) {
    return asciiLower(first) == asciiLower(second);
}

bool protectedProfileName(const std::wstring& baseName) {
    const std::wstring name = asciiLower(baseName);
    return name == L"default" || name == L"default user" || name == L"public" ||
           name == L"all users" || name == L"systemprofile" ||
           name == L"localservice" || name == L"networkservice" ||
           name == L"wdagutilityaccount" || name == L"containeradministrator" ||
           name == L"containeruser";
}

bool builtInAdministratorSid(const std::wstring& sid) {
    constexpr std::wstring_view prefix = L"s-1-5-21-";
    const std::wstring lower = asciiLower(sid);
    return lower.rfind(prefix, 0) == 0 && lower.size() > prefix.size() + 4 &&
           lower.size() >= 4 && lower.compare(lower.size() - 4, 4, L"-500") == 0;
}

DeletionPlanDecision refused(const wchar_t* reason) {
    return {DeletionPlanDisposition::Refused, reason};
}

} // namespace

DeletionPlanDecision evaluateDeletionPlan(const ProfileInfo& profile) {
    if (profile.bakEntry) return refused(L"SID_BAK");
    if (profile.signals.bakEntry) return refused(L"SID_BAK_GROUP");
    if (builtInAdministratorSid(profile.sidKey)) return refused(L"BUILTIN_ADMINISTRATOR");
    if (protectedProfileName(profile.baseName)) return refused(L"PROTECTED_PROFILE_NAME");
    if (!profile.pathKnown || profile.profilePath.empty() || profile.baseName.empty()) {
        return refused(L"PROFILE_PATH_UNKNOWN");
    }
    if (profile.wmiMatch != WmiMatchStatus::Matched || profile.wmiLocalPath.empty()) {
        return refused(L"WMI_PROFILE_UNCONFIRMED");
    }
    if (!samePath(profile.profilePath, profile.wmiLocalPath)) return refused(L"WMI_PATH_MISMATCH");
    if (profile.guard.disposition != GuardDisposition::UnloadedConfirmed) {
        return refused(L"PROFILE_NOT_UNLOADED_CONFIRMED");
    }
    return {DeletionPlanDisposition::Eligible, L"ELIGIBLE"};
}

DeletionPlanDecision evaluateDeletionPlan(const ProfileInfo& profile,
                                          const std::vector<ProfileInfo>& allProfiles) {
    return evaluateDeletionPlan(profile, allProfiles, CandidateDisposition::Eligible);
}

DeletionPlanDecision evaluateDeletionPlan(const ProfileInfo& profile,
                                          const std::vector<ProfileInfo>& allProfiles,
                                          CandidateDisposition candidateDisposition) {
    if (candidateDisposition != CandidateDisposition::Eligible) {
        return refused(L"CANDIDATE_DISPOSITION_NOT_ELIGIBLE");
    }
    const auto baseDecision = evaluateDeletionPlan(profile);
    if (baseDecision.disposition != DeletionPlanDisposition::Eligible) return baseDecision;
    for (const auto& other : allProfiles) {
        if (&other == &profile || !other.pathKnown || other.profilePath.empty() ||
            sameAsciiInsensitive(profile.sidKey, other.sidKey)) {
            continue;
        }
        if (pathsOverlap(profile.profilePath, other.profilePath)) {
            return refused(L"PROFILE_PATH_OVERLAP");
        }
    }
    return baseDecision;
}

bool mustAbortDeletionBatch(std::size_t refusedSelections, bool ignoreErrors) {
    return refusedSelections != 0 && !ignoreErrors;
}

} // namespace delprofils
