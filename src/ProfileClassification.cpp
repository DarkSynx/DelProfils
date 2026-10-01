#include "ProfileClassification.h"

#include <string_view>

namespace delprofils {
namespace {

std::wstring asciiLower(std::wstring_view value) {
    std::wstring result(value);
    for (wchar_t& character : result) {
        if (character >= L'A' && character <= L'Z') {
            character = static_cast<wchar_t>(character - L'A' + L'a');
        }
        if (character == L'/') character = L'\\';
    }
    while (result.size() > 3 && result.back() == L'\\') result.pop_back();
    return result;
}

bool samePath(std::wstring_view left, std::wstring_view right) {
    return asciiLower(left) == asciiLower(right);
}

bool pathsOverlap(std::wstring_view left, std::wstring_view right) {
    const std::wstring first = asciiLower(left);
    const std::wstring second = asciiLower(right);
    if (first == second) return true;
    const auto descendant = [](const std::wstring& child, const std::wstring& parent) {
        return child.size() > parent.size() && child.compare(0, parent.size(), parent) == 0 &&
            child[parent.size()] == L'\\';
    };
    return descendant(first, second) || descendant(second, first);
}

bool directProfileChild(std::wstring_view pathValue, std::wstring_view rootValue) {
    const std::wstring path = asciiLower(pathValue);
    const std::wstring root = asciiLower(rootValue);
    const bool rootIsDrive = root.size() >= 3 && root[1] == L':' && root[2] == L'\\' &&
        ((root[0] >= L'a' && root[0] <= L'z') || (root[0] >= L'A' && root[0] <= L'Z'));
    if (!rootIsDrive || path.size() <= root.size() + 1 || path.compare(0, root.size(), root) != 0 ||
        path[root.size()] != L'\\') {
        return false;
    }
    const std::wstring_view leaf(path.c_str() + root.size() + 1, path.size() - root.size() - 1);
    return !leaf.empty() && leaf.find(L'\\') == std::wstring_view::npos;
}

std::wstring basenameOf(std::wstring_view pathValue) {
    const std::wstring path = asciiLower(pathValue);
    const std::size_t separator = path.find_last_of(L'\\');
    return separator == std::wstring::npos ? path : path.substr(separator + 1);
}

bool sameAscii(std::wstring_view left, std::wstring_view right) {
    return asciiLower(left) == asciiLower(right);
}

bool protectedName(std::wstring_view baseName) {
    const std::wstring name = asciiLower(baseName);
    return name == L"default" || name == L"default user" || name == L"public" || name == L"all users" ||
        name == L"systemprofile" || name == L"localservice" || name == L"networkservice" ||
        name == L"wdagutilityaccount" || name == L"containeradministrator" || name == L"containeruser";
}

bool positiveLoaded(const ProfileSignals& signals) {
    return signals.userHive == LoadSignal::Present || signals.classesHive == LoadSignal::Present ||
        signals.wmiLoaded == LoadSignal::Present || (signals.wmiRefCountKnown && signals.wmiRefCount > 0);
}

CandidateDecision decision(CandidateDisposition disposition, const wchar_t* reason) {
    return {disposition, reason};
}

} // namespace

CandidateDecision classifyCandidate(const ProfileInfo& profile, const SystemProfilePaths& paths,
                                    const NamedPolicy* policy) {
    if (!paths.complete) return decision(CandidateDisposition::Unknown, L"SYSTEM_PROFILE_PATHS_UNKNOWN");
    if (profile.bakEntry || profile.signals.bakEntry) return decision(CandidateDisposition::Protected, L"SID_BAK");
    if (profile.signals.currentProcessSid) return decision(CandidateDisposition::Protected, L"CURRENT_PROCESS_SID");
    if (profile.signals.systemSid) return decision(CandidateDisposition::Protected, L"SYSTEM_SID");
    if (profile.signals.wmiSpecial == LoadSignal::Present) return decision(CandidateDisposition::Protected, L"WMI_SPECIAL_PROFILE");
    if (!profile.pathKnown || profile.profilePath.empty() || profile.baseName.empty()) {
        return decision(CandidateDisposition::Unknown, L"PROFILE_PATH_UNKNOWN");
    }
    if (!sameAscii(profile.baseName, basenameOf(profile.profilePath))) {
        return decision(CandidateDisposition::Protected, L"PROFILE_BASENAME_MISMATCH");
    }
    if (samePath(profile.profilePath, paths.defaultPath)) return decision(CandidateDisposition::Protected, L"DEFAULT_PATH");
    if (samePath(profile.profilePath, paths.publicPath)) return decision(CandidateDisposition::Protected, L"PUBLIC_PATH");
    if (pathsOverlap(profile.profilePath, paths.commonDataPath)) return decision(CandidateDisposition::Protected, L"COMMON_DATA_PATH");
    if (!directProfileChild(profile.profilePath, paths.profilesRoot)) {
        return decision(CandidateDisposition::Protected, L"PROFILE_PATH_OUTSIDE_ROOT");
    }
    if (protectedName(profile.baseName)) return decision(CandidateDisposition::Protected, L"PROTECTED_PROFILE_NAME");
    if (policy != nullptr) {
        if (policyProtectsBasename(*policy, profile.baseName)) {
            return decision(CandidateDisposition::Protected, L"POLICY_PROTECTED_NAME");
        }
        if (!policyIncludesBasename(*policy, profile.baseName)) {
            return decision(CandidateDisposition::OutOfScope, L"POLICY_OUT_OF_SCOPE");
        }
    }
    if (positiveLoaded(profile.signals)) return decision(CandidateDisposition::PendingLoaded, L"PENDING_LOADED");
    if (profile.profileDataAccessDenied) {
        return decision(CandidateDisposition::Unknown, L"PROFILE_DATA_ACCESS_DENIED");
    }
    if (profile.wmiMatch != WmiMatchStatus::Matched || profile.wmiLocalPath.empty()) {
        return decision(CandidateDisposition::Unknown, L"WMI_PROFILE_UNCONFIRMED");
    }
    if (!samePath(profile.profilePath, profile.wmiLocalPath)) {
        return decision(CandidateDisposition::Unknown, L"WMI_PATH_MISMATCH");
    }
    if (profile.guard.disposition == GuardDisposition::UnloadedConfirmed) {
        return decision(CandidateDisposition::Eligible, L"ELIGIBLE");
    }
    if (profile.guard.disposition == GuardDisposition::Protected) {
        return decision(CandidateDisposition::Protected, L"PROFILE_GUARD_PROTECTED");
    }
    return decision(CandidateDisposition::Unknown, L"PROFILE_GUARD_UNKNOWN");
}

const wchar_t* candidateDispositionLabel(CandidateDisposition disposition) {
    switch (disposition) {
    case CandidateDisposition::Eligible: return L"ELIGIBLE";
    case CandidateDisposition::PendingLoaded: return L"PENDING_LOADED";
    case CandidateDisposition::Protected: return L"PROTECTED";
    case CandidateDisposition::Unknown: return L"UNKNOWN";
    case CandidateDisposition::OutOfScope: return L"OUT_OF_SCOPE";
    }
    return L"UNKNOWN";
}

bool isListableCandidate(CandidateDisposition disposition) {
    return disposition == CandidateDisposition::Eligible;
}

} // namespace delprofils
