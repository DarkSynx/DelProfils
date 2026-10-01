#include "../src/ProfileClassification.h"

#include <cstdlib>
#include <iostream>

namespace {
void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}
}

int main() {
    delprofils::SystemProfilePaths paths;
    paths.complete = true;
    paths.profilesRoot = L"C:\\Users";
    paths.defaultPath = L"C:\\Users\\Default";
    paths.publicPath = L"C:\\Users\\Public";
    paths.commonDataPath = L"C:\\ProgramData";

    delprofils::ProfileInfo profile;
    profile.sidKey = L"S-1-5-21-1-2-3-1001";
    profile.profilePath = L"C:\\Users\\Alice";
    profile.baseName = L"Alice";
    profile.pathKnown = true;
    profile.wmiMatch = delprofils::WmiMatchStatus::Matched;
    profile.wmiLocalPath = profile.profilePath;
    profile.guard.disposition = delprofils::GuardDisposition::UnloadedConfirmed;

    auto decision = delprofils::classifyCandidate(profile, paths, nullptr);
    require(decision.disposition == delprofils::CandidateDisposition::Eligible,
            "accessible, unloaded profile must be eligible");

    profile.profileDataAccessDenied = true;
    decision = delprofils::classifyCandidate(profile, paths, nullptr);
    require(decision.disposition == delprofils::CandidateDisposition::Unknown,
            "access denied to profile data must prevent eligibility");
    require(decision.reason == L"PROFILE_DATA_ACCESS_DENIED",
            "access denied must have an explicit refusal reason");
    require(!delprofils::isListableCandidate(decision.disposition),
            "unknown profile must not appear as a /l candidate");
    require(delprofils::isListableCandidate(delprofils::CandidateDisposition::Eligible),
            "eligible unloaded profile must appear in /l");
    require(!delprofils::isListableCandidate(delprofils::CandidateDisposition::PendingLoaded),
            "loaded profile must not appear in /l");

    std::cout << "ProfileClassificationTests: PASS\n";
    return 0;
}
