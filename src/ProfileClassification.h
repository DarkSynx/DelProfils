#pragma once

#include "ProfileInfo.h"
#include "ProfilePolicy.h"
#include "SystemProfilePaths.h"

#include <string>

namespace delprofils {

enum class CandidateDisposition {
    Eligible,
    PendingLoaded,
    Protected,
    Unknown,
    OutOfScope
};

struct CandidateDecision {
    CandidateDisposition disposition = CandidateDisposition::Unknown;
    std::wstring reason;
};

CandidateDecision classifyCandidate(const ProfileInfo& profile, const SystemProfilePaths& paths,
                                    const NamedPolicy* policy);
bool isListableCandidate(CandidateDisposition disposition);
const wchar_t* candidateDispositionLabel(CandidateDisposition disposition);

} // namespace delprofils
