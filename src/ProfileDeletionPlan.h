#pragma once

#include "ProfileClassification.h"
#include "ProfileInfo.h"

#include <cstddef>
#include <string>
#include <vector>

namespace delprofils {

enum class DeletionPlanDisposition {
    Eligible,
    Refused
};

struct DeletionPlanDecision {
    DeletionPlanDisposition disposition = DeletionPlanDisposition::Refused;
    std::wstring reason;
};

DeletionPlanDecision evaluateDeletionPlan(const ProfileInfo& profile);
DeletionPlanDecision evaluateDeletionPlan(const ProfileInfo& profile,
                                          const std::vector<ProfileInfo>& allProfiles);
DeletionPlanDecision evaluateDeletionPlan(const ProfileInfo& profile,
                                          const std::vector<ProfileInfo>& allProfiles,
                                          CandidateDisposition candidateDisposition);
bool mustAbortDeletionBatch(std::size_t refusedSelections, bool ignoreErrors);

} // namespace delprofils
