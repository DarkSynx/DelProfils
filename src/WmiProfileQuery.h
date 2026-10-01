#pragma once

#include "ProfileTarget.h"
#include "WmiProfileData.h"

#include <string>
#include <vector>

namespace delprofils {

WmiProfileQueryResult queryWmiProfiles();
WmiProfileQueryResult queryWmiProfilesForSids(const std::vector<std::wstring>& sids);
WmiProfileQueryResult queryWmiProfiles(const ProfileTarget& target);
WmiProfileQueryResult queryWmiProfilesForSids(const ProfileTarget& target,
                                              const std::vector<std::wstring>& sids);

}
