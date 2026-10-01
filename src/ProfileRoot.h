#pragma once

#include <string>

namespace delprofils {

struct ProfilesRootResult {
    bool known = false;
    std::wstring path;
    unsigned long win32Error = 0;
};

// Returns the configured local profile root through Userenv.  P0.9 accepts
// only one direct child of a local drive root; it deliberately refuses nested
// and network layouts until they have a dedicated qualification matrix.
ProfilesRootResult queryProfilesRoot();
bool isDirectChildOfProfilesRoot(const std::wstring& profilePath,
                                 const std::wstring& profilesRoot);

} // namespace delprofils
