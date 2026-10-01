#pragma once

#include "ProfileTarget.h"

#include <string>

namespace delprofils {

struct SystemProfilePaths {
    bool complete = false;
    std::wstring profilesRoot;
    std::wstring defaultPath;
    std::wstring publicPath;
    std::wstring commonDataPath;
    std::wstring diagnostic;
    unsigned long win32Error = 0;
};

SystemProfilePaths querySystemProfilePaths();
SystemProfilePaths querySystemProfilePaths(const ProfileTarget& target);

} // namespace delprofils
