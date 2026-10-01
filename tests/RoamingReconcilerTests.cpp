#include "../src/ProfileReconciler.h"

#include <cstdlib>
#include <iostream>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

} // namespace

int main() {
    delprofils::WmiProfileRecord roaming;
    roaming.sid = L"S-1-5-21-100-200-300-1001";
    roaming.roamingConfigured = true;
    roaming.roamingPreference = true;
    roaming.roamingPath = L"\\\\fileserver\\profiles\\test";

    const auto accepted = delprofils::reconcileWmiProfile(
        {}, roaming.sid, std::vector<delprofils::WmiProfileRecord>{roaming});
    require(accepted.roamingConfigured, "configured roaming must be retained");
    require(accepted.roamingPreference, "enabled roaming preference must be retained");
    require(accepted.roamingPath == roaming.roamingPath, "roaming path must be retained");

    roaming.roamingPreference = false;
    const auto excluded = delprofils::reconcileWmiProfile(
        {}, roaming.sid, std::vector<delprofils::WmiProfileRecord>{roaming});
    require(!excluded.isRoamingProfile(),
            "configured profile with disabled preference must not satisfy /r");
    require(accepted.isRoamingProfile(),
            "configured profile with enabled preference must satisfy /r");
    std::cout << "RoamingReconcilerTests: PASS\n";
    return 0;
}
