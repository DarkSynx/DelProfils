#include "../src/CommandLine.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

void acceptsRoamingAndRemoteInventory() {
    const delprofils::ParseResult roaming = delprofils::parseCommandLine({L"/l", L"/r"});
    require(roaming.status == delprofils::ParseStatus::Ok,
            "/l /r must be executable, not Unsupported");
    require(roaming.options.roamingOnly, "/r must be retained in Options");

    const delprofils::ParseResult remote =
        delprofils::parseCommandLine({L"/l", L"/c:vm-profils"});
    require(remote.status == delprofils::ParseStatus::Ok,
            "/l /c:host must be executable, not Unsupported");
    require(remote.options.remoteComputer == L"vm-profils",
            "/c host must be preserved without a UNC prefix");
}

void normalizesLocalAliases() {
    const delprofils::ParseResult local =
        delprofils::parseCommandLine({L"/l", L"/c:localhost"});
    require(local.status == delprofils::ParseStatus::Ok,
            "/c:localhost must be a valid local target");
}

void acceptsEmptyComputerAsLocalInventory() {
    const delprofils::ParseResult localInventory =
        delprofils::parseCommandLine({L"/l", L"/c:"});
    require(localInventory.status == delprofils::ParseStatus::Ok,
            "/l /c: must match DelProf2 by listing the local machine");
    require(localInventory.options.remoteComputer.empty(),
            "empty /c must select the local computer");

    const delprofils::ParseResult noAction =
        delprofils::parseCommandLine({L"/c:"});
    require(noAction.status == delprofils::ParseStatus::SyntaxError,
            "/c: without /l, /u, /d or /id must still be rejected as no action");
}

void acceptsDelProf2ExclusionOnlyGpoCommand() {
    const delprofils::ParseResult result =
        delprofils::parseCommandLine({L"/q", L"/ed:admin*"});
    require(result.status == delprofils::ParseStatus::Ok,
            "DelProf2 GPO command /q /ed:admin* must be accepted");
    require(result.options.quiet, "/q must remain enabled");
    require(!result.options.listOnly, "the GPO command must remain an action");
    require(result.options.includePatterns.empty(),
            "without /id, every eligible profile is initially selected");
    require(result.options.excludePatterns.size() == 1 &&
            result.options.excludePatterns.front() == L"admin*",
            "/ed:admin* must be preserved as the exclusion pattern");

    const delprofils::ParseResult allProfiles =
        delprofils::parseCommandLine({L"/q"});
    require(allProfiles.status == delprofils::ParseStatus::Ok,
            "DelProf2 permits an action without a positive selector");
}

} // namespace

int main() {
    acceptsRoamingAndRemoteInventory();
    normalizesLocalAliases();
    acceptsEmptyComputerAsLocalInventory();
    acceptsDelProf2ExclusionOnlyGpoCommand();
    std::cout << "CommandLineTests: PASS\n";
    return 0;
}
