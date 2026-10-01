#include "src/CommandLine.h"
#include "src/Console.h"
#include "src/DeferredQueue.h"
#include "src/DeferredQueueStore.h"
#include "src/ExecutionLock.h"
#include "src/PolicyStore.h"
#include "src/ProfileAge.h"
#include "src/ProfileClassification.h"
#include "src/ProfileDelete.h"
#include "src/ProfileDeleteReport.h"
#include "src/ProfileDeletionPlan.h"
#include "src/ProfileScanner.h"
#include "src/SecurityContext.h"
#include "src/SystemProfilePaths.h"
#include "src/TextEscape.h"
#include "src/Wildcard.h"

#include <cstddef>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#endif

namespace {

struct ActiveScope {
    std::optional<delprofils::NamedPolicy> policy;
    std::wstring name = L"compatible";
    std::wstring sha256 = std::wstring(64, L'0');

    const delprofils::NamedPolicy* definition() const {
        return policy.has_value() ? &*policy : nullptr;
    }
};

struct PlannedDeletion {
    std::wstring sid;
    std::wstring profilePath;
};

std::vector<std::wstring> getArgs() {
#ifdef _WIN32
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::vector<std::wstring> result;
    if (argv == nullptr) return result;
    for (int index = 1; index < argc; ++index) result.emplace_back(argv[index]);
    LocalFree(argv);
    return result;
#else
    return {};
#endif
}

std::wstring getLocalComputerName() {
#ifdef _WIN32
    std::wstring name(static_cast<std::size_t>(MAX_COMPUTERNAME_LENGTH) + 1U, L'\0');
    DWORD length = static_cast<DWORD>(name.size());
    if (GetComputerNameW(name.data(), &length)) {
        name.resize(length);
        return name;
    }
#endif
    return {};
}

void printHelp(const delprofils::Console& console) {
    console.out(
        L"DelProfils 1.2 — gestion contrôlée des profils utilisateur Windows\n"
        L"BUILD-CVIDE-FIX-20260930\n"
        L"BUILD-SELFHOST-FIX-20260930\n"
        L"\n"
        L"DelProfils inventorie et supprime des profils utilisateur Windows inactifs.\n"
        L"Cette version reprend les commandes locales de sélection de DelProf2 et\n"
        L"ajoute un audit explicatif et des protections pour les profils incertains.\n"
        L"\n"
        L"SYNTAXE DELPROF2\n"
        L"Usage: DelProfils1.exe [/l] [/u] [/q] [/p] [/r] [/c:[\\\\]ordinateur]\n"
        L"                       [/d:jours [/ntuserini]] [/ed:motif] [/id:motif] [/i] [/?]\n"
        L"\n"
        L"ACTION ET CONFIRMATION\n"
        L"  Sans option, inventorie les profils éligibles; aucune suppression.\n"
        L"  Sans /l, traite les profils correspondant aux filtres, après confirmation\n"
        L"  globale, sauf si /u, /q ou /p est spécifié.\n"
        L"  /l              inventorie sans supprimer ni modifier les profils.\n"
        L"  /u              supprime sans confirmation globale.\n"
        L"  /q              mode silencieux: aucune sortie applicative ni confirmation.\n"
        L"  /p              demande confirmation pour chaque profil; incompatible avec\n"
        L"                  /l, /u et /q.\n"
        L"  /i              continue après une erreur de suppression.\n"
        L"\n"
        L"FILTRES\n"
        L"  /d:jours        retient les profils dont l'ancienneté atteint le seuil\n"
        L"                  indiqué (1 à 365000 jours).\n"
        L"  /ntuserini      avec /d, mesure l'ancienneté depuis NTUSER.INI plutôt que\n"
        L"                  NTUSER.DAT. Cette option exige /d.\n"
        L"  /id:motif       inclut les dossiers de profil correspondant au motif.\n"
        L"  /ed:motif       exclut les dossiers de profil correspondant au motif.\n"
        L"  /id et /ed      les motifs portent sur le nom du dossier de profil Windows,\n"
        L"                  par exemple prenom.nom ou prenom.nom.000. Ils ne ciblent pas\n"
        L"                  directement le nom du compte. * représente zéro ou plusieurs\n"
        L"                  caractères; ? représente un caractère. La comparaison ne\n"
        L"                  tient pas compte des majuscules. Plusieurs motifs /id sont\n"
        L"                  réunis; plusieurs /ed aussi. Une exclusion /ed prévaut sur\n"
        L"                  une inclusion /id. Sans /d ni /id, tous les profils éligibles\n"
        L"                  sont retenus avant application des exclusions /ed.\n"
        L"  /r              limite la sélection aux caches locaux de profils itinérants\n"
        L"                  configurés et activés pour l'itinérance.\n"
        L"\n"
        L"ORDINATEUR CIBLE ET SÉCURITÉ\n"
        L"  /c:ordinateur  inventorie l'ordinateur indiqué. La suppression distante est\n"
        L"                  refusée dans cette version. /c: sans nom ne désigne la machine\n"
        L"                  locale que dans un mode d'inventaire, par exemple /l.\n"
        L"  /?              affiche cette aide et retourne le code 1, comme DelProf2.\n"
        L"  La commande locale /q /ed:admin* est compatible avec la GPO du lycée: elle\n"
        L"  traite les profils éligibles, sauf les dossiers dont le nom commence par admin.\n"
        L"\n"
        L"GARDE-FOUS ET LIMITES\n"
        L"  Les profils protégés, chargés ou dont l'état est inconnu ne sont pas supprimés.\n"
        L"  La suppression locale utilise DeleteProfileW. Les entrées ProfileList *.bak\n"
        L"  sont protégées, mais ne sont pas nettoyées. La suppression distante est\n"
        L"  désactivée; ces limites distinguent cette version de certaines fonctions\n"
        L"  internes de DelProf2.\n"
        L"\n"
        L"EXTENSIONS DELPROFILS\n"
        L"  /policy:nom     applique la politique locale installée portant ce nom.\n"
        L"  /audit          inventorie et explique les décisions; aucune suppression.\n"
        L"  /pending        affiche la file locale des profils reportés, sans inventaire\n"
        L"                  ni suppression.\n"
        L"\n"
        L"EXEMPLES\n"
        L"  DelProfils1.exe /l /ed:admin*\n"
        L"      Prévisualise les profils que la GPO du lycée pourrait traiter.\n"
        L"  DelProfils1.exe /q /ed:admin*\n"
        L"      Exécution GPO: traite silencieusement tous les profils éligibles sauf admin*.\n"
        L"  DelProfils1.exe /l /d:30 /ed:admin*\n"
        L"      Prévisualise les profils âgés d'au moins 30 jours, sauf admin*.\n"
        L"  DelProfils1.exe /p /id:prenom.nom.000\n"
        L"      Demande confirmation avant de traiter ce nom de dossier de profil.\n"
        L"  DelProfils1.exe /c:PC-PILOTE /l /ed:admin*\n"
        L"      Tente l'inventaire distant; aucune suppression distante n'est permise.\n"
        L"  DelProfils1.exe /policy:lycee /audit\n"
        L"      Explique les décisions de la politique locale « lycee ».\n");
}

const wchar_t* signalLabel(delprofils::LoadSignal signal) {
    if (signal == delprofils::LoadSignal::Present) return L"TRUE";
    if (signal == delprofils::LoadSignal::Absent) return L"FALSE";
    return L"UNKNOWN";
}

bool matchesAny(const std::vector<std::wstring>& patterns, const std::wstring& value) {
    for (const auto& pattern : patterns) {
        if (delprofils::wildcardMatch(pattern, value)) return true;
    }
    return false;
}

std::wstring asciiLower(std::wstring value) {
    for (wchar_t& character : value) {
        if (character >= L'A' && character <= L'Z') {
            character = static_cast<wchar_t>(character - L'A' + L'a');
        }
        if (character == L'/') character = L'\\';
    }
    while (value.size() > 3 && value.back() == L'\\') value.pop_back();
    return value;
}

bool sameAsciiInsensitive(const std::wstring& first, const std::wstring& second) {
    return asciiLower(first) == asciiLower(second);
}

std::optional<std::size_t> findProfileIndexBySid(const delprofils::ScanResult& scan,
                                                  const std::wstring& sid) {
    std::optional<std::size_t> found;
    for (std::size_t index = 0; index < scan.profiles.size(); ++index) {
        const auto& profile = scan.profiles[index];
        if (profile.bakEntry || !sameAsciiInsensitive(profile.sidKey, sid)) continue;
        if (found.has_value()) return std::nullopt;
        found = index;
    }
    return found;
}

bool selectActiveScope(const delprofils::Options& options, const delprofils::Console& console,
                       ActiveScope& scope) {
    // Legacy DelProf2 commands must be invariant: merely installing a modern
    // policy cannot silently narrow /id or /d.  A policy applies only after
    // the operator selected it explicitly with /policy:<name>.
    if (!options.policyName.has_value()) return true;

    const delprofils::InstalledPolicy installed = delprofils::loadInstalledPolicy();
    if (installed.status == delprofils::InstalledPolicyStatus::Absent) {
        console.err(L"DelProfils: /policy exige DelProfils.policy installé et protégé\n");
        return false;
    }
    if (installed.status != delprofils::InstalledPolicyStatus::Loaded) {
        console.err(L"DelProfils: politique installée inutilisable: " + installed.diagnostic + L"\n");
        return false;
    }

    const delprofils::NamedPolicy* selected =
        delprofils::findNamedPolicy(installed.configuration, *options.policyName);
    if (selected == nullptr) {
        console.err(L"DelProfils: politique demandée inconnue\n");
        return false;
    }
    scope.policy = *selected;
    scope.name = selected->name;
    scope.sha256 = installed.sha256Hex;
    return true;
}

bool matchesStaticCommandSelection(const delprofils::Options& options,
                                   const delprofils::ProfileInfo& profile,
                                   delprofils::FileTimeTicks t0,
                                   std::optional<delprofils::AgeDecision>& ageDecision) {
    bool included = options.includePatterns.empty();
    if (!included && profile.pathKnown) included = matchesAny(options.includePatterns, profile.baseName);
    if (included && profile.pathKnown && matchesAny(options.excludePatterns, profile.baseName)) included = false;
    if (!included) return false;
    if (options.days.has_value()) {
        ageDecision = delprofils::evaluateLegacyFileAge(profile.ageEvidence, t0, *options.days);
        if (!delprofils::passesAgeFilter(ageDecision->disposition)) return false;
    }
    return true;
}

bool matchesCommandSelection(const delprofils::Options& options, const delprofils::ProfileInfo& profile,
                             delprofils::FileTimeTicks t0,
                             std::optional<delprofils::AgeDecision>& ageDecision) {
    if (!matchesStaticCommandSelection(options, profile, t0, ageDecision)) return false;
    return !options.roamingOnly || (profile.roamingConfigured && profile.roamingPreference);
}

bool confirm(const delprofils::Console& console, const std::wstring& question) {
    console.out(question + L" [o/N] ");
    std::wstring answer;
    if (!std::getline(std::wcin, answer)) return false;
    return answer == L"o" || answer == L"O" || answer == L"oui" || answer == L"OUI" ||
        answer == L"y" || answer == L"Y" || answer == L"yes" || answer == L"YES";
}

void printProfileInventory(const delprofils::Console& console, const delprofils::ProfileInfo& profile,
                           const std::optional<delprofils::AgeDecision>& age) {
    std::wstring line = L"[" + std::wstring(delprofils::guardDispositionLabel(profile.guard.disposition)) +
        L"] SID=" + delprofils::escapeField(profile.sidKey) + L" PATH=" +
        (profile.pathKnown ? delprofils::escapeField(profile.profilePath) : L"<UNKNOWN>");
    line += L" WMI_LOADED=" + std::wstring(signalLabel(profile.signals.wmiLoaded));
    line += L" WMI_REFCOUNT=" + (profile.signals.wmiRefCountKnown
        ? std::to_wstring(profile.signals.wmiRefCount) : std::wstring(L"UNKNOWN"));
    line += L" WMI_SPECIAL=" + std::wstring(signalLabel(profile.signals.wmiSpecial));
    line += L" ROAMING_CONFIGURED=" + std::wstring(profile.roamingConfigured ? L"TRUE" : L"FALSE");
    line += L" ROAMING_PREFERENCE=" + std::wstring(profile.roamingPreference ? L"TRUE" : L"FALSE");
    if (!profile.roamingPath.empty()) line += L" ROAMING_PATH=" + delprofils::escapeField(profile.roamingPath);
    if (age.has_value()) {
        line += L" AGE=" + std::wstring(delprofils::ageDispositionLabel(age->disposition));
        line += L" AGE_REASON=" + delprofils::escapeField(age->reason);
    }
    if (!profile.wmiLocalPath.empty()) line += L" WMI_PATH=" + delprofils::escapeField(profile.wmiLocalPath);
    for (const auto& reason : profile.guard.reasons) line += L" GUARD=" + delprofils::escapeField(reason);
    for (const auto& item : profile.diagnostics) line += L" WARN=\"" + delprofils::escapeField(item) + L"\"";
    console.out(line + L"\n");
}

delprofils::FileTimeTicks nowTicks() {
#ifdef _WIN32
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    return (static_cast<delprofils::FileTimeTicks>(now.dwHighDateTime) << 32U) |
        static_cast<delprofils::FileTimeTicks>(now.dwLowDateTime);
#else
    return 1;
#endif
}

const delprofils::DeferredRecord* findDeferredRecord(const std::vector<delprofils::DeferredRecord>& records,
                                                      const std::wstring& sid) {
    for (const auto& record : records) {
        if (sameAsciiInsensitive(record.sid, sid)) return &record;
    }
    return nullptr;
}

void upsertPendingRecord(std::vector<delprofils::DeferredRecord>& records,
                         const std::vector<delprofils::DeferredRecord>& previous,
                         const delprofils::ProfileInfo& profile, const ActiveScope& scope,
                         delprofils::FileTimeTicks observed) {
    delprofils::DeferredRecord record;
    record.sid = profile.sidKey;
    record.profilePath = profile.profilePath;
    record.policyName = scope.name;
    record.policySha256 = scope.sha256;
    record.firstObservedUtcTicks = observed;
    record.lastObservedUtcTicks = observed;
    record.observedLoadedCount = 1;
    if (const auto* old = findDeferredRecord(previous, profile.sidKey)) {
        if (delprofils::validateDeferredRecord(*old, profile.sidKey, profile.profilePath, scope.name,
            scope.sha256, false) == delprofils::QueueRecordDecision::Keep) {
            record.firstObservedUtcTicks = old->firstObservedUtcTicks;
            record.observedLoadedCount = old->observedLoadedCount == std::numeric_limits<std::uint32_t>::max()
                ? old->observedLoadedCount : old->observedLoadedCount + 1;
        }
    }
    for (auto& existing : records) {
        if (sameAsciiInsensitive(existing.sid, record.sid)) {
            existing = std::move(record);
            return;
        }
    }
    records.push_back(std::move(record));
}

void removeDeferredRecord(std::vector<delprofils::DeferredRecord>& records, const std::wstring& sid) {
    for (std::size_t index = 0; index < records.size(); ++index) {
        if (!sameAsciiInsensitive(records[index].sid, sid)) continue;
        records.erase(records.begin() + static_cast<std::ptrdiff_t>(index));
        return;
    }
}

void printAuditDecision(const delprofils::Console& console, const delprofils::ProfileInfo& profile,
                        const delprofils::CandidateDecision& decision,
                        const std::optional<delprofils::AgeDecision>& age) {
    if (decision.disposition == delprofils::CandidateDisposition::OutOfScope) {
        console.out(delprofils::formatPolicyOutOfScope(profile.sidKey) + L"\n");
        return;
    }
    if (decision.disposition == delprofils::CandidateDisposition::PendingLoaded) {
        console.out(delprofils::formatQueuePendingLoaded(profile.sidKey) + L"\n");
        return;
    }
    if (decision.disposition == delprofils::CandidateDisposition::Protected) {
        console.out(delprofils::formatProtectionReason(profile.sidKey, decision.reason) + L"\n");
        return;
    }
    printProfileInventory(console, profile, age);
}

} // namespace

int main() {
    const auto parsed = delprofils::parseCommandLine(getArgs());
    const delprofils::Console console(parsed.options.quiet);
    if (parsed.status == delprofils::ParseStatus::SyntaxError) {
        console.err(L"DelProfils: erreur de syntaxe: " + parsed.diagnostic + L"\n");
        return 2;
    }
    if (parsed.options.help) {
        printHelp(console);
        // DelProf2 writes its help text successfully but returns ERRORLEVEL 1.
        // Keep this historical command-line contract for script compatibility.
        return 1;
    }
    if (parsed.status == delprofils::ParseStatus::Unsupported ||
        parsed.status == delprofils::ParseStatus::PrototypeSafetyRefusal) {
        console.err(L"DelProfils: " + parsed.diagnostic + L"\n");
        return 3;
    }

    const delprofils::ProfileTarget target = parsed.options.remoteComputer.empty()
        ? delprofils::ProfileTarget::local()
        : delprofils::ProfileTarget::fromComputer(parsed.options.remoteComputer,
                                                   getLocalComputerName());
    if (!target.valid()) {
        console.err(L"DelProfils: cible /c invalide\n");
        return 2;
    }
    if (!target.isLocal() && !parsed.options.listOnly) {
        console.err(L"DelProfils: suppression distante refusée: validation VM requise avant activation\n");
        return 3;
    }

    std::optional<delprofils::ExecutionLock> executionLock;
    if (!parsed.options.listOnly) {
        executionLock.emplace(delprofils::ExecutionLock::tryAcquire());
        if (!executionLock->acquired()) {
            console.err(L"DelProfils: une autre exécution locale est active (WIN32=" +
                std::to_wstring(executionLock->win32Error()) + L")\n");
            return 9;
        }
    }

    ActiveScope scope;
    if (!selectActiveScope(parsed.options, console, scope)) return 3;

    const delprofils::DeferredQueueLoadResult deferred = delprofils::loadDeferredQueue();
    if (!parsed.options.listOnly && !deferred.usable) {
        console.err(L"DelProfils: file différée inutilisable; suppression refusée: " +
            deferred.diagnostic + L"\n");
        return 3;
    }
    if (parsed.options.pendingOnly) {
        if (!deferred.usable) {
            console.err(L"DelProfils: file différée inutilisable: " + deferred.diagnostic + L"\n");
            return 3;
        }
        for (const auto& record : deferred.records) {
            if (scope.policy.has_value() &&
                (record.policyName != scope.name || record.policySha256 != scope.sha256)) {
                console.out(delprofils::formatQueueStalePolicy(record.sid) + L"\n");
            } else {
                console.out(delprofils::formatQueuePendingLoaded(record.sid) + L" PATH=" +
                    delprofils::escapeField(record.profilePath) + L" COUNT=" +
                    std::to_wstring(record.observedLoadedCount) + L"\n");
            }
        }
        return 0;
    }

    const delprofils::SystemProfilePaths paths = delprofils::querySystemProfilePaths(target);
    if (!paths.complete) {
        console.err(L"DelProfils: chemins système incomplets: " + paths.diagnostic + L"\n");
        return 8;
    }
    delprofils::ScanResult scan = delprofils::enumerateProfileList(target, parsed.options.ntuserini);
    if (!scan.complete) {
        console.err(L"DelProfils: inventaire ProfileList incomplet: " + scan.diagnostic + L"\n");
        return 8;
    }

    const delprofils::FileTimeTicks t0 = nowTicks();
    std::vector<delprofils::CandidateDecision> preliminary(scan.profiles.size());
    std::vector<std::optional<delprofils::AgeDecision>> age(scan.profiles.size());
    std::vector<bool> selected(scan.profiles.size(), false);
    std::vector<std::size_t> enrichIndexes;
    for (std::size_t index = 0; index < scan.profiles.size(); ++index) {
        const auto& profile = scan.profiles[index];
        preliminary[index] = delprofils::classifyCandidate(profile, paths, scope.definition());
        if (preliminary[index].disposition == delprofils::CandidateDisposition::Protected ||
            preliminary[index].disposition == delprofils::CandidateDisposition::OutOfScope) {
            continue;
        }
        if (!matchesStaticCommandSelection(parsed.options, profile, t0, age[index])) continue;
        selected[index] = true;
        if (!profile.bakEntry && !profile.signals.bakEntry) enrichIndexes.push_back(index);
    }

    std::wstring enrichmentDiagnostic;
    if (!delprofils::enrichRuntimeSignals(scan, target, enrichIndexes, enrichmentDiagnostic)) {
        console.err(L"DelProfils: enrichissement WMI/HKU incomplet: " + enrichmentDiagnostic + L"\n");
        return 8;
    }

    // Runtime enrichment can change a profile from a possible candidate to
    // loaded, protected, or unknown. Reclassify before listing or deletion.
    for (std::size_t index = 0; index < scan.profiles.size(); ++index) {
        preliminary[index] = delprofils::classifyCandidate(
            scan.profiles[index], paths, scope.definition());
        if (!selected[index]) continue;
        const auto disposition = preliminary[index].disposition;
        if (disposition == delprofils::CandidateDisposition::Protected ||
            disposition == delprofils::CandidateDisposition::OutOfScope) {
            selected[index] = false;
            continue;
        }
        selected[index] = matchesCommandSelection(parsed.options, scan.profiles[index], t0, age[index]);
        // DelProf2 /l lists profiles eligible for the operation. Loaded and
        // unconfirmed profiles remain visible only through the explicit audit.
        if (parsed.options.listOnly && !delprofils::isListableCandidate(disposition)) {
            selected[index] = false;
        }
    }

    std::vector<delprofils::DeferredRecord> nextQueue;
    bool queueTouched = false;
    if (!parsed.options.listOnly && deferred.usable) {
        for (const auto& record : deferred.records) {
            const auto profileIndex = findProfileIndexBySid(scan, record.sid);
            if (!profileIndex.has_value()) {
                queueTouched = true;
                continue;
            }
            const auto stale = delprofils::validateDeferredRecord(record, scan.profiles[*profileIndex].sidKey,
                scan.profiles[*profileIndex].profilePath, scope.name, scope.sha256,
                preliminary[*profileIndex].disposition == delprofils::CandidateDisposition::Protected);
            if (stale != delprofils::QueueRecordDecision::Keep ||
                preliminary[*profileIndex].disposition == delprofils::CandidateDisposition::OutOfScope) {
                if (stale == delprofils::QueueRecordDecision::RemoveChangedPolicy) {
                    console.out(delprofils::formatQueueStalePolicy(record.sid) + L"\n");
                }
                queueTouched = true;
                continue;
            }
            if (!selected[*profileIndex]) nextQueue.push_back(record);
        }
    }

    console.out(L"DelProfils 1.2 - catalogue ProfileList puis enrichissement sélectionné" +
        (target.isLocal() ? std::wstring() : L" sur " + target.computer()) + L"\n");
    std::size_t shown = 0;
    std::size_t selectionRefused = 0;
    std::vector<PlannedDeletion> planned;
    for (std::size_t index = 0; index < scan.profiles.size(); ++index) {
        const auto& profile = scan.profiles[index];
        const delprofils::CandidateDecision decision = delprofils::classifyCandidate(profile, paths, scope.definition());
        if (parsed.options.audit) {
            printAuditDecision(console, profile, decision, age[index]);
            ++shown;
            continue;
        }
        if (!selected[index]) continue;
        if (parsed.options.listOnly) {
            printProfileInventory(console, profile, age[index]);
            ++shown;
            continue;
        }
        if (decision.disposition == delprofils::CandidateDisposition::PendingLoaded) {
            console.out(delprofils::formatQueuePendingLoaded(profile.sidKey) + L"\n");
            if (deferred.usable) {
                upsertPendingRecord(nextQueue, deferred.records, profile, scope, nowTicks());
                queueTouched = true;
            }
            ++shown;
            continue;
        }
        const auto deletion = delprofils::evaluateDeletionPlan(profile, scan.profiles, decision.disposition);
        if (deletion.disposition != delprofils::DeletionPlanDisposition::Eligible) {
            console.err(L"DELETE=REFUSED SID=" + delprofils::escapeField(profile.sidKey) +
                L" REASON=" + delprofils::escapeField(deletion.reason) + L"\n");
            ++selectionRefused;
        } else {
            planned.push_back({profile.sidKey, profile.profilePath});
            console.out(L"DELETE=PLAN SID=" + delprofils::escapeField(profile.sidKey) + L"\n");
        }
        ++shown;
    }
    console.out(L"Résumé: " + std::to_wstring(shown) + L" profil(s) examiné(s), " +
        std::to_wstring(scan.profiles.size()) + L" entrée(s) ProfileList.\n");

    if (parsed.options.listOnly) return 0;
    if (delprofils::mustAbortDeletionBatch(selectionRefused, parsed.options.ignoreErrors)) return 3;

    bool executionFailure = selectionRefused != 0;
    const bool confirmed = planned.empty() || parsed.options.unattended || parsed.options.quiet ||
        parsed.options.promptEach || confirm(console, L"Confirmer la suppression de " +
            std::to_wstring(planned.size()) + L" profil(s) ?");
    if (confirmed && !planned.empty()) {
        const auto privileges = delprofils::enableProfileDeletionPrivileges();
        if (privileges.status != delprofils::PrivilegeEnableStatus::Enabled) {
            console.err(L"DELETE=REFUSED REASON=PRIVILEGES_UNAVAILABLE WIN32=" +
                std::to_wstring(privileges.systemError) + L" DETAIL=" + privileges.diagnostic + L"\n");
            executionFailure = true;
        } else {
        for (const auto& item : planned) {
            if (parsed.options.promptEach && !confirm(console, L"Supprimer " + item.sid + L" ?")) continue;
            const delprofils::SystemProfilePaths currentPaths = delprofils::querySystemProfilePaths();
            const delprofils::ScanResult currentScan = delprofils::scanLocalProfiles(parsed.options.ntuserini);
            if (!currentPaths.complete || !currentScan.complete) {
                console.err(L"DELETE=REFUSED SID=" + delprofils::escapeField(item.sid) +
                    L" REASON=REVALIDATION_SCAN_INCOMPLETE\n");
                return 8;
            }
            const auto currentIndex = findProfileIndexBySid(currentScan, item.sid);
            if (!currentIndex.has_value() || !sameAsciiInsensitive(currentScan.profiles[*currentIndex].profilePath, item.profilePath)) {
                console.err(L"DELETE=REFUSED SID=" + delprofils::escapeField(item.sid) + L" REASON=TARGET_CHANGED\n");
                executionFailure = true;
            } else {
                const auto& current = currentScan.profiles[*currentIndex];
                std::optional<delprofils::AgeDecision> currentAge;
                const bool stillSelected = matchesCommandSelection(parsed.options, current, t0, currentAge);
                const delprofils::CandidateDecision currentDecision =
                    delprofils::classifyCandidate(current, currentPaths, scope.definition());
                if (currentDecision.disposition == delprofils::CandidateDisposition::PendingLoaded) {
                    console.out(delprofils::formatQueuePendingLoaded(current.sidKey) + L"\n");
                    if (deferred.usable) {
                        upsertPendingRecord(nextQueue, deferred.records, current, scope, nowTicks());
                        queueTouched = true;
                    }
                } else if (!stillSelected) {
                    console.err(L"DELETE=REFUSED SID=" + delprofils::escapeField(item.sid) +
                        L" REASON=AGE_OR_FILTER_CHANGED\n");
                    executionFailure = true;
                } else {
                    const auto deletion = delprofils::evaluateDeletionPlan(current, currentScan.profiles,
                        currentDecision.disposition);
                    if (deletion.disposition != delprofils::DeletionPlanDisposition::Eligible) {
                        console.err(L"DELETE=REFUSED SID=" + delprofils::escapeField(item.sid) +
                            L" REASON=" + delprofils::escapeField(deletion.reason) + L"\n");
                        executionFailure = true;
                    } else {
                        const auto result = delprofils::deleteLocalProfile(current.sidKey, current.profilePath);
                        if (result.status != delprofils::ProfileDeleteStatus::Deleted) executionFailure = true;
                        console.out(delprofils::formatDeleteResult(current.sidKey, result.status, result.win32Error) + L"\n");
                        if (result.status == delprofils::ProfileDeleteStatus::Deleted) {
                            removeDeferredRecord(nextQueue, current.sidKey);
                            queueTouched = true;
                        }
                    }
                }
            }
            if (executionFailure && !parsed.options.ignoreErrors) break;
        }
        }
    }

    if (deferred.usable && queueTouched) {
        std::wstring queueDiagnostic;
        unsigned long queueError = 0;
        if (!delprofils::saveDeferredQueue(nextQueue, queueDiagnostic, queueError)) {
            console.err(L"DelProfils: mise à jour de file différée impossible: " + queueDiagnostic + L"\n");
            executionFailure = true;
        }
    }
    return executionFailure ? 1 : 0;
}
