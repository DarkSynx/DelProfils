#include "WmiProfileQuery.h"

#ifdef _WIN32
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <wbemidl.h>

#include <limits>
#include <mutex>
#endif

namespace delprofils {

#ifdef _WIN32
namespace {

template <typename T>
class ComPtr {
public:
    ComPtr() = default;
    ~ComPtr() { if (value_) value_->Release(); }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    T* get() const { return value_; }
    T** put() { return &value_; }
private:
    T* value_ = nullptr;
};

class BStr {
public:
    explicit BStr(const wchar_t* value) : value_(SysAllocString(value)) {}
    ~BStr() { SysFreeString(value_); }
    BStr(const BStr&) = delete;
    BStr& operator=(const BStr&) = delete;
    BSTR get() const { return value_; }
    bool valid() const { return value_ != nullptr; }
private:
    BSTR value_ = nullptr;
};

class ComApartment {
public:
    ComApartment() : result_(CoInitializeEx(nullptr, COINIT_MULTITHREADED)) {}
    ~ComApartment() { if (SUCCEEDED(result_)) CoUninitialize(); }
    HRESULT result() const { return result_; }
private:
    HRESULT result_;
};

std::wstring hresultText(const wchar_t* operation, HRESULT hr) {
    return std::wstring(operation) + L" (HRESULT=" +
           std::to_wstring(static_cast<unsigned long>(hr)) + L")";
}

struct WmiProcessSecurity {
    HRESULT result = E_UNEXPECTED;
};

const WmiProcessSecurity& initializeWmiProcessSecurity() {
    static WmiProcessSecurity state;
    static std::once_flag once;
    std::call_once(once, [] {
        state.result = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                                            RPC_C_AUTHN_LEVEL_DEFAULT,
                                            RPC_C_IMP_LEVEL_IMPERSONATE,
                                            nullptr, EOAC_NONE, nullptr);
    });
    return state;
}

bool getVariant(IWbemClassObject* object, const wchar_t* name, VARIANT& value,
                std::vector<std::wstring>& diagnostics) {
    VariantInit(&value);
    const HRESULT hr = object->Get(name, 0, &value, nullptr, nullptr);
    if (FAILED(hr)) {
        diagnostics.push_back(std::wstring(L"WMI propriété ") + name + L" inaccessible");
        return false;
    }
    return true;
}

std::optional<std::wstring> readString(IWbemClassObject* object, const wchar_t* name,
                                       std::vector<std::wstring>& diagnostics) {
    VARIANT value;
    if (!getVariant(object, name, value, diagnostics)) return std::nullopt;
    std::optional<std::wstring> result;
    if (value.vt == VT_BSTR && value.bstrVal != nullptr) {
        result = std::wstring(value.bstrVal, SysStringLen(value.bstrVal));
    } else if (value.vt != VT_NULL && value.vt != VT_EMPTY) {
        diagnostics.push_back(std::wstring(L"WMI propriété ") + name + L" type inattendu");
    }
    VariantClear(&value);
    return result;
}

std::optional<bool> readBool(IWbemClassObject* object, const wchar_t* name,
                             std::vector<std::wstring>& diagnostics) {
    VARIANT value;
    if (!getVariant(object, name, value, diagnostics)) return std::nullopt;
    std::optional<bool> result;
    if (value.vt == VT_BOOL) {
        result = value.boolVal != VARIANT_FALSE;
    } else if (value.vt != VT_NULL && value.vt != VT_EMPTY) {
        diagnostics.push_back(std::wstring(L"WMI propriété ") + name + L" type inattendu");
    }
    VariantClear(&value);
    return result;
}

std::optional<std::uint32_t> readUint32(IWbemClassObject* object, const wchar_t* name,
                                        std::vector<std::wstring>& diagnostics) {
    VARIANT value;
    if (!getVariant(object, name, value, diagnostics)) return std::nullopt;
    std::optional<std::uint32_t> result;
    if (value.vt == VT_UI4) {
        result = static_cast<std::uint32_t>(value.ulVal);
    } else if (value.vt == VT_I4 && value.lVal >= 0) {
        result = static_cast<std::uint32_t>(value.lVal);
    } else if (value.vt != VT_NULL && value.vt != VT_EMPTY) {
        diagnostics.push_back(std::wstring(L"WMI propriété ") + name + L" type/valeur inattendu");
    }
    VariantClear(&value);
    return result;
}

bool validSidLiteral(const std::wstring& sid) {
    if (sid.size() < 5 || sid.size() > 184 || sid[0] != L'S' || sid[1] != L'-' || sid[2] != L'1' || sid[3] != L'-') {
        return false;
    }
    for (wchar_t character : sid) {
        if ((character < L'0' || character > L'9') && character != L'S' && character != L'-') return false;
    }
    return true;
}

std::wstring filteredQuery(const std::vector<std::wstring>& sids) {
    constexpr wchar_t kProjection[] =
        L"SELECT SID, LocalPath, Loaded, refCount, Special, RoamingConfigured, "
        L"RoamingPreference, RoamingPath, LastUseTime FROM Win32_UserProfile";
    if (sids.empty()) return kProjection;
    std::wstring query(kProjection);
    query += L" WHERE ";
    for (std::size_t index = 0; index < sids.size(); ++index) {
        if (index != 0) query += L" OR ";
        query += L"SID='" + sids[index] + L"'";
    }
    return query;
}

}
#endif

WmiProfileQueryResult queryWmiProfiles() {
    return queryWmiProfiles(ProfileTarget::local());
}

WmiProfileQueryResult queryWmiProfilesForSids(const std::vector<std::wstring>& sids) {
    return queryWmiProfilesForSids(ProfileTarget::local(), sids);
}

WmiProfileQueryResult queryWmiProfiles(const ProfileTarget& target) {
    return queryWmiProfilesForSids(target, {});
}

WmiProfileQueryResult queryWmiProfilesForSids(const ProfileTarget& target,
                                              const std::vector<std::wstring>& sids) {
#ifndef _WIN32
    (void)target;
    (void)sids;
    WmiProfileQueryResult result;
    result.diagnostic = L"Win32_UserProfile disponible uniquement sous Windows";
    return result;
#else
    WmiProfileQueryResult result;
    if (!target.valid()) {
        result.systemError = ERROR_INVALID_COMPUTERNAME;
        result.diagnostic = L"cible WMI invalide";
        return result;
    }
    if (sids.size() > 32) {
        result.diagnostic = L"lot WMI supérieur à 32 SID";
        result.systemError = ERROR_INVALID_PARAMETER;
        return result;
    }
    for (const auto& sid : sids) {
        if (!validSidLiteral(sid)) {
            result.diagnostic = L"SID non canonique refusé avant requête WMI";
            result.systemError = ERROR_INVALID_SID;
            return result;
        }
    }
    ComApartment apartment;
    if (FAILED(apartment.result())) {
        result.systemError = static_cast<unsigned long>(apartment.result());
        result.diagnostic = hresultText(L"CoInitializeEx a échoué", apartment.result());
        return result;
    }

    const WmiProcessSecurity& security = initializeWmiProcessSecurity();
    if (FAILED(security.result)) {
        result.systemError = static_cast<unsigned long>(security.result);
        result.diagnostic = hresultText(L"CoInitializeSecurity a échoué", security.result);
        return result;
    }

    HRESULT hr = S_OK;

    ComPtr<IWbemLocator> locator;
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, reinterpret_cast<void**>(locator.put()));
    if (FAILED(hr)) {
        result.systemError = static_cast<unsigned long>(hr);
        result.diagnostic = hresultText(L"création IWbemLocator impossible", hr);
        return result;
    }

    const std::wstring nameSpaceText = target.wmiNamespace();
    BStr nameSpace(nameSpaceText.c_str());
    if (!nameSpace.valid()) {
        result.diagnostic = L"allocation du namespace WMI impossible";
        return result;
    }
    ComPtr<IWbemServices> services;
    hr = locator.get()->ConnectServer(nameSpace.get(), nullptr, nullptr, nullptr, 0,
                                      nullptr, nullptr, services.put());
    if (FAILED(hr)) {
        result.systemError = static_cast<unsigned long>(hr);
        result.diagnostic = hresultText(L"connexion WMI de la cible impossible", hr);
        return result;
    }

    hr = CoSetProxyBlanket(services.get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                           nullptr, RPC_C_AUTHN_LEVEL_CALL,
                           RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr)) {
        result.systemError = static_cast<unsigned long>(hr);
        result.diagnostic = hresultText(L"sécurité proxy WMI impossible", hr);
        return result;
    }

    BStr language(L"WQL");
    const std::wstring queryText = filteredQuery(sids);
    BStr query(queryText.c_str());
    if (!language.valid() || !query.valid()) {
        result.diagnostic = L"allocation de la requête WMI impossible";
        return result;
    }
    ComPtr<IEnumWbemClassObject> enumerator;
    hr = services.get()->ExecQuery(language.get(), query.get(),
                                   WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                   nullptr, enumerator.put());
    if (FAILED(hr)) {
        result.systemError = static_cast<unsigned long>(hr);
        result.diagnostic = hresultText(L"requête Win32_UserProfile impossible", hr);
        return result;
    }

    const ULONGLONG deadline = GetTickCount64() + 60000ULL;
    for (;;) {
        IWbemClassObject* raw = nullptr;
        ULONG returned = 0;
        hr = enumerator.get()->Next(1000, 1, &raw, &returned);
        if (returned > 0 && raw != nullptr) {
            WmiProfileRecord record;
            const auto sid = readString(raw, L"SID", record.diagnostics);
            const auto path = readString(raw, L"LocalPath", record.diagnostics);
            record.loaded = readBool(raw, L"Loaded", record.diagnostics);
            record.refCount = readUint32(raw, L"refCount", record.diagnostics);
            record.special = readBool(raw, L"Special", record.diagnostics);
            record.roamingConfigured = readBool(raw, L"RoamingConfigured", record.diagnostics);
            record.roamingPreference = readBool(raw, L"RoamingPreference", record.diagnostics);
            record.roamingPath = readString(raw, L"RoamingPath", record.diagnostics);
            record.lastUseTimeCim = readString(raw, L"LastUseTime", record.diagnostics);
            raw->Release();

            if (!sid.has_value() || sid->empty()) {
                result.diagnostic = L"instance Win32_UserProfile sans SID exploitable";
                return result;
            }
            record.sid = *sid;
            if (path.has_value()) record.localPath = *path;
            result.profiles.push_back(std::move(record));
        }

        if (FAILED(hr)) {
            result.systemError = static_cast<unsigned long>(hr);
            result.diagnostic = hresultText(L"énumération Win32_UserProfile interrompue", hr);
            return result;
        }
        if (hr == WBEM_S_FALSE) break;
        if (GetTickCount64() >= deadline) {
            result.systemError = static_cast<unsigned long>(WBEM_S_TIMEDOUT);
            result.diagnostic = L"budget WMI de 60 secondes dépassé";
            return result;
        }
    }

    result.complete = true;
    return result;
#endif
}

}
