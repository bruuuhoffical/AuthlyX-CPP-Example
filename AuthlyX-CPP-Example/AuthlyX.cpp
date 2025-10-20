include "AuthlyX.hpp"
#include <vector>
#include <algorithm>

AuthlyX::AuthlyX(const std::string& ownerId, const std::string& appName,
    const std::string& version, const std::string& secret)
    : ownerId(ownerId), appName(appName), version(version), secret(secret) {
}

std::string AuthlyX::PostJson(const std::string& endpoint, const std::string& json) {
    HINTERNET hSession = nullptr, hConnect = nullptr, hRequest = nullptr;
    std::string response;

    hSession = WinHttpOpen(L"AuthlyX Client",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        this->response.message = "Failed to initialize WinHTTP";
        return "";
    }

    hConnect = WinHttpConnect(hSession, L"authly.cc",
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        this->response.message = "Failed to connect to authly.cc";
        return "";
    }

    std::wstring wpath = L"/api/v1/" + std::wstring(endpoint.begin(), endpoint.end());
    hRequest = WinHttpOpenRequest(hConnect, L"POST", wpath.c_str(),
        nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        this->response.message = "Failed to create HTTP request";
        return "";
    }

    // Set headers
    LPCWSTR headers = L"Content-Type: application/json";
    WinHttpAddRequestHeaders(hRequest, headers, wcslen(headers),
        WINHTTP_ADDREQ_FLAG_ADD);

    // Convert JSON to wide string for sending
    std::wstring wjson(json.begin(), json.end());

    // Send request
    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        (LPVOID)wjson.c_str(), (DWORD)(wjson.length() * sizeof(wchar_t)),
        (DWORD)(wjson.length() * sizeof(wchar_t)), 0)) {

        WinHttpReceiveResponse(hRequest, nullptr);

        // Read response
        DWORD size = 0;
        do {
            if (!WinHttpQueryDataAvailable(hRequest, &size)) {
                break;
            }

            if (size > 0) {
                std::vector<char> buffer(size + 1);
                DWORD downloaded = 0;
                if (WinHttpReadData(hRequest, buffer.data(), size, &downloaded)) {
                    response.append(buffer.data(), downloaded);
                }
            }
        } while (size > 0);
    }
    else {
        this->response.message = "Failed to send HTTP request";
    }

    // Cleanup
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return response;
}

std::string AuthlyX::BuildJson(const std::map<std::string, std::string>& data) {
    std::string json = "{";
    bool first = true;

    for (const auto& pair : data) {
        if (!first) json += ",";
        json += "\"" + pair.first + "\":\"" + EscapeJsonString(pair.second) + "\"";
        first = false;
    }
    json += "}";
    return json;
}

std::string AuthlyX::EscapeJsonString(const std::string& str) {
    std::string result;
    for (char c : str) {
        switch (c) {
        case '"': result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\b': result += "\\b"; break;
        case '\f': result += "\\f"; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default: result += c; break;
        }
    }
    return result;
}

std::string AuthlyX::GetSystemSid() {
    HANDLE hToken = nullptr;
    DWORD length = 0;
    std::string sidStr = "UNKNOWN_SID";

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &length);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::vector<BYTE> buffer(length);
            if (GetTokenInformation(hToken, TokenUser, buffer.data(), length, &length)) {
                PTOKEN_USER pTokenUser = (PTOKEN_USER)buffer.data();
                LPSTR str = nullptr;
                if (ConvertSidToStringSidA(pTokenUser->User.Sid, &str)) {
                    sidStr = str;
                    LocalFree(str);
                }
            }
        }
        CloseHandle(hToken);
    }

    return sidStr;
}

std::string AuthlyX::GetLocalIp() {
    ULONG size = 0;
    GetAdaptersAddresses(AF_INET, 0, nullptr, nullptr, &size);

    if (GetLastError() != ERROR_BUFFER_OVERFLOW) return "UNKNOWN_IP";

    std::vector<BYTE> buffer(size);
    PIP_ADAPTER_ADDRESSES addresses = (PIP_ADAPTER_ADDRESSES)buffer.data();

    if (GetAdaptersAddresses(AF_INET, 0, nullptr, addresses, &size) == ERROR_SUCCESS) {
        for (PIP_ADAPTER_ADDRESSES addr = addresses; addr; addr = addr->Next) {
            if (addr->OperStatus == IfOperStatusUp) {
                for (PIP_ADAPTER_UNICAST_ADDRESS unicast = addr->FirstUnicastAddress;
                    unicast; unicast = unicast->Next) {
                    if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
                        char ip[INET_ADDRSTRLEN];
                        sockaddr_in* sa = (sockaddr_in*)unicast->Address.lpSockaddr;
                        inet_ntop(AF_INET, &(sa->sin_addr), ip, INET_ADDRSTRLEN);
                        return ip;
                    }
                }
            }
        }
    }

    return "UNKNOWN_IP";
}

std::string AuthlyX::ExtractJsonValue(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\":\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return "";

    size_t start = pos + searchKey.length();
    size_t end = json.find('"', start);
    if (end == std::string::npos) return "";

    return json.substr(start, end - start);
}

void AuthlyX::ParseResponse(const std::string& jsonResponse) {
    response.raw = jsonResponse;

    // Extract success field
    std::string successStr = ExtractJsonValue(jsonResponse, "success");
    response.success = (successStr == "true");

    // Extract message field
    response.message = ExtractJsonValue(jsonResponse, "message");

    LoadUserData(jsonResponse);
    LoadVariableData(jsonResponse);
}

void AuthlyX::LoadUserData(const std::string& jsonResponse) {
    userData.username = ExtractJsonValue(jsonResponse, "username");
    userData.email = ExtractJsonValue(jsonResponse, "email");
    userData.licenseKey = ExtractJsonValue(jsonResponse, "license_key");
    userData.subscription = ExtractJsonValue(jsonResponse, "subscription");
    userData.expiryDate = ExtractJsonValue(jsonResponse, "expiry_date");
    userData.lastLogin = ExtractJsonValue(jsonResponse, "last_login");
    userData.registeredAt = ExtractJsonValue(jsonResponse, "created_at");

    userData.hwid = GetSystemSid();
    userData.ipAddress = GetLocalIp();
}

void AuthlyX::LoadVariableData(const std::string& jsonResponse) {
    variableData.varKey = ExtractJsonValue(jsonResponse, "var_key");
    variableData.varValue = ExtractJsonValue(jsonResponse, "var_value");
    variableData.updatedAt = ExtractJsonValue(jsonResponse, "updated_at");
}

bool AuthlyX::Init() {
    std::map<std::string, std::string> payload = {
        {"owner_id", ownerId},
        {"app_name", appName},
        {"version", version},
        {"secret", secret}
    };

    std::string responseStr = PostJson("init", BuildJson(payload));
    if (responseStr.empty()) {
        return false;
    }

    ParseResponse(responseStr);

    if (response.success) {
        sessionId = ExtractJsonValue(responseStr, "session_id");
    }

    return response.success;
}

bool AuthlyX::Login(const std::string& username, const std::string& password) {
    std::map<std::string, std::string> payload = {
        {"session_id", sessionId},
        {"username", username},
        {"password", password},
        {"hwid", GetSystemSid()},
        {"ip", GetLocalIp()}
    };

    std::string responseStr = PostJson("login", BuildJson(payload));
    if (responseStr.empty()) {
        return false;
    }

    ParseResponse(responseStr);
    return response.success;
}

bool AuthlyX::Register(const std::string& username, const std::string& password,
    const std::string& key, const std::string& email) {
    std::map<std::string, std::string> payload = {
        {"session_id", sessionId},
        {"username", username},
        {"password", password},
        {"key", key},
        {"hwid", GetSystemSid()}
    };

    if (!email.empty()) {
        payload["email"] = email;
    }

    std::string responseStr = PostJson("register", BuildJson(payload));
    if (responseStr.empty()) {
        return false;
    }

    ParseResponse(responseStr);
    return response.success;
}

bool AuthlyX::LicenseLogin(const std::string& licenseKey) {
    std::map<std::string, std::string> payload = {
        {"session_id", sessionId},
        {"license_key", licenseKey},
        {"hwid", GetSystemSid()},
        {"ip", GetLocalIp()}
    };

    std::string responseStr = PostJson("licenses", BuildJson(payload));
    if (responseStr.empty()) {
        return false;
    }

    ParseResponse(responseStr);
    return response.success;
}

std::string AuthlyX::GetVariable(const std::string& varKey) {
    std::map<std::string, std::string> payload = {
        {"session_id", sessionId},
        {"var_key", varKey}
    };

    std::string responseStr = PostJson("variables", BuildJson(payload));
    if (responseStr.empty()) {
        return "";
    }

    ParseResponse(responseStr);
    return variableData.varValue;
}

bool AuthlyX::SetVariable(const std::string& varKey, const std::string& varValue) {
    std::map<std::string, std::string> payload = {
        {"session_id", sessionId},
        {"var_key", varKey},
        {"var_value", varValue}
    };

    std::string responseStr = PostJson("variables/set", BuildJson(payload));
    if (responseStr.empty()) {
        return false;
    }

    ParseResponse(responseStr);
    return response.success;
}