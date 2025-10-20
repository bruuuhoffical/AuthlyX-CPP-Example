#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <sddl.h>
#include <iphlpapi.h>
#include <string>
#include <map>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")

class AuthlyX {
private:
    std::string baseUrl = "https://authly.cc/api/v1";
    std::string sessionId;
    std::string ownerId;
    std::string appName;
    std::string version;
    std::string secret;

public:
    struct Response {
        bool success = false;
        std::string message;
        std::string raw;
    };

    struct UserData {
        std::string username;
        std::string email;
        std::string licenseKey;
        std::string subscription;
        std::string expiryDate;
        std::string lastLogin;
        std::string hwid;
        std::string ipAddress;
        std::string registeredAt;
    };

    struct VariableData {
        std::string varKey;
        std::string varValue;
        std::string updatedAt;
    };

    Response response;
    UserData userData;
    VariableData variableData;

    std::string GetSessionId() const { return sessionId; }

    AuthlyX(const std::string& ownerId, const std::string& appName,
        const std::string& version, const std::string& secret)
        : ownerId(ownerId), appName(appName), version(version), secret(secret) {
    }

    bool Init() {
        std::map<std::string, std::string> payload = {
            {"owner_id", ownerId},
            {"app_name", appName},
            {"version", version},
            {"secret", secret}
        };

        std::string responseStr = PostJson("init", BuildJson(payload));

        if (responseStr.empty()) {
            response.message = "Connection failed - check internet connection";
            return false;
        }

        ParseResponse(responseStr);

        if (response.success) {
            sessionId = ExtractJsonValue(responseStr, "session_id");
        }

        return response.success;
    }

    bool Login(const std::string& username, const std::string& password) {
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

    bool Register(const std::string& username, const std::string& password,
        const std::string& key, const std::string& email = "") {
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

    bool LicenseLogin(const std::string& licenseKey) {
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

    std::string GetVariable(const std::string& varKey) {
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

    bool SetVariable(const std::string& varKey, const std::string& varValue) {
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

private:
    std::string PostJson(const std::string& endpoint, const std::string& json) {
        HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
        std::string response;

        hSession = WinHttpOpen(L"AuthlyX Client",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) {
            this->response.message = "Network initialization failed";
            return "";
        }

        hConnect = WinHttpConnect(hSession, L"authly.cc",
            INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            this->response.message = "Cannot connect to authentication server";
            return "";
        }

        std::wstring wpath = L"/api/v1/" + std::wstring(endpoint.begin(), endpoint.end());
        hRequest = WinHttpOpenRequest(hConnect, L"POST", wpath.c_str(),
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            this->response.message = "Failed to create secure connection";
            return "";
        }

        LPCWSTR headers = L"Content-Type: application/json; charset=utf-8";
        WinHttpAddRequestHeaders(hRequest, headers, (DWORD)wcslen(headers),
            WINHTTP_ADDREQ_FLAG_ADD);


        std::string utf8Json = json;
        DWORD jsonLength = (DWORD)utf8Json.length();

        BOOL sendResult = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            (LPVOID)utf8Json.c_str(),
            jsonLength,
            jsonLength, 0);

        if (sendResult) {
            WinHttpReceiveResponse(hRequest, NULL);

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

        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        return response;
    }

    std::string BuildJson(const std::map<std::string, std::string>& data) {
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

    std::string EscapeJsonString(const std::string& str) {
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
            default:
                if (static_cast<unsigned char>(c) < 32) {
                    char buf[7];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    result += buf;
                }
                else {
                    result += c;
                }
                break;
            }
        }
        return result;
    }

    std::string GetSystemSid() {
        HANDLE hToken = NULL;
        DWORD length = 0;
        std::string sidStr = "UNKNOWN_SID";

        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            GetTokenInformation(hToken, TokenUser, NULL, 0, &length);

            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                std::vector<BYTE> buffer(length);
                if (GetTokenInformation(hToken, TokenUser, buffer.data(), length, &length)) {
                    PTOKEN_USER pTokenUser = (PTOKEN_USER)buffer.data();
                    LPSTR str = NULL;
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

    std::string GetLocalIp() {
        std::string ip = "UNKNOWN_IP";
        HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

        hSession = WinHttpOpen(L"IP Checker",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return ip;

        hConnect = WinHttpConnect(hSession, L"api.ipify.org",
            INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return ip;
        }

        hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/",
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return ip;
        }

        if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            WinHttpReceiveResponse(hRequest, NULL);

            DWORD size = 0;
            std::vector<char> buffer(4096);
            DWORD downloaded = 0;

            if (WinHttpReadData(hRequest, buffer.data(), buffer.size() - 1, &downloaded)) {
                if (downloaded > 0) {
                    buffer[downloaded] = '\0';
                    ip = buffer.data();
                }
            }
        }

        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        return ip;
    }

    std::string ExtractJsonValue(const std::string& json, const std::string& key) {
        std::string searchKey = "\"" + key + "\":\"";
        size_t pos = json.find(searchKey);
        if (pos == std::string::npos) {
            searchKey = "\"" + key + "\":";
            pos = json.find(searchKey);
            if (pos == std::string::npos) return "";

            size_t start = pos + searchKey.length();
            size_t end = json.find_first_of(",}", start);
            if (end == std::string::npos) return "";

            std::string value = json.substr(start, end - start);
            if (value.length() >= 2 && value[0] == '"' && value[value.length() - 1] == '"') {
                value = value.substr(1, value.length() - 2);
            }
            return value;
        }

        size_t start = pos + searchKey.length();
        size_t end = json.find('"', start);
        if (end == std::string::npos) return "";

        return json.substr(start, end - start);
    }

    void ParseResponse(const std::string& jsonResponse) {
        response.raw = jsonResponse;

        if (jsonResponse.find("<!DOCTYPE html>") != std::string::npos ||
            jsonResponse.find("<html>") != std::string::npos) {
            response.success = false;
            response.message = "Server error - please try again later";
            return;
        }

        std::string successStr = ExtractJsonValue(jsonResponse, "success");
        response.success = (successStr == "true");

        response.message = ExtractJsonValue(jsonResponse, "message");

        LoadUserData(jsonResponse);
        LoadVariableData(jsonResponse);
    }

    void LoadUserData(const std::string& jsonResponse) {
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

    void LoadVariableData(const std::string& jsonResponse) {
        variableData.varKey = ExtractJsonValue(jsonResponse, "var_key");
        variableData.varValue = ExtractJsonValue(jsonResponse, "var_value");
        variableData.updatedAt = ExtractJsonValue(jsonResponse, "updated_at");
    }
};