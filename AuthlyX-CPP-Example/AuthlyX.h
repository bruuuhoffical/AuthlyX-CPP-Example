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
            {"email", email},
            {"hwid", GetSystemSid()}
        };

        std::string responseStr = PostJson("register", BuildJson(payload));

        ParseResponse(responseStr);

        if (response.success) {
            sessionId = ExtractJsonValue(responseStr, "session_id");
        }

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

        ParseResponse(responseStr);

        return response.success;
    }

    std::string GetVariable(const std::string& varKey) {
        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"var_key", varKey}
        };

        std::string responseStr = PostJson("variables", BuildJson(payload));

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

        ParseResponse(responseStr);

        return response.success;
    }

    bool Log(const std::string& message) {
        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"message", message}
        };

        std::string responseStr = PostJson("logs", BuildJson(payload));

        ParseResponse(responseStr);

        return response.success;
    }

private:
    std::string BuildJson(const std::map<std::string, std::string>& data) {
        std::string json = "{";
        for (auto it = data.begin(); it != data.end(); ++it) {
            if (it != data.begin()) json += ",";
            json += "\"" + it->first + "\":\"" + it->second + "\"";
        }
        json += "}";
        return json;
    }

    std::string PostJson(const std::string& endpoint, const std::string& jsonPayload) {
        HINTERNET hSession = WinHttpOpen(L"AuthlyX", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return "";

        HINTERNET hConnect = WinHttpConnect(hSession, L"authly.cc", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return "";
        }

        std::wstring wideEndpoint = std::wstring(endpoint.begin(), endpoint.end());
        wideEndpoint = L"/api/v1/" + wideEndpoint;

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wideEndpoint.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "";
        }

        std::wstring headers = L"Content-Type: application/json\r\n";
        BOOL bResults = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.length(), (LPVOID)jsonPayload.c_str(), (DWORD)jsonPayload.length(), (DWORD)jsonPayload.length(), 0);

        if (bResults) bResults = WinHttpReceiveResponse(hRequest, NULL);

        std::string responseStr;
        if (bResults) {
            DWORD dwSize = 0;
            DWORD dwDownloaded = 0;
            do {
                dwSize = 0;
                WinHttpQueryDataAvailable(hRequest, &dwSize);
                if (!dwSize) break;

                char* pszOutBuffer = new char[dwSize + 1];
                if (!pszOutBuffer) break;

                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
                    responseStr += std::string(pszOutBuffer, dwDownloaded);
                }

                delete[] pszOutBuffer;
            } while (dwSize > 0);
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        return responseStr;
    }

    std::string GetSystemSid() {
        HANDLE hToken = NULL;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            return "UNKNOWN_SID";
        }

        DWORD dwSize = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
        PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);

        if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
            free(pTokenUser);
            CloseHandle(hToken);
            return "UNKNOWN_SID";
        }

        LPSTR sidStr = NULL;
        ConvertSidToStringSidA(pTokenUser->User.Sid, &sidStr);

        std::string sid(sidStr);
        LocalFree(sidStr);
        free(pTokenUser);
        CloseHandle(hToken);

        return sid;
    }

    std::string GetLocalIp() {
        ULONG ulOutBufLen = sizeof(MIB_IPADDRTABLE);
        PMIB_IPADDRTABLE pIPAddrTable = (PMIB_IPADDRTABLE)malloc(ulOutBufLen);

        DWORD dwRetVal = GetIpAddrTable(pIPAddrTable, &ulOutBufLen, 0);
        if (dwRetVal == NO_ERROR) {
            for (DWORD i = 0; i < pIPAddrTable->dwNumEntries; i++) {
                IN_ADDR IPAddr;
                IPAddr.S_un.S_addr = (u_long)pIPAddrTable->table[i].dwAddr;
                std::string ip(inet_ntoa(IPAddr));
                if (ip != "127.0.0.1" && ip != "0.0.0.0") {
                    free(pIPAddrTable);
                    return ip;
                }
            }
        }

        free(pIPAddrTable);
        return "UNKNOWN_IP";
    }

    std::string ExtractJsonValue(const std::string& json, const std::string& key) {
        std::string searchKey = "\"" + key + "\":\"";
        size_t pos = json.find(searchKey);
        if (pos == std::string::npos) {
            searchKey = "\"" + key + "\":";
            pos = json.find(searchKey);
            if (pos == std::string::npos) return "";
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