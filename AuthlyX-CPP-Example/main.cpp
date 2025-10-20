#include <iostream>
#include <string>
#include <conio.h> 
#include <windows.h> 
#include "AuthlyX.h"

void SetConsoleColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}   

void ResetConsoleColor() {
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

std::string ReadPassword() {
    std::string password;
    char ch;

    while ((ch = _getch()) != '\r') {
        if (ch == '\b') {
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";
            }
        }
        else {
            password.push_back(ch);
            std::cout << '*';
        }
    }
    std::cout << std::endl;
    return password;
}
void DisplayResult(const std::string& operation, const AuthlyX::Response& response) {
    std::cout << "\n" << std::string(30, '-') << std::endl;
    if (response.success) {
        SetConsoleColor(FOREGROUND_GREEN);
        std::cout << "✓ " << operation << " SUCCESS" << std::endl;
        ResetConsoleColor();
        std::cout << "Message: " << response.message << std::endl;
    }
    else {
        SetConsoleColor(FOREGROUND_RED);
        std::cout << "✗ " << operation << " FAILED" << std::endl;
        ResetConsoleColor();
        std::cout << "Message: " << response.message << std::endl;
    }
    std::cout << std::string(30, '-') << std::endl;
}

void DisplayUserInfo(const AuthlyX::UserData& user) {
    std::cout << "\n" << std::string(50, '=') << std::endl;
    SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_GREEN);
    std::cout << "USER PROFILE" << std::endl;
    ResetConsoleColor();
    std::cout << std::string(50, '=') << std::endl;

    std::cout << "Username: " << (user.username.empty() ? "N/A" : user.username) << std::endl;
    std::cout << "Email: " << (user.email.empty() ? "N/A" : user.email) << std::endl;
    std::cout << "License Key: " << (user.licenseKey.empty() ? "N/A" : user.licenseKey) << std::endl;
    std::cout << "Subscription: " << (user.subscription.empty() ? "N/A" : user.subscription) << std::endl;
    std::cout << "Expiry Date: " << (user.expiryDate.empty() ? "N/A" : user.expiryDate) << std::endl;
    std::cout << "Last Login: " << (user.lastLogin.empty() ? "N/A" : user.lastLogin) << std::endl;
    std::cout << "Registered: " << (user.registeredAt.empty() ? "N/A" : user.registeredAt) << std::endl;
    std::cout << "HWID: " << (user.hwid.empty() ? "N/A" : user.hwid) << std::endl;
    std::cout << "IP Address: " << (user.ipAddress.empty() ? "N/A" : user.ipAddress) << std::endl;
    std::cout << std::string(50, '=') << std::endl;
}


void ShowMainMenu() {
    std::cout << "\n" << std::string(50, '=') << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN);
    std::cout << "MAIN MENU - Choose an option:" << std::endl;
    ResetConsoleColor();
    std::cout << "1. Login (Username + Password)" << std::endl;
    std::cout << "2. Register New Account" << std::endl;
    std::cout << "3. License Login (License Key Only)" << std::endl;
    std::cout << "4. Variable Operations" << std::endl;
    std::cout << "5. View User Information" << std::endl;
    std::cout << "6. Test All Features" << std::endl;
    std::cout << "0. Exit" << std::endl;
    std::cout << std::string(50, '=') << std::endl;
    std::cout << "Your choice: ";
}

void TestLogin(AuthlyX& authly) {
    std::cout << "\n" << std::string(40, '-') << std::endl;
    SetConsoleColor(FOREGROUND_BLUE);
    std::cout << "LOGIN TEST" << std::endl;
    ResetConsoleColor();

    std::cout << "Enter Username: ";
    std::string username;
    std::getline(std::cin, username);

    std::cout << "Enter Password: ";
    std::string password = ReadPassword();

    std::cout << "\nAuthenticating..." << std::endl;
    if (authly.Login(username, password)) {
        DisplayResult("Login", authly.response);
    }
    else {
        DisplayResult("Login", authly.response);
    }
}

void TestRegister(AuthlyX& authly) {
    std::cout << "\n" << std::string(40, '-') << std::endl;
    SetConsoleColor(FOREGROUND_BLUE);
    std::cout << "REGISTRATION TEST" << std::endl;
    ResetConsoleColor();

    std::cout << "Enter Username: ";
    std::string username;
    std::getline(std::cin, username);

    std::cout << "Enter Password: ";
    std::string password = ReadPassword();

    std::cout << "Enter License Key: ";
    std::string licenseKey;
    std::getline(std::cin, licenseKey);

    std::cout << "Enter Email (optional): ";
    std::string email;
    std::getline(std::cin, email);

    if (email.empty()) {
        email = "";
    }

    std::cout << "\nRegistering account..." << std::endl;
    if (authly.Register(username, password, licenseKey, email)) {
        DisplayResult("Registration", authly.response);
    }
    else {
        DisplayResult("Registration", authly.response);
    }
}

void TestLicenseLogin(AuthlyX& authly) {
    std::cout << "\n" << std::string(40, '-') << std::endl;
    SetConsoleColor(FOREGROUND_BLUE);
    std::cout << "LICENSE LOGIN TEST" << std::endl;
    ResetConsoleColor();

    std::cout << "Enter License Key: ";
    std::string licenseKey;
    std::getline(std::cin, licenseKey);

    std::cout << "\nAuthenticating with license..." << std::endl;
    if (authly.LicenseLogin(licenseKey)) {
        DisplayResult("License Login", authly.response);
    }
    else {
        DisplayResult("License Login", authly.response);
    }
}

void TestVariables(AuthlyX& authly) {
    std::cout << "\n" << std::string(40, '-') << std::endl;
    SetConsoleColor(FOREGROUND_BLUE);
    std::cout << "VARIABLE OPERATIONS" << std::endl;
    ResetConsoleColor();

    std::cout << "1. Get Variable" << std::endl;
    std::cout << "2. Set Variable" << std::endl;
    std::cout << "Choose operation: ";

    std::string choice;
    std::getline(std::cin, choice);

    if (choice == "1") {
        std::cout << "Enter Variable Key: ";
        std::string varKey;
        std::getline(std::cin, varKey);

        std::cout << "\nFetching variable..." << std::endl;
        std::string value = authly.GetVariable(varKey);

        if (authly.response.success) {
            SetConsoleColor(FOREGROUND_GREEN);
            std::cout << "Variable '" << varKey << "': " << value << std::endl;
            ResetConsoleColor();
        }
        else {
            DisplayResult("Get Variable", authly.response);
        }
    }
    else if (choice == "2") {
        std::cout << "Enter Variable Key: ";
        std::string varKey;
        std::getline(std::cin, varKey);

        std::cout << "Enter Variable Value: ";
        std::string varValue;
        std::getline(std::cin, varValue);

        std::cout << "\nSetting variable..." << std::endl;
        if (authly.SetVariable(varKey, varValue)) {
            DisplayResult("Set Variable", authly.response);
        }
        else {
            DisplayResult("Set Variable", authly.response);
        }
    }
    else {
        SetConsoleColor(FOREGROUND_RED);
        std::cout << "Invalid choice for variable operation." << std::endl;
        ResetConsoleColor();
    }
}

void TestAllFeatures(AuthlyX& authly) {
    std::cout << "\n" << std::string(40, '-') << std::endl;
    SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_RED); 
    std::cout << "COMPREHENSIVE FEATURE TEST" << std::endl;
    ResetConsoleColor();

    std::cout << "\n1. Testing Login..." << std::endl;
    std::cout << "Enter test username: ";
    std::string username;
    std::getline(std::cin, username);

    std::cout << "Enter test password: ";
    std::string password = ReadPassword();

    if (authly.Login(username, password)) {
        DisplayResult("Login", authly.response);

        std::cout << "\n2. Testing Variable Operations..." << std::endl;
        std::string testKey = "test_variable";

        SYSTEMTIME st;
        GetLocalTime(&st);
        std::string testValue = "test_value_" +
            std::to_string(st.wHour) +
            std::to_string(st.wMinute) +
            std::to_string(st.wSecond);

        if (authly.SetVariable(testKey, testValue)) {
            DisplayResult("Set Variable", authly.response);

            if (authly.response.success) {
                std::string retrievedValue = authly.GetVariable(testKey);
                DisplayResult("Get Variable", authly.response);

                if (authly.response.success) {
                    std::cout << "Retrieved value: " << retrievedValue << std::endl;
                }
            }
        }

        std::cout << "\n3. Final User Information:" << std::endl;
        DisplayUserInfo(authly.userData);
    }
    else {
        DisplayResult("Login", authly.response);
    }
}

int main() {
    SetConsoleTitleA("AuthlyX Client");

    SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_GREEN);
    std::cout << "╔══════════════════════════════════════╗" << std::endl;
    std::cout << "║           AUTHLYX C++ CLIENT         ║" << std::endl;
    std::cout << "║            Official Version          ║" << std::endl;
    std::cout << "╚══════════════════════════════════════╝" << std::endl;
    ResetConsoleColor();

    std::cout << "\nConnecting to AuthlyX..." << std::endl;

    AuthlyX AuthlyXApp(
        "469e4d9235d1",
        "BASIC",
        "1.0.0",
        "iqcmyagw1skGdgk6Nq7OxxpX5iAmC2Hlwq7iNwyG"
    );

    if (!AuthlyXApp.Init()) {
        SetConsoleColor(FOREGROUND_RED);
        std::cout << "Connection Failed: " << AuthlyXApp.response.message << std::endl;
        ResetConsoleColor();
        std::cout << "Press any key to exit...";
        std::cin.get();
        return 1;
    }

    SetConsoleColor(FOREGROUND_GREEN);
    std::cout << "✓ Connected Successfully!" << std::endl;
    ResetConsoleColor();

    bool running = true;
    while (running) {
        ShowMainMenu();
        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "1") {
            TestLogin(AuthlyXApp);
        }
        else if (choice == "2") {
            TestRegister(AuthlyXApp);
        }
        else if (choice == "3") {
            TestLicenseLogin(AuthlyXApp);
        }
        else if (choice == "4") {
            TestVariables(AuthlyXApp);
        }
        else if (choice == "5") {
            std::cout << "\n" << std::string(40, '-') << std::endl;
            SetConsoleColor(FOREGROUND_BLUE);
            std::cout << "USER INFORMATION" << std::endl;
            ResetConsoleColor();

            if (AuthlyXApp.userData.username.empty() && AuthlyXApp.userData.licenseKey.empty()) {
                SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN);
                std::cout << "No active session. Please login first." << std::endl;
                ResetConsoleColor();
            }
            else {
                DisplayUserInfo(AuthlyXApp.userData);
            }
        }
        else if (choice == "6") {
            TestAllFeatures(AuthlyXApp);
        }
        else if (choice == "0") {
            running = false;
            std::cout << "Thank you for using AuthlyX!" << std::endl;
        }
        else {
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN);
            std::cout << "Invalid choice. Please try again." << std::endl;
            ResetConsoleColor();
        }

        if (running && choice != "0") {
            std::cout << "\nPress any key to continue...";
            std::cin.get();
            system("cls");
        }
    }

    return 0;
}