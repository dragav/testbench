#include "pch.h"
using namespace MemLeak;

static ULONG ToString(PSID pSid, __out std::wstring& stringSid)
{
    LPWSTR strOut;
    if (::ConvertSidToStringSid(pSid, &strOut))
    {
        stringSid = strOut;
        ::LocalFree(strOut);

        return S_OK;
    }

    return GetLastError();
}

bool MemLeakRepro::TryGetSidFromAccountName(LPCWSTR accountName, PSID *ppSid)
{
    PSID pSid = nullptr;
    DWORD cbSid = 0, cchRefDomain = 0, err = 0;
    SID_NAME_USE sidType;
    LPWSTR refDomain = nullptr;

    for (;;)
    {
        if (::LookupAccountName(nullptr, accountName, pSid, &cbSid, refDomain, &cchRefDomain, &sidType))
        {
            *ppSid = pSid;
            err = 0;
            break;
        }

        err = ::GetLastError();
        if (err != ERROR_INSUFFICIENT_BUFFER)
        {
            std::cout << "Failed to look up sid for account " << accountName << ": " << err;

            break;
        }

        if (nullptr == pSid)
        {
            pSid = (PSID)LocalAlloc(0, cbSid);
        }
        if (nullptr == pSid)
        {
            err = ::GetLastError();
            std::cout << "Failed to allocate sid buffer for account " << accountName << ": " << err;

            break;
        }

        if (nullptr == refDomain)
        {
            refDomain = (LPWSTR)::LocalAlloc(0, cchRefDomain * sizeof(TCHAR));
        }
        if (nullptr == refDomain)
        {
            err = ::GetLastError();
            std::cout << "Failed to allocate sid buffer for account " << accountName << ": " << err;

            break;
        }
    }

    if (0 != err)
    {
        ::LocalFree(pSid);
        ::LocalFree(refDomain);
    }

    return (0 == err);
}

bool MemLeakRepro::TryGetAccountNameFromSid(PSID pSid, std::wstring & domainName, std::wstring & accountName)
{
    SID_NAME_USE SidType;
    wchar_t lpUserName[MAX_PATH];
    wchar_t lpDomainName[MAX_PATH];
    DWORD dwSize = MAX_PATH;

    if (!::LookupAccountSidW(NULL, pSid, lpUserName, &dwSize, lpDomainName, &dwSize, &SidType))
    {
        DWORD const nStatus = ::GetLastError();

        std::wstring sidStr(L"(unresolved)");

        std::cout << "LookupAccountSidW for " << ToString(pSid, sidStr) << "failed; error=" << nStatus;

        return false;
    }

    domainName = std::wstring(lpDomainName);
    accountName = std::wstring(lpUserName);

    return true;

}

void MemLeakRepro::StressNegative(int reps) 
{
    LPCWSTR inexistentSidStr = L"S-1-5-21-3041475985-1200338336-1568193219-1023";
    LPCWSTR existingAccountName = L"WF-XNve0thtzpXUKTQ";

    PSID existingAccountSid = nullptr;
    if (!TryGetSidFromAccountName(existingAccountName, &existingAccountSid))
    { 
        ::LocalFree(existingAccountSid);

        return;
    }

    for (int idx = 0; idx < reps; idx++)
    {
        PSID pSid = nullptr;
        if (!::ConvertStringSidToSid(inexistentSidStr, &pSid))
        {
            std::cout << "failed to create a Sid from the sample Sid string";
            continue;
        }

        std::wstring domainName;
        std::wstring accountName;
        TryGetAccountNameFromSid(pSid, domainName, accountName);

        ::LocalFree(pSid);
        pSid = nullptr;

    }
}

void MemLeakRepro::StressPositive(int reps)
{
    LPCWSTR existingAccountName = L"WF-XNve0thtzpXUKTQ";
    LPWSTR existingAccountStringSid = nullptr;
    PSID existingAccountSid = nullptr;
    DWORD err = 0;

    for (;;)
    {
        if (!TryGetSidFromAccountName(existingAccountName, &existingAccountSid))
        {
            err = ::GetLastError();
            std::cout << "failed to get sid from account " << existingAccountName << ": " << err;
            break;
        }

        if (!::ConvertSidToStringSid(existingAccountSid, &existingAccountStringSid))
        {
            err = ::GetLastError();
            std::cout << "failed to get sid from sid string for account " << existingAccountName << ": " << err;
            break;
        }

        for (int idx = 0; idx < reps; idx++)
        {
            PSID pSid = nullptr;
            if (!::ConvertStringSidToSid(existingAccountStringSid, &pSid))
            {
                std::cout << "failed to create a Sid from the sample Sid string";
                continue;
            }

            std::wstring domainName;
            std::wstring accountName;
            TryGetAccountNameFromSid(pSid, domainName, accountName);

            ::LocalFree(pSid);
            pSid = nullptr;
        }
    }

    ::LocalFree(existingAccountSid);
    ::LocalFree((HLOCAL)existingAccountStringSid);
}

void MemLeakRepro::Repro()
{
    const int reps = 200;
    std::cout << "running for " << reps << " repetitions";
    StressPositive(reps);
    StressNegative(reps);
}