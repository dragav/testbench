#pragma once
namespace MemLeak
{
    class MemLeakRepro
    {
    public:
        static bool TryGetSidFromAccountName(LPCWSTR accountName, PSID *ppSid);
        static bool TryGetAccountNameFromSid(PSID accountSid, std::wstring& domainName, std::wstring& accountName);
        static void StressPositive(int reps);
        static void StressNegative(int reps);

        static void Repro();
    };
}