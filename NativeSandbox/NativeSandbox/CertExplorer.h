#pragma once

namespace Certs
{
    class CertExplorer
    {
    public:
        static void Repro();

        static bool FindBySHA1TP(void* hStore, std::wstring const & sha1tp);
        static bool FindBySHA256TP(void* hStore, std::wstring const & sha2tp);
    };
};
