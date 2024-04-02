#include "pch.h"
#include <windows.h>
#include <stdio.h>
#include <Wincrypt.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <codecvt>
#pragma comment(lib, "crypt32.lib")

using namespace std;
using namespace Certs;

static std::wstring wstring_convert_from_bytes(const std::vector<unsigned char>& v)
{
    wstringstream tpStream;
    for (DWORD i = 0; i < v.size(); ++i)
    {
        unsigned long byteToWrite = v[i];
        tpStream << std::hex << std::setw(2) << std::setfill(L'0') << byteToWrite;
    }

    return tpStream.str();
}

static std::vector<char> wstring_convert_to_bytes(const std::wstring& wstr)
{
    std::wstring_convert<std::codecvt_utf16<wchar_t>, wchar_t> converter;
    std::string string = converter.to_bytes(wstr);

    return std::vector<char>(string.begin(), string.end());
}

bool CertExplorer::FindBySHA256TP(HCERTSTORE store, wstring const & tp)
{
    PCCERT_CONTEXT hCert = nullptr;
    DWORD cbData = 0;
    bool found = false;

    hCert = ::CertFindCertificateInStore(
        store, 
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
        0, 
        CERT_FIND_ANY, 
        nullptr, 
        nullptr);
    for (; hCert != nullptr; )
    {
        // retrieve SHA-256 property
        if (::CertGetCertificateContextProperty(hCert, CERT_SHA256_HASH_PROP_ID, nullptr, &cbData)
            || ERROR_MORE_DATA == GetLastError())
        {
            std::vector<BYTE> sha256HashBytes(cbData);
            if (::CertGetCertificateContextProperty(hCert, CERT_SHA256_HASH_PROP_ID, sha256HashBytes.data(), &cbData))
            {
                auto thisTP = wstring_convert_from_bytes(sha256HashBytes);
                found = tp == thisTP;
                if (found) break;
            }
        }

        hCert = ::CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY, nullptr, hCert);
    } 

    std::cout << "match" << (found ? " " : " not ") << "found";
    if (found)
    {
        if (hCert
            && hCert->pCertInfo
            && hCert->pCertInfo->SerialNumber.cbData)
        {
            auto cb = hCert->pCertInfo->SerialNumber.cbData;
            std::vector<BYTE> bytes;
            bytes.resize(cb);
            // write in reverse; lsb is at index 0
            for (unsigned int idx = 0; idx < cb; idx++)
                bytes[cb-idx-1] = *(hCert->pCertInfo->SerialNumber.pbData + idx);
            auto sn = wstring_convert_from_bytes(bytes);
            std::wcout << L"; serial: " << sn.c_str() << L"\n";
        }
    }
    ::CertFreeCertificateContext(hCert);
    hCert = nullptr;

    return found;
}

bool CertExplorer::FindBySHA1TP(HCERTSTORE store, wstring const & tp)
{
    throw new exception();
}

void CertExplorer::Repro()
{
    //--------------------------------------------------------------------
    // Declare and initialize variables.
    HANDLE          hStoreHandle = NULL;
    PCCERT_CONTEXT  pCertContext = NULL;
    const wchar_t* pszStoreName = L"my";
    int             countCerts = 0;

    auto sha1tp = L"4c1c6bfc2911b3973feead8a8ee0e3a4e35f582a";
    auto sha2tp = L"842512e1d1c33dcebc0d3a67176c10b94f67a3dcd9d1b92056c5d967f84583bf";

    //--------------------------------------------------------------------
    // Open a system certificate store.
    if (hStoreHandle = ::CertOpenSystemStore(
        NULL,
        pszStoreName))
    {
        wprintf(L"The %s store has been opened. \n", pszStoreName);
    }
    else
    {
        wprintf(L"The store was not opened.\n");
        exit(1);
    }

    auto res = FindBySHA256TP(hStoreHandle, sha2tp);

    //-------------------------------------------------------------------
    // Find the certificates in the system store. 
    PCCERT_CONTEXT pcCertContext = nullptr;
    for (pcCertContext = ::CertEnumCertificatesInStore(hStoreHandle, pcCertContext);
        nullptr != pcCertContext;
        pcCertContext = ::CertEnumCertificatesInStore(hStoreHandle, pcCertContext))
                        // on the first call to the function,
                       // this parameter is NULL 
                       // on all subsequent calls, 
                       // this parameter is the last pointer 
                       // returned by the function
    {
        countCerts++;
        wprintf(L"++\n");
    } // End of while.

    //--------------------------------------------------------------------
    //   Clean up.
    if (!::CertCloseStore(
        hStoreHandle,
        0))
    {
        wprintf(L"Failed CertCloseStore\n");
        exit(1);
    }
}
