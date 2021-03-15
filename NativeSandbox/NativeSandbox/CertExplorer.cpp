#include "pch.h"
#include <windows.h>
#include <stdio.h>
#include <Wincrypt.h>
#pragma comment(lib, "crypt32.lib")

using namespace Certs;

void CertExplorer::Repro()
{
    //--------------------------------------------------------------------
    // Declare and initialize variables.
    HANDLE          hStoreHandle = NULL;
    PCCERT_CONTEXT  pCertContext = NULL;
    const wchar_t* pszStoreName = L"ca";
    int             countCerts = 0;

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
