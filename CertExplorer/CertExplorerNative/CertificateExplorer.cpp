#include "stdafx.h"
#include "CertificateExplorer.h"

const string_t CertificateExplorer::_LocalMachine(__T("LocalMachine"));
const string_t CertificateExplorer::_CurrentUser(__T("CurrentUser"));
const string_t CertificateExplorer::_My(__T("MY"));

CertificateExplorer::CertificateExplorer()
    :CertificateExplorer(_My, _CurrentUser)
{
}


CertificateExplorer::CertificateExplorer(std::basic_string name, std::basic_string location)
{
    if (_store != nullptr)
    {
        sprintf(__T("attempting to open an already initialized store."));

        throw std::runtime_error("attempt to overwrite an opened store");
    }

    DWORD flags = CERT_STORE_OPEN_EXISTING_FLAG;

    if (_CurrentUser.compare(location) == 0)
    {
        sprintf(__T("opening the 'CurrentUser' store.."));

        flags |= CERT_SYSTEM_STORE_CURRENT_USER;
    }
    else if (_LocalMachine.compare(location) == 0)
    {
        sprintf(__T("opening the 'LocalMachine' store.."));

        flags |= CERT_SYSTEM_STORE_LOCAL_MACHINE;
    }
    else
    {
        sprintf(__T("invalid store location."));

        throw invalid_argument("location");
    }

    if (!_store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,			// the store provider type
        0,                              // the encoding type is not needed
        NULL,                           // use the default HCRYPTPROV
        flags,							// store location flags
        name.c_str())))					// store name
    {
        // failed to open the store; bail
        DWORD dwError = ::GetLastError();
        stdprintf("failed to open the store with: %d", dwError);

        throw std::system_error(dwError, std::system_category());
    }
}


CertificateExplorer::~CertificateExplorer()
{
    if (_store == nullptr)
    {
        sprintf(__T("attempting to close an unopened store"));
        throw std::runtime_error("attempt to close an unopened store");
    }

    if (!::CertCloseStore(_store, 0))
    {
        DWORD dwError = ::GetLastError();
        sprintf(__T("attempting to close store failed with: %d"), dwError);

        throw std::system_error(dwError, std::system_category());
    }

    _store = nullptr;
}
