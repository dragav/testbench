#pragma once
class CertificateExplorer
{
public:
    CertificateExplorer();
    CertificateExplorer(wstring storeName, wstring storeLocation);

    virtual ~CertificateExplorer();

    bool UnlinkCertificate(wstring x5t);
    bool LinkCertificate(wstring x5tPred, wstring x5tSucc);

    // supported store types and locations
    static const std::wstring _CurrentUser;				// current user certificate store type name
    static const std::wstring _LocalMachine;			// local machine certificate store type name
    static const std::wstring _My;						// default certificate store name

private:
    HCERTSTORE	_store;				                // handle to currently opened certificate store
};

