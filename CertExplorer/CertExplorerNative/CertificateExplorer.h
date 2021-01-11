#pragma once
class CertificateExplorer
{
public:
    CertificateExplorer();
    CertificateExplorer(string storeName, string storeLocation);

    virtual ~CertificateExplorer();

    bool UnlinkCertificate(string x5t);
    bool LinkCertificate(string x5tPred, string x5tSucc);

    // supported store types and locations
    static const string_t _CurrentUser;				// current user certificate store type name
    static const string_t _LocalMachine;			// local machine certificate store type name
    static const string_t _My;						// default certificate store name

private:
    HCERTSTORE	_store;				                // handle to currently opened certificate store
};

