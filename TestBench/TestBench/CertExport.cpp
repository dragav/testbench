#include "pch.h"

using namespace std;

const wstring CertExport::_exportableCertTP = L"c2 a9 2d d7 76 40 04 bc 90 6b 87 97 4f 41 86 e5 f9 06 41 12";
LPCSTR CertExport::_exportableCertCN = "CN=kvvmxttest.keyvault.security.ce.azure-int.net";
const wstring CertExport::_headerBeginCert = L"-----BEGIN CERTIFICATE-----";
const wstring CertExport::_headerEndCert = L"-----END CERTIFICATE-----";
const wstring CertExport::_headerBeginKey = L"-----BEGIN PRIVATE KEY-----";
const wstring CertExport::_headerEndKey = L"-----END PRIVATE KEY-----";

vector<BYTE> CertExport::HashStringToBytes(wstring hashStr)
{
    wstringstream stringStream(hashStr);
    vector<BYTE> hashBytes;

    while (!stringStream.eof())
    {
        unsigned int hashByte;
        stringStream >> std::hex >> hashByte;
        hashBytes.push_back(static_cast<byte>(hashByte));
    }

    return hashBytes;
}

PCCERT_CONTEXT CertExport::FindCertInCUStore(wstring tp)
{
    HCERTSTORE hSysStore = NULL;
    if (hSysStore = ::CertOpenStore(
        CERT_STORE_PROV_SYSTEM,          // The store provider type
        0,                               // The encoding type is
                                         // not needed
        NULL,                            // Use the default HCRYPTPROV
        CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
                                         // registry location
        L"MY"                            // The store name as a Unicode 
                                         // string
    ))
    {
        printf("The system store was created successfully.\n");
    }
    else
    {
        printf("An error occurred during creation "
            "of the system store!\n");
        exit(1);
    }

    PCCERT_CONTEXT pcCertContext = nullptr;
    DWORD dwError = 0;

    auto tpBytes = HashStringToBytes(tp);

    CRYPT_HASH_BLOB findValue = { 0 };
    findValue.cbData = tpBytes.size();
    findValue.pbData = tpBytes.data();

    pcCertContext = ::CertFindCertificateInStore(hSysStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &findValue, nullptr);
    if (!pcCertContext)
    {
        dwError = ::GetLastError();
        wprintf(L"failed to find a matching cert for %s: 0x%x..\n", tp.c_str(), dwError);
    }

    if (CertCloseStore(
        hSysStore,
        CERT_CLOSE_STORE_CHECK_FLAG))
    {
        printf("The system store was closed successfully.\n");
    }
    else
    {
        printf("An error occurred during closing of the "
            "system store.\n");
    }

    return pcCertContext;
}

void CertExport::ExportPfxToPem(wstring tp)
{
    PCCERT_CONTEXT pcCertContext = FindCertInCUStore(tp);
    if (nullptr == pcCertContext)
    {
        return;
    }

    HCERTSTORE hTempStore = nullptr;
    DWORD dwError = 0;
    DWORD dwFlags = 0;
    DWORD cbData = 0;
    PCCERT_CONTEXT pcCloneContext = nullptr;
    BYTE* pbCryptData = nullptr;
    do
    {
        hTempStore = ::CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NULL, 0, nullptr);
        if (NULL == hTempStore)
        {
            dwError = ::GetLastError();
            printf("failed to open mem cert store: 0x%x..\n", dwError);
            continue;
        }

        if (!::CertAddCertificateContextToStore(hTempStore, pcCertContext, CERT_STORE_ADD_ALWAYS, &pcCloneContext))
        {
            dwError = ::GetLastError();
            printf("failed to add cert to mem cert store: 0x%x..\n", dwError);
            continue;
        }

        CRYPT_DATA_BLOB dataBlob = { 0 };
        if (!::PFXExportCertStoreEx(hTempStore, &dataBlob, nullptr, nullptr, EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY | PKCS12_INCLUDE_EXTENDED_PROPERTIES))
        {
            dwError = ::GetLastError();
            printf("failed to export cert from mem store: 0x%x..\n", dwError);
            continue;
        }

        pbCryptData = (BYTE*)::malloc(dataBlob.cbData);
        dataBlob.pbData = pbCryptData;
        if (!::PFXExportCertStoreEx(hTempStore, &dataBlob, nullptr, nullptr, EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY | PKCS12_INCLUDE_EXTENDED_PROPERTIES))
        {
            dwError = ::GetLastError();
            printf("failed to export cert from mem store: 0x%x..\n", dwError);
            continue;
        }

    } while (false);

    ::free(pbCryptData);
    ::CertCloseStore(hTempStore, CERT_CLOSE_STORE_CHECK_FLAG);
}

void CertExport::ExportPfxToPemOldApi(wstring tp, string fileName)
{
    PCCERT_CONTEXT pcCertContext = FindCertInCUStore(tp);
    if (nullptr == pcCertContext)
    {
        return;
    }

    DWORD cbData = 0;
    DWORD dwError = 0;
    void* pbData = nullptr;
    HCRYPTPROV hCryptProv = NULL;        // handle for a cryptographic provider context
    BYTE* pCryptBlob = nullptr;
    BYTE* pbPkcs8Blob = nullptr;
    HCRYPTKEY hKey = NULL;
    BYTE* pbEncodedData = nullptr;
    LPSTR pszBase64EncodedPkcs8Key = NULL;

    do 
    {
        // check the existence and exportability of the private key
        if (!::CertGetCertificateContextProperty(pcCertContext, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &cbData))
        {
            dwError = ::GetLastError();
            printf("failed to retrieve key info: 0x%x..\n", dwError);
            continue;
        }

        pbData = ::malloc(cbData);
        if (!::CertGetCertificateContextProperty(pcCertContext, CERT_KEY_PROV_INFO_PROP_ID, pbData, &cbData)
            || !pbData)
        {
            dwError = ::GetLastError();
            printf("failed to retrieve key info: 0x%x..\n", dwError);
            continue;
        }

        CRYPT_KEY_PROV_INFO* keyProvInfo = (CRYPT_KEY_PROV_INFO*)pbData;
        if (keyProvInfo->dwProvType == 0)
        {
            // skip, CNG key
            printf("skipping CNG cert.\n");
            ::free(pbData);
            pbData = nullptr;
            continue;
        }

        // create crypt provider
        if (!::CryptAcquireContext(&hCryptProv, keyProvInfo->pwszContainerName, keyProvInfo->pwszProvName, keyProvInfo->dwProvType, keyProvInfo->dwFlags))
        {
            dwError = ::GetLastError();
            printf("failed to acquire context: 0x%x..\n", dwError);
            continue;
        }

        // get the key
        if (!::CryptGetUserKey(hCryptProv, AT_KEYEXCHANGE, &hKey))
        {
            dwError = ::GetLastError();
            printf("failed to get user key: 0x%x..\n", dwError);
            continue;
        }

        // export public key
        DWORD cbPubInfo = 0;
        CERT_PUBLIC_KEY_INFO* ppubKeyInfo = nullptr;
        //pubKeyInfo.Algorithm.pszObjId = (LPSTR)szOID_PKCS_8;
        //pubKeyInfo.Algorithm.Parameters = { 0 };
        //pubKeyInfo.PublicKey = { 0 };
        if (!::CryptExportPublicKeyInfoEx(hCryptProv, AT_KEYEXCHANGE, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, (LPSTR)szOID_PKCS_8, 0, nullptr, nullptr, &cbPubInfo))
        {
            dwError = ::GetLastError();
            printf("failed to export public key: 0x%x..\n", dwError);
            continue;
        }

        ppubKeyInfo = (CERT_PUBLIC_KEY_INFO*)::malloc(cbPubInfo);
        if (!::CryptExportPublicKeyInfoEx(hCryptProv, AT_KEYEXCHANGE, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, (LPSTR)szOID_PKCS_8, 0, nullptr, ppubKeyInfo, &cbPubInfo))
        {
            dwError = ::GetLastError();
            printf("failed to export public key: 0x%x..\n", dwError);
            continue;
        }

        // encode public key
        DWORD cbEncodedData = 0;
        if (!::CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_PUBLIC_KEY_INFO, ppubKeyInfo, 0, nullptr, nullptr, &cbEncodedData))
        {
            dwError = ::GetLastError();
            printf("failed to encode exported public key: 0x%x..\n", dwError);
            continue;
        }

        pbEncodedData = (BYTE*)::malloc(cbEncodedData);
        if (!::CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_PUBLIC_KEY_INFO, ppubKeyInfo, 0, nullptr, pbEncodedData, &cbEncodedData))
        {
            dwError = ::GetLastError();
            printf("failed to encode exported public key: 0x%x..\n", dwError);
            continue;
        }

        DWORD cchLen = 0;
        if (!::CryptBinaryToString(pbEncodedData, cbEncodedData, CRYPT_STRING_BASE64HEADER, nullptr, &cchLen))
        {
            dwError = ::GetLastError();
            printf("failed to convert PKCS8 public key to Base64: 0x%x..\n", dwError);
            continue;
        }

        pszBase64EncodedPkcs8Key = (CHAR*)::malloc(cchLen * sizeof(CHAR));
        if (!::CryptBinaryToStringA(pbEncodedData, cbEncodedData, CRYPT_STRING_BASE64HEADER, pszBase64EncodedPkcs8Key, &cchLen))
        {
            dwError = ::GetLastError();
            printf("failed to convert PKCS8 public key to Base64: 0x%x..\n", dwError);
            continue;
        }

        string fileNameWExt = fileName + ".crt";
        WriteToFile(pszBase64EncodedPkcs8Key, cchLen, fileNameWExt);

        ::free(pszBase64EncodedPkcs8Key);
        ::free(pbEncodedData);
        cbEncodedData = 0;
        cchLen = 0;

        // export private key to pkcs8
        CRYPT_PKCS8_EXPORT_PARAMS exportPara = { 0 };
        exportPara.hCryptProv = hCryptProv;
        exportPara.dwKeySpec = AT_KEYEXCHANGE;
        exportPara.pszPrivateKeyObjId = (LPSTR)szOID_RSA_RSA;
        cbData = 0;
        if (!::CryptExportPKCS8(hCryptProv, AT_KEYEXCHANGE, (LPSTR)szOID_RSA_RSA, 0, nullptr, nullptr, &cbData))
        {
            dwError = ::GetLastError();
            printf("failed to export key to PKCS8: 0x%x..\n", dwError);
            continue;
        }

        pbPkcs8Blob = (BYTE*)::malloc(cbData);
        if (!::CryptExportPKCS8(hCryptProv, AT_KEYEXCHANGE, (LPSTR)szOID_RSA_RSA, 0, nullptr, pbPkcs8Blob, &cbData)
            || !pbPkcs8Blob)
        {
            dwError = ::GetLastError();
            printf("failed to export key to PKCS8: 0x%x..\n", dwError);
            continue;
        }

        CRYPT_PRIVATE_KEY_INFO pkcs8KeyInfo = { 0 };
        pkcs8KeyInfo.Algorithm.pszObjId = (LPSTR)szOID_PKCS_8;
        pkcs8KeyInfo.Algorithm.Parameters = { 0 };
        pkcs8KeyInfo.PrivateKey.pbData = pbPkcs8Blob;
        pkcs8KeyInfo.PrivateKey.cbData = cbData;
        if (!::CryptEncodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
            PKCS_PRIVATE_KEY_INFO, 
            &pkcs8KeyInfo, 0, 
            nullptr, nullptr, &cbEncodedData))
        {
            dwError = ::GetLastError();
            printf("failed to encode PKCS8 key: 0x%x..\n", dwError);
            continue;
        }

        pbEncodedData = (BYTE*)::malloc(cbEncodedData);
        if (!::CryptEncodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            PKCS_PRIVATE_KEY_INFO,
            &pkcs8KeyInfo, 0,
            nullptr, 
            pbEncodedData, &cbEncodedData))
        {
            dwError = ::GetLastError();
            printf("failed to encode PKCS8 key: 0x%x..\n", dwError);
            continue;
        }

        if (!::CryptBinaryToString(pbEncodedData, cbEncodedData, CRYPT_STRING_BASE64, nullptr, &cchLen))
        {
            dwError = ::GetLastError();
            printf("failed to convert PKCS8 key to Base64: 0x%x..\n", dwError);
            continue;
        }

        pszBase64EncodedPkcs8Key = (CHAR*)::malloc(cchLen * sizeof(CHAR));
        if (!::CryptBinaryToStringA(pbEncodedData, cbEncodedData, CRYPT_STRING_BASE64, pszBase64EncodedPkcs8Key, &cchLen))
        {
            dwError = ::GetLastError();
            printf("failed to convert PKCS8 key to Base64: 0x%x..\n", dwError);
            continue;
        }

        fileNameWExt = fileName + ".prv";
        WriteToFile(pszBase64EncodedPkcs8Key, cchLen, fileNameWExt);

        //CRYPT_DATA_BLOB dataBlob = { 0 };
        //if (!::PFXExportCertStoreEx(hSysStore, &dataBlob, 0, 0, EXPORT_PRIVATE_KEYS | PKCS12_INCLUDE_EXTENDED_PROPERTIES))
        //{
        //    dwError = ::GetLastError();
        //    printf("failed to export pfx: 0x%x..\n", dwError);
        //    continue;
        //}

        //dataBlob.pbData = (BYTE*)::malloc(dataBlob.cbData);
        //if (!::PFXExportCertStoreEx(hSysStore, &dataBlob, nullptr, nullptr, EXPORT_PRIVATE_KEYS | PKCS12_INCLUDE_EXTENDED_PROPERTIES))
        //{
        //    dwError = ::GetLastError();
        //    printf("failed to export pfx: 0x%x..\n", dwError);
        //    continue;
        //}
    }
    while (FALSE);

    ::CryptReleaseContext(hCryptProv, 0);
    ::CertFreeCertificateContext(pcCertContext);
    ::CryptDestroyKey(hKey);
    ::free(pbEncodedData);
    ::free(pbPkcs8Blob);
    ::free(pCryptBlob);
    ::free(pbData);

    auto win32Err = ::GetLastError();
    if (CRYPT_E_NOT_FOUND == win32Err
        || ERROR_NO_MORE_FILES == win32Err)
    {
        // these are expected error codes and indicate the completion of the enumeration
        win32Err = ERROR_SUCCESS;
    }
}

void CertExport::WriteToFile(LPCSTR b64Str, DWORD cchLen, const string file)
{
    FILE* fp;
    errno_t err;
    if ((err = fopen_s(&fp, file.c_str(), "wb")) != 0)
        printf("File was not opened\n");
    else
        //for (int i = 0; i < cchLen; i++)
        //    fprintf(fp, "%c", b64Str + i);
        fprintf(fp, b64Str);
    fclose(fp);
}

void CertExport::Run()
{
    //ExportPfxToPem(_exportableCertTP);
    ExportPfxToPemOldApi(_exportableCertTP, "pfx2pemexportedcert");
}