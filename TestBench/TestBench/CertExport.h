#pragma once
class CertExport
{
public:
	static void ExportPfxToPemOldApi(std::wstring, std::string);
	static void ExportPfxToPem(std::wstring);
	static std::vector<BYTE> HashStringToBytes(std::wstring);
	static PCCERT_CONTEXT FindCertInCUStore(std::wstring);
	static void WriteToFile(LPCSTR pbData, DWORD cchLen, const std::string);
	static void Run();

private:
	static const std::wstring _exportableCertTP;
	static LPCSTR _exportableCertCN;

	static const std::wstring _headerBeginCert;
	static const std::wstring _headerEndCert;
	static const std::wstring _headerBeginKey;
	static const std::wstring _headerEndKey;
};

