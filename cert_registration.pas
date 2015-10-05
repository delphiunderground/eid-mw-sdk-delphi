unit cert_registration;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}

interface

uses
  //PKCS11T.pas can be found here :
  //http://sourceforge.net/p/projectjedi/website/HEAD/tree/trunk/delphi-jedi.org/www/files/API_Not_Assessed/SmartcardRSA/
  PKCS11T;

function ImportCertificate(certData:CK_BYTE_PTR; certSize:cardinal; cardSerialNumber:CK_BYTE_PTR; cardSerialNumberLen:CK_ULONG):integer;

implementation

uses
  Windows,sysutils,
  //wcrypt2.pas can be found here :
  //http://sourceforge.net/p/projectjedi/website/HEAD/tree/trunk/delphi-jedi.org/www/files/api/CryptoAPI2.zip?format=raw
  //http://www.delphi-jedi.org/apilibrary.html
  wcrypt2;
  //

type
  //size_t is also defined in delphi XE
  //C:\Program Files (x86)\Embarcadero\RAD Studio\10.0\source\rtl\posix\Posix.SysTypes.pas
  {$IFDEF WIN64}
  size_t = Int64;
  {$ELSE}
  size_t = integer;
  {$ENDIF}
  //Pascal pointers management
  CK_BYTES = array[0..65535] of CK_BYTE;
  CK_BYTES_PTR = ^CK_BYTES;
  CK_CHAR_PTR_PTR = ^CK_CHAR_PTR;

const
  CRYPT_E_NOT_FOUND=$80092004;  //http://sourceforge.net/p/mingw/mingw-org-wsl/ci/master/tree/include/winerror.h
  CERT_FIND_EXISTING=851968;    //http://sourceforge.net/p/mingw/mingw-org-wsl/ci/master/tree/include/wincrypt.h
                                // CERT_FIND_EXISTING defined in Microsoft wincrypt.h :
                                //  CERT_COMPARE_EXISTING=13;
                                //  CERT_COMPARE_SHIFT=16;
                                //  CERT_FIND_EXISTING=CERT_COMPARE_EXISTING shl CERT_COMPARE_SHIFT;
  CERT_STORE_ADD_NEWER=6;       //http://sourceforge.net/p/mingw/mingw-org-wsl/ci/master/tree/include/wincrypt.h

function ToHex(uc:CK_BYTE):char;
begin
  if uc<=9 then Result:=Chr(48+uc)
           else Result:=Chr(55+uc);
end;

function ByteArrayToString(byteArray:CK_BYTES_PTR; ulArrayLen:CK_ULONG):String;
var
  ulOffset:cardinal;
  i:CK_ULONG;
begin
  setlength(Result,ulArrayLen*2+1);
  ulOffset:=1;  
  for i:=0 to ulArrayLen-1 do
  begin
    Result[ulOffset]:=ToHex(CK_BYTES_PTR(byteArray)^[i] div 16);
    inc(ulOffset);
    Result[ulOffset]:=ToHex(CK_BYTES_PTR(byteArray)^[i] mod 16);
    inc(ulOffset);
  end;
  Result[ulOffset]:=#0;
end;


//**************************************************
// Use Minidriver if OS is Vista or later
//**************************************************
function UseMinidriver:boolean;
var
  osvi:OSVERSIONINFO;
begin
  osvi.dwOSVersionInfoSize:=sizeof(OSVERSIONINFO);
  GetVersionEx(osvi);
  Result:=(osvi.dwMajorVersion >= 6);  //Vista or later
end;

//**************************************************
// Checks of older registered certificates are not
// still bound to the CSP when the minidriver is used
//**************************************************
function ProviderNameCorrect(pCertContext:PCCERT_CONTEXT):boolean;
var
  dwPropId:cardinal;
  cbData:cardinal;
  pCryptKeyProvInfo:PCRYPT_KEY_PROV_INFO;
begin
  Result:=true;
  dwPropId:=CERT_KEY_PROV_INFO_PROP_ID;
  cbData:=0;

  if not UseMinidriver then exit;

  if not CertGetCertificateContextProperty(
      pCertContext,   // A pointer to the certificate where the property will be set.
      dwPropId,       // An identifier of the property to get.
      nil,            // NULL on the first call to get the length.
      @cbData)        // The number of bytes that must be allocated for the structure.
  then
    if GetLastError<>CRYPT_E_NOT_FOUND then
    begin
      Result:=false;  // The certificate does not have the specified property.
      exit;
    end;

  getmem(pCryptKeyProvInfo,cbData);
  if CertGetCertificateContextProperty(pCertContext, dwPropId, pCryptKeyProvInfo, @cbData) then
  begin
    if pCryptKeyProvInfo^.pwszProvName<>'Belgium Identity Card CSP'
    then
      result:=false;
  end;
end;

function StoreAuthorityCert(pCertContext:PCCERT_CONTEXT; KeyUsageBits:byte):integer;
var
  hMemoryStore:HCERTSTORE;
  pDesiredCert:PCCERT_CONTEXT;
begin
  Result:=0;
  hMemoryStore:=nil;
  pDesiredCert:=nil;

  if CompareMem(pCertContext^.pCertInfo^.Issuer.pbData,pCertContext^.pCertInfo^.Subject.pbData,pCertContext^.pCertInfo^.Subject.cbData)
  then
    hMemoryStore:=CertOpenSystemStore(0,WideString('ROOT'))
  else
    hMemoryStore:=CertOpenSystemStore(0,WideString('CA'));

  if hMemoryStore=nil then
  begin
    Result:=GetLastError;
    writeln('StoreAuthorityCerts: Unable to open the system certificate store. Error code: '+IntToStr(Result)+'.');
    exit;
  end;

  pDesiredCert:=CertFindCertificateInStore(
                hMemoryStore,
		X509_ASN_ENCODING,
		0,
		CERT_FIND_EXISTING,
		pCertContext,
		nil);
  if pDesiredCert<>nil
  then
    CertFreeCertificateContext(pDesiredCert)
  else
  if GetLastError<>0 then  //pDesiredCert=nil
  begin
    CertAddEnhancedKeyUsageIdentifier(pCertContext,szOID_PKIX_KP_EMAIL_PROTECTION);
    CertAddEnhancedKeyUsageIdentifier(pCertContext,szOID_PKIX_KP_SERVER_AUTH);
    if CertAddCertificateContextToStore(hMemoryStore,pCertContext,CERT_STORE_ADD_NEWER,pDesiredCert) then
    begin
      writeln('StoreAuthorityCerts: Certificate context added to store.');
      Result:=0;
    end	else
    begin
      Result:=GetLastError;
      writeln('StoreAuthorityCerts: Unable to add certificate context to store. Error code: '+IntToStr(Result)+'.');
    end;
    CertCloseStore(hMemoryStore,CERT_CLOSE_STORE_FORCE_FLAG);
  end;
end;

function StoreUserCert(pCertContext:PCCERT_CONTEXT; KeyUsageBits:byte; cardSerialNumber:CK_BYTE_PTR; cardSerialNumberLen:CK_ULONG):integer;
var
  hMyStore:HCERTSTORE;
  pDesiredCert:PCCERT_CONTEXT;
  pPrevCert:PCCERT_CONTEXT;
  ContainerName:WideString;
  //ContainerNameCharLen:size_t;
  cardSerialNrString:String;
  cryptKeyProvInfo:CRYPT_KEY_PROV_INFO;
  dwPropId:Cardinal;
  dwFlags:Cardinal;

  // Set friendly names for the certificates
  //dwsize:longword;
  //pname:PwideChar;  //http://stackoverflow.com/questions/21867113/how-to-use-unicode-from-delphi-in-c-dll
  //tpFriendlyName:CRYPT_DATA_BLOB;
begin
  Result:=0;
  pDesiredCert:=nil;
  pPrevCert:=nil;

  dwPropId:=CERT_KEY_PROV_INFO_PROP_ID;
  dwFlags:=CERT_STORE_NO_CRYPT_RELEASE_FLAG;

  hMyStore:=CertOpenSystemStore(0,WideString('MY'));
  if hMyStore=nil then
  begin
    Result:=GetLastError;
    writeln('StoreUserCerts: Unable to open the system certificate store. Error code: '+IntToStr(Result)+'.');
    exit;
  end;

  // ----------------------------------------------------
  // look if we already have a certificate with the same
  // subject (contains name and NNR) in the store
  // If the certificate is not found --> nil
  // ----------------------------------------------------
  repeat
    pDesiredCert:=CertFindCertificateInStore(hMyStore, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_NAME, @pCertContext^.pCertInfo^.Subject, pPrevCert);
    if pDesiredCert<>nil then
    begin
      // ----------------------------------------------------
      // If the certificates are identical and function
      // succeeds, the return value is nonzero, or TRUE.
      // ----------------------------------------------------
      if (not CertCompareCertificate(X509_ASN_ENCODING,pCertContext^.pCertInfo,pDesiredCert^.pCertInfo)) or
         (not ProviderNameCorrect(pDesiredCert)) then
      begin
        // ----------------------------------------------------
        // certificates are not identical, but have the same
        // subject (contains name and NNR),
        // so we remove the one that was already in the store
        // ----------------------------------------------------
        if not CertDeleteCertificateFromStore(pDesiredCert) then
          if (GetLastError=Cardinal(E_ACCESSDENIED)) then continue;

	pPrevCert:=nil;
        continue;
      end;
    end;
    pPrevCert:=pDesiredCert;
  until pDesiredCert=nil;

  // ----------------------------------------------------
  // look if we already have the certificate in the store
  // If the certificate is not found --> NULL
  // ----------------------------------------------------
  pDesiredCert:=CertFindCertificateInStore(hMyStore, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, pCertContext, nil);
  if pDesiredCert<>nil then
  begin
    // ----------------------------------------------------
    // certificate is already in the store, then just return
    // ----------------------------------------------------
    CertFreeCertificateContext(pDesiredCert);
    CertCloseStore(hMyStore, CERT_CLOSE_STORE_FORCE_FLAG);
    Result:=0;
    exit;
  end;

  cardSerialNrString:=ByteArrayToString(pointer(cardSerialNumber),cardSerialNumberLen);

  if UseMinidriver then
  begin
    if (KeyUsageBits and CERT_NON_REPUDIATION_KEY_USAGE)=CERT_NON_REPUDIATION_KEY_USAGE
    then
      ContainerName:='NR_'+cardSerialNrString
    else
      ContainerName:='DS_'+cardSerialNrString;

    cryptKeyProvInfo.pwszProvName:=WideString('Microsoft Base Smart Card Crypto Provider');
    cryptKeyProvInfo.dwKeySpec:=AT_SIGNATURE;
  end else
  begin
    if (KeyUsageBits and CERT_NON_REPUDIATION_KEY_USAGE)=CERT_NON_REPUDIATION_KEY_USAGE
    then
      ContainerName:='Signature('+cardSerialNrString+')'
    else
      ContainerName:='Authentication('+cardSerialNrString+')';

    cryptKeyProvInfo.pwszProvName:=WideString('Belgium Identity Card CSP');
    cryptKeyProvInfo.dwKeySpec:=AT_KEYEXCHANGE;
  end;
  cryptKeyProvInfo.pwszContainerName:=PwideChar(ContainerName);

  cryptKeyProvInfo.dwProvType:=PROV_RSA_FULL;
  cryptKeyProvInfo.dwFlags:=0;
  cryptKeyProvInfo.cProvParam:=0;
  cryptKeyProvInfo.rgProvParam:=nil;

(*
  // Set friendly names for the certificates
  dwsize:=CertGetNameStringW(pCertContext, CERT_NAME_ATTR_TYPE, 0, PAnsiChar(szOID_COMMON_NAME), nil, dwsize);
  getmem(pname,dwsize*sizeof(widechar));

  dwsize:=CertGetNameStringW(pCertContext, CERT_NAME_ATTR_TYPE, 0, PAnsiChar(szOID_COMMON_NAME), pname, dwsize);

  tpFriendlyName.pbData:=PBYTE(pname);
  tpFriendlyName.cbData:=dwsize*sizeof(WideChar);

  if CertSetCertificateContextProperty(
                      pCertContext,               // A pointer to the certificate
                      // where the propertiy will be set.
                      CERT_FRIENDLY_NAME_PROP_ID, // An identifier of the property to be set.
                      // In this case, CERT_KEY_PROV_INFO_PROP_ID
                      // is to be set to provide a pointer with the
                      // certificate to its associated private key
                      // container.
                      dwFlags,                    // The flag used in this case is
                      // CERT_STORE_NO_CRYPT_RELEASE_FLAG
                      // indicating that the cryptographic
                      // context aquired should not
                      // be released when the function finishes.
                      @tpFriendlyName            // A pointer to a data structure that holds
                      // infomation on the private key container to
                      // be associated with this certificate.
                      ) then
*)
  // Set the property.
  if CertSetCertificateContextProperty(
    pCertContext,     // A pointer to the certificate where the property will be set.
    dwPropId,         // An identifier of the property to be set.
		      // In this case, CERT_KEY_PROV_INFO_PROP_ID is to be set to provide
                      // a pointer with the certificate to its associated private key container.
    dwFlags,          // The flag used in this case is
		      // CERT_STORE_NO_CRYPT_RELEASE_FLAG indicating that the cryptographic context
                      // acquired should not be released when the function finishes.
    @cryptKeyProvInfo // A pointer to a data structure that holds infomation on
                      // the private key container to be associated with this certificate.
    ) then
  begin
    if (KeyUsageBits and CERT_NON_REPUDIATION_KEY_USAGE)=CERT_NON_REPUDIATION_KEY_USAGE then
    begin
      CertAddEnhancedKeyUsageIdentifier(pCertContext, szOID_PKIX_KP_EMAIL_PROTECTION);
    end else
    begin
      CertAddEnhancedKeyUsageIdentifier(pCertContext, szOID_PKIX_KP_EMAIL_PROTECTION);
      CertAddEnhancedKeyUsageIdentifier(pCertContext, szOID_PKIX_KP_CLIENT_AUTH);
    end;
    assert(pDesiredCert=nil);  
    if CertAddCertificateContextToStore(hMyStore, pCertContext, CERT_STORE_ADD_REPLACE_EXISTING, pDesiredCert) then  //here pDesiredCert=nil
    begin
      writeln('StoreUserCerts: Certificate context added to store.');
      Result:=0;
    end	else
    begin
      Result:=GetLastError;
      writeln('StoreUserCerts: Unable to add certificate context to store. Error code: '+IntToStr(Result)+'.');
    end;
    CertCloseStore(hMyStore, CERT_CLOSE_STORE_FORCE_FLAG);
    hMyStore:=nil;
  end;
  (*
  freemem(pname);
  *)
end;

function ImportCertificate(certData:CK_BYTE_PTR; certSize:cardinal; cardSerialNumber:CK_BYTE_PTR; cardSerialNumberLen:CK_ULONG):integer;
var
  pCertContext:PCCERT_CONTEXT;
  KeyUsageBits:byte;    // Intended key usage bits copied to here.
begin
  Result:=0;
  // ------------------------------------------------------------
  // create the certificate context with the certificate raw data
  // ------------------------------------------------------------
  pCertContext:=CertCreateCertificateContext(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, pointer(certData),certSize);

  if pCertContext=nil then
  begin
    Result:=GetLastError;
    if Result=E_INVALIDARG
    then
      writeln('ImportCertificates: Unable to create certificate context. The certificate encoding type is not supported. Error code: '+IntToStr(Result)+'.')
    else
      writeln('ImportCertificates: Unable to create certificate context. Error code: '+IntToStr(Result)+'.');
  end else
  begin
    KeyUsageBits:=0;      // Intended key usage bits copied to here.
    CertGetIntendedKeyUsage(X509_ASN_ENCODING, pCertContext.pCertInfo,@KeyUsageBits, 1);
    // ----------------------------------------------------------------------
    // Only store the context of the certificates with usages for an end-user
    // i.e. no CA or root certificates
    // ----------------------------------------------------------------------
    if((KeyUsageBits and CERT_KEY_CERT_SIGN_KEY_USAGE)=CERT_KEY_CERT_SIGN_KEY_USAGE)
    then
      Result:=StoreAuthorityCert(pCertContext, KeyUsageBits)
    else
      Result:=StoreUserCert(pCertContext, KeyUsageBits, cardSerialNumber, cardSerialNumberLen);

    if pCertContext<>nil then CertFreeCertificateContext(pCertContext);
  end;
end;


end.
