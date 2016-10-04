(*
 * https://github.com/delphiunderground/eid-mw-sdk-delphi
 * Copyright (C) 2015-2016 Vincent Hardy <vincent.hardy.be@gmail.com>
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see
 * http://www.gnu.org/licenses/.
 *)


unit get_X509cert;

interface

//OpenSC for Windows can be found here :
//http://sourceforge.net/projects/opensc/files/OpenSC/

//PKCS11T.pas can be found here :
//http://sourceforge.net/p/projectjedi/website/HEAD/tree/trunk/delphi-jedi.org/www/files/API_Not_Assessed/SmartcardRSA/

uses
  PKCS11T;

function beid_Main:CK_ULONG;

implementation

uses
  Windows, sysutils,
  {$IFDEF OpenSSL-Delphi}
  ssl_lib,ssl_x509,ssl_asn,ssl_bio,ssl_bn,ssl_ec,ssl_pem,ssl_types,ssl_util,
  {$ELSE}
  IdSSLOpenSSLHeaders,
  {$ENDIF}
  utils;

const
  PKCS11DLL = 'beidpkcs11.dll';


procedure Beid_PrintValue_PEM(pValue:CK_BYTE_PTR; valueLen:CK_ULONG);
const
  X509_MAX_Length = 2048;
var
  counter:integer;
  sValue:AnsiString;
begin
  if pValue<>nil then
  begin
    setlength(sValue, X509_MAX_Length);    //define a maximum memory area
    counter:=dumpcert(pValue, valueLen, PAnsiChar(sValue), X509_MAX_Length);
    setlength(sValue,counter);             //Delphi don't care about #0
    writeln(sValue);
  end;
end;

procedure Beid_PrintValue_DER(pValue:CK_BYTE_PTR; valueLen:CK_ULONG);
var
  counter:longword;
  sValue:AnsiString;
begin
  //pValue contains the same value as that obtained with the command :
  //pkcs11-tool --module beidpkcs11.dll --read-object Signature --id 03000000 --type cert > signSC.der

  if pValue<>nil then
  begin
    SetLength(sValue,valueLen);
    counter:=0;
    while counter<valueLen do
    begin
      inc(counter);
      sValue[counter]:=AnsiChar(pValue^);
      inc(pValue);
    end;
    //DER format :
    writeln(sValue);
  end;
end;

{$IFNDEF OpenSSL-Delphi}
procedure OpenSSL_free(ptr: Pointer);
begin
  if @CRYPTO_Free <> nil then
    CRYPTO_free(ptr);
end;
{$ENDIF}

procedure X509Info(pValue:pointer; valueLen:Cardinal);
var
  aX509:PX509;
  FX509Name:PX509_NAME;
  LOneLine: array[0..2048] of AnsiChar;
  Serial:PASN1_INTEGER;
  bn:PBIGNUM;
  tmp:PAnsiChar;
  sSerial:string;
begin
  aX509:=d2i_X509(nil, @pvalue, valueLen);
  if (aX509<>nil) then
  begin
    FX509Name:=X509_get_issuer_name(aX509);
    if FX509Name<>nil then
    begin
      Writeln('IssuerName: '+X509_NAME_oneline(FX509Name, PAnsiChar(@LOneLine), SizeOf(LOneLine)));
    end else
      Writeln('Unable to find issuer_name');

    Serial:=X509_get_serialNumber(aX509);
    bn:=ASN1_INTEGER_to_BN(Serial, nil);
    if bn<>nil then
    begin
      tmp:=BN_bn2dec(bn);
      if tmp<>nil then
      begin
        sSerial:=tmp;
        OpenSSL_free(tmp);
      end else Writeln('unable to convert BN to decimal string');
      BN_free(bn);
    end else writeln('Unable to convert ASN1INTEGER to BN');
    writeln('SerialNumber: '+sSerial);

    X509_free(aX509);
  end;
end;

function Beid_X509Certificate(
               pFunctions:CK_FUNCTION_LIST_PTR;
               session_handle:CK_SESSION_HANDLE):CK_RV;
var
  searchtemplate:array[1..2] of CK_ATTRIBUTE;
  classType:CK_ULONG;
  hObject:CK_OBJECT_HANDLE;
  ulObjectCount:CK_ULONG;
  attr_templ:CK_ATTRIBUTE;
  pValue_:CK_BYTE_PTR;
begin
  pValue_:=nil;
  classType:=CKO_CERTIFICATE;
  with searchtemplate[1] do
  begin
    _type:=CKA_CLASS;
    pValue:=@classType;
    ulValueLen:=sizeof(CK_ULONG);
  end;
  with searchtemplate[2] do
  begin
    _type:=CKA_LABEL;
    pValue:=pAnsiChar('Signature');
    ulValueLen:=strlen(pAnsiChar(pValue));
  end;
  //initialize the search for the objects with label <filename>
  Result:=pFunctions^.C_FindObjectsInit(session_handle, @searchtemplate, 2);
  if (Result<>CKR_OK) then exit;

  //find the first object with class CKO_CERTIFICATE
  Result:=pFunctions^.C_FindObjects(session_handle,@hObject,1,@ulObjectCount);
  while ((ulObjectCount=1) and (Result=CKR_OK)) do
  begin
    //NULL_PTR as second argument, so the length of value is filled in to retValueLen
    with attr_templ do
    begin
      _type:=CKA_VALUE;
      pValue:=nil;
      ulValueLen:=0;
    end;
    //retrieve the length of the data from the object
    Result:=pFunctions^.C_GetAttributeValue(session_handle,hObject,@attr_templ,1);
    if ((Result=CKR_OK) and (CK_LONG(attr_templ.ulValueLen)<>-1)) then
    begin
      getmem(pValue_,attr_templ.ulValueLen);
      if pValue_<>nil then
      begin
        attr_templ.pValue:=pValue_;
        //retrieve the data from the object
        Result:=pFunctions^.C_GetAttributeValue(session_handle,hObject,@attr_templ,1);
        if (Result=CKR_OK) then
        begin
          {$IFDEF OpenSSL-Delphi}
          SSL_InitX509;
          SSL_InitBIO;
          SSL_InitPEM;
          SSL_InitASN1;
          SSL_InitBN;
          SSL_InitEC;
          {$ELSE}
          load;   //SSL loadLib
          {$ENDIF}
          //Beid_PrintValue_DER(pValue_,attr_templ.ulValueLen);
          Beid_PrintValue_PEM(pValue_,attr_templ.ulValueLen);
          X509Info(pValue_,attr_templ.ulValueLen);
        end;
        freemem(pValue_);
      end else
      begin
        //error allocating memory for pValue
        Result:=CKR_GENERAL_ERROR;
      end;
    end;
    Result:=pFunctions^.C_FindObjects(session_handle,@hObject,1,@ulObjectCount);
  end;
  //finalize the search
  Result:=pFunctions^.C_FindObjectsFinal(session_handle);
end;

function beid_Main:CK_ULONG;
var
  pkcs11Handle:THandle;                       //handle to the pkcs11 library
  pFunctions:CK_FUNCTION_LIST_PTR;            //list of the pkcs11 function pointers
  pC_GetFunctionList:pointer;
  slotIds:CK_SLOT_ID_PTR;
  slot_count:CK_ULONG;
  slotIdx:CK_ULONG;
  session_handle:CK_SESSION_HANDLE;
  err:cardinal;
begin
  Result:=CKR_OK;
  //open the pkcs11 library
  pkcs11Handle:=LoadLibrary(PKCS11DLL);
  if pkcs11Handle>=32 then
  begin
    // get function pointer to C_GetFunctionList
    pC_GetFunctionList:=GetProcAddress(pkcs11Handle,'C_GetFunctionList');
    if pC_GetFunctionList<>nil then
    begin
      // invoke C_GetFunctionList to get the list of pkcs11 function pointers
      Result:=TfC_GetFunctionList(pC_GetFunctionList)(@pFunctions);
      if (Result=CKR_OK) then
      begin
        // initialize Cryptoki
        Result:=pFunctions^.C_Initialize(nil);
        if Result=CKR_OK then
        begin
          slot_count:=0;
          // retrieve the number of slots (cardreaders) found
          Result:=pFunctions^.C_GetSlotList(CK_TRUE,nil,@Slot_Count);
          if (Result=CKR_OK) and (slot_count>0) then
          begin
            getmem(SlotIds,Slot_Count*sizeof(CK_SLOT_ID));
            // retrieve the list of slots (cardreaders)
            Result:=pFunctions^.C_GetSlotList(CK_TRUE,SlotIds,@Slot_Count);
            if (Result=CKR_OK) then
            begin
              for slotIdx:=0 to slot_count-1 do
              begin
                //open a session
                Result:=pFunctions^.C_OpenSession(PByteArray(SlotIds)^[slotIdx],CKF_SERIAL_SESSION,nil,nil,@session_handle);
                if (Result=CKR_OK) then
                begin
                  Beid_X509Certificate(pFunctions,session_handle);
                end;
                //close the session
                if (Result=CKR_OK)
                then
                  Result:=pFunctions^.C_CloseSession(session_handle)
                else
                  pFunctions^.C_CloseSession(session_handle);
              end; //end of for loop
            end;
            freemem(SlotIds);
          end else //no slots found
            if (slot_count=0) then writeln('no slots found');

          if (Result=CKR_OK) then Result:=pFunctions^.C_Finalize(nil)
                             else pFunctions^.C_Finalize(nil);
        end; //C_Initialize failed
      end else //CK_C_GetFunctionList failed
      begin
        Result:=CKR_GENERAL_ERROR;
        writeln(Format('error 0x%.8x C_GetFunctionList',[Result]));
      end;
    end else  //GetProcAddress failed
    begin
      Result:=CKR_GENERAL_ERROR;
    end;
    FreeLibrary(pkcs11Handle);
  end else //LoadLibrary failed
  begin
    Result:=CKR_GENERAL_ERROR;
    writeln(PKCS11DLL+' not found');
    err:=GetLastError;
    writeln(Format('err is 0x%.8x',[err]));
  end;
end;

end.
