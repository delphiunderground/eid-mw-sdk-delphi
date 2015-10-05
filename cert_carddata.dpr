(* ****************************************************************************

* eID Middleware Project.
* Copyright (C) 2009-2011 FedICT.
* Copyright (C) 2015 Vincent Hardy <vincent.hardy.be@gmail.com>
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

**************************************************************************** *)

{$APPTYPE CONSOLE}
program cert_carddata;

//PKCS11T.pas can be found here :
//http://sourceforge.net/p/projectjedi/website/HEAD/tree/trunk/delphi-jedi.org/www/files/API_Not_Assessed/SmartcardRSA/

uses
  {$IFDEF FPC}
  crt,
  {$ENDIF}
  Windows,sysutils,
  PKCS11T,
  cert_registration;

const
  PKCS11DLL = 'beidpkcs11.dll';

//Pascal pointers management
type
  CK_SLOT_IDS=array[0..255] of CK_SLOT_ID;
  CK_SLOT_IDS_PTR=^CK_SLOT_IDS;
  CK_BYTES = array[0..65535] of CK_BYTE;
  CK_BYTES_PTR = ^CK_BYTES;

{$IFNDEF FPC}
//In Delphi, crt unit and Readkey function don't exist anymore
Function ReadKey:Char;
var
  Buffer:TInputRecord;
  EventRead:Cardinal;
  stdin:Thandle;
begin
  stdin := GetStdHandle(STD_INPUT_HANDLE);
  Result:=#0;
  repeat
    ReadConsoleInput(stdin,Buffer,1,EventRead);
    if (EventRead=1) and
       (Buffer.EventType=KEY_EVENT) and
       (Buffer.Event.KeyEvent.bKeyDown) and
       (Buffer.Event.KeyEvent.AsciiChar<>#0) then
      {$IFDEF UNICODE}
      Result:=Buffer.Event.KeyEvent.UnicodeChar;
      {$ELSE}
      Result:=Buffer.Event.KeyEvent.AsciiChar;
      {$ENDIF}
  until Result<>#0;
end;
{$ENDIF}

procedure Beidsdk_PrintValue(pName:CK_CHAR_PTR; pValue:CK_BYTE_PTR; valueLen:CK_ULONG);
var
  counter:longword;
  b:CK_BYTE;
begin
  writeln;
  Writeln(PAnsiChar(pName)+':');
  Writeln;
  if pValue<>nil then
  begin
    counter:=0;
    while counter<valueLen do
    begin
      b:=CK_BYTES_PTR(pValue)^[counter];
      if ($29<b) and (b<$81)
      then
        Write(Chr(b))
      else
        Write('.');
      inc(counter);
    end;
  end;
  writeln;
end;

function Beidsdk_GetObjectValue(pFunctions:CK_FUNCTION_LIST_PTR;
                                session_handle:CK_SESSION_HANDLE;
                                pName:CK_CHAR_PTR;
                                ppValue:CK_VOID_PTR;
                                pvalueLen:CK_ULONG_PTR):CK_RV;
var
  classType:CK_ULONG;
  searchtemplate:array[1..2] of CK_ATTRIBUTE;
  attrtemplate:CK_ATTRIBUTE;
  hObject:CK_OBJECT_HANDLE;
  ulObjectCount:CK_ULONG;
begin
  Result:=CKR_OK;
  classType:=CKO_DATA;
  With searchtemplate[1] do
  begin
    _type:=CKA_LABEL;
    pValue:=pName;
    ulValueLen:=strlen(pAnsiChar(pName));
  end;
  With searchtemplate[2] do
  begin
    _type:=CKA_CLASS;
    pValue:=@classType;
    ulValueLen:=sizeof(CK_ULONG);
  end;
  pvalueLen^:=0;
  //initialize the search for the objects with label <filename>
  Result:=pFunctions^.C_FindObjectsInit(session_handle, @searchtemplate, 2);
  if (Result<>CKR_OK) then exit;
  
  //find the first object with label <filename>
  Result:=pFunctions^.C_FindObjects(session_handle,@hObject,1,@ulObjectCount);
  if ((ulObjectCount=1) and (Result=CKR_OK)) then
  begin
    with attrtemplate do
    begin
      //NULL_PTR as second argument, so the length of value is filled in to retValueLen
      _type:=CKA_VALUE;
      pValue:=nil;
      ulValueLen:=0;
    end;
    //retrieve the length of the data from the object
    Result:=pFunctions^.C_GetAttributeValue(session_handle,hObject,@attrtemplate,1);
    if ((Result=CKR_OK) and  (CK_LONG(attrtemplate.ulValueLen)<>-1)) then
    begin
      getmem(pointer(ppValue^),attrtemplate.ulValueLen);
      attrtemplate.pValue:=pointer(ppValue^);
      //retrieve the data from the object
      Result:=pFunctions^.C_GetAttributeValue(session_handle,hObject,@attrtemplate,1);
      pvalueLen^:=attrtemplate.ulValueLen;
    end;
  end;
  //finalize the search
  Result:=pFunctions^.C_FindObjectsFinal(session_handle);
end;

function Beidsdk_RegisterCertificates(
               pFunctions:CK_FUNCTION_LIST_PTR;
               session_handle:CK_SESSION_HANDLE;
               cardSerialNumber:CK_BYTE_PTR;
               SerialNumberValueLen:CK_ULONG):CK_RV;
var
  searchtemplate:CK_ATTRIBUTE;
  classType:CK_ULONG;
  hObject:CK_OBJECT_HANDLE;
  ulObjectCount:CK_ULONG;
  attr_templ:CK_ATTRIBUTE;
  pValue_:CK_BYTE_PTR;
begin
  pValue_:=nil;

  classType:=CKO_CERTIFICATE;
  with searchtemplate do
  begin
    _type:=CKA_CLASS;
    pValue:=@classType;
    ulValueLen:=sizeof(CK_ULONG);
  end;
  //initialize the search for the objects with label <filename>
  Result:=pFunctions^.C_FindObjectsInit(session_handle, @searchtemplate, 1);
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
        if (Result=CKR_OK)
        then
          ImportCertificate(pValue_,attr_templ.ulValueLen,cardSerialNumber,SerialNumberValueLen);
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

function beidsdk_Main:CK_ULONG;
var
  pkcs11Handle:THandle;                       //handle to the pkcs11 library
  pFunctions:CK_FUNCTION_LIST_PTR;            //list of the pkcs11 function pointers
  pC_GetFunctionList:pointer;
  slotIds:CK_SLOT_ID_PTR;
  slot_count:CK_ULONG;
  slotIdx:CK_ULONG;
  session_handle:CK_SESSION_HANDLE;
  pSerialNumber:CK_CHAR_PTR;
  pSerialNumberValue:CK_VOID_PTR;
  SerialNumberValueLen:CK_ULONG;
  err:cardinal;
begin
  Result:=CKR_OK;
  pSerialNumberValue:=nil;
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
                Result:=pFunctions^.C_OpenSession(CK_SLOT_IDS_PTR(SlotIds)^[slotIdx],CKF_SERIAL_SESSION,nil,nil,@session_handle);
                if (Result=CKR_OK) then
                begin
                  PAnsiChar(pSerialNumber):='carddata_serialnumber';
                  //retrieve the data of the file
                  Result:=Beidsdk_GetObjectValue(pFunctions,
                                                 session_handle,
                                                 pSerialNumber,
                                                 @pSerialNumberValue,
                                                 @SerialNumberValueLen);
                  if (Result=CKR_OK) then
                  begin
                    Beidsdk_RegisterCertificates(pFunctions,session_handle,CK_BYTE_PTR(pSerialNumberValue),SerialNumberValueLen);
                    Beidsdk_PrintValue(pSerialNumber,CK_BYTE_PTR(pSerialNumberValue),SerialNumberValueLen);
                  end else
                    Writeln(Format('error 0x%.8x Beidsdk_GetObjectValue',[Result]));

                  if pSerialNumberValue<>nil then FreeMem(pSerialNumberValue);
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

var
  retval:CK_ULONG;
begin
  retval:=beidsdk_Main;

  write('Done. Return value: '+IntToStr(retval)+' (');
  if retval=CKR_OK then write('ok') else write('NOT ok');
  writeln(')');
  writeln('press a key to exit...');
  
  readkey;
end.
