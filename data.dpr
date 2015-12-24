(* ****************************************************************************

* eID Middleware Project.
* Copyright (C) 2011-2012 FedICT.
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
program data;

//PKCS11T.pas can be found here :
//http://sourceforge.net/p/projectjedi/website/HEAD/tree/trunk/delphi-jedi.org/www/files/API_Not_Assessed/SmartcardRSA/

uses
  {$IFDEF FPC}
  crt,
  {$ENDIF}
  Windows,sysutils,
  PKCS11T;

const
  PKCS11DLL = 'beidpkcs11.dll';

//Pascal pointers management
type
  CK_SLOT_IDS=array[0..255] of CK_SLOT_ID;
  CK_SLOT_IDS_PTR=^CK_SLOT_IDS;

//Quick and dirty Pascal equivalent to isprint
function isprint(b:byte):boolean;
begin
  result:=(b>=32) and (b<=127);
end;

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
begin
  Writeln(PAnsiChar(pName)+':');
  Writeln;
  if pValue<>nil then
  begin
    counter:=0;
    while counter<valueLen do
    begin
      if isprint(pValue^)
      then
        Write(Chr(pValue^))
      else
        Write('.');
      inc(pValue);
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
  data:CK_ULONG;
  searchtemplate:array[1..2] of CK_ATTRIBUTE;
  attrtemplate:CK_ATTRIBUTE;
  hObject:CK_OBJECT_HANDLE;
  ulObjectCount:CK_ULONG;
begin
  Result:=CKR_OK;
  data:=CKO_DATA;
  With searchtemplate[1] do
  begin
    _type:=CKA_CLASS;
    pValue:=@data;
    ulValueLen:=sizeof(CK_ULONG);
  end;
  With searchtemplate[2] do
  begin
    _type:=CKA_LABEL;
    pValue:=pName;
    ulValueLen:=strlen(pAnsiChar(pName));
  end;
  pvalueLen^:=0;
  //initialize the search for the objects with label <filename>
  Result:=pFunctions^.C_FindObjectsInit(session_handle, @searchtemplate, 2);
  if (Result<>CKR_OK) then exit;

  //find the first object with label <filename>
  Result:=pFunctions^.C_FindObjects(session_handle,@hObject,1,@ulObjectCount);
  if ((ulObjectCount=1) and (Result=CKR_OK)) then
  begin
    //nil as second argument, so the length of value is filled in to
    //retValueLen. See the definition of C_GetAttributeValue in the PKCS#11
    //standard for more details.
    with attrtemplate do
    begin
      _type:=CKA_VALUE;
      pValue:=nil;
      ulValueLen:=0;
    end;
    //now run C_GetAttributeValue a second time to actually retrieve the
    //data from the object
    Result:=pFunctions^.C_GetAttributeValue(session_handle,hObject,@attrtemplate,1);
    if ((Result=CKR_OK) and (CK_LONG(attrtemplate.ulValueLen)<>-1)) then
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

function beidsdk_GetData:CK_ULONG;
var
  pkcs11Handle:THandle;                       //handle to the pkcs11 library
  pFunctions:CK_FUNCTION_LIST_PTR;            //list of the pkcs11 function pointers
  pC_GetFunctionList:pointer;
  err:cardinal;
  slotIds:CK_SLOT_ID_PTR;
  slot_count:CK_ULONG;
  slotIdx:CK_ULONG;
  session_handle:CK_SESSION_HANDLE;

  pFileName:CK_CHAR_PTR;
  pSignatureFilename:CK_CHAR_PTR;
  pLastname:CK_CHAR_PTR;
  pFileValue:CK_VOID_PTR;
  pSignatureValue:CK_VOID_PTR;
  pLastnameValue:CK_VOID_PTR;
  FileValueLen:CK_ULONG;
  SignatureValueLen:CK_ULONG;
  LastnameValueLen:CK_ULONG;
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
          // set first parameter to CK_FALSE if you also want to find the slots without a card inserted
          Result:=pFunctions^.C_GetSlotList(CK_TRUE,nil,@Slot_Count);
          if (Result=CKR_OK) and (slot_count>0) then
          begin
            getmem(SlotIds,Slot_Count*sizeof(CK_SLOT_ID));
            Result:=pFunctions^.C_GetSlotList(CK_TRUE,SlotIds,@Slot_Count);
            if (Result=CKR_OK) then
            begin
              for slotIdx:=0 to slot_count-1 do
              begin
                //open a session
                Result:=pFunctions^.C_OpenSession(CK_SLOT_IDS_PTR(SlotIds)^[slotIdx],CKF_SERIAL_SESSION,nil,nil,@session_handle);
                if (Result=CKR_OK) then
                begin
                  PAnsiChar(pFilename):='carddata_glob_os_version';
                  PAnsiChar(pSignatureFilename):='CARD_DATA';
                  PansiChar(pLastname):='surname';
                  pFileValue:=nil;
                  pSignatureValue:=nil;
                  pLastnameValue:=nil;

                  //retrieve the data of the file
                  Result:=Beidsdk_GetObjectValue(pFunctions,
                                                 session_handle,
                                                 pFilename,
                                                 @pFileValue,
                                                 @FileValueLen);
                  if (Result=CKR_OK)
                  then
                    Beidsdk_PrintValue(pFilename,CK_BYTE_PTR(pFileValue),FileValueLen)
                  else
                    Writeln(Format('error 0x%.8x Beidsdk_GetObjectValue',[Result]));

                  //retrieve the data of the signature file
                  Result:=Beidsdk_GetObjectValue(pFunctions,
                                                 session_handle,
                                                 pSignatureFilename,
                                                 @pSignatureValue,
                                                 @SignatureValueLen);
                  if (Result=CKR_OK)
                  then
                    Beidsdk_PrintValue(pSignatureFilename,CK_BYTE_PTR(pSignatureValue),SignatureValueLen)
                  else
                    writeln(Format('error 0x%.8x Beidsdk_GetObjectValue',[Result]));

                  //retrieve the lastname
                  Result:=Beidsdk_GetObjectValue(pFunctions,
                                                 session_handle,
                                                 pLastname,
                                                 @pLastnameValue,
                                                 @LastnameValueLen);
                  if (Result=CKR_OK)
                  then
                    Beidsdk_PrintValue(pLastname,CK_BYTE_PTR(pLastnameValue),LastnameValueLen)
                  else
                    writeln(Format('error 0x%.8x Beidsdk_GetObjectValue',[Result]));

                  if pFileValue<>nil then FreeMem(pFileValue);
                  if pSignatureValue<>nil then FreeMem(pSignatureValue);
                  if pLastnameValue<>nil then FreeMem(pLastnameValue);
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
    //14001 is "MSVCR80.DLL not found"
  end;
end;

var
  retval:CK_ULONG;
begin
  retval:=beidsdk_GetData();

  writeln('Done. Press a key to continue...');
  readkey;
end.
