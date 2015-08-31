(* ****************************************************************************

* eID Middleware Project.
* Copyright (C) 2009-2011 FedICT.
* Copyright (C) 2015 Vincent Hardy <vincent.hardy.be@gmail.com>.
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
program sign;

//PKCS11T.pas can be found here :
//http://sourceforge.net/p/projectjedi/website/HEAD/tree/trunk/delphi-jedi.org/www/files/API_Not_Assessed/SmartcardRSA/

uses
  {$IFDEF FPC}
  crt,
  {$ENDIF}
  Windows,Sysutils,
  PKCS11T;

const
  PKCS11DLL = 'beidpkcs11.dll';

//Pascal pointers management
type
  CK_SLOT_IDS=array[0..255] of CK_SLOT_ID;
  CK_SLOT_IDS_PTR=^CK_SLOT_IDS;

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
      Result:=Buffer.Event.KeyEvent.AsciiChar;
  until Result<>#0;
end;
{$ENDIF}

function beidsdk_sign(textToSign:CK_CHAR_PTR):CK_ULONG;
var
  pkcs11Handle:THandle;                  //handle to the pkcs11 library
  pFunctions:CK_FUNCTION_LIST_PTR;       //list of the pkcs11 function pointers
  pC_GetFunctionList:pointer;
  slot_count:CK_ULONG;
  slotIds:CK_SLOT_ID_PTR;
  slotIdx:CK_ULONG;
  session_handle:CK_SESSION_HANDLE;

  private_key:CK_ULONG;
  attribute_len:CK_ULONG;
  attributes:array[1..2] of CK_ATTRIBUTE;
  ulMaxObjectCount:CK_ULONG;
  ulObjectCount:CK_ULONG;       //returns the number of objects found
  hKey:CK_OBJECT_HANDLE;        //retrieve the private key with label 'signature'
  mechanism:CK_MECHANISM;
  signature:array[0..127] of CK_BYTE;
  signLength:CK_ULONG ;
  counter:cardinal;

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
          // retrieve the number of slots (cardreaders) found that hold a token (card)
          // to find also the slots without tokens inserted, set the first parameter to CK_FALSE
          Result:=pFunctions^.C_GetSlotList(CK_TRUE,nil,@Slot_Count);
          if (Result=CKR_OK) and (slot_count>0) then
          begin
            getmem(SlotIds,Slot_Count*sizeof(CK_SLOT_ID));
            Result:=pFunctions^.C_GetSlotList(CK_TRUE,SlotIds,@Slot_Count);
            if (Result=CKR_OK) then
            begin
              //move(slotIds^,SlotIdss[0],Slot_Count*sizeof(CK_SLOT_ID));
              for slotIdx:=0 to slot_count-1 do
              begin
                //open a session
                Result:=pFunctions^.C_OpenSession(CK_SLOT_IDS_PTR(SlotIds)^[slotIdx],CKF_SERIAL_SESSION,nil,nil,@session_handle);
                if (Result=CKR_OK) then
                begin
                  private_key:=CKO_PRIVATE_KEY;
                  attribute_len:=2; //the number of attributes in the search template below
                  //the searchtemplate that will be used to initialize the search
                  With attributes[1] do
                  begin
                    _type:=CKA_CLASS;
                    pValue:=@private_key;
                    ulValueLen:=sizeof(CK_ULONG);
                  end;
                  With attributes[2] do
                  begin
                    _type:=CKA_LABEL;
                    pValue:=PAnsiChar('Signature');
                    ulValueLen:=strlen(pAnsiChar('Signature'));
                  end;
                  //prepare the findobjects function to find all objects with attributes
                  //CKA_CLASS set to CKO_PRIVATE_KEY and with CKA_LABEL set to Signature
                  Result:=pFunctions^.C_FindObjectsInit(session_handle, @attributes, attribute_len);
                  if (Result=CKR_OK) then
                  begin
                    ulMaxObjectCount:=1;     //we want max one object returned
                    //retrieve the private key with label "signature"
                    Result:=pFunctions^.C_FindObjects(session_handle,@hkey,ulMaxObjectCount,@ulObjectCount);
                    if Result=CKR_OK then
                    begin
                      //terminate the search
                      Result:=pFunctions^.C_FindObjectsFinal(session_handle);
                      if Result=CKR_OK then
                      begin
                        //use the CKM_SHA1_RSA_PKCS mechanism for signing
                        with mechanism do
                        begin
                          mechanism:=CKM_SHA1_RSA_PKCS;
                          pParameter:=nil;
                          ulParameterLen:=0;
                        end;
                        signLength:=128;
                        //initialize the signature operation
                        Result:=pFunctions^.C_SignInit(session_handle,@mechanism,hKey);
                        if Result=CKR_OK then
                        begin
                          Result:=pFunctions^.C_Sign(session_handle,CK_BYTE_PTR(textToSign),CK_ULONG(strlen(PAnsiChar(textToSign))),@signature,@signLength);
                          if Result=CKR_OK then
                          begin
                            writeln('The Signature:');
                            counter:=0;
                            while counter<signLength do
                            begin
                              write(AnsiChar(signature[counter]));
                              inc(counter);
                            end;
                          end;
                        end;
                      end;
                    end;
                    if (Result=CKR_OK)
                    then
                      Result:=pFunctions^.C_FindObjectsFinal(session_handle)
                    else
                      pFunctions^.C_FindObjectsFinal(session_handle);
                  end;
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
  copyrightText:ansistring;
begin
  copyrightText:=
    '* eID Middleware Project.'+#13#10+
    '* Copyright (C) 2009-2010 FedICT.'+#13#10+
    '* Copyright (C) 2015 Vincent Hardy <vincent.hardy.be@gmail.com>.'+#13#10+
    '*'+#13#10+
    '* This is free software; you can redistribute it and/or modify it'+#13#10+
    '* under the terms of the GNU Lesser General Public License version'+#13#10+
    '* 3.0 as published by the Free Software Foundation.'+#13#10+
    '*'+#13#10+
    '* This software is distributed in the hope that it will be useful,'+#13#10+
    '* but WITHOUT ANY WARRANTY; without even the implied warranty of'+#13#10+
    '* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU'+#13#10+
    '* Lesser General Public License for more details.'+#13#10+
    '*'+#13#10+
    '* You should have received a copy of the GNU Lesser General Public'+#13#10+
    '* License along with this software; if not, see'+#13#10+
    '* http://www.gnu.org/licenses/.'+#13#10+#0;

  retval:=beidsdk_sign(@copyrightText[1]);

  readkey;
end.
