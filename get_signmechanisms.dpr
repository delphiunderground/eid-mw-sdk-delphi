(* ****************************************************************************

* eID Middleware Project.
* Copyright (C) 2009-2010 FedICT.
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
program get_signmechanisms;

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
  CK_MECHANISMS_TYPE=array[0..65535] of CK_MECHANISM_TYPE;
  CK_MECHANISMS_TYPE_PTR=^CK_MECHANISMS_TYPE;

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

function beidsdk_getsignmechanisms:CK_ULONG;
var
  pkcs11Handle:THandle;                       //handle to the pkcs11 library
  pFunctions:CK_FUNCTION_LIST_PTR;            //list of the pkcs11 function pointers
  pC_GetFunctionList:pointer;
  err:cardinal;
  slotIds:CK_SLOT_ID_PTR;
  slot_count:CK_ULONG;
  slotIdx:CK_ULONG;

  ulMechCount:CK_ULONG;
  pMechanismList:CK_MECHANISM_TYPE_PTR;
  mechanismInfo:CK_MECHANISM_INFO;
  ulCount:CK_ULONG;
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
          //slot_count:=0; pas dans le source C
          // retrieve the number of slots (cardreaders) found that hold a token (card)
          // to find also the slots without tokens inserted, set the first parameter to CK_FALSE
          Result:=pFunctions^.C_GetSlotList(CK_TRUE,nil,@Slot_Count);
          if (Result=CKR_OK) and (slot_count>0) then
          begin
            getmem(SlotIds,Slot_Count*sizeof(CK_SLOT_ID));
            // retrieve the list of slots (cardreaders) found that hold a token (card)
            Result:=pFunctions^.C_GetSlotList(CK_TRUE,SlotIds,@Slot_Count);
            if (Result=CKR_OK) then
            begin
              for slotIdx:=0 to slot_count-1 do
              begin
                ulMechCount:=0;
                pMechanismList:=nil;
                // C_GetMechanismList
                Result:=pFunctions^.C_GetMechanismList(CK_SLOT_IDS_PTR(slotIds)^[slotIdx],nil,@ulMechCount);
                if (Result=CKR_OK) and (ulMechCount>0) then
                begin
                  getmem(pMechanismList,ulMechCount*sizeof(CK_MECHANISM_TYPE));
                  Result:=pFunctions^.C_GetMechanismList(CK_SLOT_IDS_PTR(slotIds)^[slotIdx],pMechanismList,@ulMechCount);
                  if (Result=CKR_OK) then
                  begin
                    writeln('Card Mechanisms found :');
                    for ulCount:=0 to ulMechCount-1 do
                    begin
                      Result:=pFunctions^.C_GetMechanismInfo(CK_SLOT_IDS_PTR(slotIds)^[slotIdx],CK_MECHANISMS_TYPE_PTR(pMechanismList)^[ulCount],@mechanismInfo);
                      if (Result=CKR_OK) then
                      begin
                        if (mechanismInfo.flags and CKF_SIGN)=CKF_SIGN
                        then
                          writeln('Mechanism 0x'+IntTOHex(CK_MECHANISMS_TYPE_PTR(pMechanismList)^[ulCount],8)+', which supports signing')  // ,pMechanismList[ulCount])
                        else
                          writeln('Mechanism 0x'+IntTOHex(CK_MECHANISMS_TYPE_PTR(pMechanismList)^[ulCount],8)+', which doesn''t support signing'); //,pMechanismList[ulCount]);
                      end;
                    end;
                  end;
                  freemem(pMechanismList);
                end;
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
  retval:=beidsdk_getsignmechanisms;

  readkey;
end.
