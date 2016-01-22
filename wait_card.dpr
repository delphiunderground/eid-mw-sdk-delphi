(* ****************************************************************************

* eID Middleware Project.
* Copyright (C) 2009-2010 FedICT.
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

**************************************************************************** *)

{$APPTYPE CONSOLE}
program wait_card;

//PKCS11T.pas can be found here :
//http://sourceforge.net/p/projectjedi/website/HEAD/tree/trunk/delphi-jedi.org/www/files/API_Not_Assessed/SmartcardRSA/

uses
  {$IFDEF FPC}
  crt,
  {$ENDIF}
  Windows, sysutils,
  PKCS11T;

const
  PKCS11DLL = 'beidpkcs11.dll';

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

function beidsdk_waitcard:CK_ULONG;
var
  pkcs11Handle:THandle;                       //handle to the pkcs11 library
  pFunctions:CK_FUNCTION_LIST_PTR;            //list of the pkcs11 function pointers
  pC_GetFunctionList:pointer;
  err:cardinal;
  slotIds:CK_SLOT_ID_PTR;
  slot_count:CK_ULONG;
  slotIdx:CK_ULONG;
  slotinfo:CK_SLOT_INFO;
  slotDescription:array[0..64] of CK_UTF8CHAR;
  cardInserted:CK_BBOOL;
  flags:CK_FLAGS;
  slotId:CK_SLOT_ID;
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
          // retrieve the number of slots (cardreaders)
          // to find also the slots without tokens inserted, set the first parameter to CK_FALSE
          Result:=pFunctions^.C_GetSlotList(CK_FALSE,nil,@Slot_Count);
          if (Result=CKR_OK) and (slot_count>0) then
          begin
            getmem(SlotIds,Slot_Count*sizeof(CK_SLOT_ID));
            Result:=pFunctions^.C_GetSlotList(CK_FALSE,SlotIds,@Slot_Count);
            if (Result=CKR_OK) then
            begin
              cardInserted:=CK_FALSE;
              //check if a card is already present in one of the readers
              for slotIdx:=0 to slot_count-1 do
              begin
                Result:=pFunctions^.C_GetSlotInfo(PByteArray(SlotIds)^[slotIdx],@slotinfo);
                if (Result=CKR_OK) and ((slotinfo.flags and CKF_TOKEN_PRESENT)=CKF_TOKEN_PRESENT) then
                begin
                  move(slotinfo.slotDescription,slotDescription,64);
                  slotDescription[64]:=0;  //make the string null terminated
                  writeln('Card found in reader ',trim(PAnsiChar(@slotDescription[0])));
                  //a card is found in the slot
                  cardInserted:=CK_TRUE;
                end;
              end;

              if (cardInserted=CK_FALSE) then
              begin
                flags:=0;  //use CKF_DONT_BLOCK if you don't want C_WaitForSlotEvent to block
                           //slotId will receive the ID of the slot that the event occurred in
                writeln('Please insert a beid card');
                Result:=pFunctions^.C_WaitForSlotEvent(flags,@slotId,nil);
                if (Result=CKR_OK) then
                begin
                  writeln('Card inserted');
                  for slotIdx:=0 to slot_count-1 do
                  begin
                    if PByteArray(SlotIds)^[slotIdx]=slotId then  //(slotId=slotIds[slotIdx])
                    begin
                      Result:=pFunctions^.C_GetSlotInfo(slotId,@slotinfo);
                      if (Result=CKR_OK) then
                      begin
                        move(slotinfo.slotDescription,slotDescription,64);
                        slotDescription[64]:=0;  //make the string null terminated
                        writeln('into reader ',trim(PAnsiChar(@slotDescription[0])));
                      end;
                    end;
                  end;
                end;
              end;
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
  retval:=beidsdk_waitcard;

  readkey;
end.
