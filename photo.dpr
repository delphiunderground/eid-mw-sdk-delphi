(*
 * https://github.com/delphiunderground/eid-mw-sdk-delphi
 * Copyright (C) 2016 Vincent Hardy <vincent.hardy.be@gmail.com>
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


{$APPTYPE CONSOLE}
program photo;

uses
  classes,
  Shlobj,
  Windows,
  sysutils,
  jpeg,
  graphics,
  PKCS11T;

const
  PKCS11DLL = 'beidpkcs11.dll';

  TOPLEFT = 0;
  TOPCENTER = 1;
  TOPRIGHT = 2;
  CENTLEFT = 3;
  CENTER = 4;
  CENTRIGHT = 5;
  BOTLEFT = 6;
  BOTCENTER = 7;
  BOTRIGHT = 8;
  SLASH = 9;
  BACKSLASH = 10;

  orientations: array[0..15] of integer=
  (            //br bl tr tl
    CENTER,    // 0  0  0  0
    TOPLEFT,   // 0  0  0  1
    TOPRIGHT,  // 0  0  1  0
    TOPCENTER, // 0  0  1  1
    BOTLEFT,   // 0  1  0  0
    CENTLEFT,  // 0  1  0  1
    SLASH,     // 0  1  1  0
    TOPLEFT,   // 0  1  1  1
    BOTRIGHT,  // 1  0  0  0
    BACKSLASH, // 1  0  0  1
    CENTRIGHT, // 1  0  1  0
    TOPRIGHT,  // 1  0  1  1
    BOTCENTER, // 1  1  0  0
    BOTLEFT,   // 1  1  0  1
    BOTRIGHT,  // 1  1  1  0
    CENTER     // 1  1  1  1
  );

  translate: array[0..3,0..10] of ansichar =
  (
    ( ' ',  ' ',  ' ',  ' ',  ' ',  ' ',  ' ',  ' ',  ' ', ' ', ' ' ),
    ( #96, '''',  #39,  '>',  '-',  '<',  ',',  '_',  '.', '/', '\' ),
    ( '"',  '?',  '"',  '[',  '*',  ']',  'b',  'o',  'd', '/', '\' ),
    ( 'F',  'V',  '$',  '#',  '@',  '#',  '&',  'W',  'Q', '/', '\' )
  );


procedure jpegdump(pFileValue:CK_VOID_PTR; FileValueLen:CK_ULONG);
var
  St:TMemoryStream;
  Jpg:TJpegImage;
  Photo:TBitmap;
  L1,L2:PByteArray;
  bpp:byte;
  rlen,x,y:Integer;
  p:array[0..3] of integer;     //pixel
  d:array[0..3] of integer;     //duty
  dt:integer;
  k,m,ori:integer;
begin
  St:=TMemoryStream.create;
  St.WriteBuffer(pFileValue^,FileValueLen);
  St.Seek(0,0);
  Jpg:=TJpegImage.Create;
  Jpg.LoadFromStream(St);
  Photo:=TBitmap.create;
  Photo.Assign(Jpg);
  Jpg.Free;
  St.Free;
  With Photo do
  try
    case PixelFormat of
    pf8bit:bpp:=1;
    pf16bit:bpp:=2;  //should never happen
    pf24bit:bpp:=3;
    pf32bit:bpp:=4;  //should never happen
    else bpp:=0;     //not supported / should never happen
    end;

    writeln('image has '+IntToStr(bpp)+' byte(s) per pixel');
    rlen:=width*bpp;
    writeln('Read '+IntToStr(height)+' scanlines');

    y:=0;
    while y<height do
    begin
      L1:=ScanLine[y];
      L2:=ScanLine[y+1];
      x:=0;
      while x<rlen do
      begin
        p[0]:=255-L1[x];
        p[1]:=255-L1[x+1];
        p[2]:=255-L2[x];
        p[3]:=255-L2[x+1];
        ori:=0;
        m:=0;
        for k:=0 to 3 do
        begin
          d[k]:=p[k] shr 6;
          if d[k]>m then
          begin
            m:=d[k];
            ori:=1 shl k;
          end else
          if d[k]=m then
          begin
            ori:=ori or (1 shl k);
          end;
        end;
        dt:=(p[0] + p[1] + p[2] + p[3]) shr 8;
        ori:=orientations[ori];
        write(translate[dt][ori]);
        inc(x,2)
      end;
      writeln;
      inc(y,2);
    end;
  finally
    Photo.free;
  end;
end;

procedure save_photo(data:CK_VOID_PTR; len:CK_ULONG);
var
  SFolder:pItemIDList;
  SpecialPath:Array[0..MAX_PATH] Of Char;
  f:file;
begin
  SHGetSpecialFolderLocation(0, CSIDL_PERSONAL, SFolder);   // "My Documents"
  SHGetPathFromIDList(SFolder, @SpecialPath);
  AssignFile(f,string(SpecialPath)+'\eid-photo.jpg');
  Rewrite(f,len);
  BlockWrite(f,data^,1);
  CloseFile(f);
end;

function Beidsdk_Decode_Photo(pFunctions:CK_FUNCTION_LIST_PTR;
                              session_handle:CK_SESSION_HANDLE):CK_RV;
var
  typesearch:CK_ULONG;
  searchtemplate:array[1..2] of CK_ATTRIBUTE;
  hObject:CK_OBJECT_HANDLE;
  ObjectCount:CK_ULONG;
  label_str:pointer;
  value_str:pointer;
  objid_str:pointer;
  data:array[1..3] of CK_ATTRIBUTE;
begin
  Result:=CKR_OK;
  label_str:=nil;
  value_str:=nil;
  objid_str:=nil;
  typesearch:=CKO_DATA;
  With searchtemplate[1] do
  begin
    _type:=CKA_CLASS;
    pValue:=@typesearch;
    ulValueLen:=sizeof(CK_ULONG);
  end;
  With searchtemplate[2] do
  begin
    _type:=CKA_LABEL;
    pValue:=pAnsiChar('PHOTO_FILE');
    ulValueLen:=strlen(pAnsiChar('PHOTO_FILE'));
  end;
  //initialize the search for the objects 'PHOTO_FILE'
  Result:=pFunctions^.C_FindObjectsInit(session_handle, @searchtemplate, 2);
  if (Result=CKR_OK) then
  begin
    //find the first object with label 'PHOTO_FILE'
    Result:=pFunctions^.C_FindObjects(session_handle,@hObject,1,@ObjectCount);
    if ObjectCount=1 then
    begin
      //retrieve the length of the data from the object
      With data[1] do
      begin
        _type:=CKA_LABEL;
        pValue:=nil;
        ulValueLen:=0;
      end;
      With data[2] do
      begin
        _type:=CKA_VALUE;
        pValue:=nil;
        ulValueLen:=0;
      end;
      With data[3] do
      begin
        _type:=CKA_OBJECT_ID;
        pValue:=nil;
        ulValueLen:=0;
      end;

      Result:=pFunctions^.C_GetAttributeValue(session_handle,hObject,@data,3);
      if (Result=CKR_OK) and
         (integer(data[1].ulValueLen)>=0) and
         (integer(data[2].ulValueLen)>=0) and
         (integer(data[3].ulValueLen)>=0) then
      begin
        GetMem(label_str,data[1].ulValueLen+1);
        data[1].pValue:=label_str;
        GetMem(value_str,data[2].ulValueLen);
        data[2].pValue:=value_str;
        GetMem(objid_str,data[3].ulValueLen+1);
        data[3].pValue:=objid_str;
        if (label_str<>nil) and (value_str<>nil) and (objid_str<>nil) then
        begin
          fillchar(label_str^,data[1].ulValueLen+1,0); //like this, it will be null terminated
          fillchar(objid_str^,data[3].ulValueLen+1,0); //like this, it will be null terminated
          //now run C_GetAttributeValue a second time to actually retrieve the
          //data from the object
          Result:=pFunctions^.C_GetAttributeValue(session_handle,hObject,@data,3);
          save_photo(value_str,data[2].ulValueLen);
          writeln('Data object with object ID: '+PAnsiChar(objid_str)+'; label: '+
                  PAnsiChar(label_str)+'; length: '+IntToStr(data[2].ulValueLen));
          writeln('Contents(ASCII art representation):');
          jpegdump(value_str, data[2].ulValueLen);
        end;
        if label_str<>nil then FreeMem(label_str);
        if value_str<>nil then FreeMem(value_str);
        if objid_str<>nil then FreeMem(objid_str);
      end;
    end;
    //finalize the search
    Result:=pFunctions^.C_FindObjectsFinal(session_handle);
  end;
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
                Result:=pFunctions^.C_OpenSession(PByteArray(SlotIds)^[slotIdx],CKF_SERIAL_SESSION,nil,nil,@session_handle);
                if (Result=CKR_OK) then
                begin
                  Result:=Beidsdk_Decode_Photo(pFunctions, session_handle);
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

begin
  beidsdk_GetData;
end.
