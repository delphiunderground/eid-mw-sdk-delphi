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


unit utils;

interface

function EncodeB64(input:Pointer; input_len:integer; output:PAnsiChar; output_maxlen:integer): integer;
function dumpcert(derdata:Pointer; len:integer; pemdata:PAnsiChar; pem_maxlen:integer): integer;


implementation

uses
  {$IFDEF OpenSSL-Delphi}
  ssl_bio, ssl_const, ssl_pem, ssl_types, ssl_x509;
  {$ELSE}
  IdSSLOpenSSLHeaders;
  {$ENDIF}


function EncodeB64(input:pointer; input_len:integer; output:PAnsiChar; output_maxlen:integer): integer;
var
  b64:PBIO;
  bio:PBIO;
begin
  b64:=BIO_new(BIO_f_base64);
  bio:=BIO_new(BIO_s_mem);
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_push(b64, bio);
  result:=BIO_write(b64, input, input_len);
  BIO_flush(b64);
  if result>0 then result:=BIO_read(bio, output, output_maxlen);   //return data length in output
  BIO_free_all(b64);
end;

function dumpcert(derdata:pointer; len:integer; pemdata:PAnsiChar; pem_maxlen:integer): integer;
var
  bio: PBIO;
  aX509: PX509;
begin
  bio:=BIO_new(BIO_s_mem);
  //bio:=BIO_new_fd(handle,0); send pemdata to a file
  aX509:=d2i_X509(nil, @derdata, len);
  if (aX509<>nil) then
  begin
    Result:=PEM_write_bio_X509(bio, aX509);  // 1=OK 0=error
    BIO_flush(bio);
    if Result>0 then Result:=BIO_read(bio, pemdata, pem_maxlen);   //return data length in pemdata
  end else Result:=0;
  BIO_free(bio);
end;


end.

