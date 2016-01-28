(* ****************************************************************************

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

**************************************************************************** *)

unit get_X509data;

(*
 * OpenSSL Windows DLL (libeay32.dll) can be found here :
 * https://indy.fulgan.com/SSL/
 *)

interface

uses
  {$IFDEF OpenSSL-Delphi}
  ssl_lib,ssl_x509,ssl_asn,ssl_bn,ssl_ec,ssl_types,ssl_util
  {$ELSE}
  IdSSLOpenSSLHeaders
  {$ENDIF}
  ;

procedure X509Info(pValue:pointer; valueLen:Cardinal);

implementation

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
  {$IFDEF OpenSSL-Delphi}
  SSL_InitX509;
  SSL_InitASN1;
  SSL_InitBN;
  SSL_InitEC;
  {$ELSE}
  IdSSLOpenSSLHeaders.Load;
  {$ENDIF}
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
        OPENSSL_free(tmp);
      end else Writeln('unable to convert BN to decimal string');
      BN_free(bn);
    end else writeln('Unable to convert ASN1INTEGER to BN');
    writeln('SerialNumber: '+sSerial);

    X509_free(aX509);
  end;
  {$IFNDEF OpenSSL-Delphi}
  IdSSLOpenSSLHeaders.unLoad;
  {$ENDIF}
end;

end.
