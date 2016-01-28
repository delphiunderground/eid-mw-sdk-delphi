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

{$APPTYPE CONSOLE}
program X509cert;

uses
  {$IFDEF OpenSSL-Delphi}
  ssl_ec in 'OpenSSL-Delphi\ssl_ec.pas',
  ssl_bn in 'OpenSSL-Delphi\ssl_bn.pas',
  ssl_util in 'OpenSSL-Delphi\ssl_util.pas',
  ssl_objects in 'OpenSSL-Delphi\ssl_objects.pas',
  ssl_lib in'OpenSSL-Delphi\ssl_lib.pas',
  ssl_err in 'OpenSSL-Delphi\ssl_err.pas',
  ssl_evp in 'OpenSSL-Delphi\ssl_evp.pas',
  ssl_types in 'OpenSSL-Delphi\ssl_types.pas',
  ssl_x509 in 'OpenSSL-Delphi\ssl_x509.pas',
  ssl_const in 'OpenSSL-Delphi\ssl_const.pas',
  ssl_asn in 'OpenSSL-Delphi\ssl_asn.pas',
  {$ELSE}
  IdSSLOpenSSLHeaders in 'indy_minimal\IdSSLOpenSSLHeaders.pas',
  IdBaseComponent in 'indy_minimal\IdBaseComponent.pas',
  IdCTypes in 'indy_minimal\IdCTypes.pas',
  IdFIPS in 'indy_minimal\IdFIPS.pas',
  IdGlobal in 'indy_minimal\IdGlobal.pas',
  IdGlobalProtocols in 'indy_minimal\IdGlobalProtocols.pas',
  IdIPAddress in 'indy_minimal\IdIPAddress.pas',
  IdResourceStrings in 'indy_minimal\IdResourceStrings.pas',
  IdResourceStringsOpenSSL in 'indy_minimal\IdResourceStringsOpenSSL.pas',
  IdStack in 'indy_minimal\IdStack.pas',
  IdStackBSDBase in 'indy_minimal\IdStackBSDBase.pas',
  IdStackConsts in 'indy_minimal\IdStackConsts.pas',
  IdStackWindows in 'indy_minimal\IdStackWindows.pas',
  IdStream in 'indy_minimal\IdStream.pas',
  IdStreamVCL in 'indy_minimal\IdStreamVCL.pas',
  IdWinsock2 in 'indy_minimal\IdWinsock2.pas',
  IdWship6 in 'indy_minimal\IdWship6.pas',
  {$ENDIF}
  get_X509cert;

begin
  beid_Main;
end.
