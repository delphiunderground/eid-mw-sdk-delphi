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


{$APPTYPE CONSOLE}
program sign;

uses
  IdSSLOpenSSLHeaders in 'indy_minimal\IdSSLOpenSSLHeaders.pas',
  IdAssignedNumbers in 'indy_minimal\IdAssignedNumbers.pas',
  IdBaseComponent in 'indy_minimal\IdBaseComponent.pas',
  IdCharsets in 'indy_minimal\IdCharsets.pas',
  IdCTypes in 'indy_minimal\IdCTypes.pas',
  IdException in 'indy_minimal\IdException.pas',
  IdFIPS in 'indy_minimal\IdFIPS.pas',
  IdGlobal in 'indy_minimal\IdGlobal.pas',
  IdGlobalProtocols in 'indy_minimal\IdGlobalProtocols.pas',
  IdIDN in 'indy_minimal\IdIDN.pas',
  IdIPAddress in 'indy_minimal\IdIPAddress.pas',
  IdResourceStrings in 'indy_minimal\IdResourceStrings.pas',
  IdResourceStringsCore in 'indy_minimal\IdResourceStringsCore.pas',
  IdResourceStringsOpenSSL in 'indy_minimal\IdResourceStringsOpenSSL.pas',
  IdResourceStringsProtocols in 'indy_minimal\IdResourceStringsProtocols.pas',
  IdStack in 'indy_minimal\IdStack.pas',
  IdStackBSDBase in 'indy_minimal\IdStackBSDBase.pas',
  IdStackConsts in 'indy_minimal\IdStackConsts.pas',
  IdStackWindows in 'indy_minimal\IdStackWindows.pas',
  IdStream in 'indy_minimal\IdStream.pas',
  IdStreamVCL in 'indy_minimal\IdStreamVCL.pas',
  IdWinsock2 in 'indy_minimal\IdWinsock2.pas',
  IdWship6 in 'indy_minimal\IdWship6.pas',
  get_sign;

begin
  beid_Main;
end.
