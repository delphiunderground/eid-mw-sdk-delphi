eid-mw-sdk-delphi is a translation of C code from 
https://github.com/Fedict/eid-mw/tree/master/doc/sdk/examples/C
to Delphi.

Initially, the main goal was to make the Delphi code as close as possible to
the original C code of Fedict.

Now, the goal is rather to make the Delphi code as close as possible
to https://github.com/linuxunderground/eid-mw-sdk-c, which is also a fork of
the original C code of Fedict.

It should work with all versions of Delphi and even with 
Lazarus/FreePascal.

Any suggestions or improvements are welcome.
Send them to vincent.hardy.be@gmail.com


Homepage:
  https://github.com/delphiunderground/eid-mw-sdk-delphi


Indy:

  Required Indy files are embedded with eid-mw-sdk-delphi project.
  However, to run some .exe files, you need libeay32.dll and ssleay32.dll.
  Copy/paste these 2 files in the same directory as your eid-mw-sdk-delphi .exe files.

  Theses 2 dll are available at https://indy.fulgan.com/SSL/


Third-party files:

  PKCS11T.pas:
  http://sourceforge.net/p/projectjedi/website/HEAD/tree/trunk/delphi-jedi.org/www/files/API_Not_Assessed/SmartcardRSA/
  
  wcrypt2.pas:
  You may retrieve the original version of this file here : 
  http://sourceforge.net/p/projectjedi/website/HEAD/tree/trunk/delphi-jedi.org/www/files/api/CryptoAPI2.zip?format=raw
  Howerver, I improved wcrypt2.pas by adding CertGetNameStringW function
  required by cert_registration.pas unit.
  Generally speaking, waiting a more official repository, the latest version
  of wcrypt2.pas is in this github repository.

  
  These 2 files have been released by delphi-jedi.org under Mozilla Public License Version 1.1.
