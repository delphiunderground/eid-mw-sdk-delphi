eid-mw-sdk-delphi is a translation of C code from 
https://github.com/Fedict/eid-mw/tree/master/doc/sdk/examples/C
to Delphi.

The main goal is to make the Delphi code as close as possible to
the original C code of Fedict.

It should work with all versions of Delphi and even with 
Lazarus/FreePascal.

Any suggestions or improvements are welcome.
Send them to vincent.hardy.be@gmail.com

Homepage:
  https://github.com/delphiunderground/eid-mw-sdk-delphi

Third-party files:

  PKCS11T.pas:
  http://sourceforge.net/p/projectjedi/website/HEAD/tree/trunk/delphi-jedi.org/www/files/API_Not_Assessed/SmartcardRSA/
  
  wcrypt2.pas:
  I improved wcrypt2.pas for cert_registration.pas -> CertGetNameStringW
  http://sourceforge.net/p/projectjedi/website/HEAD/tree/trunk/delphi-jedi.org/www/files/api/CryptoAPI2.zip?format=raw
  
  These 2 files have been released by delphi-jedi.org under Mozilla Public License Version 1.1.