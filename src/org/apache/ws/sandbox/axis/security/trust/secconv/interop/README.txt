This is an implementation of "WS-SecureConversation and WS-Trust 
Interop Scenarios"

Version 0.8
July 24, 2004

User Instructions
=================
Please set the properties of Inerop_data.properties file correctly.
Then in the "interop_saml_STS.properties" set the absolute path to the interop2 folder.



TODO
=====
MustDo
 Fix RSA too much data problem

Will work without the fixing the following, but incorect.
 Right now absolute path of the folder containing certificates must be specified in the data.properties. Find a 
 better way to load certificates.
 Right now list of trusted services are hardcoded. Remove the hardcoding
 Right now list of users are hardcoded. Remove the hardcoding
 Remove the critical System.out problem. If this line is commented then doesn't work
 Use addressing corectly at the client side- we are not usig it corectly at client side.
 
 