using System;
using Microsoft.Web.Services;
using Microsoft.Web.Services.Security;
using System.Web.Services.Protocols;
using Microsoft.Web.Services.Security.X509;

namespace Client
{
	class Class1
	{
        private static void Syntax()
        {
            Console.WriteLine("Usage:  Client /a number /b number [certificate_key_id]");
            Console.WriteLine(" Required arguments:");
            Console.WriteLine("	/a			An integer.  First number to add.");
            Console.WriteLine("	/b			An integer.  Second number to add.");
            Console.WriteLine("\nOne or more of the required arguments are missing or incorrectly formed.\n");
        }

		static void Main(string[] args)
		{
            // Check the syntax
            if (args.Length < 4)
            {
                Syntax();
                return;
            }

            String alias = "";
            if(args.Length == 5) {
                alias = args[4];
            }

            // Set the arguments
            int argA = Int32.Parse(args[1]);
            int argB = Int32.Parse(args[3]);

            JavaProxy ip = new JavaProxy();
            
            // Create new contexts from the services
            SoapContext ipReqContext = ip.RequestSoapContext;

            // Prompt the user for the required X509 Certificate to use...
            X509SecurityToken token = GetSecurityToken(alias);
            if (token == null)
                throw new ApplicationException("No key provided for signature.");

            // Add the security token to the Java Proxy
            ipReqContext.Security.Tokens.Add(token);
            ipReqContext.Security.Elements.Add(new Signature(token));
            ipReqContext.Path.MustUnderstand = false;
            
            Console.WriteLine("Calling the Java X509 Service...");
            Console.WriteLine(ip.addInt(argA,argB));	
		}

        /// <summary>
        /// Gets the security token for signing messages.
        /// </summary>
        /// <returns>The X509SecurityToken to sign with</returns>
        protected static X509SecurityToken GetSecurityToken(string certKeyID)
        {            
            X509SecurityToken securityToken;  
            //
            // open the current user's certificate store
            //
            X509CertificateStore store = X509CertificateStore.CurrentUserStore(X509CertificateStore.MyStore);
            bool open = store.OpenRead();

            try 
            {
                Microsoft.Web.Services.Security.X509.X509Certificate cert = null;
                if (certKeyID == null || certKeyID.Length == 0)
                {
                    //
                    // Open a dialog to allow user to select the certificate to use
                    //
                    StoreDialog dialog = new StoreDialog(store);
                    cert = dialog.SelectCertificate(IntPtr.Zero, "Select Certificate", "Choose a Certificate below for signing.");                    
                }
                else
                {
                    byte[] keyId = Convert.FromBase64String(certKeyID);
                    X509CertificateCollection matchingCerts = store.FindCertificateByKeyIdentifier(keyId);
                    if (matchingCerts.Count == 0)
                    {
                        throw new ApplicationException("No matching certificates were found for the key ID provided.");
                    }
                    else
                    {
                        // pick the first one arbitrarily
                        cert = matchingCerts[0];
                    }
                }

                if (cert == null) 
                {
                    throw new ApplicationException("You chose not to select an X509 certificate for signing your messages.");
                }
                else if (!cert.SupportsDigitalSignature || cert.Key == null ) 
                {
                    throw new ApplicationException("The certificate must support digital signatures and have a private key available.");
                }
                else 
                {
                    byte[] keyId = cert.GetKeyIdentifier();
                    Console.WriteLine("Key Name                       : {0}", cert.GetName());
                    Console.WriteLine("Key ID of Certificate selected : {0}\n", Convert.ToBase64String(keyId));
                    securityToken = new X509SecurityToken(cert);
                }
            } 
            finally 
            {
                if (store != null) { store.Close(); }
            }            
            return securityToken;            
        }
	}
}
