/*
 * Created on Sep 8, 2004
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
package org.apache.ws.axis.security.trust.secconv.interop;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Hashtable;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSEncryptBody;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.saml.SAMLIssuer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAudienceRestrictionCondition;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLCondition;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.opensaml.SAMLStatement;
import org.opensaml.SAMLSubject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import sun.security.util.DerValue;

/**
 * This issues signed SAML tokens using the STS's certificate and includes the secret key encrypted by the 
 * service's public key
 * @author Ruchith
 */

public class InteropSAMLIssuerImpl implements SAMLIssuer {


	private static Log log = LogFactory.getLog(InteropSAMLIssuerImpl.class.getName());

	private SAMLAssertion sa = null;

	private Document instanceDoc = null;

   
	private Properties properties = null;

	private Crypto issuerCrypto = null;
	private String issuerKeyPassword = null;
	private String issuerKeyName = null;

	private boolean senderVouches = true;

	private String[] confirmationMethods = new String[1];
	private Crypto userCrypto = null;
	private String username = null;
    
	private String epr = null;
	private byte[] sx;
    
	/**
	 * This holds the set of file paths of the trusted certs of the web services trusted by this STS
	 * The EPRs are used as the keys. This should be initialized in the construtor
	 */
	private Hashtable trustedCertsTable = null;

	/**
	 * @param epr The epr to set.
	 */
	public void setEpr(String epr) {
		this.epr = epr;
	}
	/**
	 * @param sx The sx to set.
	 */
	public void setSx(byte[] sx) {
		this.sx = sx;
	}
	/**
	 * Constructor.
	 */
	public InteropSAMLIssuerImpl() {
	}

	public InteropSAMLIssuerImpl(Properties prop) {
		/*
		 * if no properties .. just return an instance, the rest will be done
		 * later or this instance is just used to handle certificate
		 * conversions in this implementatio
		 */
		if (prop == null) {
			return;
		}
		properties = prop;

		String cryptoProp =
				properties.getProperty("org.apache.ws.security.saml.issuer.cryptoProp.file");
		if (cryptoProp != null) {
			issuerCrypto = CryptoFactory.getInstance(cryptoProp);
			issuerKeyName =
					properties.getProperty("org.apache.ws.security.saml.issuer.key.name");
			issuerKeyPassword =
					properties.getProperty("org.apache.ws.security.saml.issuer.key.password");
		}

		if ("senderVouches"
				.equals(properties.getProperty("org.apache.ws.security.saml.confirmationMethod"))) {
			confirmationMethods[0] = SAMLSubject.CONF_SENDER_VOUCHES;
		} else if (
				"keyHolder".equals(properties.getProperty("org.apache.ws.security.saml.confirmationMethod"))) {
			confirmationMethods[0] = SAMLSubject.CONF_HOLDER_KEY;
			senderVouches = false;
		} else {
			// throw something here - this is a mandatory property
		}
        
		this.initializeTrustedServicesList(properties.getProperty("org.apache.ws.security.saml.certPath"));
	}

	/**
	 * Creates a new <code>SAMLAssertion</code>.
	 * 
	 * <p/>
	 * <p/>
	 * A complete <code>SAMLAssertion</code> is constructed.
	 *
	 * @return SAMLAssertion
	 */
	public SAMLAssertion newAssertion() { // throws Exception {

		String issuer =
				properties.getProperty("org.apache.ws.security.saml.issuer");
        
		String format = properties.getProperty("org.apache.ws.security.saml.subjectNameId.format");
        
		try {
			SAMLNameIdentifier nameId =
					new SAMLNameIdentifier(this.username, "", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
			String subjectIP = null;
			String authMethod = null;
			if ("password"
					.equals(properties.getProperty("org.apache.ws.security.saml.authenticationMethod"))) {
				authMethod =
						SAMLAuthenticationStatement.AuthenticationMethod_Password;
			}
			Date authInstant = new Date();
			Collection bindings = null;

			SAMLSubject subject =
					new SAMLSubject(nameId,
							Arrays.asList(confirmationMethods),
							null,
							null);
			SAMLStatement[] statements =
					{
						new SAMLAuthenticationStatement(subject,
								authMethod,
								authInstant,
								subjectIP,
								null,
								bindings)};
			//SAML Conditions
			SAMLAudienceRestrictionCondition sarc = new SAMLAudienceRestrictionCondition();
			sarc.addAudience(epr);            
			SAMLCondition[] conditions = {sarc};
            
			sa =
					new SAMLAssertion(issuer,
							null,
							null,
							Arrays.asList(conditions),
							null,
							Arrays.asList(statements));
      
			Date now = new Date();
			sa.setNotBefore(now);
			sa.setNotOnOrAfter(new Date(now.getTime()+ 12*60*60*1000));
			
    
			if (!senderVouches) {
				Element soapEnvelope = (Element)this.instanceDoc.getFirstChild();
				soapEnvelope.setAttribute("xmlns:wsse",WSConstants.WSSE_NS);
				KeyInfo ki = new KeyInfo(instanceDoc);             	
				try {
					X509Certificate cer = this.getCertificate(this.epr);
					Element xencEnckey =  this.encryptSx(this.instanceDoc, cer);
                    
					WSSecurityUtil.appendChildElement(this.instanceDoc, ki.getElement(), xencEnckey);
					subject.setKeyInfo(ki); //Set the key info
				} catch (WSSecurityException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (CertificateException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (FileNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
            	
//				  KeyInfo ki = new KeyInfo(instanceDoc);
//				  Element xencEncryptedKey = WSEncryptBody.createEnrcyptedKey(this.instanceDoc, WSConstants.KEYTRANSPORT_RSAOEP);
//				  try {
					//Create encrypted key - BEGIN
                    
					//Use XML Security RSAOEP to encrypt the key sx - BEGIN
//					  XMLCipher xmlCipher = null;
//						  xmlCipher = XMLCipher.getInstance(WSConstants.KEYTRANSPORT_RSAOEP);
//                        
//                    
//					  X509Certificate remoteCert = this.getCertificate(this.epr); //Get the public key cert of service
//                    
//					  xmlCipher.init(XMLCipher.ENCRYPT_MODE,remoteCert.getPublicKey());
//                    
//					  EncryptedKey encKey = xmlCipher.createEncryptedKey(CipherData.VALUE_TYPE,new String("1234567890123456"));
//					  String cipherValue = encKey.getCipherData().getCipherValue().getValue(); //Cipher value
//					System.out.println("xyz is " + cipherValue);
//					  /*
//					   * IMPORTANT: have to do this because without this when the xml is parsed at the next handler
//					   * (AddressingHandler in this case) it throws an exception saying prefix "wsse" is not bound
//					   */
//					  Element soapEnvelope = (Element)this.instanceDoc.getFirstChild();
//					  soapEnvelope.setAttribute("xmlns:wsse",WSConstants.WSSE_NS);
//					  //Use XML Security RSAOEP to encrypt the key sx - END
//                    
//					SecurityTokenReference secToken = new SecurityTokenReference(WSSConfig.getDefaultWSConfig(),this.instanceDoc);
//					secToken.setKeyIdentifier(remoteCert);
//	                
//					KeyInfo keyInfo = new KeyInfo(this.instanceDoc);
//					keyInfo.addUnknownElement(secToken.getElement());
//	                
//					WSSecurityUtil.appendChildElement(this.instanceDoc, xencEncryptedKey, keyInfo.getElement());
//
//					Element xencCipherValue = WSEncryptBody.createCipherValue(this.instanceDoc, xencEncryptedKey);
//	                
//					System.out.println("xyz is " + cipherValue);
//					  //Base64 encoded cipher value
//					Text keyText = WSSecurityUtil.createBase64EncodedTextNode(this.instanceDoc, cipherValue.getBytes());
//					xencCipherValue.appendChild(keyText); //Set the cipher value
//	                
//					//Create encrypted key - END
//	                
//				  } catch (Exception e) {
//					e.printStackTrace();
//				  }
//
//				  WSSecurityUtil.appendChildElement(this.instanceDoc, ki.getElement(), xencEncryptedKey);
//				  subject.setKeyInfo(ki); //Set the key info

				// prepare to sign the SAML token
				try {
					X509Certificate[] issuerCerts =
							issuerCrypto.getCertificates(issuerKeyName);

					String sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_RSA;
					String pubKeyAlgo =
							issuerCerts[0].getPublicKey().getAlgorithm();
					log.debug("automatic sig algo detection: " + pubKeyAlgo);
					if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
						sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_DSA;
					}
					java.security.Key issuerPK =
							issuerCrypto.getPrivateKey(issuerKeyName,
									issuerKeyPassword);
					sa.sign(sigAlgo, issuerPK, Arrays.asList(issuerCerts));
				} catch (WSSecurityException e1) {
					e1.printStackTrace();
					return null;
				} catch (Exception e1) {
					e1.printStackTrace();
					return null;
				}
			}
		} catch (SAMLException ex) {
			ex.printStackTrace();
			throw new RuntimeException(ex.toString());
		}
		return sa;
	}

	/**
	 * @param userCrypto The userCrypto to set.
	 */
	public void setUserCrypto(Crypto userCrypto) {
		this.userCrypto = userCrypto;
	}

	/**
	 * @param username The username to set.
	 */
	public void setUsername(String username) {
		this.username = username;
	}

	/**
	 * @return Returns the issuerCrypto.
	 */
	public Crypto getIssuerCrypto() {
		return issuerCrypto;
	}

	/**
	 * @return Returns the issuerKeyName.
	 */
	public String getIssuerKeyName() {
		return issuerKeyName;
	}

	/**
	 * @return Returns the issuerKeyPassword.
	 */
	public String getIssuerKeyPassword() {
		return issuerKeyPassword;
	}

	/**
	 * @return Returns the senderVouches.
	 */
	public boolean isSenderVouches() {
		return senderVouches;
	}

	/**
	 * @param instanceDoc The instanceDoc to set.
	 */
	public void setInstanceDoc(Document instanceDoc) {
		this.instanceDoc = instanceDoc;
	}

	/**
	 * This returns the certificate of a trusted service
	 * @param epr The endpoint reference uri as a <code>String</code>
	 * @return X509 Certificate of the service 
	 * @throws CertificateException
	 * @throws FileNotFoundException
	 */
	private X509Certificate getCertificate(String epr) throws CertificateException, FileNotFoundException {
		String certPath = (String)this.trustedCertsTable.get(epr);//Lookup the table and get the cert location
		CertificateFactory certFac = CertificateFactory.getInstance("X.509");
		System.out.println(certPath +" : "+epr);
		return (X509Certificate)certFac.generateCertificate(new FileInputStream(certPath));
	}

	/**
	 * Read the trustedServices.xml and load the certificates 
	 */
	private void initializeTrustedServicesList(String certPath) {
		this.trustedCertsTable =  new Hashtable();
		System.out.println("***** If you are getting trouble, change the seravices *****\n" +
			"FIND ANOTHER WAY TO STORE THE TRUSTED LIST OF SERVICES WITH THE RELAVENT CERTIFICATES");
		this.trustedCertsTable.put("http://127.0.0.1:9080/axis/services/EchoInterop",certPath+"/WSETEST.cer");
		//Microsoft
		this.trustedCertsTable.put("http://192.168.1.106/Service/Service.ashx",certPath+"TrustSecConvinterop/ms1/cert1.cer");//"C:/TrustSecConvinterop/ms1/cert1.cer");
		//IBM
		this.trustedCertsTable.put("http://192.168.1.50:8080/sct/Service",certPath+"TrustSecConvinterop/ibm/ibm-sp.cer");
		this.trustedCertsTable.put("http://192.35.232.216:8080/sct/Service",certPath+"TrustSecConvinterop/ibm/ibm-sp2.cer");
		//systinet
		this.trustedCertsTable.put("http://192.168.1.104:7070/Service",certPath+"TrustSecConvinterop/systinet/Systinet-S.crt");
		
	}

	
	
	public Element encryptSx(Document doc, X509Certificate remoteCert) throws WSSecurityException {
			log.debug("Beginning Encryption...");
			

			  /*
         * First step: set the encryption encoding namespace in the SOAP:Envelope
         */
        Element envelope = doc.getDocumentElement();
        envelope.setAttributeNS(WSConstants.XMLNS_NS,
                "xmlns:" + WSConstants.ENC_PREFIX,
                WSConstants.ENC_NS);

       // SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(envelope);


			/*
			 * Second step: generate a symmetric key (session key) for
			 * this alogrithm, and set the cipher into encryption mode.
			 */
			SecretKey symmetricKey = new SecretKeySpec(sx,WSConstants.AES_128);
						      
		
		//
		
			String certUri = "EncCertId-" + remoteCert.hashCode();
			
			Cipher cipher = WSSecurityUtil.getCipherInstance(WSConstants.KEYTRANSPORT_RSA15);
			
			try {
				cipher.init(Cipher.ENCRYPT_MODE, remoteCert);
			} catch (InvalidKeyException e) {
				throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC, null, null, e);
			}
			byte[] encKey = symmetricKey.getEncoded();
			
			byte[] encryptedKey = null;
			
			try {
				encryptedKey = cipher.doFinal(encKey);
			} catch (IllegalStateException e1) {
				throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC, null, null, e1);
			} catch (IllegalBlockSizeException e1) {
				throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC, null, null, e1);
			} catch (BadPaddingException e1) {
				throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC, null, null, e1);
			}
			Text keyText =
					WSSecurityUtil.createBase64EncodedTextNode(doc, encryptedKey);

			/*
			 * Now we need to setup the wsse:Security header block
			 * 1) get (or create) the wsse:Security header block
			 * 2) create the xenc:EncryptedKey element. This already includes
			 *    the ExcrpytionMethod element with attributes that define
			 *    the key transport encryption algorithm
			 * 3) Generate ds:KeyInfo element, this wraps the wsse:SecurityTokenReference
			 * 4) set up the SecurityTokenReference, either with KeyIdentifier or
			 *    X509IssuerSerial. The SecTokenRef defines how to get to security
			 *    token used to encrypt the session key (this security token usually
			 *    contains a public key)
			 * 5) Create the CipherValue element structure and insert the encrypted
			 *    session key
			 * 6) The last step sets up the reference list that pints to the encrypted
			 *    data that was encrypted with this encrypted session key :-)
			 */
			Element xencEncryptedKey = WSEncryptBody.createEnrcyptedKey(doc, WSConstants.KEYTRANSPORT_RSAOEP);
			
			X509Data x509Data = new X509Data(doc);
			x509Data.addSKI(getSKIBytesFromCert(remoteCert));
			
			KeyInfo keyInfo = new KeyInfo(doc);
			keyInfo.addUnknownElement(x509Data.getElement());
			//SecurityTokenReference secTokRef = new SecurityTokenReference(WSSConfig.getDefaultWSConfig(), doc);
		    //WSSecurityUtil.appendChildElement(doc, secTokRef.getElement(), keyInfo.getElement());
			WSSecurityUtil.appendChildElement(doc, xencEncryptedKey, keyInfo.getElement());

			Element xencCipherValue = WSEncryptBody.createCipherValue(doc, xencEncryptedKey);
			xencCipherValue.appendChild(keyText);
			
			log.debug("Encryption complete.");
			
			return xencEncryptedKey;
		}


	//This was stolen from Merlin :D
	public byte[] getSKIBytesFromCert(X509Certificate cert)
		 throws WSSecurityException {

	 byte data[] = null;
	 byte abyte0[] = null;
	 if (cert.getVersion() < 3) {
		 throw new WSSecurityException(1, "noSKIHandling",
				 new Object[] { "Wrong certificate version (<3)" });
	 }

	 /*
	  * Gets the DER-encoded OCTET string for the extension value (extnValue)
	  * identified by the passed-in oid String. The oid string is
	  * represented by a set of positive whole numbers separated by periods.
	  */
	 data = cert.getExtensionValue("2.5.29.14");//Not sure what this is !!!!

	 if (data == null) {
		 throw new WSSecurityException(
				 WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
				 "noSKIHandling", new Object[] { "No extension data" });
	 }
	 DerValue derValue = null;
	 try {
		 derValue = new DerValue(data);
	 } catch (IOException e) {
		 throw new WSSecurityException(
				 WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
				 "noSKIHandling", new Object[] { "cannot read SKI value" });
	 }

	 if (derValue == null) {
		 throw new WSSecurityException(
				 WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
				 "noSKIHandling", new Object[] { "No DER value" });
	 }
	 if (derValue.tag != DerValue.tag_OctetString) {
		 throw new WSSecurityException(
				 WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
				 "noSKIHandling", new Object[] { "No octet string" });
	 }
	 byte[] extensionValue = null;
	 try {
		 extensionValue = derValue.getOctetString();
	 } catch (IOException e1) {
		 throw new WSSecurityException(
				 WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
				 "noSKIHandling",
				 new Object[] { "cannot read SKI value as octet data" });
	 }

	 /**
	  * Strip away first two bytes from the DerValue (tag and length)
	  */
	 abyte0 = new byte[extensionValue.length - 2];

	 System.arraycopy(extensionValue, 2, abyte0, 0, abyte0.length);

	 /*
	  byte abyte0[] = new byte[derEncodedValue.length - 4];
	  System.arraycopy(derEncodedValue, 4, abyte0, 0, abyte0.length);
	  */
	 return abyte0;
 }	
	
}
