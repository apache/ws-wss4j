/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.apache.ws.security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.EnvelopeIdResolver;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.PKIPathSecurity;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.transform.STRTransform;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Base64;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.Map;
import java.util.Vector;

/**
 * WS-Security Engine.
 * <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com).
 * @author Werner Dittmann (Werner.Dittmann@siemens.com).
 */
public class WSSecurityEngine {
    private static Log log = LogFactory.getLog(WSSecurityEngine.class.getName());
	private static Log tlog =
		LogFactory.getLog("org.apache.ws.security.TIME");

    private static final Class[] constructorType = {org.w3c.dom.Element.class};
    private static Map tokenImpl = new Hashtable();
    private static boolean sigCheck = true;
    private static WSSecurityEngine engine = null;
    
    private boolean doDebug = false;
    /**
     * <code>wsse:BinarySecurityToken</code> as defined by WS Security specification
     */
    protected static final QName BINARY_TOKEN = new QName(WSConstants.WSSE_NS, WSConstants.BINARY_TOKEN_LN);
	/**
	 * <code>wsse:UsernameToken</code> as defined by WS Security specification
	 */
    protected static final QName USERNAME_TOKEN = new QName(WSConstants.WSSE_NS, WSConstants.USERNAME_TOKEN_LN);
	/**
	 * <code>ds:Signature</code> as defined by XML Signature specification,
	 * enhanced by WS Security specification
	 */
    protected static final QName SIGNATURE = new QName(WSConstants.SIG_NS, WSConstants.SIG_LN);
	/**
	 * <code>xenc:EncryptedKey</code> as defined by XML Encryption specification,
	 * enhanced by WS Security specification
	 */
    protected static final QName ENCRYPTED_KEY = new QName(WSConstants.ENC_NS, WSConstants.ENC_KEY_LN);
	/**
	 * <code>xenc:ReferenceList</code> as defined by XML Encryption specification,
	 */
    protected static final QName REFERENCE_LIST = new QName(WSConstants.ENC_NS, WSConstants.REF_LIST_LN);
	/**
	 * <code>wsu:Timestamp</code> as defined by OASIS WS Security specification,
	 */
	protected static final QName TIMESTAMP = new QName(WSConstants.WSU_NS, "wsu:Timestamp");


    static {
        org.apache.xml.security.Init.init();
        String Id = "BC";
        if (java.security.Security.getProvider(Id) == null) {
            log.debug("The provider " + Id
                    + " had to be added to the java.security.Security");
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
        tokenImpl.put(PKIPathSecurity.TYPE, PKIPathSecurity.class);
        tokenImpl.put(X509Security.TYPE, X509Security.class);
		Transform.init();
		try {
			Transform.register(STRTransform.implementedTransformURI,
				"org.apache.ws.security.transform.STRTransform");
		} catch (Exception ex) {
		};
    }

    /**
     * Singleton instance of security engine.
     * <p/>
     * 
     * @return ws-security engine.
     */
    public synchronized static WSSecurityEngine getInstance() {
        if (engine == null) {
            engine = new WSSecurityEngine();
        }
        return engine;
    }

    /**
     * Process the security header given the soap envelope as W3C document.
     * <p/>
     * This is the main entry point to verify or decrypt a SOAP enevelope.
     * First check if a <code>wsse:Security</code> is availabe with the
     * defined actor.
     * 
     * @param doc		the SOAP envelope as {@link Document}
     * @param actor		the engine works on behalf of this <code>actor</code>. Refer
     * 					to the SOAP specification about <code>actor</code> or <code>role
     * 					</code>
     * @param cb		a callback hander to the caller to resolve passwords during
     * 					encryption and {@link UsernameToken} handling
     * @param crypto	the object that implements the access to the keystore and the
     * 					handling of certificates.
     * @return			a validated principal if a the SOAP enevlope conatined a signature
     * 					or a UsernameToken and signature or UsernameToken were successfully
     * 					verified. The functions returns <code>null</code> if no
     * 					Signature or UeernameToken were found and only a decryption 
     * 					was done  
     * @throws Exception 
     */
	public WSSecurityEngineResult processSecurityHeader(Document doc, 
										   String actor, 
										   CallbackHandler cb, 
										   Crypto crypto) throws Exception {
		return processSecurityHeader(doc, actor, cb, crypto, crypto);	
	}
	
	public WSSecurityEngineResult processSecurityHeader(Document doc, 
										   String actor, 
										   CallbackHandler cb, 
										   Crypto sigCrypto, 
										   Crypto decCrypto) throws Exception {
										   	
		doDebug = log.isDebugEnabled();
		if (doDebug) {
			log.debug("WSSecurityEnging: enter processSecurityHeader()");
		}
										   	
        if (actor == null) {
            actor = "";
        }
        NodeList list = doc.getElementsByTagNameNS(WSConstants.WSSE_NS, WSConstants.WSSE_LN);
        int len = list.getLength();
        if (len == 0) {		// No Security headers found
            return null;
        }
        if (doDebug) {
			log.debug("Found WS-Security header(s): " + len);
        }
        Element elem = null;
        Attr attr = null;
        String headerActor = null;
		WSSecurityEngineResult wsResult = null;
		SOAPConstants sc = WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());

        for (int i = 0; i < len; i++) {
            elem = (Element) list.item(i);
            attr = elem.getAttributeNodeNS(sc.getEnvelopeURI(), sc.getRoleAttributeQName().getLocalPart());
            if (attr != null) {
                headerActor = attr.getValue();
            }
            if ((headerActor == null) || (headerActor.length() == 0) ||
            	headerActor.equalsIgnoreCase(actor) ||
       			headerActor.equals(sc.getNextRoleURI())) {
       			if (doDebug) {
                	log.debug("Processing WS-Security header for '" + actor + "' actor.");
       			}
                wsResult = processSecurityHeader(elem, cb, sigCrypto, decCrypto);
            }
        }
        return wsResult;
    }

    /**
     * Process the security header given the <code>wsse:Security</code> DOM Element.
     * <p/>
     * This function loops over all direct child elements of the
     * <code>wsse:Security</code> header. If it finds a knwon element, it transfers
     * control to the appropriate handling function. The mehtod processes the
     * known child elements in the same order as they appear in the
     * <code>wsse:Security</code> element. This is in accordance to the
     * WS Security specification. 
     * <p/>
     * Currently the functions can handle the following child elements:
     * here:
     * <ul>
     * <li> {@link #SIGNATURE <code>ds:Signature</code>} </li>
     * <li> {@link #ENCRYPTED_KEY <code>xenc:EncryptedKey</code>} </li>
     * <li> {@link #USERNAME_TOKEN <code>wsse:UsernameToken</code>} </li>
     * </ul>
     * <p/>
     * 
     * @param securityHeader the <code>wsse:Security</code> header element
     * @param cb            a callback hander to the caller to resolve passwords during
     * 						encryption and {@link UsernameToken} handling
     * @param crypto		the object that implements the access to the keystore and the
     * 						handling of certificates.
     * @return				a validated principal if a the SOAP enevlope conatined a signature
     * 						or a UsernameToken and signature or UsernameToken were successfully
     * 						verified. The functions returns <code>null</code> if no
     * 						Signature or UsernameToken were found and only a decryption 
     * 						was done.
     * @throws Exception 
     */
    protected WSSecurityEngineResult processSecurityHeader(Element securityHeader, 
    									   CallbackHandler cb,
    									   Crypto sigCrypto,
    									   Crypto decCrypto) throws Exception {
 
		long t0=0, t1=0, t2=0;
		if( tlog.isDebugEnabled() ) {
			t0=System.currentTimeMillis();
		}
		/*
		 * Gather some info about the document to process and store
		 * it for retrival. Store the implemenation of signature crypto
		 * (no need for encryption --- yet) 
		 */
		WSDocInfo wsDocInfo = new WSDocInfo(securityHeader.getOwnerDocument().hashCode());
		wsDocInfo.setCrypto(sigCrypto);
				
        NodeList list = securityHeader.getChildNodes();
        int len = list.getLength();
        Node elem;
        String localName = null;
        String namespace = null;
        Principal lastPrincipalFound = null;
		if( tlog.isDebugEnabled() ) {
			t1=System.currentTimeMillis();
		}
		Vector actions = new Vector();
		Vector principals = new Vector();
		
        for (int i = 0; i < len; i++) {
            elem = list.item(i);
            if (elem.getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            QName el = new QName(elem.getNamespaceURI(), elem.getLocalName());
            if (el.equals(SIGNATURE)) {
            	if (doDebug) {
                	log.debug("Found signature element");
            	}
				long t00=0, t01=0;
				if( tlog.isDebugEnabled() ) {
					t00=System.currentTimeMillis();
				}
                XMLSignature sig = new XMLSignature((Element) elem, null);
				if( tlog.isDebugEnabled() ) {
					t01=System.currentTimeMillis();
					tlog.debug("newXMLSig(elem)= " + (t01-t00));
				}
                sig.addResourceResolver(EnvelopeIdResolver.getInstance());

				if (sigCrypto == null) {
					throw new WSSecurityException(WSSecurityException.FAILURE, 
												  "noSigCryptoFile");
				}
				WSDocInfoStore.store(wsDocInfo);
				try {
					lastPrincipalFound = verifyXMLSignature(sig, sigCrypto);
				}
				catch (Exception ex) {
					throw ex;
				}
				finally {
					WSDocInfoStore.delete(wsDocInfo);        
				}
				actions.add(0, new Integer(WSConstants.SIGN));
				principals.add(0, lastPrincipalFound);
            } else if (el.equals(ENCRYPTED_KEY)) {
            	if (doDebug) {
					log.debug("Found encrypted key element");
            	}
				if (decCrypto == null) {
					throw new WSSecurityException(WSSecurityException.FAILURE, 
												  "noDecCryptoFile");
				}
				if (cb == null) {
					throw new WSSecurityException(WSSecurityException.FAILURE, 
												  "noCallback");
				}
                handleEncryptedKey((Element) elem, cb, decCrypto);
				actions.add(0, new Integer(WSConstants.ENCR));
				principals.add(0, null);
            } else if (el.equals(REFERENCE_LIST)) {
            	if (doDebug) {
					log.debug("Found reference list element");
            	}
				if (cb == null) {
					throw new WSSecurityException(WSSecurityException.FAILURE, 
												  "noCallback");
				}
                handleReferenceList((Element) elem, cb);
				actions.add(0, new Integer(WSConstants.ENCR));
				principals.add(0, null);
           } else if (el.equals(USERNAME_TOKEN)) {
				if (doDebug) {
					log.debug("Found UsernameToken list element");
				}
				if (cb == null) {
					throw new WSSecurityException(WSSecurityException.FAILURE, 
												  "noCallback");
				}
                lastPrincipalFound = handleUsernameToken((Element) elem, cb);
				actions.add(0, new Integer(WSConstants.UT));
				principals.add(0, lastPrincipalFound);
			} else if (el.equals(TIMESTAMP)) {
				if (doDebug) {
					log.debug("Found Timestamp list element");
				}
				/*
				 * Decode Timestamp, add the found time (created/expiry) to result
				 */
            } else {
            	/*
            	 * Add check for a BinarySecurityToken, add info to WSDocInfo. If BST is
            	 * found before a Signature token this would speed up (at least a little
            	 * bit) the processing of STR Transform.
            	 */
				if (doDebug) {
               		log.debug("Unknown Element: " + elem.getLocalName() + " " + elem.getNamespaceURI());
				}
            }
        }
		if( tlog.isDebugEnabled() ) {
			t2=System.currentTimeMillis();
			tlog.debug("processHeader: total= " + (t2-t0) +
			", prepare= " + (t1-t0) +
			", handle= " + (t2-t1));
		}
        return new WSSecurityEngineResult(principals, actions);
    }

    /**
     * Verify the WS-Security signature.
     * <p/>
     * The functions at first checks if then <code>KeyInfo</code> that is 
     * contained in the signature contains standard X509 data. If yes then 
     * get the certificate data via the standard <code>KeyInfo</code> methods.
     * <p/>
     * Otherwise, if the <code>KeyInfo</code> info does not contain X509 data, check
     * if we can find a <code>wsse:SecurityTokenReference</code> element. If yes, the next
     * step is to check how to get the certificate. Two methods are currently supported
     * here:
     * <ul>
     * <li> A URI reference to a binary security token contained in the <code>wsse:Security
     * 		</code> header. The {@link #getTokenElement(SecurityTokenReference)} 
     * 		dereferences and returns the security token. If the derefenced token is
     * 		of the correct type the contained certificate is extracted.
     * </li>
     * <li> Issuer name an serial number of the certificate. In this case the method
     * 		looks up the certificate in the keystore via the <code>crypto</code> parameter.
     * </li>
     * </ul>
     * <p/>
     * The methods checks is the certificate is valid and calls the
     * {@link XMLSignature#checkSignatureValue(X509Certificate) verfication} function.
     * 
     * @param sig 		the XMLSignature element that contains the parsed <code>
     * 					ds:Signature</code> elements.
     * @param crypto	the object that implements the access to the keystore and the
     * 					handling of certificates.
     * @return 			the subject principal of the validated X509 certificate (the
     * 					authenticated subject). The calling function may use this
     * 					principal for further authentication or authorization. 
     * @throws Exception 
     */
    protected Principal verifyXMLSignature(XMLSignature sig, Crypto crypto) throws Exception {
        if (doDebug) {
			log.debug("Verify XML Signature");
        }
		long t0=0, t1=0, t2=0;
		if( tlog.isDebugEnabled() ) {
			t0=System.currentTimeMillis();
		}        
        X509Certificate[] certs = null;
        KeyInfo info = sig.getKeyInfo();
        if (info.containsX509Data()) {
            certs = getCertificatesX509Data(info, crypto);
        } else {
            Node node = WSSecurityUtil.getDirectChild(info.getElement(),
                    SecurityTokenReference.TOKEN.getLocalPart(),
                    SecurityTokenReference.TOKEN.getNamespaceURI());
            if (node == null) {
                throw new WSSecurityException(WSSecurityException.INVALID_SECURITY,
                        "unsupportedKeyInfo", null);
            }
            SecurityTokenReference secRef = new SecurityTokenReference((Element) node);
            if (secRef.containsReference()) {
                Element token = secRef.getTokenElement(secRef, secRef.getElement().getOwnerDocument());

                // at this point ... check token type: Binary
                QName el = new QName(token.getNamespaceURI(), token.getLocalName());
                if (el.equals(BINARY_TOKEN)) {
                    certs = getCertificatesTokenReference((Element)token, crypto);
                } else {
                    throw new WSSecurityException(WSSecurityException.INVALID_SECURITY,
                            "unsupportedToken", null);
                }
            } else if (secRef.containsX509IssuerSerial()) {
                certs = secRef.getX509IssuerSerial(crypto);
			} else if (secRef.containsKeyIdentifier()) {
				certs = secRef.getKeyIdentifier(crypto);
            }
        }
		if( tlog.isDebugEnabled() ) {
			t1=System.currentTimeMillis();
		}                
        if (certs != null && certs.length > 0 && certs[0] != null) {
			certs[0].checkValidity();
			if (sigCheck && sig.checkSignatureValue(certs[0])) {
				if( tlog.isDebugEnabled() ) {
					t2=System.currentTimeMillis();
					tlog.debug("Verify: total= " + (t2-t0) + 
					", prepare-cert= " + (t1-t0) +
					", verify= " + (t2-t1));
				}        			
				return certs[0].getSubjectDN();
			}
        }
		throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
    }

    /**
     * Get an array of certificates from data contained in {@link KeyInfo}. 
     * <p/>
     * The {@link XMLSignature} parses the <code>ds:KeyInfo</code> element and
     * create a <KeyInfo</code> object. This mehtod handles the standard
     * <code>ds:KeyInfo</code> element and does not support the WS Security 
     * extensions.
     * <p/>
     * Currently supports only the <code>wsse:IssuerSerial</code> reference or
     * a directly included certificate.
     * <p/>
     * 
     * @param info 		KeyInfo object created by {@link XMLSignature} during parsing
     * @return 			an array of X509Certificate certificates.
     * @throws Exception Thrown when there is a problem in getting the certificates.
     */
    protected X509Certificate[] getCertificatesX509Data(KeyInfo info, Crypto crypto) throws Exception {
        int len = info.lengthX509Data();
        if (len != 1) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidX509Data", new Object[]{new Integer(len)});
        }
        X509Data data = info.itemX509Data(0);
        int certLen = 0;
        X509Certificate[] certs = null;
        if (data.containsCertificate()) {
            certLen = data.lengthCertificate();
            if (certLen <= 0) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "invalidCertData", new Object[]{new Integer(certLen)});
            }
            certs = new X509Certificate[certLen];
            XMLX509Certificate xmlCert;
            ByteArrayInputStream input;
            for (int i = 0; i < certLen; i++) {
                xmlCert = data.itemCertificate(i);
                input = new ByteArrayInputStream(xmlCert.getCertificateBytes());
                certs[i] = crypto.loadCertificate(input);
            }
        } else if (data.containsIssuerSerial()) {
            XMLX509IssuerSerial issuerSerial = data.itemIssuerSerial(0);
            String alias = crypto.getAliasForX509Cert(issuerSerial.getIssuerName(),
                    issuerSerial.getSerialNumber());
            if (doDebug) {
				log.info("Verify X509IssuerSerial alias: " + alias);
            }
            certs = crypto.getCertificates(alias);
        }
        return certs;
    }

    
    /**
     * Extracts the certificate(s) from the token reference.
     * <p/>
     * 
     * @param elem		The element containing the binary security token. This
     * 					is either X509 certificate(s) or a PKIPath.
     * @return 			an array of X509 certificates
     * @throws 			Exception
     */
    protected X509Certificate[] getCertificatesTokenReference(Element elem, Crypto crypto) throws Exception {
        BinarySecurity token = createSecurityToken(elem);
        if (token instanceof PKIPathSecurity) {
            return ((PKIPathSecurity) token).getX509Certificates(true);
        } else if (token instanceof X509Security) {
            X509Certificate cert = ((X509Security) token).getX509Certificate(crypto);
            X509Certificate[] certs = new X509Certificate[1];
            certs[0] = cert;
            if (cert == null) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "invalidCertData", new Object[]{new Integer(0)});
            }
            return certs;
        } else {
            throw new WSSecurityException(WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                    "unhandledToken", new Object[]{token.getClass().getName()});
        }
    }
    
    /**
     * Checks the <code>element</code> and creates an appropriate binary security object.
     * 
     * @param element The XML element that contains either a <code>BinarySecurityToken
     * </code> or a <code>PKIPath</code> element. Other element types a not
     * supported
     * @return 		the BinarySecurity object, either a <code>X509Security</code> or a
     * 				<code>PKIPathSecurity</code> object.
     * @throws 		WSSecurityException 
     */
    private BinarySecurity createSecurityToken(Element element) throws WSSecurityException {
        BinarySecurity token = new BinarySecurity(element);
        String type = token.getValueType();
        Class clazz = (Class) tokenImpl.get(type);
        if (clazz == null) {
            throw new WSSecurityException(WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                    "unsupportedBinaryTokenType", new Object[]{type});
        }
        try {
            Constructor constructor = clazz.getConstructor(constructorType);
            if (constructor == null) {
                throw new WSSecurityException(WSSecurityException.FAILURE, 
					"invalidConstructor", new Object[]{clazz});
            }
            return (BinarySecurity) constructor.newInstance(new Object[]{element});
        } catch (InvocationTargetException e) {
            Throwable ee = e.getTargetException();
            if (ee instanceof WSSecurityException) {
                throw (WSSecurityException) ee;
            } else {
                throw new WSSecurityException(WSSecurityException.FAILURE, null, null, e);
            }
        } catch (NoSuchMethodException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE, null, null, e);
        } catch (InstantiationException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE, null, null, e);
        } catch (IllegalAccessException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE, null, null, e);
        }
    }

    public WSUsernameTokenPrincipal handleUsernameToken(Element token, CallbackHandler cb) throws Exception {
        UsernameToken ut = new UsernameToken(token);
        String user = ut.getName();
        if (doDebug) {
			log.debug("UsernameToken user " + user);
        }
        WSPasswordCallback pwCb = new WSPasswordCallback(user, WSPasswordCallback.USERNAME_TOKEN);
        Callback[] callbacks = new Callback[1];
        callbacks[0] = pwCb;
        cb.handle(callbacks);
        String origPassword = pwCb.getPassword();
		if (doDebug) {
			log.debug("UsernameToken password " + origPassword);
		}
        if (origPassword == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "noPassword", new Object[]{user});
        }
        String password = ut.getPassword();
        boolean result = false;
        WSUsernameTokenPrincipal principal = new WSUsernameTokenPrincipal(user, ut.isHashed());
		String nonce = ut.getNonce();
		String createdTime = ut.getCreated();
		principal.setNonce(nonce);
		principal.setCreatedTime(createdTime);
        if (ut.isHashed()) {
            if (nonce != null && createdTime != null) {
                String passDigest = UsernameToken.doPasswordDigest(nonce, createdTime, origPassword);
                if (passDigest.equals(password)) {
                    result = true;
                }
            }
        } else {
            if (origPassword.equals(password)) {
                result = true;
            }
        }
        if (!result) {
            throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
        }
        return principal;
    }

    public void handleEncryptedKey(Element xencEncryptedKey, CallbackHandler cb, Crypto crypto) throws Exception {
		long t0=0, t1=0, t2=0;
		if( tlog.isDebugEnabled() ) {
			t0=System.currentTimeMillis();
		}        
        // need to have it to find the encryped data elements in the envelope
        Document doc = xencEncryptedKey.getOwnerDocument();
        Element envelope = doc.getDocumentElement();
        Element nsContext = WSSecurityUtil.createNamespaceContext(doc);

        // lookup xenc:EncryptionMethod, get the Algorithm attribute to determine
        // how the key was encrypted. Then check if we support the algorithm

        Element tmpE = null;	// short living Element used for lookups only
        tmpE = (Element) WSSecurityUtil.getDirectChild((Node) xencEncryptedKey,
                "EncryptionMethod", WSConstants.ENC_NS);
        String keyEncAlgo = null;
        if (tmpE != null) {
            keyEncAlgo = tmpE.getAttribute("Algorithm");
        }
        if (keyEncAlgo == null) {
            throw new WSSecurityException
                    (WSSecurityException.UNSUPPORTED_ALGORITHM, "noEncAlgo");
        }
        Cipher cipher = null;
        if (keyEncAlgo.equalsIgnoreCase(WSConstants.KEYTRANSPORT_RSA15)) {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING","BC");
        } 
        else if (keyEncAlgo.equalsIgnoreCase(WSConstants.KEYTRANSPORT_RSAOEP)) {
			cipher = Cipher.getInstance("RSA/NONE/OAEPPADDING","BC");
        }
        else {
            throw new WSSecurityException
                    (WSSecurityException.UNSUPPORTED_ALGORITHM,
                            "unsupportedKeyTransp", new Object[]{keyEncAlgo});
        }
        /*
         * Well, we can decrypt the session (symmetric) key. Now lookup CipherValue, this is the value of the
         * encrypted session key (session key usually is a symmetrical key that encrypts
         * the referenced content). This is a 2-step lookup
         */
        Element xencCipherValue = null;
        tmpE = (Element) WSSecurityUtil.getDirectChild((Node) xencEncryptedKey, "CipherData", WSConstants.ENC_NS);
        if (tmpE != null) {
            xencCipherValue = (Element) WSSecurityUtil.getDirectChild((Node) tmpE,
                    "CipherValue", WSConstants.ENC_NS);
        }
        if (xencCipherValue == null) {
            throw new WSSecurityException
                    (WSSecurityException.INVALID_SECURITY, "noCipher");
        }
        // here get the reference to the private key / shared secret key. 
        // Shared secret key not yet supported
        // see check above ... maybe later
        Element keyInfo = (Element) WSSecurityUtil.getDirectChild((Node) xencEncryptedKey,
                "KeyInfo", WSConstants.SIG_NS);
        if (keyInfo == null) {
            throw new WSSecurityException
                    (WSSecurityException.INVALID_SECURITY, "noKeyinfo");
        }
        Element secRefToken = (Element) WSSecurityUtil.getDirectChild((Node) keyInfo,
                "SecurityTokenReference", WSConstants.WSSE_NS);
        if (secRefToken == null) {
            throw new WSSecurityException
                    (WSSecurityException.INVALID_SECURITY, "noSecTokRef");
        }
        SecurityTokenReference secRef = new SecurityTokenReference(secRefToken);
        /*
         * Well, at this point there are several ways to get the key. Try to handle all of them :-).
         */
        String alias = null;
        /*
         * handle X509IssuerSerial here. First check if all elements are available,
         * get the appropriate data, check if all data is available.
         * If all is ok up to that point, look up the certificate alias according
         * to issuer name and serial number.
         * This method is recommended by OASIS WS-S specification, X509 profile
         */
        if (secRef.containsX509IssuerSerial()) {
            alias = secRef.getX509IssuerSerialAlias(crypto);
            if (doDebug) {
				log.debug("X509IssuerSerial alias: " + alias);
            }
        }
		/*
         * If wsse:KeyIdentifier found, then the public key of the attached cert was used to
         * encrypt the session (symmetric) key that encrypts the data. Extract the certificate
         * using the BinarySecurity token (was enhanced to handle KeyIdentifier too).
         * This method is _not_recommended by OASIS WS-S specification, X509 profile
         */
		else if (secRef.containsKeyIdentifier()) {
			X509Certificate[] certs = secRef.getKeyIdentifier(crypto);
            if (certs == null || certs.length == 0 || certs[0] == null) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
					"invalidX509Data", new Object[]{"for decryption (KeyId)"});
            }
            /*
             * Here we have the certificate. Now find the alias for it. Needed to identify
             * the private key associated with this certificate
             */
            alias = crypto.getAliasForX509Cert(certs[0]);
            if (doDebug) {
				log.debug("KeyIdentifier Alias: " + alias);
            }
		} else if (secRef.containsReference()) {
			Element bstElement = secRef.getTokenElement(secRef, secRef.getElement().getOwnerDocument());

			// at this point ... check token type: Binary
			QName el =
				new QName(
					bstElement.getNamespaceURI(),
					bstElement.getLocalName());
			if (el.equals(BINARY_TOKEN)) {
				X509Security token = null;
				String value = bstElement.getAttribute("ValueType");
				if (!value.equals("wsse:X509v3")
					|| ((token = new X509Security(bstElement)) == null)) {
					throw new WSSecurityException(
						WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
						"unsupportedBinaryTokenType",
						new Object[] { "for decryption (BST)" });
				}
				X509Certificate cert = token.getX509Certificate(crypto);
				if (cert == null) {
					throw new WSSecurityException(
						WSSecurityException.FAILURE,
						"invalidX509Data",
						new Object[] { "for decryption" });
				}
				/*
				 * Here we have the certificate. Now find the alias for it. Needed to identify
				 * the private key associated with this certificate
				 */
				alias = crypto.getAliasForX509Cert(cert);
				if (doDebug) {
					log.debug("BST Alias: " + alias);
				}
			} else {
				throw new WSSecurityException(
					WSSecurityException.INVALID_SECURITY,
					"unsupportedToken",
					null);
			}
		} else {
			throw new WSSecurityException(
				WSSecurityException.FAILURE,
				"unsupportedKeyId");
		}

        /*
	 	 * At this point we have all information necessary to decrypt the session
	 	 * key: 
	 	 * - the Cipher object intialized with the correct methods
	 	 * - The data that holds the encrypted session key
	 	 * - the alias name for the private key
	 	 *
         * Now use the callback here to get password that enables
	 	 * us to read the private key
         */
        WSPasswordCallback pwCb = new WSPasswordCallback(alias, WSPasswordCallback.DECRYPT);
        Callback[] callbacks = new Callback[1];
        callbacks[0] = pwCb;
        cb.handle(callbacks);
        String password = pwCb.getPassword();
        if (password == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "noPassword", new Object[]{alias});
        }
        cipher.init(Cipher.DECRYPT_MODE, crypto.getPrivateKey(alias, password));
        byte[] decryptedBytes = cipher.doFinal(getDecodedBase64EncodedData(xencCipherValue));

		if( tlog.isDebugEnabled() ) {
			t1=System.currentTimeMillis();
		}        

        /* At this point we have the decrypted session (symmetric) key. According
         * to W3C XML-Enc this key is used to decrypt _any_ references contained in
         * the reference list
		 * Now lookup the references that are encrypted with this key
         */ 
        String dataRefURI = null;
        String keyRefURI = null;
        Element refList = (Element) WSSecurityUtil.getDirectChild((Node) xencEncryptedKey,
                "ReferenceList", WSConstants.ENC_NS);
        if (refList != null) {
            for (tmpE = (Element)refList.getFirstChild();
            	 tmpE != null; tmpE = (Element)tmpE.getNextSibling()) {
            	if (tmpE.getNodeType() != Node.ELEMENT_NODE) {
            		continue;
            	}
            	if (!tmpE.getNamespaceURI().equals(WSConstants.ENC_NS)) {
            		continue;
            	}
            	if (tmpE.getLocalName().equals("DataReference")) {
					dataRefURI = tmpE.getAttribute("URI");
					decryptDataRef(doc, dataRefURI, decryptedBytes);
            	}
            	else if (tmpE.getLocalName().equals("KeyReference")) {
					keyRefURI = tmpE.getAttribute("URI");
            	}
            }
        }

		if (tlog.isDebugEnabled()) {
			t2=System.currentTimeMillis();
			tlog.debug("XMLDecrypt: total= " + (t2-t0) + 
			", get-sym-key= " + (t1-t0) +
			", decrypt= " + (t2-t1));
		}        
        return;
    }

	private void decryptDataRef(Document doc, String dataRefURI, byte[] decryptedBytes) throws Exception {
		if (doDebug) {
			log.debug("found data refernce: " + dataRefURI);
		}
		/*
		 * Look up the encrypted data. First try wsu:Id="someURI". If no such Id then
		 * try the generic lookup to find Id="someURI"
		 */
		Element encBodyData = null;
		if ((encBodyData = WSSecurityUtil.getElementByWsuId(doc, dataRefURI)) == null) {
			encBodyData = WSSecurityUtil.getElementByGenId(doc, dataRefURI);
		}
		if (encBodyData == null) {
			throw new WSSecurityException
			(WSSecurityException.INVALID_SECURITY,
					"dataRef", new Object[] {dataRefURI});
		}

		boolean content = isContent(encBodyData);;

		// get the encryprion method
		String symEncAlgo = getEncAlgo(encBodyData);

		SecretKey symmetricKey = WSSecurityUtil.prepareSecretKey(symEncAlgo, decryptedBytes);

		// initialize Cipher ....
		XMLCipher xmlCipher = null;
		xmlCipher = XMLCipher.getInstance(symEncAlgo);
		xmlCipher.init(XMLCipher.DECRYPT_MODE, symmetricKey);

		if (content) {
			encBodyData = (Element)encBodyData.getParentNode();
		}
		xmlCipher.doFinal(doc, encBodyData, content);
		// wsseSecurity.getParentNode().removeChild(wsseSecurity);  // don't do - this would remove wsse:Security

	}

	/**
	 * Dereferences and decodes encrypted data elements.
	 * 
	 * @param elem  contains the <code>ReferenceList</code> to the
	 * 				encrypted data elements
	 * @param cb	the callback handler to get the key for a key name
	 * 				stored if <code>KeyInfo</code> inside the encrypted
	 * 				data elements
	 */
	private void handleReferenceList(Element elem, CallbackHandler cb)
		throws Exception {

		Document doc = elem.getOwnerDocument();

		Element tmpE = null;
		for (tmpE = (Element) elem.getFirstChild();
			tmpE != null;
			tmpE = (Element) tmpE.getNextSibling()) {
			if (tmpE.getNodeType() != Node.ELEMENT_NODE) {
				continue;
			}
			if (!tmpE.getNamespaceURI().equals(WSConstants.ENC_NS)) {
				continue;
			}
			if (tmpE.getLocalName().equals("DataReference")) {
				String dataRefURI = tmpE.getAttribute("URI");
				decryptDataRefEmbedded(doc, dataRefURI, cb);
			} else if (tmpE.getLocalName().equals("KeyReference")) {
				String keyRefURI = tmpE.getAttribute("URI");
			}
		}
	}

	private void decryptDataRefEmbedded(
		Document doc,
		String dataRefURI,
		CallbackHandler cb)
		throws Exception {

		if (doDebug) {
			log.debug("Embedded found data refernce: " + dataRefURI);
		}
		/*
		 * Look up the encrypted data. First try wsu:Id="someURI". If no such Id then
		 * try the generic lookup to find Id="someURI"
		 */
		Element encBodyData = null;
		if ((encBodyData = WSSecurityUtil.getElementByWsuId(doc, dataRefURI)) == null) {
			encBodyData = WSSecurityUtil.getElementByGenId(doc, dataRefURI);
		}
		if (encBodyData == null) {
			throw new WSSecurityException
			(WSSecurityException.INVALID_SECURITY,
					"dataRef", new Object[] {dataRefURI});
		}

		boolean content = isContent(encBodyData);

		// Now figure out the encryption algorithm
		String symEncAlgo = getEncAlgo(encBodyData);

		Element tmpE =
			(Element) WSSecurityUtil.findElement(
				(Node) encBodyData,
				"KeyName",
				WSConstants.SIG_NS);

		byte[]decryptedBytes = getSharedKey(tmpE, cb);
		
		SecretKey symmetricKey = WSSecurityUtil.prepareSecretKey(symEncAlgo, decryptedBytes);

		// initialize Cipher ....
		XMLCipher xmlCipher = null;
		xmlCipher = XMLCipher.getInstance(symEncAlgo);
		xmlCipher.init(XMLCipher.DECRYPT_MODE, symmetricKey);

		if (content) {
			encBodyData = (Element)encBodyData.getParentNode();
		}
		xmlCipher.doFinal(doc, encBodyData, content);
	}

	private boolean isContent(Node encBodyData) {
		/*
		 * Depending on the encrypted data type (Content or Element) the encBodyData either
		 * holds the element whose contents where encrypted, e.g. soapenv:Body, or the
		 * xenc:EncryptedData element (in case of Element encryption). In either case we need
		 * to get the xenc:EncryptedData element. So get it. The findElement method returns
		 * immediatly if its already the correct element.
		 * Then we can get the Type attribute.
		 */
		
		Element tmpE = (Element) WSSecurityUtil.findElement(encBodyData,
				"EncryptedData", WSConstants.ENC_NS);
		String typeStr = null;
		boolean content = true;
		if (tmpE != null) {
			typeStr= tmpE.getAttribute("Type");
		} 
		if (typeStr != null) {
			content = typeStr.equals("http://www.w3.org/2001/04/xmlenc#Content") ? true : false;
		}
		return content;
	}

	private String getEncAlgo(Node encBodyData) throws WSSecurityException {
		Element tmpE = (Element) WSSecurityUtil.findElement(encBodyData,
				"EncryptionMethod", WSConstants.ENC_NS);

		String symEncAlgo = null;
		if (tmpE != null) {
			symEncAlgo = tmpE.getAttribute("Algorithm");
		}
		if (symEncAlgo == null) {
			throw new WSSecurityException
					(WSSecurityException.UNSUPPORTED_ALGORITHM,
							"noEncAlgo");
		}
		if (doDebug) {
			log.debug("Sym Enc Algo: " + symEncAlgo);
		}
		return symEncAlgo;
	}

	private byte[] getSharedKey(Element keyNmElem, CallbackHandler cb)
		throws Exception {
		String keyName = null;
		if (keyNmElem != null) {
			keyNmElem.normalize();
			Node tmpN;
			if ((tmpN = keyNmElem.getFirstChild()) != null
				&& tmpN.getNodeType() == Node.TEXT_NODE) {
				keyName = tmpN.getNodeValue();
			}
		}
		if (keyName == null) {
			throw new WSSecurityException(
				WSSecurityException.INVALID_SECURITY,
				"noKeyname");
		}
		WSPasswordCallback pwCb = new WSPasswordCallback(keyName, WSPasswordCallback.KEY_NAME);
		Callback[] callbacks = new Callback[1];
		callbacks[0] = pwCb;
		cb.handle(callbacks);
		byte[]decryptedBytes = pwCb.getKey();
		if (decryptedBytes == null) {
			throw new WSSecurityException(
				WSSecurityException.FAILURE,
				"noPassword",
				new Object[] { keyName });
		}
		return decryptedBytes;
	}
    /**
     * Put description here.
     * <p/>
     * 
     * @param element 
     * @return 
     * @throws Exception 
     */
    public static byte[] getDecodedBase64EncodedData(Element element) throws Exception {
        StringBuffer sb = new StringBuffer();
        NodeList children = element.getChildNodes();
        int iMax = children.getLength();
        for (int i = 0; i < iMax; i++) {
            Node curr = children.item(i);
            if (curr.getNodeType() == Node.TEXT_NODE)
                sb.append(((Text) curr).getData());
        }
        String encodedData = sb.toString();
		return Base64.decode(encodedData);
    }
}
