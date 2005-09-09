/*
 * Copyright  2003-2005 The Apache Software Foundation.
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
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.EnvelopeIdResolver;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.PKIPathSecurity;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.Timestamp;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.message.token.SignatureConfirmation;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.ws.security.util.XmlSchemaDateFormat;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.ws.security.util.Base64;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLException;
import org.opensaml.SAMLObject;
import org.opensaml.SAMLSubject;
import org.opensaml.SAMLSubjectStatement;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.Calendar;
import java.util.Iterator;
import java.util.Vector;

/**
 * WS-Security Engine.
 * <p/>
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 * @author Werner Dittmann (Werner.Dittmann@t-online.de).
 */
public class WSSecurityEngine {
    private static final String VALUE_TYPE = "ValueType";
    private static Log log = LogFactory.getLog(WSSecurityEngine.class.getName());
    private static Log tlog =
            LogFactory.getLog("org.apache.ws.security.TIME");

    private static final Class[] constructorType = {org.w3c.dom.Element.class};
    private static WSSecurityEngine engine = null;
    private static WSSConfig wssConfig = WSSConfig.getDefaultWSConfig();
    /**
     * The symmetric key.
     */
    private byte[] decryptedBytes = null;

    private boolean doDebug = false;
    /**
     * <code>wsse:BinarySecurityToken</code> as defined by WS Security specification
     */
    protected static final QName binaryToken = new QName(WSConstants.WSSE_NS, WSConstants.BINARY_TOKEN_LN);
    /**
     * <code>wsse:UsernameToken</code> as defined by WS Security specification
     */
    protected static final QName usernameToken = new QName(WSConstants.WSSE_NS, WSConstants.USERNAME_TOKEN_LN);
    /**
     * <code>wsu:Timestamp</code> as defined by OASIS WS Security specification,
     */
    protected static final QName timeStamp = new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN);
    /**
     * <code>wsse11:signatureConfirmation</code> as defined by OASIS WS Security specification,
     */
   protected static final QName signatureConfirmation = new QName(WSConstants.WSSE11_NS, WSConstants.SIGNATURE_CONFIRMATION_LN);
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
     * <code>saml:Assertion</code> as defined by SAML specification
     */
    protected static final QName SAML_TOKEN = new QName(WSConstants.SAML_NS, WSConstants.ASSERTION_LN);

    static {
    }

    public WSSecurityEngine() {
    }

    /**
     * Get a singleton instance of security engine.
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
     * @param wsc set the static WSSConfig to other than default
     */
    public static void setWssConfig(WSSConfig wsc) {
        wssConfig = wsc;
    }
    /**
     * Process the security header given the soap envelope as W3C document.
     * <p/>
     * This is the main entry point to verify or decrypt a SOAP enevelope.
     * First check if a <code>wsse:Security</code> is availabe with the
     * defined actor.
     *
     * @param doc    the SOAP envelope as {@link Document}
     * @param actor  the engine works on behalf of this <code>actor</code>. Refer
     *               to the SOAP specification about <code>actor</code> or <code>role
     *               </code>
     * @param cb     a callback hander to the caller to resolve passwords during
     *               encryption and {@link UsernameToken} handling
     * @param crypto the object that implements the access to the keystore and the
     *               handling of certificates.
     * @return a result vector
     * @throws WSSecurityException
     * @see WSSecurityEngine#processSecurityHeader(Element securityHeader, CallbackHandler cb,Crypto sigCrypto, Crypto decCrypto)
     */
    public Vector processSecurityHeader(Document doc,
                                        String actor,
                                        CallbackHandler cb,
                                        Crypto crypto)
            throws WSSecurityException {
        return processSecurityHeader(doc, actor, cb, crypto, crypto);
    }

    /**
     * Process the security header given the soap envelope as W3C document.
     * <p/>
     * This is the main entry point to verify or decrypt a SOAP enevelope.
     * First check if a <code>wsse:Security</code> is availabe with the
     * defined actor.
     *
     * @param doc       the SOAP envelope as {@link Document}
     * @param actor     the engine works on behalf of this <code>actor</code>. Refer
     *                  to the SOAP specification about <code>actor</code> or <code>role
     *                  </code>
     * @param cb        a callback hander to the caller to resolve passwords during
     *                  encryption and {@link UsernameToken} handling
     * @param sigCrypto the object that implements the access to the keystore and the
     *                  handling of certificates for Signature
     * @param decCrypto the object that implements the access to the keystore and the
     *                  handling of certificates for Decryption
     * @return a result vector
     * @throws WSSecurityException
     * @see WSSecurityEngine#processSecurityHeader(Element securityHeader, CallbackHandler cb,Crypto sigCrypto, Crypto decCrypto)
     */
    public Vector processSecurityHeader(Document doc,
                                        String actor,
                                        CallbackHandler cb,
                                        Crypto sigCrypto,
                                        Crypto decCrypto)
            throws WSSecurityException {

        doDebug = log.isDebugEnabled();
        if (doDebug) {
            log.debug("enter processSecurityHeader()");
        }

        if (actor == null) {
            actor = "";
        }
        Vector wsResult = null;
        SOAPConstants sc = WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
        Element elem = WSSecurityUtil.getSecurityHeader(doc, actor, sc);
        if (elem != null) {
            if (doDebug) {
                log.debug("Processing WS-Security header for '" + actor
                        + "' actor.");
            }
            wsResult = processSecurityHeader(elem, cb, sigCrypto, decCrypto);
        }
        return wsResult;
    }

    /**
     * Process the security header given the <code>wsse:Security</code> DOM
     * Element. <p/>This function loops over all direct child elements of the
     * <code>wsse:Security</code> header. If it finds a knwon element, it
     * transfers control to the appropriate handling function. The mehtod
     * processes the known child elements in the same order as they appear in
     * the <code>wsse:Security</code> element. This is in accordance to the WS
     * Security specification. <p/>Currently the functions can handle the
     * following child elements: here:
     * <ul>
     * <li>{@link #SIGNATURE <code>ds:Signature</code>}</li>
     * <li>{@link #ENCRYPTED_KEY <code>xenc:EncryptedKey</code>}</li>
     * <li>{@link #USERNAME_TOKEN <code>wsse:UsernameToken</code>}</li>
     * </ul>
     * <p/>
     *
     * @param securityHeader the <code>wsse:Security</code> header element
     * @param cb             a callback hander to the caller to resolve passwords during
     *                       encryption and {@link UsernameToken}handling
     * @param sigCrypto      the object that implements the access to the keystore and the
     *                       handling of certificates used for Signature
     * @param decCrypto      the object that implements the access to the keystore and the
     *                       handling of certificates used for Decryption
     * @return a Vector of {@link WSSecurityEngineResult}. Each element in the
     *         the Vector represents the result of a security action. The elements
     *         are ordered according to the sequence of the security actions in the
     *         wsse:Signature header. The Vector maybe empty if no security processing
     *         was performed.
     * @throws WSSecurityException
     */
    protected Vector processSecurityHeader(Element securityHeader,
                                           CallbackHandler cb,
                                           Crypto sigCrypto,
                                           Crypto decCrypto) throws WSSecurityException {

        long t0 = 0, t1 = 0, t2 = 0;
        if (tlog.isDebugEnabled()) {
            t0 = System.currentTimeMillis();
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
        Principal lastPrincipalFound = null;
        if (tlog.isDebugEnabled()) {
            t1 = System.currentTimeMillis();
        }
        Vector returnResults = new Vector();

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
                WSDocInfoStore.store(wsDocInfo);
                X509Certificate[] returnCert = new X509Certificate[1];
                Vector returnQname[] = new Vector[1];
                byte[][] signatureValue = new byte[1][];
                try {
					lastPrincipalFound = verifyXMLSignature((Element) elem,
							sigCrypto, returnCert, returnQname, signatureValue);
				} catch (WSSecurityException ex) {
					throw ex;
				} finally {
					WSDocInfoStore.delete(wsDocInfo);
				}
                if (lastPrincipalFound instanceof WSUsernameTokenPrincipal) {
					returnResults.add(0, new WSSecurityEngineResult(
							WSConstants.UT_SIGN, lastPrincipalFound, null,
							returnQname[0], signatureValue[0]));

				} else {
					returnResults.add(0, new WSSecurityEngineResult(
							WSConstants.SIGN, lastPrincipalFound,
							returnCert[0], returnQname[0], signatureValue[0]));
				}
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
                returnResults.add(0, new WSSecurityEngineResult(WSConstants.ENCR, null, null, null, null));
            } else if (el.equals(REFERENCE_LIST)) {
                if (doDebug) {
                    log.debug("Found reference list element");
                }
                if (cb == null) {
                    throw new WSSecurityException(WSSecurityException.FAILURE,
                            "noCallback");
                }
                handleReferenceList((Element) elem, cb);
                returnResults.add(0, new WSSecurityEngineResult(WSConstants.ENCR, null, null, null, null));
            } else if (el.equals(usernameToken)) {
                if (doDebug) {
                    log.debug("Found UsernameToken list element");
                }
                lastPrincipalFound = handleUsernameToken((Element) elem, cb);
                returnResults.add(0, new WSSecurityEngineResult(WSConstants.UT,
                        lastPrincipalFound, null, null, null));
            } else if (el.equals(SAML_TOKEN)) {
                if (doDebug) {
                    log.debug("Found SAML Assertion element");
                }
                SAMLAssertion assertion = handleSAMLToken((Element) elem);
                wsDocInfo.setAssertion((Element) elem);
                returnResults.add(0,
                        new WSSecurityEngineResult(WSConstants.ST_UNSIGNED, assertion));
            } else if (el.equals(timeStamp)) {
                if (doDebug) {
                    log.debug("Found Timestamp list element");
                }
                /*
                 * Decode Timestamp, add the found time (created/expiry) to result
                 */
                Timestamp timestamp = new Timestamp((Element) elem);
                handleTimestamp(timestamp);
                returnResults.add(0,
                        new WSSecurityEngineResult(WSConstants.TS,
                                timestamp));
            } else if (el.equals(signatureConfirmation)) {
                if (doDebug) {
                    log.debug("Found SignatureConfirmation list element");
                }
                /*
                 * Decode SignatureConfirmation, just store in result
                 */
                SignatureConfirmation sigConf = new SignatureConfirmation(
                        (Element) elem);
                returnResults.add(0, new WSSecurityEngineResult(WSConstants.SC,
                        sigConf));
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
        if (tlog.isDebugEnabled()) {
            t2 = System.currentTimeMillis();
            tlog.debug("processHeader: total= " + (t2 - t0) +
                    ", prepare= " + (t1 - t0) +
                    ", handle= " + (t2 - t1));
        }
        return returnResults;
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
     * </code> header.  If the derefenced token is
     * of the correct type the contained certificate is extracted.
     * </li>
     * <li> Issuer name an serial number of the certificate. In this case the method
     * looks up the certificate in the keystore via the <code>crypto</code> parameter.
     * </li>
     * </ul>
     * <p/>
     * The methods checks is the certificate is valid and calls the
     * {@link XMLSignature#checkSignatureValue(X509Certificate) verfication} function.
     *
     * @param elem        the XMLSignature DOM Element.
     * @param crypto      the object that implements the access to the keystore and the
     *                    handling of certificates.
     * @param returnCert  verifyXMLSignature stores the certificate in the first
     *                    entry of this array. Ther caller may then further validate
     *                    the certificate
     * @param returnQname verifyXMLSignature store the Qnames of all signed elements
     *                    in this Vector ordered according the sequence in the Signature
     *                    header.
     * @return the subject principal of the validated X509 certificate (the
     *         authenticated subject). The calling function may use this
     *         principal for further authentication or authorization.
     * @throws WSSecurityException
     */
    protected Principal verifyXMLSignature(Element elem,
                                           Crypto crypto,
                                           X509Certificate[] returnCert,
                                           Vector[] returnQname,
                                           byte[][] signatureValue)
            throws WSSecurityException {
        if (doDebug) {
            log.debug("Verify XML Signature");
        }
        long t0 = 0, t1 = 0, t2 = 0;
        if (tlog.isDebugEnabled()) {
            t0 = System.currentTimeMillis();
        }

        XMLSignature sig = null;
        try {
            sig = new XMLSignature(elem, null);
        } catch (XMLSecurityException e2) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK,
                    "noXMLSig");
        }

        sig.addResourceResolver(EnvelopeIdResolver.getInstance());

        X509Certificate[] certs = null;
        KeyInfo info = sig.getKeyInfo();
        byte[] secretKey = null;
        UsernameToken ut = null;

        if (info != null) {
			Node node = WSSecurityUtil.getDirectChild(info.getElement(),
						SecurityTokenReference.SECURITY_TOKEN_REFERENCE,
                        WSConstants.WSSE_NS);
			if (node == null) {
				throw new WSSecurityException(
						WSSecurityException.INVALID_SECURITY,
						"unsupportedKeyInfo");
			}
			SecurityTokenReference secRef = new SecurityTokenReference((Element) node);

			int docHash = elem.getOwnerDocument().hashCode();
			/*
			 * Her we get some information about the document that is being
			 * processed, in partucular the crypto implementation, and already
			 * detected BST that may be used later during dereferencing.
			 */
			WSDocInfo wsDocInfo = WSDocInfoStore.lookup(docHash);

			if (secRef.containsReference()) {
				Element token = secRef.getTokenElement(elem.getOwnerDocument(),
						wsDocInfo);
				/*
				 * at this point check token type: UsernameToken, Binary, SAML
				 * Crypto required only for Binary and SAML
				 */
				QName el = new QName(token.getNamespaceURI(), token
						.getLocalName());
				if (token.getLocalName().equals(WSConstants.USERNAME_TOKEN_LN)) {
			        ut = new UsernameToken(token);
			        secretKey = ut.getSecretKey();
				} else {
					if (crypto == null) {
						throw new WSSecurityException(WSSecurityException.FAILURE,
								"noSigCryptoFile");
					}
					if (token.getLocalName().equals(binaryToken.getLocalPart())) {
						certs = getCertificatesTokenReference((Element) token,
								crypto);
					} else if (el.equals(SAML_TOKEN)) {
						certs = getCertificatesFromSAML((Element) token, crypto);
					} else {
						throw new WSSecurityException(
								WSSecurityException.INVALID_SECURITY,
								"unsupportedKeyInfo", new Object[] { el
										.toString() });
					}
				}
			} else if (secRef.containsX509Data() || secRef.containsX509IssuerSerial()) {
				certs = secRef.getX509IssuerSerial(crypto);
			} else if (secRef.containsKeyIdentifier()) {
				certs = secRef.getKeyIdentifier(crypto);
			} else {
				throw new WSSecurityException(
						WSSecurityException.INVALID_SECURITY,
						"unsupportedKeyInfo", new Object[] { node.toString() });
			}
		} else {
			if (crypto == null) {
				throw new WSSecurityException(WSSecurityException.FAILURE,
						"noSigCryptoFile");
			}
			if (crypto.getDefaultX509Alias() != null) {
				certs = crypto.getCertificates(crypto.getDefaultX509Alias());
			} else {
				throw new WSSecurityException(
						WSSecurityException.INVALID_SECURITY,
						"unsupportedKeyInfo");
			}
		}
		if (tlog.isDebugEnabled()) {
            t1 = System.currentTimeMillis();
        }
        if ((certs == null || certs.length == 0 || certs[0] == null) && secretKey == null) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
        }
        if (certs != null) {
			try {
				certs[0].checkValidity();
			} catch (CertificateExpiredException e) {
				throw new WSSecurityException(WSSecurityException.FAILED_CHECK,
						"invalidCert");
			} catch (CertificateNotYetValidException e) {
				throw new WSSecurityException(WSSecurityException.FAILED_CHECK,
						"invalidCert");
			}
		}
        try {
			boolean signatureOk = false;
			if (certs != null) {
				signatureOk = sig.checkSignatureValue(certs[0]);
			} else {
				signatureOk = sig.checkSignatureValue(sig
						.createSecretKey(secretKey));
			}
			if (signatureOk) {
				if (tlog.isDebugEnabled()) {
					t2 = System.currentTimeMillis();
					tlog.debug("Verify: total= " + (t2 - t0)
							+ ", prepare-cert= " + (t1 - t0) + ", verify= "
							+ (t2 - t1));
				}
                signatureValue[0] = sig.getSignatureValue();
				/*
				 * Now dig into the Signature element to get the elements that
				 * this Signature covers. Build the QName of these Elements and
				 * return them to caller
				 */
				SignedInfo si = sig.getSignedInfo();
				int numReferences = si.getLength();
				Vector qvec = new Vector(numReferences);
				for (int i = 0; i < numReferences; i++) {
					Reference siRef;
					try {
						siRef = si.item(i);
					} catch (XMLSecurityException e3) {
						throw new WSSecurityException(
								WSSecurityException.FAILED_CHECK);
					}
					String uri = siRef.getURI();
					Element se = WSSecurityUtil.getElementByWsuId(elem.getOwnerDocument(), uri);
					if (se == null) {
						se = WSSecurityUtil.getElementByGenId(elem
								.getOwnerDocument(), uri);
					}
					if (se == null) {
						throw new WSSecurityException(
								WSSecurityException.FAILED_CHECK);
					}
					QName qn = new QName(se.getNamespaceURI(), se
							.getLocalName());
					qvec.add(qn);
				}
				returnQname[0] = qvec;
				if (certs != null) {
					returnCert[0] = certs[0];
					return certs[0].getSubjectDN();
				} else {
					WSUsernameTokenPrincipal principal = new WSUsernameTokenPrincipal(
							ut.getName(), ut.isHashed());
					principal.setNonce(ut.getNonce());
					principal.setPassword(ut.getPassword());
					principal.setCreatedTime(ut.getCreated());
					return principal;
				}
			} else {
				throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
			}
		} catch (XMLSignatureException e1) {
			throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
		}
	}

    /**
	 * Extracts the certificate(s) from the Binary Security token reference.
	 * <p/>
	 *
	 * @param elem
	 *            The element containing the binary security token. This is
	 *            either X509 certificate(s) or a PKIPath.
	 * @return an array of X509 certificates
	 * @throws WSSecurityException
	 */
    public X509Certificate[] getCertificatesTokenReference(Element elem,
                                                           Crypto crypto)
            throws WSSecurityException {
        BinarySecurity token = createSecurityToken(elem);
        if (token instanceof PKIPathSecurity) {
            return ((PKIPathSecurity) token).getX509Certificates(false, crypto);
        } else if (token instanceof X509Security) {
            X509Certificate cert = ((X509Security) token).getX509Certificate(crypto);
            X509Certificate[] certs = new X509Certificate[1];
            certs[0] = cert;
            return certs;
        } else {
            throw new WSSecurityException(WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                    "unhandledToken", new Object[]{token.getClass().getName()});
        }
    }

    /**
     * Extracts the certificate(s) from the SAML token reference.
     * <p/>
     *
     * @param elem The element containing the SAML token.
     * @return an array of X509 certificates
     * @throws WSSecurityException
     */
    protected X509Certificate[] getCertificatesFromSAML(Element elem,
                                                        Crypto crypto)
            throws WSSecurityException {

        /*
         * Get some information about the SAML token content. This controls how
         * to deal with the whole stuff. First get the Authentication statement
         * (includes Subject), then get the _first_ confirmation method only.
         */
        SAMLAssertion assertion;
        try {
            assertion = new SAMLAssertion(elem);
        } catch (SAMLException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidSAMLToken", new Object[]{"for Signature (cannot parse)"});
        }
        SAMLSubjectStatement samlSubjS = null;
        Iterator it = assertion.getStatements();
        while (it.hasNext()) {
            SAMLObject so = (SAMLObject) it.next();
            if (so instanceof SAMLSubjectStatement) {
                samlSubjS = (SAMLSubjectStatement) so;
                break;
            }
        }
        SAMLSubject samlSubj = null;
        if (samlSubjS != null) {
            samlSubj = samlSubjS.getSubject();
        }
        if (samlSubj == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidSAMLToken", new Object[]{"for Signature (no Subject)"});
        }

//        String confirmMethod = null;
//        it = samlSubj.getConfirmationMethods();
//        if (it.hasNext()) {
//            confirmMethod = (String) it.next();
//        }
//        boolean senderVouches = false;
//        if (SAMLSubject.CONF_SENDER_VOUCHES.equals(confirmMethod)) {
//            senderVouches = true;
//        }
        Element e = samlSubj.getKeyInfo();
        X509Certificate[] certs = null;
        try {
            KeyInfo ki = new KeyInfo(e, null);

            if (ki.containsX509Data()) {
                X509Data data = ki.itemX509Data(0);
                XMLX509Certificate certElem = null;
                if (data != null && data.containsCertificate()) {
                    certElem = data.itemCertificate(0);
                }
                if (certElem != null) {
                    X509Certificate cert = certElem.getX509Certificate();
                    certs = new X509Certificate[1];
                    certs[0] = cert;
                }
            }
            // TODO: get alias name for cert, check against username set by caller
        } catch (XMLSecurityException e3) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidSAMLsecurity",
                    new Object[]{"cannot get certificate (key holder)"});
        }
        return certs;
    }

    /**
     * Checks the <code>element</code> and creates appropriate binary security object.
     *
     * @param element The XML element that contains either a <code>BinarySecurityToken
     *                </code> or a <code>PKIPath</code> element. Other element types a not
     *                supported
     * @return the BinarySecurity object, either a <code>X509Security</code> or a
     *         <code>PKIPathSecurity</code> object.
     * @throws WSSecurityException
     */
    private BinarySecurity createSecurityToken(Element element) throws WSSecurityException {
        BinarySecurity token = new BinarySecurity(element);
        String type = token.getValueType();
        Class clazz = null;
        if (type.equals(X509Security.getType())) {
            clazz = X509Security.class;
        } else if (type.equals(PKIPathSecurity.getType())) {
            clazz = PKIPathSecurity.class;
        }
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

    /**
     * Check the UsernameToken element. Depending on the password type
     * contained in the element the processing differs. If the password type
     * is password digest (a hashed password) then process the password
     * commpletely here. Use the callback class to get a stored password
     * perform hash algorithm and compare the result with the transmitted
     * password.
     * <p/>
     * If the password is of type password text or any other yet unknown
     * password type the delegate the password validation to the callback
     * class. To do so the security engine hands over all necessary data to
     * the callback class via the WSPasswordCallback object. To distinguish
     * from digested usernam token the usage parameter of WSPasswordCallback
     * is set to <code>USERNAME_TOKEN_UNKNOWN</code>
     *
     * @param token the DOM element that contains the UsernameToken
     * @param cb the refernce to the callback object
     * @return WSUsernameTokenPrincipal that contain data that an application
     * may use to further validate the password/user combination.
     * @throws WSSecurityException
     */
    public WSUsernameTokenPrincipal handleUsernameToken(Element token, CallbackHandler cb) throws WSSecurityException {
        UsernameToken ut = new UsernameToken(token);
        String user = ut.getName();
        String password = ut.getPassword();
        String nonce = ut.getNonce();
        String createdTime = ut.getCreated();
        String pwType = ut.getPasswordType();
        if (doDebug) {
            log.debug("UsernameToken user " + user);
            log.debug("UsernameToken password " + password);
        }

        Callback[] callbacks = new Callback[1];
        if (ut.isHashed()) {
            if (cb == null) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "noCallback");
            }

            WSPasswordCallback pwCb = new WSPasswordCallback(user, WSPasswordCallback.USERNAME_TOKEN);
            callbacks[0] = pwCb;
            try {
                cb.handle(callbacks);
            } catch (IOException e) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "noPassword",
                        new Object[]{user});
            } catch (UnsupportedCallbackException e) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "noPassword",
                        new Object[]{user});
            }
            String origPassword = pwCb.getPassword();
            if (doDebug) {
                log.debug("UsernameToken callback password " + origPassword);
            }
            if (origPassword == null) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "noPassword", new Object[]{user});
            }
            if (nonce != null && createdTime != null) {
                String passDigest = UsernameToken.doPasswordDigest(nonce, createdTime, origPassword);
                if (!passDigest.equals(password)) {
                    throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
                }
            }
        }
        else if (cb != null) {
			WSPasswordCallback pwCb = new WSPasswordCallback(user, password,
					pwType, WSPasswordCallback.USERNAME_TOKEN_UNKNOWN);
			callbacks[0] = pwCb;
			try {
				cb.handle(callbacks);
			} catch (IOException e) {
				throw new WSSecurityException(WSSecurityException.FAILURE,
						"noPassword", new Object[] { user });
			} catch (UnsupportedCallbackException e) {
				throw new WSSecurityException(WSSecurityException.FAILURE,
						"noPassword", new Object[] { user });
			}
       }

        WSUsernameTokenPrincipal principal = new WSUsernameTokenPrincipal(user, ut.isHashed());
        principal.setNonce(nonce);
        principal.setPassword(password);
        principal.setCreatedTime(createdTime);
        principal.setPasswordType(pwType);

        return principal;
    }

    public SAMLAssertion handleSAMLToken(Element token) throws WSSecurityException {
        boolean result = false;
        SAMLAssertion assertion = null;
        try {
            assertion = new SAMLAssertion(token);
            result = true;
            if (doDebug) {
                log.debug("SAML Assertion issuer " + assertion.getIssuer());
            }
        } catch (SAMLException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidSAMLsecurity", null, e);
        }
        if (!result) {
            throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
        }
        return assertion;
    }

    public void handleTimestamp(Timestamp timestamp) throws WSSecurityException {
        if (doDebug) {
            log.debug("Preparing to verify the timestamp");

            DateFormat zulu = new XmlSchemaDateFormat();

            log.debug("Current time: " + zulu.format(Calendar.getInstance().getTime()));
            log.debug("Timestamp created: " + zulu.format(timestamp.getCreated().getTime()));
            log.debug("Timestamp expires: " + zulu.format(timestamp.getExpires().getTime()));
        }

        // Validate whether the security semantics have expired
        Calendar rightNow = Calendar.getInstance();
        if (timestamp.getExpires().before(rightNow)) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY, "invalidTimestamp", new Object[]{"The security semantics of message have expired"});
        }

        return;
    }

    public void handleEncryptedKey(Element xencEncryptedKey,
			CallbackHandler cb, Crypto crypto) throws WSSecurityException {
		handleEncryptedKey(xencEncryptedKey, cb, crypto, null);
	}

	public void handleEncryptedKey(Element xencEncryptedKey,
			PrivateKey privatekey) throws WSSecurityException {
		handleEncryptedKey(xencEncryptedKey, null, null, privatekey);
	}

    public void handleEncryptedKey(Element xencEncryptedKey,
			CallbackHandler cb, Crypto crypto, PrivateKey privateKey)
			throws WSSecurityException {
        long t0 = 0, t1 = 0, t2 = 0;
        if (tlog.isDebugEnabled()) {
            t0 = System.currentTimeMillis();
        }
        // need to have it to find the encryped data elements in the envelope
        Document doc = xencEncryptedKey.getOwnerDocument();

        // lookup xenc:EncryptionMethod, get the Algorithm attribute to determine
        // how the key was encrypted. Then check if we support the algorithm

        Node tmpE = null;    // short living Element used for lookups only
        tmpE = (Element) WSSecurityUtil.getDirectChild((Node) xencEncryptedKey,
                "EncryptionMethod", WSConstants.ENC_NS);
        String keyEncAlgo = null;
        if (tmpE != null) {
            keyEncAlgo = ((Element) tmpE).getAttribute("Algorithm");
        }
        if (keyEncAlgo == null) {
            throw new WSSecurityException
                    (WSSecurityException.UNSUPPORTED_ALGORITHM, "noEncAlgo");
        }
        Cipher cipher = WSSecurityUtil.getCipherInstance(keyEncAlgo);
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
        if (privateKey == null) {
            Element keyInfo = (Element) WSSecurityUtil.getDirectChild((Node) xencEncryptedKey,
                    "KeyInfo", WSConstants.SIG_NS);
            String alias;
            if (keyInfo != null) {
                Element secRefToken;
                secRefToken = (Element) WSSecurityUtil.getDirectChild(keyInfo,
                        "SecurityTokenReference", WSConstants.WSSE_NS);
                if (secRefToken == null) {
                    secRefToken = (Element) WSSecurityUtil.getDirectChild(keyInfo,
                            "KeyName", WSConstants.SIG_NS);
                }
                if (secRefToken == null) {
                    throw new WSSecurityException
                            (WSSecurityException.INVALID_SECURITY, "noSecTokRef");
                }
                SecurityTokenReference secRef = new SecurityTokenReference(secRefToken);
                /*
				 * Well, at this point there are several ways to get the key.
				 * Try to handle all of them :-).
				 */
                alias = null;
                /*
                * handle X509IssuerSerial here. First check if all elements are available,
                * get the appropriate data, check if all data is available.
                * If all is ok up to that point, look up the certificate alias according
                * to issuer name and serial number.
                * This method is recommended by OASIS WS-S specification, X509 profile
                */
                if (secRef.containsX509Data() || secRef.containsX509IssuerSerial()) {
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
                    if (certs == null || certs.length < 1 || certs[0] == null) {
                        throw new WSSecurityException(WSSecurityException.FAILURE,
                                "invalidX509Data", new Object[]{"for decryption (KeyId)"});
                    }
                    /*
                    * Here we have the certificate. Now find the alias for it. Needed to identify
                    * the private key associated with this certificate
                    */
                    alias = crypto.getAliasForX509Cert(certs[0]);
                    if (doDebug) {
                        log.debug("cert: " + certs[0]);
                        log.debug("KeyIdentifier Alias: " + alias);
                    }
                } else if (secRef.containsReference()) {
                    Element bstElement = secRef.getTokenElement(doc, null);

                    // at this point ... check token type: Binary
                    QName el =
                            new QName(bstElement.getNamespaceURI(),
                                    bstElement.getLocalName());
                    if (el.equals(binaryToken)) {
                        X509Security token = null;
                        String value = bstElement.getAttribute(VALUE_TYPE);
                        if (!X509Security.getType().equals(value)
                                || ((token = new X509Security(bstElement)) == null)) {
                            throw new WSSecurityException(WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                                    "unsupportedBinaryTokenType",
                                    new Object[]{"for decryption (BST)"});
                        }
                        X509Certificate cert = token.getX509Certificate(crypto);
                        if (cert == null) {
                            throw new WSSecurityException(WSSecurityException.FAILURE,
                                    "invalidX509Data",
                                    new Object[]{"for decryption"});
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
                        throw new WSSecurityException(WSSecurityException.INVALID_SECURITY,
                                "unsupportedToken",
                                null);
                    }
                } else if (secRef.containsKeyName()) {
                    alias = crypto.getAliasForX509Cert(secRef.getKeyNameValue());
                    if (doDebug) {
                        log.debug("KeyName alias: " + alias);
                    }
                } else {
                    throw new WSSecurityException(WSSecurityException.FAILURE, "unsupportedKeyId");
                }
            } else if (crypto.getDefaultX509Alias() != null) {
                alias = crypto.getDefaultX509Alias();
            } else {
                throw new WSSecurityException
                        (WSSecurityException.INVALID_SECURITY, "noKeyinfo");
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
            try {
                cb.handle(callbacks);
            } catch (IOException e) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "noPassword",
                        new Object[]{alias});
            } catch (UnsupportedCallbackException e) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "noPassword",
                        new Object[]{alias});
            }
            String password = pwCb.getPassword();
            if (password == null) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "noPassword", new Object[]{alias});
            }

            try {
                privateKey = crypto.getPrivateKey(alias, password);
            } catch (Exception e) {
                throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC, null, null, e);
            }
        }

        try {
            cipher.init(Cipher.DECRYPT_MODE,
                        privateKey);
        } catch (Exception e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC, null, null, e1);
        }
        try {
            decryptedBytes =
                    cipher.doFinal(getDecodedBase64EncodedData(xencCipherValue));
        } catch (IllegalStateException e2) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC, null, null, e2);
        } catch (IllegalBlockSizeException e2) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC, null, null, e2);
        } catch (BadPaddingException e2) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC, null, null, e2);
        }

        if (tlog.isDebugEnabled()) {
            t1 = System.currentTimeMillis();
        }

        /* At this point we have the decrypted session (symmetric) key. According
         * to W3C XML-Enc this key is used to decrypt _any_ references contained in
         * the reference list
         * Now lookup the references that are encrypted with this key
         */
        String dataRefURI = null;
        Element refList = (Element) WSSecurityUtil.getDirectChild((Node) xencEncryptedKey,
                "ReferenceList", WSConstants.ENC_NS);
        if (refList != null) {
            for (tmpE = refList.getFirstChild();
                 tmpE != null; tmpE = tmpE.getNextSibling()) {
                if (tmpE.getNodeType() != Node.ELEMENT_NODE) {
                    continue;
                }
                if (!tmpE.getNamespaceURI().equals(WSConstants.ENC_NS)) {
                    continue;
                }
                if (tmpE.getLocalName().equals("DataReference")) {
                    dataRefURI = ((Element) tmpE).getAttribute("URI");
                    decryptDataRef(doc, dataRefURI, decryptedBytes);
                }
            }
        }

        if (tlog.isDebugEnabled()) {
            t2 = System.currentTimeMillis();
            tlog.debug("XMLDecrypt: total= " + (t2 - t0) +
                    ", get-sym-key= " + (t1 - t0) +
                    ", decrypt= " + (t2 - t1));
        }
        return;
    }

    private void decryptDataRef(Document doc, String dataRefURI, byte[] decryptedData) throws WSSecurityException {
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
                            "dataRef", new Object[]{dataRefURI});
        }

        boolean content = isContent(encBodyData);

        // get the encryprion method
        String symEncAlgo = getEncAlgo(encBodyData);

        SecretKey symmetricKey = WSSecurityUtil.prepareSecretKey(
            symEncAlgo, decryptedData);

        // initialize Cipher ....
        XMLCipher xmlCipher = null;
        try {
            xmlCipher = XMLCipher.getInstance(symEncAlgo);
            xmlCipher.init(XMLCipher.DECRYPT_MODE, symmetricKey);
        } catch (XMLEncryptionException e) {
            throw new WSSecurityException(WSSecurityException.UNSUPPORTED_ALGORITHM, null, null, e);
        }

        if (content) {
            encBodyData = (Element) encBodyData.getParentNode();
        }
        try {
            xmlCipher.doFinal(doc, encBodyData, content);
        } catch (Exception e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC, null, null, e1);
        }
    }

    /**
     * Dereferences and decodes encrypted data elements.
     *
     * @param elem contains the <code>ReferenceList</code> to the
     *             encrypted data elements
     * @param cb   the callback handler to get the key for a key name
     *             stored if <code>KeyInfo</code> inside the encrypted
     *             data elements
     */
    private void handleReferenceList(Element elem, CallbackHandler cb)
            throws WSSecurityException {

        Document doc = elem.getOwnerDocument();

        Node tmpE = null;
        for (tmpE = elem.getFirstChild();
             tmpE != null;
             tmpE = tmpE.getNextSibling()) {
            if (tmpE.getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            if (!tmpE.getNamespaceURI().equals(WSConstants.ENC_NS)) {
                continue;
            }
            if (tmpE.getLocalName().equals("DataReference")) {
                String dataRefURI = ((Element) tmpE).getAttribute("URI");
                decryptDataRefEmbedded(doc, dataRefURI, cb);
            }
        }
    }

    public void decryptDataRefEmbedded(Document doc,
                                       String dataRefURI,
                                       CallbackHandler cb)
            throws WSSecurityException {

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
                            "dataRef", new Object[]{dataRefURI});
        }

        boolean content = isContent(encBodyData);

        // Now figure out the encryption algorithm
        String symEncAlgo = getEncAlgo(encBodyData);

        Element tmpE =
                (Element) WSSecurityUtil.findElement((Node) encBodyData,
                        "KeyInfo",
                        WSConstants.SIG_NS);

        SecretKey symmetricKey = getSharedKey(tmpE, symEncAlgo, cb);

        // initialize Cipher ....
        XMLCipher xmlCipher = null;
        try {
            xmlCipher = XMLCipher.getInstance(symEncAlgo);
            xmlCipher.init(XMLCipher.DECRYPT_MODE, symmetricKey);
        } catch (XMLEncryptionException e1) {
            throw new WSSecurityException(WSSecurityException.UNSUPPORTED_ALGORITHM, null, null, e1);
        }

        if (content) {
            encBodyData = (Element) encBodyData.getParentNode();
        }
        try {
            xmlCipher.doFinal(doc, encBodyData, content);
        } catch (Exception e) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC, null, null, e);
        }
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
            typeStr = tmpE.getAttribute("Type");
        }
        if (typeStr != null) {
            content = typeStr.equals(WSConstants.ENC_NS + "Content") ? true : false;
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

    protected SecretKey getSharedKey(Element keyInfoElem,
                                     String algorithm,
                                     CallbackHandler cb)
            throws WSSecurityException {
        String keyName = null;
        Element keyNmElem =
            (Element) WSSecurityUtil.getDirectChild(keyInfoElem,
                                                    "KeyName",
                                                    WSConstants.SIG_NS);
        if (keyNmElem != null) {
            keyNmElem.normalize();
            Node tmpN;
            if ((tmpN = keyNmElem.getFirstChild()) != null
                    && tmpN.getNodeType() == Node.TEXT_NODE) {
                keyName = tmpN.getNodeValue();
            }
        }
        if (keyName == null) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY,
                    "noKeyname");
        }
        WSPasswordCallback pwCb = new WSPasswordCallback(
                keyName, WSPasswordCallback.KEY_NAME);
        Callback[] callbacks = new Callback[1];
        callbacks[0] = pwCb;
        try {
            cb.handle(callbacks);
        } catch (IOException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "noPassword",
                    new Object[]{keyName});
        } catch (UnsupportedCallbackException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "noPassword",
                    new Object[]{keyName});
        }
        byte[] decryptedData = pwCb.getKey();
        if (decryptedData == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "noPassword",
                    new Object[]{keyName});
        }
        return WSSecurityUtil.prepareSecretKey(algorithm, decryptedData);
    }

    /**
     * Method getDecodedBase64EncodedData
     * @param element
     * @return a byte array containing the decoded data
     * @throws WSSecurityException
     */
    public static byte[] getDecodedBase64EncodedData(Element element) throws WSSecurityException {
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

    /**
     * @return the strored decrypted bytes
     */
    public byte[] getDecryptedBytes() {
        return decryptedBytes;
    }
}
