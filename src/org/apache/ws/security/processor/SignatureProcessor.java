/*
 * Copyright  2003-2006 The Apache Software Foundation, or their licensors, as
 * appropriate.
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

package org.apache.ws.security.processor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDerivedKeyTokenPrincipal;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSDocInfoStore;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSUsernameTokenPrincipal;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.EnvelopeIdResolver;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.DerivedKeyToken;
import org.apache.ws.security.message.token.PKIPathSecurity;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.saml.SAMLUtil;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.exceptions.XMLSecurityException;

import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.namespace.QName;
import javax.security.auth.callback.CallbackHandler;
import java.security.Principal;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Vector;
import java.util.HashSet;
import java.util.Set;

public class SignatureProcessor implements Processor {
    private static Log log = LogFactory.getLog(SignatureProcessor.class.getName());
    private static Log tlog =
            LogFactory.getLog("org.apache.ws.security.TIME");
    
    private String signatureId;

    public void handleToken(Element elem, Crypto crypto, Crypto decCrypto, CallbackHandler cb, WSDocInfo wsDocInfo, Vector returnResults, WSSConfig wsc) throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Found signature element");
        }
        WSDocInfoStore.store(wsDocInfo);
        X509Certificate[] returnCert = new X509Certificate[1];
        Set returnElements = new HashSet();
        byte[][] signatureValue = new byte[1][];
        Principal lastPrincipalFound = null;
        try {
            lastPrincipalFound = verifyXMLSignature((Element) elem,
                    crypto, returnCert, returnElements, signatureValue);
        } catch (WSSecurityException ex) {
            throw ex;
        } finally {
            WSDocInfoStore.delete(wsDocInfo);
        }
        if (lastPrincipalFound instanceof WSUsernameTokenPrincipal) {
            returnResults.add(0, new WSSecurityEngineResult(
                    WSConstants.UT_SIGN, lastPrincipalFound, null,
                    returnElements, signatureValue[0]));

        } else {
            returnResults.add(0, new WSSecurityEngineResult(
                    WSConstants.SIGN, lastPrincipalFound,
                    returnCert[0], returnElements, signatureValue[0]));
        }
        signatureId = elem.getAttributeNS(null, "Id");
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
     * {@link org.apache.xml.security.signature.XMLSignature#checkSignatureValue(X509Certificate) verfication} function.
     *
     * @param elem        the XMLSignature DOM Element.
     * @param crypto      the object that implements the access to the keystore and the
     *                    handling of certificates.
     * @param returnCert  verifyXMLSignature stores the certificate in the first
     *                    entry of this array. Ther caller may then further validate
     *                    the certificate
     * @param returnElements verifyXMLSignature adds the wsu:ID attribute values for
     * 			     the signed elements to this Set
     * @return the subject principal of the validated X509 certificate (the
     *         authenticated subject). The calling function may use this
     *         principal for further authentication or authorization.
     * @throws WSSecurityException
     */
    protected Principal verifyXMLSignature(Element elem,
                                           Crypto crypto,
                                           X509Certificate[] returnCert,
                                           Set returnElements,
                                           byte[][] signatureValue)
            throws WSSecurityException {
        if (log.isDebugEnabled()) {
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
        DerivedKeyToken dkt = null;

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
                if (el.equals(WSSecurityEngine.usernameToken)) {
                    ut = new UsernameToken(token);
                    secretKey = ut.getSecretKey();
                } else if(el.equals(WSSecurityEngine.DERIVED_KEY_TOKEN_05_02) ||
                        el.equals(WSSecurityEngine.DERIVED_KEY_TOKEN_05_12)) {
                    dkt = new DerivedKeyToken(token);
                    String id = dkt.getID();
                    DerivedKeyTokenProcessor dktProcessor = (DerivedKeyTokenProcessor) wsDocInfo
                            .getProcessor(id);
                    String signatureMethodURI = sig.getSignedInfo().getSignatureMethodURI();
                    int keyLength = (dkt.getLength() > 0) ? dkt.getLength() : 
                        WSSecurityUtil.getKeyLength(signatureMethodURI);
                    
                    secretKey = dktProcessor.getKeyBytes(keyLength);
                } else {
                    if (crypto == null) {
                        throw new WSSecurityException(WSSecurityException.FAILURE,
                                "noSigCryptoFile");
                    }
                    if (el.equals(WSSecurityEngine.binaryToken)) {
                        certs = getCertificatesTokenReference((Element) token,
                                crypto);
                    } else if (el.equals(WSSecurityEngine.SAML_TOKEN)) {
                        certs = SAMLUtil.getCertificatesFromSAML((Element) token);
                    } else {
                        throw new WSSecurityException(
                                WSSecurityException.INVALID_SECURITY,
                                "unsupportedKeyInfo", new Object[]{el
                                .toString()});
                    }
                }
            } else if (secRef.containsX509Data() || secRef.containsX509IssuerSerial()) {
                certs = secRef.getX509IssuerSerial(crypto);
            } else if (secRef.containsKeyIdentifier()) {
                certs = secRef.getKeyIdentifier(crypto);
            } else {
                throw new WSSecurityException(
                        WSSecurityException.INVALID_SECURITY,
                        "unsupportedKeyInfo", new Object[]{node.toString()});
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
                    returnElements.add(WSSecurityUtil.getIDfromReference(uri));                    
                }
                
                if (certs != null) {
                    returnCert[0] = certs[0];
                    return certs[0].getSubjectDN();
                } else if(ut != null){
                    WSUsernameTokenPrincipal principal = new WSUsernameTokenPrincipal(
                            ut.getName(), ut.isHashed());
                    principal.setNonce(ut.getNonce());
                    principal.setPassword(ut.getPassword());
                    principal.setCreatedTime(ut.getCreated());
                    return principal;
                } else if (dkt != null) {
                    WSDerivedKeyTokenPrincipal principal = new WSDerivedKeyTokenPrincipal(dkt.getID());
                    principal.setNonce(dkt.getNonce());
                    principal.setLabel(dkt.getLabel());
                    principal.setLength(dkt.getLength());
                    principal.setOffset(dkt.getOffset());
                    String basetokenId = dkt.getSecuityTokenReference().getReference().getURI().substring(1);
                    principal.setBasetokenId(basetokenId);
                    return principal;
                } else {
                    throw new WSSecurityException("Cannot determine principal");
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
     * @param elem The element containing the binary security token. This is
     *             either X509 certificate(s) or a PKIPath.
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
        }
        return null;
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
        X509Security x509 = null;
        PKIPathSecurity pkiPath = null;

        if (X509Security.getType().equals(type)) {
            x509 = new X509Security(element);
            return (BinarySecurity) x509;
        } else if (PKIPathSecurity.getType().equals(type)) {
            pkiPath = new PKIPathSecurity(element);
            return (BinarySecurity) pkiPath;
        }
        throw new WSSecurityException(WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                "unsupportedBinaryTokenType", new Object[]{type});
    }

    /* (non-Javadoc)
     * @see org.apache.ws.security.processor.Processor#getId()
     */
    public String getId() {
    	return signatureId;
    }

}
