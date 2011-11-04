/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.ws.security.message;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.ConversationException;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.transform.STRTransform;
import org.apache.ws.security.util.WSSecurityUtil;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;

/**
 * Builder to sign with derived keys
 * 
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 * @author Davanum Srinivas (dims@yahoo.com)
 * @author Werner Dittmann (werner@apache.org)
 */
public class WSSecDKSign extends WSSecDerivedKeyBase {

    private static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(WSSecDKSign.class);

    private String sigAlgo = WSConstants.HMAC_SHA1;
    private String digestAlgo = WSConstants.SHA1;
    private String canonAlgo = WSConstants.C14N_EXCL_OMIT_COMMENTS;
    private byte[] signatureValue = null;
    
    private String keyInfoUri = null;
    private SecurityTokenReference secRef = null;
    private String strUri = null;
    private WSDocInfo wsDocInfo;
    
    private KeyInfoFactory keyInfoFactory;
    private XMLSignatureFactory signatureFactory;
    private XMLSignature sig;
    private KeyInfo keyInfo;
    private CanonicalizationMethod c14nMethod;
    private Element securityHeader = null;

    public WSSecDKSign() {
        super();
        init();
    }
    
    public WSSecDKSign(WSSConfig config) {
        super(config);
        init();
    }
    
    private void init() {
        // Try to install the Santuario Provider - fall back to the JDK provider if this does
        // not work
        try {
            signatureFactory = XMLSignatureFactory.getInstance("DOM", "ApacheXMLDSig");
        } catch (NoSuchProviderException ex) {
            signatureFactory = XMLSignatureFactory.getInstance("DOM");
        }
        try {
            keyInfoFactory = KeyInfoFactory.getInstance("DOM", "ApacheXMLDSig");
        } catch (NoSuchProviderException ex) {
            keyInfoFactory = KeyInfoFactory.getInstance("DOM");
        }
    }
    
    public Document build(Document doc, WSSecHeader secHeader)
        throws WSSecurityException, ConversationException {
        
        prepare(doc, secHeader);
        String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
        if (parts == null) {
            parts = new ArrayList<WSEncryptionPart>(1);
            WSEncryptionPart encP = 
                new WSEncryptionPart(
                    WSConstants.ELEM_BODY,
                    soapNamespace, 
                    "Content"
                );
            parts.add(encP);
        } else {
            for (WSEncryptionPart part : parts) {
                if ("STRTransform".equals(part.getName()) && part.getId() == null) {
                    part.setId(strUri);
                }
            }
        }
        
        List<javax.xml.crypto.dsig.Reference> referenceList = 
            addReferencesToSign(parts, secHeader);
        computeSignature(referenceList);
        
        //
        // prepend elements in the right order to the security header
        //
        prependDKElementToHeader(secHeader);

        return doc;
    }
    
    public void prepare(Document doc, WSSecHeader secHeader)
        throws WSSecurityException, ConversationException {
        super.prepare(doc);
        wsDocInfo = new WSDocInfo(doc);
        securityHeader = secHeader.getSecurityHeader();
        sig = null;
        
        try {
            C14NMethodParameterSpec c14nSpec = null;
            if (getWsConfig().isWsiBSPCompliant() && canonAlgo.equals(WSConstants.C14N_EXCL_OMIT_COMMENTS)) {
                List<String> prefixes = 
                    getInclusivePrefixes(secHeader.getSecurityHeader(), false);
                c14nSpec = new ExcC14NParameterSpec(prefixes);
            }
            
           c14nMethod = signatureFactory.newCanonicalizationMethod(canonAlgo, c14nSpec);
        } catch (Exception ex) {
            log.error("", ex);
            throw new WSSecurityException(
                WSSecurityException.FAILED_SIGNATURE, "noXMLSig", null, ex
            );
        }

        keyInfoUri = getWsConfig().getIdAllocator().createSecureId("KI-", keyInfo);
        
        secRef = new SecurityTokenReference(doc);
        strUri = getWsConfig().getIdAllocator().createSecureId("STR-", secRef);
        secRef.setID(strUri);
        
        Reference refUt = new Reference(document);
        refUt.setURI("#" + dktId);
        secRef.setReference(refUt);
        
        XMLStructure structure = new DOMStructure(secRef.getElement());
        wsDocInfo.addTokenElement(secRef.getElement(), false);
        keyInfo = 
            keyInfoFactory.newKeyInfo(
                java.util.Collections.singletonList(structure), keyInfoUri
            );
        
    }
    
    /**
     * Returns the SignatureElement.
     * The method can be called any time after <code>prepare()</code>.
     * @return The DOM Element of the signature.
     */
    public Element getSignatureElement() {
        return
            WSSecurityUtil.getDirectChildElement(
                securityHeader,
                WSConstants.SIG_LN,
                WSConstants.SIG_NS
            );
    }
    
    /**
     * This method adds references to the Signature.
     * 
     * @param references The list of references to sign
     * @param secHeader The Security Header
     * @throws WSSecurityException
     */
    public List<javax.xml.crypto.dsig.Reference> addReferencesToSign(
        List<WSEncryptionPart> references, 
        WSSecHeader secHeader
    ) throws WSSecurityException {
        return 
            addReferencesToSign(
                document, 
                references,
                wsDocInfo,
                signatureFactory, 
                secHeader, 
                getWsConfig(), 
                digestAlgo
            );
    }
    
    /**
     * Compute the Signature over the references.
     * 
     * After references are set this method computes the Signature for them.
     * This method can be called any time after the references were set. See
     * <code>addReferencesToSign()</code>.
     * 
     * @throws WSSecurityException
     */
    public void computeSignature(
        List<javax.xml.crypto.dsig.Reference> referenceList
    ) throws WSSecurityException {
        computeSignature(referenceList, true, null);
    }
    
    /**
     * Compute the Signature over the references.
     * 
     * After references are set this method computes the Signature for them.
     * This method can be called any time after the references were set. See
     * <code>addReferencesToSign()</code>.
     * 
     * @throws WSSecurityException
     */
    public void computeSignature(
        List<javax.xml.crypto.dsig.Reference> referenceList, 
        boolean prepend,
        Element siblingElement
    ) throws WSSecurityException {
        try {
            java.security.Key key = 
                WSSecurityUtil.prepareSecretKey(sigAlgo, derivedKeyBytes);
            SignatureMethod signatureMethod = 
                signatureFactory.newSignatureMethod(sigAlgo, null);
            SignedInfo signedInfo = 
                signatureFactory.newSignedInfo(c14nMethod, signatureMethod, referenceList);
            
            sig = signatureFactory.newXMLSignature(
                    signedInfo, 
                    keyInfo,
                    null,
                    getWsConfig().getIdAllocator().createId("SIG-", null),
                    null);
            
            //
            // Figure out where to insert the signature element
            //
            XMLSignContext signContext = null;
            if (prepend) {
                if (siblingElement == null) {
                    siblingElement = (Element)securityHeader.getFirstChild();
                }
                if (siblingElement == null) {
                    signContext = new DOMSignContext(key, securityHeader);
                } else {
                    signContext = new DOMSignContext(key, securityHeader, siblingElement);
                }
            } else {
                signContext = new DOMSignContext(key, securityHeader);
            }
            
            signContext.putNamespacePrefix(WSConstants.SIG_NS, WSConstants.SIG_PREFIX);
            if (WSConstants.C14N_EXCL_OMIT_COMMENTS.equals(canonAlgo)) {
                signContext.putNamespacePrefix(
                    WSConstants.C14N_EXCL_OMIT_COMMENTS, 
                    WSConstants.C14N_EXCL_OMIT_COMMENTS_PREFIX
                );
            }
            signContext.setProperty(STRTransform.TRANSFORM_WS_DOC_INFO, wsDocInfo);
            wsDocInfo.setCallbackLookup(callbackLookup);
            
            // Add the elements to sign to the Signature Context
            wsDocInfo.setTokensOnContext((DOMSignContext)signContext);
            if (secRef != null && secRef.getElement() != null) {
                WSSecurityUtil.storeElementInContext((DOMSignContext)signContext, secRef.getElement());
            }
            
            sig.sign(signContext);
            
            signatureValue = sig.getSignatureValue().getValue();
        } catch (Exception ex) {
            log.error(ex);
            throw new WSSecurityException(
                WSSecurityException.FAILED_SIGNATURE, null, null, ex
            );
        }
    }
    
    /**
     * @see org.apache.ws.security.message.WSSecDerivedKeyBase#getDerivedKeyLength()
     */
    protected int getDerivedKeyLength() throws WSSecurityException {
        return (derivedKeyLength > 0) ? derivedKeyLength : 
            WSSecurityUtil.getKeyLength(sigAlgo);
    }
    
    /**
     * Set the signature algorithm to use. The default is WSConstants.SHA1.
     * @param algorithm the signature algorithm to use.
     */
    public void setSignatureAlgorithm(String algorithm) {
        sigAlgo = algorithm;
    }
    
    /**
     * @return the signature algorithm to use
     */
    public String getSignatureAlgorithm() {
        return sigAlgo;
    }
    
    /**
     * Returns the the value of wsu:Id attribute of the Signature element.
     * 
     * @return Return the wsu:Id of this token or null if the signature has not been generated.
     */
    public String getSignatureId() {
        if (sig == null) {
            return null;
        }
        return sig.getId();
    }
    
    /**
     * Set the digest algorithm to use. The default is Constants.ALGO_ID_DIGEST_SHA1.
     * @param algorithm the digest algorithm to use.
     */
    public void setDigestAlgorithm(String algorithm) {
        digestAlgo = algorithm;
    }
    
    /**
     * @return the digest algorithm to use
     */
    public String getDigestAlgorithm() {
        return digestAlgo;
    }

    /**
     * @return Returns the signatureValue.
     */
    public byte[] getSignatureValue() {
        return signatureValue;
    }
    
    /**
     * Set the canonicalization method to use.
     * 
     * If the canonicalization method is not set then the recommended Exclusive
     * XML Canonicalization is used by default Refer to WSConstants which
     * algorithms are supported.
     * 
     * @param algo Is the name of the signature algorithm
     * @see WSConstants#C14N_OMIT_COMMENTS
     * @see WSConstants#C14N_WITH_COMMENTS
     * @see WSConstants#C14N_EXCL_OMIT_COMMENTS
     * @see WSConstants#C14N_EXCL_WITH_COMMENTS
     */
    public void setSigCanonicalization(String algo) {
        canonAlgo = algo;
    }

    /**
     * Get the canonicalization method.
     * 
     * If the canonicalization method was not set then Exclusive XML
     * Canonicalization is used by default.
     * 
     * @return The string describing the canonicalization algorithm.
     */
    public String getSigCanonicalization() {
        return canonAlgo;
    }

}
