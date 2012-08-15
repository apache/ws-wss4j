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
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.ConversationConstants;
import org.apache.ws.security.conversation.ConversationException;
import org.apache.ws.security.conversation.dkalgo.AlgoFactory;
import org.apache.ws.security.conversation.dkalgo.DerivationAlgorithm;
import org.apache.ws.security.message.token.DerivedKeyToken;
import org.apache.ws.security.message.token.KerberosSecurity;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.UnsupportedEncodingException;

/**
 * Base class for DerivedKey encryption and signature
 *
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 * @author Davanum Srinivas (dims@yahoo.com)
 * @author Werner Dittmann (werner@apache.org)
 */
public abstract class WSSecDerivedKeyBase extends WSSecSignatureBase {
    
    protected Document document;
    
    /**
     * Session key used as the secret in key derivation
     */
    protected byte[] ephemeralKey;
     
    /**
     * DerivedKeyToken of this builder
     */
    protected DerivedKeyToken dkt = null;
    
    /**
     * Raw bytes of the derived key
     */
    protected byte[] derivedKeyBytes = null; 
    
    /**
     * wsu:Id of the wsc:DerivedKeyToken
     */
    protected String dktId = null;
    
    /**
     * Client's label value
     */
    protected String clientLabel = ConversationConstants.DEFAULT_LABEL;
    
    /**
     * Service's label value
     */
    protected String serviceLabel = ConversationConstants.DEFAULT_LABEL;
    
    /**
     * soap:Envelope element
     */
    protected Element envelope = null;
    
    /**
     * The Token identifier of the token that the <code>DerivedKeyToken</code> 
     * is (or to be) derived from.
     */
    protected String tokenIdentifier = null;
    
    /**
     * True if the tokenIdentifier is a direct reference to a key identifier
     * instead of a URI to a key
     */
    protected boolean tokenIdDirectId;

    /**
     * The derived key will change depending on the sig/encr algorithm.
     * Therefore the child classes are expected to provide this value.
     * @return the derived key length
     * @throws WSSecurityException
     */
    protected abstract int getDerivedKeyLength() throws WSSecurityException;
   
    /**
     * The wsse:SecurityTokenReference element to be used
     */
    protected Element strElem;
    
    private int wscVersion = ConversationConstants.DEFAULT_VERSION;
    
    protected int derivedKeyLength = -1;
    
    private String customValueType;
    
    
    public WSSecDerivedKeyBase() {
        super();
    }
    public WSSecDerivedKeyBase(WSSConfig config) {
        super(config);
    }

    
    /**
     * @param ephemeralKey The ephemeralKey to set.
     */
    public void setExternalKey(byte[] ephemeralKey, String tokenIdentifier) {
        this.ephemeralKey = ephemeralKey;
        this.tokenIdentifier = tokenIdentifier;
    }
    
    /**
     * @param ephemeralKey The ephemeralKey to set.
     */
    public void setExternalKey(byte[] ephemeralKey, Element strElem) {
        this.ephemeralKey = ephemeralKey;
        this.strElem = strElem;
    }
    
    /**
     * @return Returns the tokenIdentifier.
     */
    public String getTokenIdentifier() {
        return tokenIdentifier;
    }
    
    /**
     * Get the id generated during <code>prepare()</code>.
     * 
     * Returns the the value of wsu:Id attribute of the DerivedKeyToken element.
     * 
     * @return Return the wsu:Id of this token or null if <code>prepare()</code>
     *         was not called before.
     */
    public String getId() {
        return dktId;
    }
    
    /**
     * Set the label value of the client.
     * @param clientLabel
     */    
    public void setClientLabel(String clientLabel) {
        this.clientLabel = clientLabel;
    }

    /**
     * Set the label value of the service.
     * @param serviceLabel
     */
    public void setServiceLabel(String serviceLabel) {
        this.serviceLabel = serviceLabel;
    }

    /**
     * Initialize a WSSec Derived key.
     * 
     * The method prepares and initializes a WSSec derived key structure after the
     * relevant information was set. This method also creates and initializes the
     * derived token using the ephemeral key. After preparation references
     * can be added, encrypted and signed as required.
     * 
     * This method does not add any element to the security header. This must be
     * done explicitly.
     * 
     * @param doc The unsigned SOAP envelope as <code>Document</code>
     * @throws WSSecurityException
     */
    public void prepare(Document doc) throws WSSecurityException, ConversationException {
        
        document = doc;

        // Create the derived keys
        // At this point figure out the key length according to the symencAlgo
        int offset = 0;
        int length = getDerivedKeyLength();
        byte[] label;
        try {
            label = (clientLabel + serviceLabel).getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new WSSecurityException("UTF-8 encoding is not supported", e);
        }
        byte[] nonce = WSSecurityUtil.generateNonce(16);
        
        byte[] seed = new byte[label.length + nonce.length];
        System.arraycopy(label, 0, seed, 0, label.length);
        System.arraycopy(nonce, 0, seed, label.length, nonce.length);
        
        DerivationAlgorithm algo = 
            AlgoFactory.getInstance(ConversationConstants.DerivationAlgorithm.P_SHA_1);
        
        derivedKeyBytes = algo.createKey(ephemeralKey, seed, offset, length);
        
        // Add the DKTs
        dkt = new DerivedKeyToken(wscVersion, document);
        dktId = getWsConfig().getIdAllocator().createId("DK-", dkt);
        
        dkt.setOffset(offset);
        dkt.setLength(length);
        dkt.setNonce(Base64.encode(nonce));
        dkt.setID(dktId);
        
        if (strElem == null) {
            SecurityTokenReference secRef = new SecurityTokenReference(document);
            String strUri = getWsConfig().getIdAllocator().createSecureId("STR-", secRef);
            secRef.setID(strUri);
            
            switch (keyIdentifierType) {
            case WSConstants.CUSTOM_KEY_IDENTIFIER:
                secRef.setKeyIdentifier(customValueType, tokenIdentifier);
                if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(customValueType)) {
                    secRef.addTokenType(WSConstants.WSS_SAML_TOKEN_TYPE);
                } else if (WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(customValueType)) {
                    secRef.addTokenType(WSConstants.WSS_SAML2_TOKEN_TYPE);
                } else if (WSConstants.WSS_ENC_KEY_VALUE_TYPE.equals(customValueType)) {
                    secRef.addTokenType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
                }
                break;
            default:
                Reference ref = new Reference(document);
                
                if (tokenIdDirectId) {
                    ref.setURI(tokenIdentifier);
                } else {
                    ref.setURI("#" + tokenIdentifier);
                }
                if (customValueType != null && !"".equals(customValueType)) {
                    ref.setValueType(customValueType);
                } 
                if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(customValueType)) {
                    secRef.addTokenType(WSConstants.WSS_SAML_TOKEN_TYPE);
                    ref.setValueType(customValueType);
                } else if (WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(customValueType)) {
                    secRef.addTokenType(WSConstants.WSS_SAML2_TOKEN_TYPE);
                } else if (WSConstants.WSS_ENC_KEY_VALUE_TYPE.equals(customValueType)) {
                    secRef.addTokenType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
                    ref.setValueType(customValueType);
                } else if (KerberosSecurity.isKerberosToken(customValueType)) {
                    secRef.addTokenType(customValueType);
                    ref.setValueType(customValueType);
                } else if (WSConstants.WSC_SCT.equals(customValueType)
                    || WSConstants.WSC_SCT_05_12.equals(customValueType)) {
                    ref.setValueType(customValueType);
                } else if (!WSConstants.WSS_USERNAME_TOKEN_VALUE_TYPE.equals(customValueType)) {
                    secRef.addTokenType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
                } 

                secRef.setReference(ref);
            }
            
            dkt.setSecurityTokenReference(secRef); 
        } else {
            dkt.setSecurityTokenReference(strElem);
        }
    }


    /**
     * Prepend the DerivedKey element to the elements already in the Security
     * header.
     * 
     * The method can be called any time after <code>prepare()</code>. This
     * allows to insert the DerivedKey element at any position in the Security
     * header.
     * 
     * @param secHeader The security header that holds the Signature element.
     */
    public void prependDKElementToHeader(WSSecHeader secHeader) {
        WSSecurityUtil.prependChildElement(
            secHeader.getSecurityHeader(), dkt.getElement()
        );
    }
    
    public void appendDKElementToHeader(WSSecHeader secHeader) {
        Element secHeaderElement = secHeader.getSecurityHeader();
        secHeaderElement.appendChild(dkt.getElement());
    }

    /**
     * @param wscVersion The wscVersion to set.
     */
    public void setWscVersion(int wscVersion) {
        this.wscVersion = wscVersion;
    }
    
    public Element getdktElement() {
        return dkt.getElement();
    }

    public void setDerivedKeyLength(int keyLength) {
        derivedKeyLength = keyLength;
    }

    public void setCustomValueType(String customValueType) {
        this.customValueType = customValueType;
    }
    
    public void setTokenIdDirectId(boolean b) {
        tokenIdDirectId = b;
    }
}
