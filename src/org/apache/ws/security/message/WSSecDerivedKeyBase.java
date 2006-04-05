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

package org.apache.ws.security.message;

import java.io.UnsupportedEncodingException;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.conversation.ConversationConstants;
import org.apache.ws.security.conversation.dkalgo.AlgoFactory;
import org.apache.ws.security.conversation.dkalgo.DerivationAlgorithm;
import org.apache.ws.security.message.token.DerivedKeyToken;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.utils.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Base class for DerivedKey encryption and signature
 *
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 * @author Davanum Srinivas (dims@yahoo.com)
 * @author Werner Dittmann (werner@apache.org)
 */
public abstract class WSSecDerivedKeyBase extends WSSecBase {
    
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
     * soap:Envelope element
     */
    protected Element envelope = null;
    
    /**
     * The Token identifier of the token that the <code>DerivedKeyToken</code> 
     * is (or to be) derived from.
     */
    protected String tokenIdentifier = null;
    
    /**
     * The derived key will change depending on the sig/encr algorithm.
     * Therefore the child classes are expected to provide this value.
     * @return
     * @throws WSSecurityException
     */
    protected abstract int getDerivedKeyLength() throws WSSecurityException;
   
    
    /**
     * @param ephemeralKey The ephemeralKey to set.
     */
    public void setExternalKey(byte[] ephemeralKey, 
                                String tokenIdentifier) {
        this.ephemeralKey = ephemeralKey;
        this.tokenIdentifier = tokenIdentifier;
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
     * Initialize a WSSec Derived key.
     * 
     * The method prepares and initializes a WSSec dereived key structure after the
     * relevant information was set. This method also creates and initializes the
     * derived token using the ephemeral key. After preparation references
     * can be added, encrypted and signed as required.
     * 
     * </p>
     * 
     * This method does not add any element to the security header. This must be
     * done explicitly.
     * 
     * @param doc
     *            The unsigned SOAP envelope as <code>Document</code>
     * @param crypto
     *            An instance of the Crypto API to handle keystore and
     *            certificates
     * @throws WSSecurityException
     */
    public void prepare(Document doc, Crypto crypto)
        throws WSSecurityException {
        
        document = doc;

        //Create the derived keys
        //At this point figure out the key length accordng to teh symencAlgo
        int offset = 0;
        int length = this.getDerivedKeyLength();
        byte[] label;
        try {
            label = ConversationConstants.DEFAULT_LABEL.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new WSSecurityException("UTF-8 encoding is not supported", e);
        }
        byte[] nonce = WSSecurityUtil.generateNonce(16);
        
        byte[] seed = new byte[label.length + nonce.length];
        System.arraycopy(label, 0, seed, 0, label.length);
        System.arraycopy(nonce, 0, seed, label.length, nonce.length);
        
        DerivationAlgorithm algo = AlgoFactory.getInstance(ConversationConstants.DerivationAlgorithm.P_SHA_1);
        
        this.derivedKeyBytes = algo.createKey(this.ephemeralKey, seed, offset, length);
        
        
        //Add the DKTs
        dkt = new DerivedKeyToken(document);
        dktId = "derivedKeyId-" + dkt.hashCode();
        
        dkt.setLength(length);
        dkt.setNonce(Base64.encode(nonce));
        dkt.setOffset(offset);
        dkt.setID(dktId);
        //Create the SecurityTokenRef to the Encrypted Key
        SecurityTokenReference strEncKey = new SecurityTokenReference(document);
        Reference ref = new Reference(document);
        ref.setURI("#" + this.tokenIdentifier);
        strEncKey.setReference(ref);
        dkt.setSecuityTokenReference(strEncKey);
    }



    /**
     * Prepend the DerivedKey element to the elements already in the Security
     * header.
     * 
     * The method can be called any time after <code>prepare()</code>. This
     * allows to insert the DereivedKey element at any position in the Security
     * header.
     * 
     * @param secHeader
     *            The security header that holds the Signature element.
     */
    public void prependDKElementToHeader(WSSecHeader secHeader) {
        WSSecurityUtil.prependChildElement(document, secHeader
            .getSecurityHeader(), dkt.getElement(), false);
    }

}
