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

package org.apache.wss4j.dom.message;

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.UsernameTokenUtil;
import org.apache.wss4j.common.util.WSCurrentTimeSource;
import org.apache.wss4j.common.util.WSTimeSource;
import org.apache.wss4j.dom.message.token.UsernameToken;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Builds a WS UsernameToken.
 * 
 * Refer to the WS specification, UsernameToken profile
 */
public class WSSecUsernameToken extends WSSecBase {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(WSSecUsernameToken.class);

    private String passwordType = WSConstants.PASSWORD_DIGEST;
    private UsernameToken ut;
    private boolean nonce;
    private boolean created;
    private boolean useDerivedKey;
    private boolean useMac;
    private byte[] saltValue;
    private int iteration = UsernameToken.DEFAULT_ITERATION;
    private boolean passwordsAreEncoded;
    private boolean precisionInMilliSeconds = true;
    private WSTimeSource wsTimeSource = new WSCurrentTimeSource();

    public WSSecUsernameToken() {
        super();
    }

    /**
     * Defines how to construct the password element of the
     * <code>UsernameToken</code>.
     * 
     * @param pwType
     *            contains the password type. Only allowed values are
     *            {@link WSConstants#PASSWORD_DIGEST} and
     *            {@link WSConstants#PASSWORD_TEXT}.
     *            or null when no password is needed.
     */
    public void setPasswordType(String pwType) {
        this.passwordType = pwType;
    }

    /**
     * Add a Nonce element to the UsernameToken.
     */
    public void addNonce() {
        nonce = true;
    }

    /**
     * Add a Created element to the UsernameToken.
     */
    public void addCreated() {
        created = true;
    }
    
    /**
     * Add a derived key to the UsernameToken
     * @param useMac whether the derived key is to be used for a MAC or not
     * @param saltValue The salt value to use
     * @param iteration The number of iterations to use in deriving a key
     */
    public void addDerivedKey(boolean useMac, byte[] saltValue, int iteration) {
        passwordType = null;
        useDerivedKey = true;
        this.useMac = useMac;
        this.saltValue = saltValue;
        if (iteration > 0) {
            this.iteration = iteration;
        }
    }

    /**
     * Get the derived key.
     * 
     * After the <code>prepare()</code> method was called use this method
     * to compute a derived key. The generation of this secret key is according
     * to the UsernameTokenProfile 1.1 specification (section 4 - Key Derivation).
     * 
     * @return Return the derived key of this token or null if <code>prepare()</code>
     * was not called before.
     */
    public byte[] getDerivedKey() throws WSSecurityException {
        if (ut == null || !useDerivedKey) {
            return null;
        }
        if (passwordsAreEncoded) {
            try {
                return UsernameTokenUtil.generateDerivedKey(Base64.decode(password), saltValue, iteration);
            } catch (Base64DecodingException e) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, "decoding.general", e
                );
            }
        } else {
            return UsernameTokenUtil.generateDerivedKey(password, saltValue, iteration);
        }
    }

    /**
     * @param passwordsAreEncoded
     * whether passwords are encoded
     */
    public void setPasswordsAreEncoded(boolean passwordsAreEncoded) {
        this.passwordsAreEncoded = passwordsAreEncoded;
    }

    /**
     * @return whether passwords are encoded
     */
    public boolean getPasswordsAreEncoded() {
        return passwordsAreEncoded;
    }

    /**
     * Get the id generated during <code>prepare()</code>.
     * 
     * Returns the the value of wsu:Id attribute of this UsernameToken. 
     * 
     * @return Return the wsu:Id of this token or null if <code>prepare()</code>
     * was not called before.
     */
    public String getId() {
        if (ut == null) {
            return null;
        }
        return ut.getID();
    }

    /**
     * Creates a Username token.
     * 
     * The method prepares and initializes a WSSec UsernameToken structure after
     * the relevant information was set. A Before calling
     * <code>prepare()</code> all parameters such as user, password,
     * passwordType etc. must be set. A complete <code>UsernameToken</code> is
     * constructed.
     * 
     * @param doc The SOAP envelope as W3C document
     */
    public void prepare(Document doc) {
        ut = new UsernameToken(precisionInMilliSeconds, doc, wsTimeSource, passwordType);
        ut.setPasswordsAreEncoded(passwordsAreEncoded);
        ut.setName(user);
        if (useDerivedKey) {
            saltValue = ut.addSalt(doc, saltValue, useMac);
            ut.addIteration(doc, iteration);
        } else {
            ut.setPassword(password);
        }
        if (nonce) {
            ut.addNonce(doc);
        }
        if (created) {
            ut.addCreated(precisionInMilliSeconds, wsTimeSource, doc);
        }
        ut.setID(getIdAllocator().createId("UsernameToken-", ut));
    }

    /**
     * Prepends the UsernameToken element to the elements already in the
     * Security header.
     * 
     * The method can be called any time after <code>prepare()</code>.
     * This allows to insert the UsernameToken element at any position in the
     * Security header.
     * 
     * @param secHeader The security header that holds the Signature element.
     */
    public void prependToHeader(WSSecHeader secHeader) {
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), ut.getElement());
    }

    /**
     * Appends the UsernameToken element to the elements already in the
     * Security header.
     * 
     * The method can be called any time after <code>prepare()</code>.
     * This allows to insert the UsernameToken element at any position in the
     * Security header.
     * 
     * @param secHeader The security header that holds the Signature element.
     */
    public void appendToHeader(WSSecHeader secHeader) {
        Element secHeaderElement = secHeader.getSecurityHeader();
        secHeaderElement.appendChild(ut.getElement());
    }
    
    /**
     * Adds a new <code>UsernameToken</code> to a soap envelope.
     * 
     * Before calling <code>build()</code> all parameters such as user,
     * password, passwordType etc. must be set. A complete
     * <code>UsernameToken</code> is constructed and added to the
     * <code>wsse:Security</code> header.
     * 
     * @param doc The SOAP envelope as W3C document
     * @param secHeader The security header inside the SOAP envelope
     * @return Document with UsernameToken added
     */
    public Document build(Document doc, WSSecHeader secHeader) {
        LOG.debug("Begin add username token...");

        prepare(doc);
        prependToHeader(secHeader);

        return doc;
    }

    /**
     * Returns the <code>UsernameToken</code> element.
     * 
     * The method can be called any time after <code>prepare()</code>.
     * This allows to insert the UsernameToken element at any position in the
     * Security header.
     * 
     * @return the Username Token element
     */
    public Element getUsernameTokenElement() {
       return ut.getElement(); 
    }

    public boolean isPrecisionInMilliSeconds() {
        return precisionInMilliSeconds;
    }

    public void setPrecisionInMilliSeconds(boolean precisionInMilliSeconds) {
        this.precisionInMilliSeconds = precisionInMilliSeconds;
    }

    public WSTimeSource getWsTimeSource() {
        return wsTimeSource;
    }

    public void setWsTimeSource(WSTimeSource wsTimeSource) {
        this.wsTimeSource = wsTimeSource;
    }
}
