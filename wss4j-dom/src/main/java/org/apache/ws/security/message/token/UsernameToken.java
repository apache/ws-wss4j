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

package org.apache.ws.security.message.token;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSUsernameTokenPrincipal;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.ws.security.util.XmlSchemaDateFormat;
import org.apache.ws.security.util.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.text.DateFormat;
import java.util.TimeZone;

/**
 * UsernameToken according to WS Security specifications, UsernameToken profile.
 * 
 * Enhanced to support digest password type for username token signature
 * Enhanced to support passwordless usernametokens as allowed by spec.
 * 
 * @author Davanum Srinivas (dims@yahoo.com)
 * @author Werner Dittmann (Werner.Dittmann@t-online.de)
 */
public class UsernameToken {
    public static final String BASE64_ENCODING = WSConstants.SOAPMESSAGE_NS + "#Base64Binary";
    public static final String PASSWORD_TYPE = "passwordType";
    public static final int DEFAULT_ITERATION = 1000;
    public static final QName TOKEN = 
        new QName(WSConstants.WSSE_NS, WSConstants.USERNAME_TOKEN_LN);
    
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(UsernameToken.class);
    private static final boolean DO_DEBUG = LOG.isDebugEnabled();

    protected Element element = null;
    protected Element elementUsername = null;
    protected Element elementPassword = null;
    protected Element elementNonce = null;
    protected Element elementCreated = null;
    protected Element elementSalt = null;
    protected Element elementIteration = null;
    protected String passwordType = null;
    protected boolean hashed = true;
    private String rawPassword;        // enhancement by Alberto Coletti
    private boolean passwordsAreEncoded = false;
    private boolean bspCompliantDerivedKey = true;
    
    /**
     * Constructs a <code>UsernameToken</code> object and parses the
     * <code>wsse:UsernameToken</code> element to initialize it.
     * 
     * @param elem the <code>wsse:UsernameToken</code> element that contains
     *             the UsernameToken data
     * @throws WSSecurityException
     */
    public UsernameToken(Element elem) throws WSSecurityException {
        this (elem, false, true);
    }

    /**
     * Constructs a <code>UsernameToken</code> object and parses the
     * <code>wsse:UsernameToken</code> element to initialize it.
     * 
     * @param elem the <code>wsse:UsernameToken</code> element that contains
     *             the UsernameToken data
     * @param allowNamespaceQualifiedPasswordTypes whether to allow (wsse)
     *        namespace qualified password types or not (for interop with WCF)
     * @param bspCompliant whether the UsernameToken processing complies with the BSP spec
     * @throws WSSecurityException
     */
    public UsernameToken(
        Element elem, 
        boolean allowNamespaceQualifiedPasswordTypes,
        boolean bspCompliant
    ) throws WSSecurityException {
        element = elem;
        QName el = new QName(element.getNamespaceURI(), element.getLocalName());
        if (!el.equals(TOKEN)) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY_TOKEN,
                "badUsernameToken"
            );
        }
        elementUsername = 
            WSSecurityUtil.getDirectChildElement(
                element, WSConstants.USERNAME_LN, WSConstants.WSSE_NS
            );
        elementPassword = 
            WSSecurityUtil.getDirectChildElement(
                element, WSConstants.PASSWORD_LN, WSConstants.WSSE_NS
            );
        elementNonce = 
            WSSecurityUtil.getDirectChildElement(
                element, WSConstants.NONCE_LN, WSConstants.WSSE_NS
            );
        elementCreated = 
            WSSecurityUtil.getDirectChildElement(
                element, WSConstants.CREATED_LN, WSConstants.WSU_NS
            );
        elementSalt = 
            WSSecurityUtil.getDirectChildElement(
                element, WSConstants.SALT_LN, WSConstants.WSSE11_NS
            );
        elementIteration = 
            WSSecurityUtil.getDirectChildElement(
                element, WSConstants.ITERATION_LN, WSConstants.WSSE11_NS
            );
        if (elementUsername == null) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY_TOKEN,
                "badUsernameToken"
            );
        }
        
        if (bspCompliant) {
            checkBSPCompliance();
        }
        
        hashed = false;
        if (elementSalt != null) {
            //
            // If the UsernameToken is to be used for key derivation, the (1.1)
            // spec says that it cannot contain a password, and it must contain
            // an Iteration element
            //
            if (elementPassword != null || elementIteration == null) {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY_TOKEN,
                    "badUsernameToken"
                );
            }
            return;
        }
        
        // Guard against a malicious user sending a bogus iteration value
        if (elementIteration != null) {
            String iter = nodeString(elementIteration);
            if (iter != null) {
                int iterInt = Integer.parseInt(iter);
                if (iterInt < 0 || iterInt > 10000) {
                    throw new WSSecurityException(
                        WSSecurityException.INVALID_SECURITY_TOKEN,
                        "badUsernameToken"
                    );
                }
            }
        }
        
        if (elementPassword != null) {
            if (elementPassword.hasAttribute(WSConstants.PASSWORD_TYPE_ATTR)) {
                passwordType = elementPassword.getAttribute(WSConstants.PASSWORD_TYPE_ATTR);
            } else if (elementPassword.hasAttributeNS(
                WSConstants.WSSE_NS, WSConstants.PASSWORD_TYPE_ATTR)
            ) {
                if (allowNamespaceQualifiedPasswordTypes) {
                    passwordType = 
                        elementPassword.getAttributeNS(
                            WSConstants.WSSE_NS, WSConstants.PASSWORD_TYPE_ATTR
                        );
                } else {
                    throw new WSSecurityException(
                        WSSecurityException.INVALID_SECURITY_TOKEN,
                        "badUsernameToken"
                    );
                }
            }
            
        }
        if (WSConstants.PASSWORD_DIGEST.equals(passwordType)) {
            hashed = true;
            if (elementNonce == null || elementCreated == null) {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY_TOKEN,
                    "badUsernameToken"
                );
            }
        }
    }

    /**
     * Constructs a <code>UsernameToken</code> object according to the defined
     * parameters. <p/> This constructs set the password encoding to
     * {@link WSConstants#PASSWORD_DIGEST}
     * 
     * @param doc the SOAP envelope as <code>Document</code>
     */
    public UsernameToken(boolean milliseconds, Document doc) {
        this(milliseconds, doc, WSConstants.PASSWORD_DIGEST);
    }

    /**
     * Constructs a <code>UsernameToken</code> object according to the defined
     * parameters.
     * 
     * @param doc the SOAP envelope as <code>Document</code>
     * @param pwType the required password encoding, either
     *               {@link WSConstants#PASSWORD_DIGEST} or
     *               {@link WSConstants#PASSWORD_TEXT} or 
     *               {@link WSConstants#PW_NONE} <code>null</code> if no
     *               password required
     */
    public UsernameToken(boolean milliseconds, Document doc, String pwType) {
        element = 
            doc.createElementNS(WSConstants.WSSE_NS, "wsse:" + WSConstants.USERNAME_TOKEN_LN);

        elementUsername = 
            doc.createElementNS(WSConstants.WSSE_NS, "wsse:" + WSConstants.USERNAME_LN);
        elementUsername.appendChild(doc.createTextNode(""));
        element.appendChild(elementUsername);

        if (pwType != null) {
            elementPassword = 
                doc.createElementNS(WSConstants.WSSE_NS, "wsse:" + WSConstants.PASSWORD_LN);
            elementPassword.appendChild(doc.createTextNode(""));
            element.appendChild(elementPassword);

            passwordType = pwType;
            if (passwordType.equals(WSConstants.PASSWORD_DIGEST)) {
                addNonce(doc);
                addCreated(milliseconds, doc);
            } else {
                hashed = false;
            }
        }
    }
    
    /**
     * Add the WSSE Namespace to this UT. The namespace is not added by default for
     * efficiency purposes.
     */
    public void addWSSENamespace() {
        WSSecurityUtil.setNamespace(element, WSConstants.WSSE_NS, WSConstants.WSSE_PREFIX);
    }
    
    /**
     * Add the WSU Namespace to this UT. The namespace is not added by default for
     * efficiency purposes.
     */
    public void addWSUNamespace() {
        WSSecurityUtil.setNamespace(element, WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
    }

    /**
     * Creates and adds a Nonce element to this UsernameToken
     */
    public void addNonce(Document doc) {
        if (elementNonce != null) {
            return;
        }
        byte[] nonceValue = null;
        try {
            nonceValue = WSSecurityUtil.generateNonce(16);
        } catch (WSSecurityException ex) {
            LOG.debug(ex.getMessage(), ex);
            return;
        }
        elementNonce = doc.createElementNS(WSConstants.WSSE_NS, "wsse:" + WSConstants.NONCE_LN);
        elementNonce.appendChild(doc.createTextNode(Base64.encode(nonceValue)));
        elementNonce.setAttributeNS(null, "EncodingType", BASE64_ENCODING);
        element.appendChild(elementNonce);
    }

    /**
     * Creates and adds a Created element to this UsernameToken
     */
    public void addCreated(boolean milliseconds, Document doc) {
        if (elementCreated != null) {
            return;
        }
        DateFormat zulu = null;
        if (milliseconds) {
            zulu = new XmlSchemaDateFormat();
        } else {
            zulu = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            zulu.setTimeZone(TimeZone.getTimeZone("UTC"));
        }
        elementCreated = 
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        Date currentTime = new Date();
        elementCreated.appendChild(doc.createTextNode(zulu.format(currentTime)));
        element.appendChild(elementCreated);
    }

    /**
     * Adds and optionally creates a Salt element to this UsernameToken.
     * 
     * If the <code>saltValue</code> is <code>null</code> the the method
     * generates a new salt. Otherwise it uses the the given value.
     * 
     * @param doc The Document for the UsernameToken
     * @param saltValue The salt to add, if null generate a new salt value
     * @param mac If <code>true</code> then an optionally generated value is
     *            usable for a MAC
     * @return Returns the added salt
     */
    public byte[] addSalt(Document doc, byte[] saltValue, boolean mac) {
        if (saltValue == null) {
            saltValue = generateSalt(mac);
        }
        elementSalt = 
            doc.createElementNS(
                WSConstants.WSSE11_NS, WSConstants.WSSE11_PREFIX + ":" + WSConstants.SALT_LN
            );
        WSSecurityUtil.setNamespace(element, WSConstants.WSSE11_NS, WSConstants.WSSE11_PREFIX);
        elementSalt.appendChild(doc.createTextNode(Base64.encode(saltValue)));
        element.appendChild(elementSalt);
        return saltValue;
    }

    /**
     * Creates and adds a Iteration element to this UsernameToken
     */
    public void addIteration(Document doc, int iteration) {
        String text = "" + iteration;
        elementIteration = 
            doc.createElementNS(
                WSConstants.WSSE11_NS, WSConstants.WSSE11_PREFIX + ":" + WSConstants.ITERATION_LN
            );
        WSSecurityUtil.setNamespace(element, WSConstants.WSSE11_NS, WSConstants.WSSE11_PREFIX);
        elementIteration.appendChild(doc.createTextNode(text));
        element.appendChild(elementIteration);
    }

    /**
     * Get the user name.
     * 
     * @return the data from the user name element.
     */
    public String getName() {
        return nodeString(elementUsername);
    }

    /**
     * Set the user name.
     * 
     * @param name sets a text node containing the use name into the user name
     *             element.
     */
    public void setName(String name) {
        Text node = getFirstNode(elementUsername);
        node.setData(name);
    }

    /**
     * Get the nonce.
     * 
     * @return the data from the nonce element.
     */
    public String getNonce() {
        return nodeString(elementNonce);
    }

    /**
     * Get the created timestamp.
     * 
     * @return the data from the created time element.
     */
    public String getCreated() {
        return nodeString(elementCreated);
    }

    /**
     * Gets the password string. This is the password as it is in the password
     * element of a username token. Thus it can be either plain text or the
     * password digest value.
     * 
     * @return the password string or <code>null</code> if no such node exists.
     */
    public String getPassword() {
        String password = nodeString(elementPassword);
        // See WSS-219
        if (password == null && elementPassword != null) {
            return "";
        }
        return password;
    }

    /**
     * Get the Salt value of this UsernameToken.
     * 
     * @return Returns the binary Salt value or <code>null</code> if no Salt
     *         value is available in the username token.
     * @throws WSSecurityException
     */
    public byte[] getSalt() throws WSSecurityException {
        String salt = nodeString(elementSalt);
        if (salt != null) {
            return Base64.decode(salt);
        }
        return null;
    }

    /**
     * Get the Iteration value of this UsernameToken.
     * 
     * @return Returns the Iteration value. If no Iteration was specified in the
     *         username token the default value according to the specification
     *         is returned.
     */
    public int getIteration() {
        String iter = nodeString(elementIteration);
        if (iter != null) {
            return Integer.parseInt(iter);
        }
        return DEFAULT_ITERATION;
    }

    /**
     * Get the hashed indicator. If the indicator is <code>true> the password of the
     * <code>UsernameToken</code> was encoded using {@link WSConstants#PASSWORD_DIGEST}
     *
     * @return the hashed indicator.
     */
    public boolean isHashed() {
        return hashed;
    }

    /**
     * @return Returns the passwordType.
     */
    public String getPasswordType() {
        return passwordType;
    }

    /**
     * Sets the password string. This function sets the password in the
     * <code>UsernameToken</code> either as plain text or encodes the password
     * according to the WS Security specifications, UsernameToken profile, into
     * a password digest.
     * 
     * @param pwd the password to use
     */
    public void setPassword(String pwd) {
        if (pwd == null) {
            if (passwordType != null) {
                throw new IllegalArgumentException("pwd == null but a password is needed");
            } else {
                // Ignore setting the password.
                return;
            }
        }
        
        rawPassword = pwd;             // enhancement by Alberto coletti
        Text node = getFirstNode(elementPassword);
        try {
            if (hashed) {
                if (passwordsAreEncoded) {
                    node.setData(doPasswordDigest(getNonce(), getCreated(), Base64.decode(pwd)));
                } else {
                    node.setData(doPasswordDigest(getNonce(), getCreated(), pwd));
                }
            } else {
                node.setData(pwd);
            }
            if (passwordType != null) {
                elementPassword.setAttributeNS(null, "Type", passwordType);
            }
        } catch (Exception e) {
            if (DO_DEBUG) {
                LOG.debug(e.getMessage(), e);
            }
        }
    }

    /**
     * Set the raw (plain text) password used to compute secret key.
     */
    public void setRawPassword(RequestData data) throws WSSecurityException {
        WSPasswordCallback pwCb = 
            new WSPasswordCallback(
                getName(), getPassword(), getPasswordType(), 
                WSPasswordCallback.USERNAME_TOKEN, data
            );
        
        if (data.getCallbackHandler() == null) {
            LOG.debug("CallbackHandler is null");
            throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
        }
        try {
            data.getCallbackHandler().handle(new Callback[]{pwCb});
        } catch (IOException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(e);
            }
            throw new WSSecurityException(
                WSSecurityException.FAILED_AUTHENTICATION, null, null, e
            );
        } catch (UnsupportedCallbackException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(e);
            }
            throw new WSSecurityException(
                WSSecurityException.FAILED_AUTHENTICATION, null, null, e
            );
        }
        rawPassword = pwCb.getPassword();
    }
    
    /**
     * @param passwordsAreEncoded whether passwords are encoded
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
    
    public static String doPasswordDigest(String nonce, String created, byte[] password) {
        String passwdDigest = null;
        try {
            byte[] b1 = nonce != null ? Base64.decode(nonce) : new byte[0];
            byte[] b2 = created != null ? created.getBytes("UTF-8") : new byte[0];
            byte[] b3 = password;
            byte[] b4 = new byte[b1.length + b2.length + b3.length];
            int offset = 0;
            System.arraycopy(b1, 0, b4, offset, b1.length);
            offset += b1.length;
            
            System.arraycopy(b2, 0, b4, offset, b2.length);
            offset += b2.length;

            System.arraycopy(b3, 0, b4, offset, b3.length);
            
            byte[] digestBytes = WSSecurityUtil.generateDigest(b4);
            passwdDigest = Base64.encode(digestBytes);
        } catch (Exception e) {
            if (DO_DEBUG) {
                LOG.debug(e.getMessage(), e);
            }
        }
        return passwdDigest;
    }

    public static String doPasswordDigest(String nonce, String created, String password) {
        String passwdDigest = null;
        try {
            passwdDigest = doPasswordDigest(nonce, created, password.getBytes("UTF-8"));
        } catch (Exception e) {
            if (DO_DEBUG) {
                LOG.debug(e.getMessage(), e);
            }
        }
        return passwdDigest;
    }

    /**
     * Returns the first text node of an element.
     * 
     * @param e the element to get the node from
     * @return the first text node or <code>null</code> if node is null or is
     *         not a text node
     */
    private Text getFirstNode(Element e) {
        Node node = e.getFirstChild();
        return (node != null && Node.TEXT_NODE == node.getNodeType()) ? (Text) node : null;
    }

    /**
     * Returns the data of an element as String or null if either the the element
     * does not contain a Text node or the node is empty.
     * 
     * @param e DOM element
     * @return Element text node data as String
     */
    private String nodeString(Element e) {
        if (e != null) {
            Node node = e.getFirstChild();
            StringBuilder builder = new StringBuilder();
            boolean found = false;
            while (node != null) {
                if (Node.TEXT_NODE == node.getNodeType()) {
                    found = true;
                    builder.append(((Text)node).getData());
                }
                node = node.getNextSibling();
            }
            
            if (!found) {
                return null;
            }
            return builder.toString();
        }
        return null;
    }

    /**
     * Returns the dom element of this <code>UsernameToken</code> object.
     * 
     * @return the <code>wsse:UsernameToken</code> element
     */
    public Element getElement() {
        return element;
    }

    /**
     * Returns the string representation of the token.
     * 
     * @return a XML string representation
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node)element);
    }

    /**
     * Gets the id.
     * 
     * @return the value of the <code>wsu:Id</code> attribute of this username
     *         token
     */
    public String getID() {
        return element.getAttributeNS(WSConstants.WSU_NS, "Id");
    }

    /**
     * Set the id of this username token.
     * 
     * @param id
     *            the value for the <code>wsu:Id</code> attribute of this
     *            username token
     */
    public void setID(String id) {
        element.setAttributeNS(WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":Id", id);
    }

    /**
     * Gets the secret key as per WS-Trust spec. This method uses default setting
     * to generate the secret key. These default values are suitable for .NET
     * WSE.
     * 
     * @return a secret key constructed from information contained in this
     *         username token
     */
    public byte[] getSecretKey() {
        return getSecretKey(WSConstants.WSE_DERIVED_KEY_LEN, WSConstants.LABEL_FOR_DERIVED_KEY);
    }
    
    /**
     * Gets the secret key as per WS-Trust spec. This method uses default setting
     * to generate the secret key. These default values are suitable for .NET
     * WSE.
     * 
     * @return a secret key constructed from information contained in this
     *         username token
     */
    public byte[] getSecretKey(int keylen) {
        return getSecretKey(keylen, WSConstants.LABEL_FOR_DERIVED_KEY);
    }

    /**
     * Gets the secret key as per WS-Trust spec.
     * 
     * @param keylen How many bytes to generate for the key
     * @param labelString the label used to generate the seed
     * @return a secret key constructed from information contained in this
     *         username token
     */
    public byte[] getSecretKey(int keylen, String labelString) {
        byte[] key = null;
        try {
            Mac mac = Mac.getInstance("HMACSHA1");
            byte[] password;
            if (passwordsAreEncoded) {
                password = Base64.decode(rawPassword);
            } else {
                password = rawPassword.getBytes("UTF-8"); // enhancement by Alberto Coletti
            }
            byte[] label = labelString.getBytes("UTF-8");
            byte[] nonce = Base64.decode(getNonce());
            byte[] created = getCreated().getBytes("UTF-8");
            byte[] seed = new byte[label.length + nonce.length + created.length];

            int offset = 0;
            System.arraycopy(label, 0, seed, offset, label.length);
            offset += label.length;
            
            System.arraycopy(nonce, 0, seed, offset, nonce.length);
            offset += nonce.length;

            System.arraycopy(created, 0, seed, offset, created.length);
            
            key = P_hash(password, seed, mac, keylen);

            if (LOG.isDebugEnabled()) {
                LOG.debug("label      :" + Base64.encode(label));
                LOG.debug("nonce      :" + Base64.encode(nonce));
                LOG.debug("created    :" + Base64.encode(created));
                LOG.debug("seed       :" + Base64.encode(seed));
                LOG.debug("Key        :" + Base64.encode(key));
            }
        } catch (Exception e) {
            if (DO_DEBUG) {
                LOG.debug(e.getMessage(), e);
            }
            return null;
        }
        return key;
    }
    
    
    /**
     * This static method generates a derived key as defined in WSS Username
     * Token Profile.
     * 
     * @param password The password to include in the key generation
     * @param salt The Salt value
     * @param iteration The Iteration value. If zero (0) is given the method uses the
     *                  default value
     * @return Returns the derived key a byte array
     * @throws WSSecurityException
     */
    public static byte[] generateDerivedKey(
        byte[] password, 
        byte[] salt, 
        int iteration
    ) throws WSSecurityException {
        if (iteration == 0) {
            iteration = DEFAULT_ITERATION;
        }

        byte[] pwSalt = new byte[salt.length + password.length];
        System.arraycopy(password, 0, pwSalt, 0, password.length);
        System.arraycopy(salt, 0, pwSalt, password.length, salt.length);

        MessageDigest sha = null;
        try {
            sha = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            if (DO_DEBUG) {
                LOG.debug(e.getMessage(), e);
            }
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "noSHA1availabe", null, e
            );
        }
        //
        // Make the first hash round with start value
        //
        byte[] k = sha.digest(pwSalt);
        //
        // Perform the 1st up to iteration-1 hash rounds
        //
        for (int i = 1; i < iteration; i++) {
            k = sha.digest(k);
        }
        return k;
    }
    
    /**
     * This static method generates a derived key as defined in WSS Username
     * Token Profile.
     * 
     * @param password The password to include in the key generation
     * @param salt The Salt value
     * @param iteration The Iteration value. If zero (0) is given the method uses the
     *                  default value
     * @return Returns the derived key a byte array
     * @throws WSSecurityException
     */
    public static byte[] generateDerivedKey(
        String password, 
        byte[] salt, 
        int iteration
    ) throws WSSecurityException {
        try {
            return generateDerivedKey(password.getBytes("UTF-8"), salt, iteration);
        } catch (final java.io.UnsupportedEncodingException e) {
            if (DO_DEBUG) {
                LOG.debug(e.getMessage(), e);
            }
            throw new WSSecurityException("Unable to convert password to UTF-8", e);
        }
    }
    
    
    /**
     * This method gets a derived key as defined in WSS Username Token Profile.
     * 
     * @return Returns the derived key as a byte array
     * @throws WSSecurityException
     */
    public byte[] getDerivedKey() throws WSSecurityException {
        if (rawPassword == null || !bspCompliantDerivedKey) {
            LOG.debug("The raw password was null or the Username Token is not BSP compliant");
            throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
        }
        int iteration = getIteration();
        byte[] salt = getSalt();
        if (passwordsAreEncoded) {
            return generateDerivedKey(Base64.decode(rawPassword), salt, iteration);
        } else {
            return generateDerivedKey(rawPassword, salt, iteration);
        }
    }
    
    /**
     * Return whether the UsernameToken represented by this class is to be used
     * for key derivation as per the UsernameToken Profile 1.1. It does this by
     * checking that the username token has salt and iteration values.
     * 
     * @throws WSSecurityException
     */
    public boolean isDerivedKey() throws WSSecurityException {
        if (elementSalt != null && elementIteration != null) {
            return true;
        }
        return false;
    }
    
    /**
     * Create a WSUsernameTokenPrincipal from this UsernameToken object
     */
    public Principal createPrincipal() {
        WSUsernameTokenPrincipal principal = 
            new WSUsernameTokenPrincipal(getName(), isHashed());
        principal.setNonce(getNonce());
        principal.setPassword(getPassword());
        principal.setCreatedTime(getCreated());
        return principal;
    }
    
    /**
     * This static method generates a 128 bit salt value as defined in WSS
     * Username Token Profile.
     * 
     * @param useForMac If <code>true</code> define the Salt for use in a MAC
     * @return Returns the 128 bit salt value as byte array
     */
    public static byte[] generateSalt(boolean useForMac) {
        byte[] saltValue = null;
        try {
            saltValue = WSSecurityUtil.generateNonce(16);
        } catch (WSSecurityException ex) {
            LOG.debug(ex.getMessage(), ex);
            return null;
        }
        if (useForMac) {
            saltValue[0] = 0x01;
        } else {
            saltValue[0] = 0x02;
        }
        return saltValue;
    }

    @Override
    public int hashCode() {
        int result = 17;
        String username = getName();
        if (username != null) {
            result = 31 * result + username.hashCode();
        }
        String password = getPassword();
        if (password != null) {
            result = 31 * result + password.hashCode();
        }
        String passwordType = getPasswordType();
        if (passwordType != null) {
            result = 31 * result + passwordType.hashCode();
        }
        String nonce = getNonce();
        if (nonce != null) {
            result = 31 * result + nonce.hashCode();
        }
        String created = getCreated();
        if (created != null) {
            result = 31 * result + created.hashCode();
        }
        try {
            byte[] salt = getSalt();
            if (salt != null) {
                result = 31 * result + Arrays.hashCode(salt);
            }
        } catch (WSSecurityException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(ex.getMessage(), ex);
            }
        }
        result = 31 * result + Integer.valueOf(getIteration()).hashCode();
        
        return result;
    }
    
    @Override
    public boolean equals(Object object) {
        if (!(object instanceof UsernameToken)) {
            return false;
        }
        UsernameToken usernameToken = (UsernameToken)object;
        if (!compare(usernameToken.getName(), getName())) {
            return false;
        }
        if (!compare(usernameToken.getPassword(), getPassword())) {
            return false;
        }
        if (!compare(usernameToken.getPasswordType(), getPasswordType())) {
            return false;
        }
        if (!compare(usernameToken.getNonce(), getNonce())) {
            return false;
        }
        if (!compare(usernameToken.getCreated(), getCreated())) {
            return false;
        }
        try {
            byte[] salt = usernameToken.getSalt();
            if (!Arrays.equals(salt, getSalt())) {
                return false;
            }
        } catch (WSSecurityException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(ex.getMessage(), ex);
            }
        }
        int iteration = usernameToken.getIteration();
        if (iteration != getIteration()) {
            return false;
        }
        return true;
    }
    
    private boolean compare(String item1, String item2) {
        if (item1 == null && item2 != null) { 
            return false;
        } else if (item1 != null && !item1.equals(item2)) {
            return false;
        }
        return true;
    }
    
    /**
     * P_hash as defined in RFC 2246 for TLS.
     * 
     * @param secret is the key for the HMAC
     * @param seed the seed value to start the generation - A(0)
     * @param mac the HMAC algorithm
     * @param required number of bytes to generate
     * @return a byte array that contains a secret key
     * @throws Exception
     */
    private static byte[] P_hash(
        byte[] secret, 
        byte[] seed, 
        Mac mac, 
        int required
    ) throws Exception {
        byte[] out = new byte[required];
        int offset = 0, tocpy;
        byte[] a, tmp;
        //
        // a(0) is the seed
        //
        a = seed;
        SecretKeySpec key = new SecretKeySpec(secret, "HMACSHA1");
        mac.init(key);
        while (required > 0) {
            mac.update(a);
            a = mac.doFinal();
            mac.update(a);
            mac.update(seed);
            tmp = mac.doFinal();
            tocpy = min(required, tmp.length);
            System.arraycopy(tmp, 0, out, offset, tocpy);
            offset += tocpy;
            required -= tocpy;
        }
        return out;
    }

    /**
     * helper method.
     *
     * @param a
     * @param b
     * @return
     */
    private static int min(int a, int b) {
        return (a > b) ? b : a;
    }
    
    /**
     * A method to check that the UsernameToken is compliant with the BSP spec.
     * @throws WSSecurityException
     */
    private void checkBSPCompliance() throws WSSecurityException {
        List<Element> passwordElements = 
            WSSecurityUtil.getDirectChildElements(
                element, WSConstants.PASSWORD_LN, WSConstants.WSSE_NS
            );
        // We can only have one password element
        if (passwordElements.size() > 1) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("The Username Token had more than one password element");
            }
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY_TOKEN, "badUsernameToken"
            );
        }
        
        // We must have a password type
        if (passwordElements.size() == 1) {
            Element passwordChild = passwordElements.get(0);
            String type = passwordChild.getAttributeNS(null, WSConstants.PASSWORD_TYPE_ATTR);
            if (type == null || "".equals(type)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("The Username Token password does not have a Type attribute");
                }
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY_TOKEN, "badUsernameToken"
                );
            }
        }
        
        if (elementSalt == null) {
            // We must have a salt element to use this token for a derived key
            bspCompliantDerivedKey = false;
        }
        if (elementIteration == null) {
            // we must have an iteration element to use this token for a derived key
            bspCompliantDerivedKey = false;
        } else {
            String iter = nodeString(elementIteration);
            if (iter == null || Integer.parseInt(iter) < 1000) {
                bspCompliantDerivedKey = false;
            }
        }
        
        List<Element> createdElements = 
            WSSecurityUtil.getDirectChildElements(
                element, WSConstants.CREATED_LN, WSConstants.WSU_NS
            );
        // We can only have one created element
        if (createdElements.size() > 1) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("The Username Token has more than one created element");
            }
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY_TOKEN, "badUsernameToken"
            );
        }
        
        List<Element> nonceElements = 
            WSSecurityUtil.getDirectChildElements(
                element, WSConstants.NONCE_LN, WSConstants.WSSE_NS
            );
        // We can only have one nonce element
        if (nonceElements.size() > 1) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("The Username Token has more than one nonce element");
            }
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY_TOKEN, "badUsernameToken"
            );
        }
        
        if (nonceElements.size() == 1) {
            Element nonce = nonceElements.get(0);
            String encodingType = nonce.getAttribute("EncodingType");
            // Encoding Type must be equal to Base64Binary
            if (encodingType == null || "".equals(encodingType)
                || !BinarySecurity.BASE64_ENCODING.equals(encodingType)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("The Username Token's nonce element has a bad encoding type");
                }
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY_TOKEN, 
                    "badUsernameToken" 
                );
            }
        }
    }
}
