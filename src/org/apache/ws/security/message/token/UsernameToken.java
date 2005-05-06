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

package org.apache.ws.security.message.token;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.utils.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.namespace.QName;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.TimeZone;

/**
 * UsernameToken according to WS Security specifications,
 * UsernameToken profile.
 *
 * @author Davanum Srinivas (dims@yahoo.com)
 * @author Werner Dittmann (Werner.Dittmann@siemens.com)
 */
public class UsernameToken {
    private static Log log = LogFactory.getLog(UsernameToken.class.getName());

    public QName token;
    public static final String PASSWORD_TYPE = "passwordType";

    protected Element element = null;
    protected Element elementUsername = null;
    protected Element elementPassword = null;
    protected Element elementNonce = null;
    protected Element elementCreated = null;
    protected String passwordType = null;
    protected boolean hashed = true;
    private static SecureRandom random = null;
    protected WSSConfig wssConfig = WSSConfig.getDefaultWSConfig();
    
    public static String TOKEN = "UsernameToken";

    static {
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
        }
    }

    /**
     * Constructs a <code>UsernameToken</code> object and parses the
     * <code>wsse:UsernameToken</code> element to initialize it.
     *
     * @param wssConfig Configuration options for processing and building the <code>wsse:Security</code> header
     * @param elem      the <code>wsse:UsernameToken</code> element that
     *                  contains the UsernameToken data
     * @throws WSSecurityException
     */
    public UsernameToken(WSSConfig wssConfig, Element elem) throws WSSecurityException {
        this.element = elem;
        this.wssConfig = wssConfig;
        token = new QName(wssConfig.getWsseNS(), TOKEN);
        QName el = new QName(this.element.getNamespaceURI(), this.element.getLocalName());
        if (!el.equals(token)) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badTokenType00", new Object[]{el});
        }
        if (wssConfig.getProcessNonCompliantMessages()) {
            elementUsername = (Element) WSSecurityUtil.getDirectChildWSSE(element, "Username");
            elementPassword = (Element) WSSecurityUtil.getDirectChildWSSE(element, "Password");
            elementNonce = (Element) WSSecurityUtil.getDirectChildWSSE(element, "Nonce");
            elementCreated = (Element) WSSecurityUtil.getDirectChildWSU(element, "Created");
        } else {
            elementUsername = (Element) WSSecurityUtil.getDirectChild(element, "Username", wssConfig.getWsseNS());
            elementPassword = (Element) WSSecurityUtil.getDirectChild(element, "Password", wssConfig.getWsseNS());
            elementNonce = (Element) WSSecurityUtil.getDirectChild(element, "Nonce", wssConfig.getWsseNS());
            elementCreated = (Element) WSSecurityUtil.getDirectChild(element, "Created", wssConfig.getWsuNS());
        }
        if (elementUsername == null) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badTokenType01", new Object[]{el});
        }
        hashed = false;
        passwordType = elementPassword.getAttribute("Type");
        if (passwordType != null && passwordType.equals(WSConstants.PASSWORD_DIGEST)) {
            hashed = true;
            if (elementNonce == null || elementCreated == null) {
                throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badTokenType01", new Object[]{el});
            }
        }
    }

    /**
     * Constructs a <code>UsernameToken</code> object according
     * to the defined parameters.
     * <p/>
     * This constructes set the password encoding to
     * {@link WSConstants#PASSWORD_DIGEST}
     *
     * @param wssConfig Configuration options for processing and building the <code>wsse:Security</code> header
     * @param doc       the SOAP envelope as <code>Document</code>
     */
    public UsernameToken(WSSConfig wssConfig, Document doc) {
        this(wssConfig, doc, WSConstants.PASSWORD_DIGEST);
    }

    /**
     * Constructs a <code>UsernameToken</code> object according
     * to the defined parameters.
     * <p/>
     *
     * @param wssConfig    Configuration options for processing and building the <code>wsse:Security</code> header
     * @param doc          the SOAP envelope as <code>Document</code>
     * @param passwordType the required password encoding, either
     *                     {@link WSConstants#PASSWORD_DIGEST} or
     *                     {@link WSConstants#PASSWORD_TEXT}
     */
    public UsernameToken(WSSConfig wssConfig, Document doc, String pwType) {
        this.wssConfig = wssConfig;
        this.element = doc.createElementNS(wssConfig.getWsseNS(), "wsse:" + WSConstants.USERNAME_TOKEN_LN);
        WSSecurityUtil.setNamespace(this.element, wssConfig.getWsseNS(), WSConstants.WSSE_PREFIX);

        this.elementUsername = doc.createElementNS(wssConfig.getWsseNS(), "wsse:" + WSConstants.USERNAME_LN);
        WSSecurityUtil.setNamespace(this.elementUsername, wssConfig.getWsseNS(), WSConstants.WSSE_PREFIX);
        this.elementUsername.appendChild(doc.createTextNode(""));
        element.appendChild(elementUsername);

        this.elementPassword = doc.createElementNS(wssConfig.getWsseNS(), "wsse:" + WSConstants.PASSWORD_LN);
        WSSecurityUtil.setNamespace(this.elementPassword, wssConfig.getWsseNS(), WSConstants.WSSE_PREFIX);
        this.elementPassword.appendChild(doc.createTextNode(""));
        element.appendChild(elementPassword);

        hashed = false;
        passwordType = pwType;
        if (passwordType != null && passwordType.equals(WSConstants.PASSWORD_DIGEST)) {
            hashed = true;
            addNonce(doc);
            addCreated(doc);
        }
    }

    /**
     * Creates and adds a Nonce element to this UsernameToken
     */
    public void addNonce(Document doc) {
        if (elementNonce != null) {
            return;
        }
        byte[] nonceValue = new byte[16];
        random.nextBytes(nonceValue);
        this.elementNonce = doc.createElementNS(wssConfig.getWsseNS(), "wsse:" + WSConstants.NONCE_LN);
        WSSecurityUtil.setNamespace(this.elementNonce, wssConfig.getWsseNS(), WSConstants.WSSE_PREFIX);
        this.elementNonce.appendChild(doc.createTextNode(Base64.encode(nonceValue)));
        element.appendChild(elementNonce);
    }

    /**
     * Creates and adds a Created element to this UsernameToken
     */
    public void addCreated(Document doc) {
        if (elementCreated != null) {
            return;
        }
        SimpleDateFormat zulu = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        zulu.setTimeZone(TimeZone.getTimeZone("UTC"));
        Calendar rightNow = Calendar.getInstance();
        this.elementCreated = doc.createElementNS(wssConfig.getWsuNS(), "wsu:" + WSConstants.CREATED_LN);
        WSSecurityUtil.setNamespace(this.elementCreated, wssConfig.getWsuNS(), WSConstants.WSU_PREFIX);
        this.elementCreated.appendChild(doc.createTextNode(zulu.format(rightNow.getTime())));
        element.appendChild(elementCreated);
    }

    /**
     * Get the user name.
     *
     * @return the data from the user name element.
     */
    public String getName() {
		return nodeString (this.elementUsername);
	}

    /**
	 * Set the user name.
	 * 
	 * @param name
	 *            sets a text node containing the use name into the user name
	 *            element.
	 */
    public void setName(String name) {
        Text node = getFirstNode(this.elementUsername);
        node.setData(name);
    }

    /**
     * Get the nonce.
     *
     * @return the data from the nonce element.
     */
    public String getNonce() {
		return nodeString(this.elementNonce);
	}

    /**
	 * Get the created timestamp.
	 * 
	 * @return the data from the created time element.
	 */
    public String getCreated() {
		return nodeString(this.elementCreated);
	}

    /**
	 * Gets the password string. This is the password as it is in the password
	 * element of a username, token. Thus it can be either plain text or the
	 * password digest value.
	 * 
	 * @return the password string or <code>null</code> if no such node
	 *         exists.
	 */
    public String getPassword() {
    	return nodeString(this.elementPassword);
    }

    /**
     * Get the hashed inidicator.
     * If the indicator is <code>true> the password of the
     * <code>UsernameToken</code> was encoded using
     * {@link WSConstants#PASSWORD_DIGEST}
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
     * Sets the password string.
     * This function sets the password in the <code>UsernameToken</code>
     * either as plain text or encodes the password according to the
     * WS Security specifications, UsernameToken profile, into a password
     * digest.
     *
     * @param pwd the password to use
     */
    public void setPassword(String pwd) {
        if (pwd == null) {
            throw new IllegalArgumentException("pwd == null");
        }
        Text node = getFirstNode(this.elementPassword);
        try {
            if (!hashed) {
                node.setData(pwd);
                this.elementPassword.setAttribute("Type", WSConstants.PASSWORD_TEXT);
            } else {
                byte[] b1 = Base64.decode(getNonce());
                byte[] b2 = getCreated().getBytes("UTF-8");
                byte[] b3 = pwd.getBytes("UTF-8");
                byte[] b4 = new byte[b1.length + b2.length + b3.length];
                int i = 0;
                int count = 0;
                for (i = 0; i < b1.length; i++) {
                    b4[count++] = b1[i];
                }
                for (i = 0; i < b2.length; i++) {
                    b4[count++] = b2[i];
                }
                for (i = 0; i < b3.length; i++) {
                    b4[count++] = b3[i];
                }
                MessageDigest sha = MessageDigest.getInstance("SHA-1");
                sha.reset();
                sha.update(b4);
                node.setData(Base64.encode(sha.digest()));
                this.elementPassword.setAttribute("Type", WSConstants.PASSWORD_DIGEST);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String doPasswordDigest(String nonce, String created, String password) {
        String passwdDigest = null;
        try {
            byte[] b1 = Base64.decode(nonce);
            byte[] b2 = created.getBytes("UTF-8");
            byte[] b3 = password.getBytes("UTF-8");
            byte[] b4 = new byte[b1.length + b2.length + b3.length];
            int i = 0;
            int count = 0;
            for (i = 0; i < b1.length; i++) {
                b4[count++] = b1[i];
            }
            for (i = 0; i < b2.length; i++) {
                b4[count++] = b2[i];
            }
            for (i = 0; i < b3.length; i++) {
                b4[count++] = b3[i];
            }
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            sha.reset();
            sha.update(b4);
            passwdDigest = Base64.encode(sha.digest());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return passwdDigest;
    }

    /**
     * Returns the first text node of an element.
     *
     * @param e the element to get the node from
     * @return the first text node or <code>null</code> if node
     *         is null or is not a text node
     */
    private Text getFirstNode(Element e) {
        Node node = e.getFirstChild();
        return ((node != null) && node instanceof Text) ? (Text) node : null;
    }

    /**
     * Returns the data of an elemen as String or null if either the
     * the element does not contain a Text node or the node is empty.
     * 
     * @param e DOM element
     * @return Element text node data as String
     */
    private String nodeString(Element e) {
        if (e != null) {
			Text node = getFirstNode(e);
			if (node != null) {
				return node.getData();
			}
		}
		return null;
    	
    }
    /**
     * Returns the dom element of this <code>UsernameToken</code> object.
     *
     * @return the <code>wsse:UsernameToken</code> element
     */
    public Element getElement() {
        return this.element;
    }

    /**
     * Returns the string representation of the token.
     *
     * @return a XML string representation
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node) this.element);
    }

    /**
     * Gets the id.
     *
     * @return the value of the <code>wsu:Id</code> attribute of this
     *         username token
     */
    public String getID() {
        if (wssConfig.getProcessNonCompliantMessages()) {
            return WSSecurityUtil.getAttributeValueWSU(element, "Id", null);
        } else {
            return WSSecurityUtil.getAttributeValueWSU(element, "Id", wssConfig.getWsuNS());
        }
    }

    /**
     * Set the id of this username token.
     *
     * @param id the value for the <code>wsu:Id</code> attribute of this
     *           username token
     */
    public void setID(String id) {
		String prefix = WSSecurityUtil.setNamespace(this.element, wssConfig
				.getWsuNS(), WSConstants.WSU_PREFIX);
		this.element.setAttributeNS(wssConfig.getWsuNS(), prefix + ":Id", id);
    }

    /**
     * Gets the secret key as per WS-Trust spec.
     * This mthod uses default setting to generate the secret key. These
     * default values are suitable for .NET WSE.
     *
     * @return a secret key constructed from information conatined in
     *         this username token
     */
    public byte[] getSecretKey() {
		return getSecretKey(WSConstants.WSE_DERIVED_KEY_LEN,
				WSConstants.LABEL_FOR_DERIVED_KEY);
	}
    
    /**
     * Gets the secret key as per WS-Trust spec.
     *
     * @param keylen How many bytes to generate for the key
     * @param labelString the label used to generate the seed
     * @return a secret key constructed from information conatined in
     *         this username token 
     */
    public byte[] getSecretKey(int keylen, String labelString) {
        byte[] key = null;
        try {
            Mac mac = Mac.getInstance("HMACSHA1");
            byte[] password = getPassword().getBytes("UTF-8");
            byte[] label = labelString.getBytes("UTF-8");
            byte[] nonce = Base64.decode(getNonce());
            byte[] created = getCreated().getBytes("UTF-8");
            byte[] seed = new byte[label.length + nonce.length + created.length];
            int i = 0;
            int count = 0;
            for (i = 0; i < label.length; i++) {
                seed[count++] = label[i];
            }
            for (i = 0; i < nonce.length; i++) {
                seed[count++] = nonce[i];
            }
            for (i = 0; i < created.length; i++) {
                seed[count++] = created[i];
            }
            key = P_hash(password, seed, mac, keylen);
            
            if (log.isDebugEnabled()) {
				log.debug("password   :" + Base64.encode(password));
				log.debug("label      :" + Base64.encode(label));
				log.debug("nonce      :" + Base64.encode(nonce));
				log.debug("created    :" + Base64.encode(created));
				log.debug("seed       :" + Base64.encode(seed));
				log.debug("Key        :" + Base64.encode(key));
			}
        } catch (Exception e) {
            return null;
        }
        return key;
    }

    /**
     * P_hash as defined in RFC 2246 for TLS.
     * <p/>
     *
     * @param secret is the key for the HMAC
     * @param seed the seed value to start the generation - A(0)
     * @param mac the HMAC algorithm
     * @param required number of bytes to generate
     * @return a byte array that conatins a secrect key
     * @throws Exception
     */
    private static byte[] P_hash(byte[] secret, byte[] seed, Mac mac,
			int required) throws Exception {
		byte[] out = new byte[required];
		int offset = 0, tocpy;
		byte[] A, tmp;
		/*
		 * A(0) is the seed
		 */
		A = seed;
		SecretKeySpec key = new SecretKeySpec(secret, "HMACSHA1");
		mac.init(key);
		while (required > 0) {
			mac.update(A);
			A = mac.doFinal();
			mac.update(A);
			mac.update(seed);
			tmp = mac.doFinal();
			tocpy = min(required, tmp.length);
			System.arraycopy(tmp, 0, out, offset, tocpy);
			offset += tocpy;
			required -= tocpy;
		}
		return out;
	}
    
/*
 * public static void main(String[] args) throws Exception { byte[] secret =
 * Base64.decode("A4BKgeqUKi9VDwWyYPDrskwCwEQ5RIqH"); byte[] seed =
 * Base64.decode("bWFzdGVyIHNlY3JldAAAAAAAAAAAAAAAAAAAAAAy+BE8DDEUf+XnAynZEVU0PUQR4QHesAbNCmt8/Ry6NqBELuBAiZV4Z0FuCT58Fi8=");
 * int required = 48; Mac mac = Mac.getInstance("HMACSHA1"); byte[] out =
 * UsernameToken.P_hash(secret, seed, mac, 48);
 * System.out.println(Base64.encode(out));
 * //UCbz0pT2DxRfx4IpY6iWRE0KCa4Fg9JKNRlrxE8AtjNjb1NEK17NI6XdrMRMOKM2 }
 */

    /**
     * helper method.
     * <p/>
     *
     * @param a
     * @param b
     * @return
     */
    private static int min(int a, int b) {
        return (a > b) ? b : a;
    }
}
