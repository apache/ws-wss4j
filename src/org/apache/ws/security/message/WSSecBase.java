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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.Vector;

/**
 * This is the base class for WS Security messages. It provides common functions
 * and fields used by the specific message classes such as sign, encrypt, and
 * username token.
 * 
 * @author Werner Dittmann (Werner.Dittmann@apache.org)
 */
public class WSSecBase {
	private static Log log = LogFactory.getLog(WSSecBase.class.getName());

	protected String user = null;

	protected String password = null;

	protected int keyIdentifierType = WSConstants.ISSUER_SERIAL;

	protected Vector parts = null;

	protected int timeToLive = 300; // time between Created and Expires

	protected boolean doDebug = false;

	protected WSSConfig wssConfig = WSSConfig.getDefaultWSConfig();

	/**
	 * Constructor.
	 */
	public WSSecBase() {
	}

	/**
	 * Set the time to live. This is the time difference in seconds between the
	 * <code>Created</code> and the <code>Expires</code> in
	 * <code>Timestamp</code>. <p/>
	 * 
	 * @param ttl
	 *            The time to live in second
	 */
	public void setTimeToLive(int ttl) {
		timeToLive = ttl;
	}

	/**
	 * Set which parts of the message to encrypt/sign. <p/>
	 * 
	 * @param parts
	 *            The vector containing the WSEncryptionPart objects
	 */
	public void setParts(Vector parts) {
		this.parts = parts;
	}

	/**
	 * Sets which key identifier to use. <p/> Defines the key identifier type to
	 * use in the {@link WSSignEnvelope#build(Document, Crypto) signature} or
	 * the {@link WSEncryptBody#build(Document, Crypto) ecnryption} function to
	 * set up the key identification elements.
	 * 
	 * @param keyIdType
	 * @see WSConstants#ISSUER_SERIAL
	 * @see WSConstants#BST_DIRECT_REFERENCE
	 * @see WSConstants#X509_KEY_IDENTIFIER
	 * @see WSConstants#SKI_KEY_IDENTIFIER
	 */
	public void setKeyIdentifierType(int keyIdType) {
		keyIdentifierType = keyIdType;
	}

	/**
	 * Gets the value of the <code>keyIdentifyerType</code>.
	 * 
	 * @return The <code>keyIdentifyerType</code>.
	 * @see WSConstants#ISSUER_SERIAL
	 * @see WSConstants#BST_DIRECT_REFERENCE
	 * @see WSConstants#X509_KEY_IDENTIFIER
	 * @see WSConstants#SKI_KEY_IDENTIFIER
	 */
	public int getKeyIdentifierType() {
		return keyIdentifierType;
	}

	/**
	 * @param wsConfig
	 *            The wsConfig to set.
	 */
	public void setWsConfig(WSSConfig wsConfig) {
		this.wssConfig = wsConfig;
	}

	/**
	 * Looks up or adds a body id. <p/> First try to locate the
	 * <code>wsu:Id</code> in the SOAP body element. If one is found, the
	 * value of the <code>wsu:Id</code> attribute is returned. Otherwise the
	 * methode generates a new <code>wsu:Id</code> and an appropriate value.
	 * 
	 * @param doc
	 *            The SOAP envelope as <code>Document</code>
	 * @return The value of the <code>wsu:Id</code> attribute of the SOAP body
	 * @throws Exception
	 */
	protected String setBodyID(Document doc) throws Exception {
		SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(doc
				.getDocumentElement());
		Element bodyElement = (Element) WSSecurityUtil.getDirectChild(doc
				.getFirstChild(), soapConstants.getBodyQName().getLocalPart(),
				soapConstants.getEnvelopeURI());
		if (bodyElement == null) {
			throw new Exception("SOAP Body Element node not found");
		}
		return setWsuId(bodyElement);
	}

	protected String setWsuId(Element bodyElement) {
		String id = null;
		id = bodyElement.getAttributeNS(WSConstants.WSU_NS, "Id");

		if ((id == null) || (id.length() == 0)) {
			id = "id-" + Integer.toString(bodyElement.hashCode());
			String prefix = WSSecurityUtil.setNamespace(bodyElement,
					WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
			bodyElement.setAttributeNS(WSConstants.WSU_NS, prefix + ":Id", id);
		}
		return id;
	}

	/**
	 * Set the user and password info. <p/> Both information is used to get the
	 * user's private signing key.
	 * 
	 * @param user
	 *            This is the user's alias name in the keystore that identifies
	 *            the private key to sign the document
	 * @param password
	 *            The user's password to get the private signing key from the
	 *            keystore
	 */
	public void setUserInfo(String user, String password) {
		this.user = user;
		this.password = password;
	}
}
