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
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;

/**
 * Builds a WS UsernameToken.
 * 
 * Refer to the WS specification, UsernameToken profile
 * 
 * @author Werner Dittmann (werner@apache.org).
 */

public class WSSecUsernameToken extends WSSecBase {
	private static Log log = LogFactory.getLog(WSSecUsernameToken.class
			.getName());

	private String passwordType = WSConstants.PASSWORD_DIGEST;

	private UsernameToken ut = null;

	private String id = null;

	private boolean nonce = false;

	private boolean created = false;

	private Document document = null;

	/**
	 * Constructor.
	 */
	public WSSecUsernameToken() {
	}

	/**
	 * Defines how to construct the password element of the
	 * <code>UsernameToken</code>.
	 * 
	 * @param pwType
	 *            contains the password type. Only allowed values are
	 *            {@link WSConstants#PASSWORD_DIGEST} and
	 *            {@link WSConstants#PASSWORD_TEXT}.
	 */
	public void setPasswordType(String pwType) {
		if (pwType == null) {
			passwordType = WSConstants.PASSWORD_DIGEST;
		} else if (pwType.equals(WSConstants.PASSWORD_DIGEST)
				|| pwType.equals(WSConstants.PASSWORD_TEXT)) {
			passwordType = pwType;
		}
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
	 * Get the derived secret key.
	 * 
	 * After the <code>prepare()</code> method was called use this method
	 * to compute a derived secret key. The generation of this secret key is according
	 * to WS-Trust specification.
	 * 
	 * @return Return the derived secret key of this token or null if <code>prepare()</code>
	 * was not called before.
	 */
	public byte[] getSecretKey() {
		if (ut == null) {
			return null;
		}
		return ut.getSecretKey();
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
	 * @param doc
	 *            The SOAP enevlope as W3C document
	 */
	public void prepare(Document doc) {
		document = doc;
		ut = new UsernameToken(wssConfig.isPrecisionInMilliSeconds(), doc,
				passwordType);
		ut.setName(user);
		ut.setPassword(password);
		String utId = "UsernameToken-" + ut.hashCode();
		ut.setID(utId);
		if (nonce) {
			ut.addNonce(doc);
		}
		if (created) {
			ut.addCreated(wssConfig.isPrecisionInMilliSeconds(), doc);
		}
	}

	/**
	 * Prepends the UsernameToken element to the elements already in the
	 * Security header.
	 * 
	 * The method can be called any time after <code>prepare()</code>.
	 * This allows to insert the UsernameToken element at any position in the
	 * Security header.
	 * 
	 * @param secHeader
	 *            The security header that holds the Signature element.
	 */
	public void prependToHeader(WSSecHeader secHeader) {
		WSSecurityUtil.prependChildElement(document, secHeader
				.getSecurityHeader(), ut.getElement(), false);
	}

	/**
	 * Adds a new <code>UsernameToken</code> to a soap envelope.
	 * 
	 * Before calling <code>build()</code> all parameters such as user,
	 * password, passwordType etc. must be set. A complete
	 * <code>UsernameToken</code> is constructed and added to the
	 * <code>wsse:Security</code> header.
	 * 
	 * @param doc
	 *            The SOAP enevlope as W3C document
	 * @param secHeader
	 *            The security header inside the SOAP envelope
	 * @return Document with UsernameToken added
	 */
	public Document build(Document doc, WSSecHeader secHeader) {
		log.debug("Begin add username token...");

		prepare(doc);
		prependToHeader(secHeader);

		return doc;
	}

}
