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
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.TimeZone;
import java.util.Vector;

/**
 * This is the base class for WS Security messages.
 * It provides common functions and fields used by the specific message 
 * classes such as sign, encrypt, and username token.
 * 
 * @author Werner Dittmann (Werner.Dittmann@siemens.com)
 *
 */
public class WSBaseMessage {
	private static Log log = LogFactory.getLog(WSBaseMessage.class.getName());
	protected String actor = null;
	protected boolean mustunderstand = true;
	protected String user = null;
	protected String password = null;
	protected int keyIdentifierType = WSConstants.ISSUER_SERIAL;
	protected Vector parts = null;
	
	protected boolean doDebug = false;

	/**
	 * Constructor.
	 */
	public WSBaseMessage() {
	}

	/**
	 * Constructor.
	 * <p/>
	 * 
	 * @param actor The actor name of the <code>wsse:Security</code> header
	 */
	public WSBaseMessage(String actor) {
		setActor(actor);
	}

	/**
	 * Constructor.
	 * <p/>
	 * 
	 * @param actor The actor name of the <code>wsse:Security</code> header
	 * @param mu    Set <code>mustUnderstand</code> to true or false
	 */
	public WSBaseMessage(String actor, boolean mu) {
		setActor(actor);
		setMustUnderstand(mu);
	}

	/**
	 * set actor name.
	 * <p/>
	 * 
	 * @param act The actor name of the <code>wsse:Security</code> header
	 */
	public void setActor(String act) {
		actor = act;
	}

	/**
	 * Set which parts of the message to encrypt/sign.
	 * <p/>
	 * 
	 * @param act The vector containing the WSEncryptionPart objects
	 */
	public void setParts(Vector parts) {
		this.parts = parts;
	}
	/**
	 * Set the <code>mustUnderstand</code> flag for the
	 * <code>wsse:Security</code> header
	 * 
	 * @param mu Set <code>mustUnderstand</code> to true or false
	 */
	public void setMustUnderstand(boolean mu) {
		mustunderstand = mu;
	}

	/**
	 * Sets which key identifier to use.
	 * <p/>
	 * Defines the key identifier type to use in the
	 * {@link WSSignEnvelope#build(Document, Crypto) signature} or the
	 * {@link WSEncryptBody#build(Document, Crypto) ecnryption}
	 * function to set up the key identification elements.
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
	 * Looks up or adds a body id.
	 * <p/>
	 * First try to locate the <code>wsu:Id</code> in the SOAP body element.
	 * If one is found, the value of the <code>wsu:Id</code> attribute is returned.
	 * Otherwise the methode generates a new <code>wsu:Id</code> and an
	 * appropriate value.
	 * 
	 * @param doc			The SOAP envelope as <code>Document</code>
	 * @return 				The value of the <code>wsu:Id</code> attribute
	 * 						of the SOAP body
	 * @throws Exception 
	 */
	protected String setBodyID(Document doc) throws Exception {
		SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
		Element bodyElement =
			(Element) WSSecurityUtil.getDirectChild(
				doc.getFirstChild(),
				soapConstants.getBodyQName().getLocalPart(),
				soapConstants.getEnvelopeURI());
		if (bodyElement == null) {
			throw new Exception("SOAP Body Element node not found");
		}
		return setWsuId(bodyElement);
	}
	
	protected String setWsuId(Element bodyElement) {
		String id = bodyElement.getAttributeNS(WSConstants.WSU_NS, "Id");
		if ((id == null) || (id.length() == 0)) {
			id = "id-" + Integer.toString(bodyElement.hashCode());
			String prefix =
				WSSecurityUtil.setNamespace(
					bodyElement,
					WSConstants.WSU_NS,
					WSConstants.WSU_PREFIX);
			bodyElement.setAttributeNS(WSConstants.WSU_NS, prefix + ":Id", id);
		}
		return id;
	}

	/**
	 * Set the user and password info. 
	 * <p/>
	 * Both information is used to get the user's private signing key.
	 * 
	 * @param user		This is the user's alias name in the keystore that
	 * 					identifies the private key to sign the document
	 * @param password	The user's password to get the private signing key
	 * 					from the keystore
	 */
	public void setUserInfo(String user, String password) {
		this.user = user;
		this.password = password;
	}

	/**
	 * Creates a security header and inserts it as child into the SOAP Envelope.
	 * <p/>
	 * Check if a WS Security header block for an actor is already available
	 * in the document. If a header block is found return it, otherwise a new
	 * wsse:Security header block is created and the attributes set
	 * 
	 * @param doc 	A SOAP envelope as <code>Document</code>
	 * @return		A <code>wsse:Security</code> element
	 */
	protected Element insertSecurityHeader(Document doc, boolean timestamp) {
		SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
		// lookup a security header block that matches actor
		Element securityHeader =
			WSSecurityUtil.getSecurityHeader(doc, actor, soapConstants);
		if (securityHeader == null) { 			// create if nothing found
			securityHeader =
				WSSecurityUtil.findWsseSecurityHeaderBlock(
					doc,
					doc.getDocumentElement(),
					true);
					
			String soapPrefix =
				WSSecurityUtil.getPrefix(soapConstants.getEnvelopeURI(),
														 securityHeader);
			if (actor != null && actor.length() > 0) {
				// Check for SOAP 1.2 here and use "role" instead of "actor"
				securityHeader.setAttributeNS(
					soapConstants.getEnvelopeURI(),
					soapPrefix
						+ ":"
						+ soapConstants.getRoleAttributeQName().getLocalPart(),
					actor);
			}
			if (mustunderstand) {
				securityHeader.setAttributeNS(
					soapConstants.getEnvelopeURI(),
					soapPrefix + ":" + WSConstants.ATTR_MUST_UNDERSTAND,
					soapConstants.getMustunderstand());
			}
			if (timestamp) {
				Element elementTime = doc.createElementNS(WSConstants.WSU_NS, "wsu:Timestamp");
				WSSecurityUtil.setNamespace(elementTime, WSConstants.WSU_NS, WSConstants.WSU_PREFIX);

				SimpleDateFormat zulu = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
				zulu.setTimeZone(TimeZone.getTimeZone("GMT"));
				Calendar rightNow = Calendar.getInstance();

				Element elementCreated = doc.createElementNS(WSConstants.WSU_NS, "wsu:" + WSConstants.CREATED_LN);
				WSSecurityUtil.setNamespace(elementTime, WSConstants.WSU_NS, WSConstants.WSU_PREFIX);				
				elementCreated.appendChild(doc.createTextNode(zulu.format(rightNow.getTime())));
				
				elementTime.appendChild(elementCreated);
				securityHeader.appendChild(elementTime);
			}
		}
		return securityHeader;
	}
}
