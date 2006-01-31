/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.ws.security.policy;

/**
 * @author Werner Dittmann (werner@apache.org)
 */
import java.util.ArrayList;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.policy.model.AlgorithmSuite;
import org.apache.ws.security.policy.model.Token;
import org.apache.ws.security.policy.model.X509Token;

public class WSS4JPolicyData {

	/*
	 * Global settings for overall security processing
	 */
	private boolean symmetricBinding;
	
	private String layout;

	private boolean includeTimestamp;

	private boolean entireHeaderAndBodySignatures;

	private String protectionOrder;

	private boolean signatureProtection;

	private boolean tokenProtection;
	
	private boolean signatureConfirmation;

	/*
	 * Message tokens for symmetrical binding
	 */
	private WSS4JPolicyToken encryptionToken;

	private WSS4JPolicyToken signatureToken;

	/*
	 * Message tokens for asymmetrical binding
	 */
	private WSS4JPolicyToken recipientToken; // used to encrypt data to receipient

	private WSS4JPolicyToken initiatorToken; // used to sign data by initiator

	/*
	 * Which parts or elements of the message to sign/encrypt with
	 * the messagen tokens. Parts or elements to sign/encrypt with
	 * supporting tokens are stored together with the tokens (see
	 * WSS4JPolicyToken).
	 */
	private boolean signBody;
	
	private boolean encryptBody;
	
	private ArrayList signedParts;

	private ArrayList signedElements;

	private ArrayList encryptedParts;

	private ArrayList encryptedElements;

	/**
	 * @return Returns the symmetricBinding.
	 */
	public boolean isSymmetricBinding() {
		return symmetricBinding;
	}

	/**
	 * @param symmetricBinding The symmetricBinding to set.
	 */
	public void setSymmetricBinding(boolean symmetricBinding) {
		this.symmetricBinding = symmetricBinding;
	}

	/**
	 * @return Returns the entireHeaderAndBodySignatures.
	 */
	public boolean isEntireHeaderAndBodySignatures() {
		return entireHeaderAndBodySignatures;
	}

	/**
	 * @param entireHeaderAndBodySignatures
	 *            The entireHeaderAndBodySignatures to set.
	 */
	public void setEntireHeaderAndBodySignatures(
			boolean entireHeaderAndBodySignatures) {
		this.entireHeaderAndBodySignatures = entireHeaderAndBodySignatures;
	}

	/**
	 * @return Returns the includeTimestamp.
	 */
	public boolean isIncludeTimestamp() {
		return includeTimestamp;
	}

	/**
	 * @param includeTimestamp
	 *            The includeTimestamp to set.
	 */
	public void setIncludeTimestamp(boolean includeTimestamp) {
		this.includeTimestamp = includeTimestamp;
	}

	/**
	 * @return Returns the layout.
	 */
	public String getLayout() {
		return layout;
	}

	/**
	 * @param layout
	 *            The layout to set.
	 */
	public void setLayout(String layout) {
		this.layout = layout;
	}

	/**
	 * @return Returns the protectionOrder.
	 */
	public String getProtectionOrder() {
		return protectionOrder;
	}

	/**
	 * @param protectionOrder
	 *            The protectionOrder to set.
	 */
	public void setProtectionOrder(String protectionOrder) {
		this.protectionOrder = protectionOrder;
	}

	/**
	 * @return Returns the signatureProtection.
	 */
	public boolean isSignatureProtection() {
		return signatureProtection;
	}

	/**
	 * @param signatureProtection
	 *            The signatureProtection to set.
	 */
	public void setSignatureProtection(boolean signatureProtection) {
		this.signatureProtection = signatureProtection;
	}

	/**
	 * @return Returns the tokenProtection.
	 */
	public boolean isTokenProtection() {
		return tokenProtection;
	}

	/**
	 * @param tokenProtection
	 *            The tokenProtection to set.
	 */
	public void setTokenProtection(boolean tokenProtection) {
		this.tokenProtection = tokenProtection;
	}

	/**
	 * @return Returns the signatureConfirmation.
	 */
	public boolean isSignatureConfirmation() {
		return signatureConfirmation;
	}

	/**
	 * @param signatureConfirmation The signatureConfirmation to set.
	 */
	public void setSignatureConfirmation(boolean signatureConfirmation) {
		this.signatureConfirmation = signatureConfirmation;
	}

	/**
	 * Return the encryption token data.
	 * 
	 * The returned token data may be empty.
	 * 
	 * @return Returns the encryptionToken.
	 */
	public WSS4JPolicyToken getEncryptionToken() {
		if (encryptionToken == null) {
			encryptionToken = new WSS4JPolicyToken();
		}
		return encryptionToken;
	}

	/**
	 * Sets the parameters for the encryption token according to parsed policy.
	 * 
	 * The encryption token is specific to the symmetric binding.
	 * 
	 * @param encryptionToken
	 *            The encryptionToken to set.
	 */
	public void setEncryptionToken(Token encToken, AlgorithmSuite suite)
			throws WSSPolicyException {
		if (encToken instanceof X509Token) {
			if (encryptionToken == null) {
				encryptionToken = new WSS4JPolicyToken();
			}
			encryptionToken.encAlgorithm = suite.getEncryption();
			encryptionToken.tokenType = WSS4JPolicyToken.X509Token;
			encryptionToken.encTransportAlgorithm = suite
					.getAsymmetricKeyWrap();
			X509Token tok = (X509Token) encToken;
			if (tok.isRequireIssuerSerialReference()) {
				encryptionToken.encKeyIdentifier = WSConstants.ISSUER_SERIAL;
			} else if (tok.isRequireThumbprintReference()) {
				encryptionToken.encKeyIdentifier = WSConstants.THUMBPRINT_IDENTIFIER;
			} else if (tok.isRequireEmbeddedTokenReference()) {
				encryptionToken.encKeyIdentifier = WSConstants.BST_DIRECT_REFERENCE;
			} else {
				throw new WSSPolicyException(
						"Unknown key reference specifier for X509Token");

			}
		}
	}

	/**
	 * Sets the parameters for the protection token according to parsed policy.
	 * 
	 * The protection token is specific to the symmetric binding.
	 * 
	 * @param protectionToken
	 *            The protectionToken to set.
	 */
	public void setProtectionToken(Token protectionToken, AlgorithmSuite suite)
			throws WSSPolicyException {
		setEncryptionToken(protectionToken, suite);
		setSignatureToken(protectionToken, suite);
	}

	/**
	 * Return the signature token data.
	 * 
	 * The returned token data may be empty.
	 * 
	 * @return Returns the signatureToken.
	 */
	public WSS4JPolicyToken getSignatureToken() {
		if (signatureToken == null) {
			signatureToken = new WSS4JPolicyToken();				
		}
		return signatureToken;
	}

	/**
	 * Sets the parameters for the signature token according to parsed policy.
	 * 
	 * The signature token is specific to the symmetric binding.
	 * 
	 * @param signatureToken
	 *            The signatureToken to set.
	 */
	public void setSignatureToken(Token sigToken, AlgorithmSuite suite)
			throws WSSPolicyException {
		if (sigToken instanceof X509Token) {
			if (signatureToken == null) {
				signatureToken = new WSS4JPolicyToken();				
			}
			signatureToken.sigAlgorithm = suite.getAsymmetricSignature();
			signatureToken.tokenType = WSS4JPolicyToken.X509Token;
			X509Token tok = (X509Token) sigToken;
			if (tok.isRequireIssuerSerialReference()) {
				signatureToken.encKeyIdentifier = WSConstants.ISSUER_SERIAL;
			} else if (tok.isRequireThumbprintReference()) {
				signatureToken.encKeyIdentifier = WSConstants.THUMBPRINT_IDENTIFIER;
			} else if (tok.isRequireEmbeddedTokenReference()) {
				signatureToken.encKeyIdentifier = WSConstants.BST_DIRECT_REFERENCE;
			} else {
				throw new WSSPolicyException(
						"Unknown key reference specifier for X509Token");

			}
		}
	}

	/**
	 * Return the initiator token data.
	 * 
	 * The returned token data may be empty.
	 * 
	 * @return Returns the initiatorToken.
	 */
	public WSS4JPolicyToken getInitiatorToken() {
		if (initiatorToken == null) {
			initiatorToken = new WSS4JPolicyToken();
		}
		return initiatorToken;
	}

	/**
	 * Sets the parameters for the initiator token according to parsed policy.
	 * 
	 * The initiator token is specific to the symmetric binding. The message
	 * initiator uses this token to sign its data. Thus this method initializes
	 * the signature relevant parts of the WSS4JPolicyToken data.
	 * 
	 * @param initiatorToken
	 *            The initiatorToken to set.
	 */
	public void setInitiatorToken(Token iniToken, AlgorithmSuite suite)
			throws WSSPolicyException {
		if (iniToken instanceof X509Token) {
			if (initiatorToken == null) {
				initiatorToken = new WSS4JPolicyToken();
			}
			initiatorToken.sigAlgorithm = suite.getAsymmetricSignature();
			initiatorToken.tokenType = WSS4JPolicyToken.X509Token;
			X509Token tok = (X509Token) iniToken;
			if (tok.isRequireIssuerSerialReference()) {
				initiatorToken.sigKeyIdentifier = WSConstants.ISSUER_SERIAL;
			} else if (tok.isRequireThumbprintReference()) {
				initiatorToken.sigKeyIdentifier = WSConstants.THUMBPRINT_IDENTIFIER;
			} else if (tok.isRequireEmbeddedTokenReference()) {
				initiatorToken.sigKeyIdentifier = WSConstants.BST_DIRECT_REFERENCE;
			} else {
				throw new WSSPolicyException(
						"Unknown key reference specifier for X509Token");

			}
		}
	}

	/**
	 * Return the recipient token data.
	 * 
	 * The returned token data may be empty.
	 * 
	 * @return Returns the recipientToken.
	 */
	public WSS4JPolicyToken getRecipientToken() {
		if (recipientToken == null) {
			recipientToken = new WSS4JPolicyToken();
		}
		return recipientToken;
	}

	/**
	 * Sets the parameters for the initiator token according to parsed policy.
	 * 
	 * The initiator token is specific to the symmetric binding. The message
	 * initiator uses this token to encrypt data sent to the reipient. Thus this
	 * method initializes the encryption relevant parts of the WSS4JPolicyToken data.
	 * 
	 * @param recipientToken
	 *            The recipientToken to set.
	 */
	public void setRecipientToken(Token recToken, AlgorithmSuite suite)
			throws WSSPolicyException {
		if (recToken instanceof X509Token) {
			if (recipientToken == null) {
				recipientToken = new WSS4JPolicyToken();
			}
			recipientToken.tokenType = WSS4JPolicyToken.X509Token;
			recipientToken.encAlgorithm = suite.getEncryption();
			recipientToken.encTransportAlgorithm = suite.getAsymmetricKeyWrap();
			X509Token tok = (X509Token) recToken;
			if (tok.isRequireIssuerSerialReference()) {
				recipientToken.encKeyIdentifier = WSConstants.ISSUER_SERIAL;
			} else if (tok.isRequireThumbprintReference()) {
				recipientToken.encKeyIdentifier = WSConstants.THUMBPRINT_IDENTIFIER;
			} else if (tok.isRequireEmbeddedTokenReference()) {
				recipientToken.encKeyIdentifier = WSConstants.BST_DIRECT_REFERENCE;
			} else {
				throw new WSSPolicyException(
						"Unknown key reference specifier for X509Token");

			}
		}
	}

	/**
	 * @return Returns the encryptedElements.
	 */
	public ArrayList getEncryptedElements() {
		return encryptedElements;
	}

	/**
	 * @param encElement  The encrypted Element (XPath) to set.
	 */
	public void setEncryptedElements(String encElement) {
		if (encryptedElements == null) {
			encryptedElements = new ArrayList();
		}		
		encryptedElements.add(encElement);
	}

	/**
	 * @return Returns the encryptedParts.
	 */
	public ArrayList getEncryptedParts() {
		return encryptedParts;
	}

	/**
	 * @param namespace The namespace of the part.
	 * @param element The part's element name.
	 */
	public void setEncryptedParts(String namespace, String element) {
		if (encryptedParts == null) {
			encryptedParts = new ArrayList();
		}		
		WSEncryptionPart wep = new WSEncryptionPart(element, namespace, "Content");
		encryptedParts.add(wep);
	}

	/**
	 * @return Returns the encryptBody.
	 */
	public boolean isEncryptBody() {
		return encryptBody;
	}

	/**
	 * @param encryptBody The encryptBody to set.
	 */
	public void setEncryptBody(boolean encryptBody) {
		this.encryptBody = encryptBody;
	}

	/**
	 * @return Returns the signBody.
	 */
	public boolean isSignBody() {
		return signBody;
	}

	/**
	 * @param signBody The signBody to set.
	 */
	public void setSignBody(boolean signBody) {
		this.signBody = signBody;
	}

	/**
	 * @return Returns the signedElements.
	 */
	public ArrayList getSignedElements() {
		return signedElements;
	}

	/**
	 * @param sigElement  The signed Element (XPath) to set.
	 */
	public void setSignedElements(String sigElement) {
		if (signedElements == null) {
			signedElements = new ArrayList();
		}
		signedElements.add(sigElement);
	}

	/**
	 * @return Returns the signedParts.
	 */
	public ArrayList getSignedParts() {
		return signedParts;
	}

	/**
	 * @param namespace The namespace of the part.
	 * @param element The part's element name.
	 */
	public void setSignedParts(String namespace, String element) {
		if (signedParts == null) {
			signedParts = new ArrayList();
		}
		WSEncryptionPart wep = new WSEncryptionPart(element, namespace, "Content");
		signedParts.add(wep);
	}	
}
