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
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.Vector;

/**
 * Encrypts a parts of a message according to WS Specification, X509 profile,
 * and adds the encryption data. <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com).
 * @author Werner Dittmann (Werner.Dittmann@apache.org).
 */
public class WSSecEncrypt extends WSSecBase {
	private static Log log = LogFactory.getLog(WSSecEncrypt.class.getName());

	private static Log tlog = LogFactory.getLog("org.apache.ws.security.TIME");

	protected String symEncAlgo = WSConstants.AES_128;

	protected String keyEncAlgo = WSConstants.KEYTRANSPORT_RSA15;

	protected String encCanonAlgo = null;

	protected byte[] embeddedKey = null;

	protected String embeddedKeyName = null;

	protected X509Certificate useThisCert = null;

	/**
	 * Symmetric key used in the EncrytpedKey.
	 */
	protected SecretKey symmetricKey = null;

	/**
	 * Symmetric key that's actually used.
	 */
	protected SecretKey encryptionKey = null;

	/**
	 * Parent node to which the EncryptedKeyElement should be added.
	 */
	protected Element parentNode = null;

	/**
	 * SecurityTokenReference to be inserted into EncryptedData/keyInfo element.
	 */
	protected SecurityTokenReference securityTokenReference = null;

	private BinarySecurity bstToken = null;

	private Element xencEncryptedKey = null;

	private Document document = null;

	private Element envelope = null;

	private String encKeyId = null;

	/**
	 * Constructor.
	 */
	public WSSecEncrypt() {
	}

	/**
	 * Sets the key to use during embedded encryption.
	 * 
	 * <p/>
	 * 
	 * @param key
	 *            to use during encryption. The key must fit the selected
	 *            symmetrical encryption algorithm
	 */
	public void setKey(byte[] key) {
		this.embeddedKey = key;
	}

	/**
	 * Sets the algorithm to encode the symmetric key.
	 * 
	 * <p/>
	 * 
	 * Default is the <code>WSConstants.KEYTRANSPORT_RSA15</code> algorithm.
	 * 
	 * @param keyEnc
	 *            specifies the key encoding algorithm.
	 * @see WSConstants#KEYTRANSPORT_RSA15
	 * @see WSConstants#KEYTRANSPORT_RSAOEP
	 */
	public void setKeyEnc(String keyEnc) {
		keyEncAlgo = keyEnc;
	}

	/**
	 * Set the user name to get the encryption certificate.
	 * 
	 * The public key of this certificate is used, thus no password necessary.
	 * The user name is a keystore alias usually.
	 * 
	 * @param user
	 */
	public void setUserInfo(String user) {
		this.user = user;
	}

	/**
	 * Set the key name for EMBEDDED_KEYNAME
	 * 
	 * @param embeddedKeyName
	 */
	public void setEmbeddedKeyName(String embeddedKeyName) {
		this.embeddedKeyName = embeddedKeyName;
	}

	/**
	 * Set the X509 Certificate to use for encryption.
	 * 
	 * If this is set <b>and</b> the key identifier is set to
	 * <code>DirectReference</code> then use this certificate to get the
	 * public key for encryption.
	 * 
	 * @param cert
	 *            is the X509 certificate to use for encryption
	 */
	public void setUseThisCert(X509Certificate cert) {
		useThisCert = cert;
	}

	/**
	 * Set the name of the symmetric encryption algorithm to use.
	 * 
	 * This encryption alogrithm is used to encrypt the data. If the algorithm
	 * is not set then AES128 is used. Refer to WSConstants which algorithms are
	 * supported.
	 * 
	 * @param algo
	 *            Is the name of the encryption algorithm
	 * @see WSConstants#TRIPLE_DES
	 * @see WSConstants#AES_128
	 * @see WSConstants#AES_192
	 * @see WSConstants#AES_256
	 */
	public void setSymmetricEncAlgorithm(String algo) {
		symEncAlgo = algo;
	}

	/**
	 * Set the name of an optional canonicalization algorithm to use before
	 * encryption.
	 * 
	 * This c14n alogrithm is used to serialize the data before encryption. If
	 * the algorithm is not set then a standard serialization is used (provided
	 * by XMLCipher, usually a XMLSerializer according to DOM 3 specification).
	 * 
	 * @param algo
	 *            Is the name of the canonicalization algorithm
	 */
	public void setEncCanonicalization(String algo) {
		encCanonAlgo = algo;
	}

	/**
	 * Get the name of symmetric encryption algorithm to use.
	 * 
	 * The name of the encryption alogrithm to encrypt the data, i.e. the SOAP
	 * Body. Refer to WSConstants which algorithms are supported.
	 * 
	 * @return the name of the currently selected symmetric encryption algorithm
	 * @see WSConstants#TRIPLE_DES
	 * @see WSConstants#AES_128
	 * @see WSConstants#AES_192
	 * @see WSConstants#AES_256
	 */
	public String getSymmetricEncAlgorithm() {
		return symEncAlgo;
	}

	/**
	 * Initialize a WSSec Encrypt.
	 * 
	 * The method sets up and initializes a WSSec Encrypt structure after the
	 * relevant token information was set. After setup of the token references
	 * may be added. After all references are added they can be signed.
	 * 
	 * 
	 * @param doc
	 *            The unsigned SOAP envelope as <code>Document</code>
	 * @param cr
	 *            An instance of the Crypto API to handle keystore and
	 *            certificates
	 * @throws WSSecurityException
	 */
	public void setupToken(Document doc, Crypto crypto, Element securityHeader)
			throws WSSecurityException {

		document = doc;

		/*
		 * Generate a symmetric key (session key) for this Encrypt element. This
		 * symmetric key will be encrypted using the public key of the receiver
		 */
		// This variable is made a classs attribute :: SecretKey symmetricKey =
		// null;
		this.encryptionKey = this.symmetricKey;
		if (encryptionKey == null) {
			KeyGenerator keyGen = getKeyGenerator();
			this.encryptionKey = keyGen.generateKey();
		}

		/*
		 * Get the certificate that contains the public key for the public key
		 * algorithm that will encrypt the generated symmetric (session) key.
		 */
		X509Certificate remoteCert = null;
		if (useThisCert != null) {
			remoteCert = useThisCert;
		} else {
			X509Certificate[] certs = crypto.getCertificates(user);
			if (certs == null || certs.length <= 0) {
				throw new WSSecurityException(WSSecurityException.FAILURE,
						"invalidX509Data", new Object[] { "for Encryption" });
			}
			remoteCert = certs[0];
		}
		String certUri = "EncCertId-" + remoteCert.hashCode();
		Cipher cipher = WSSecurityUtil.getCipherInstance(keyEncAlgo, wssConfig
				.getJceProviderId());
		try {
			cipher.init(Cipher.ENCRYPT_MODE, remoteCert);
		} catch (InvalidKeyException e) {
			throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC,
					null, null, e);
		}
		byte[] encKey = this.encryptionKey.getEncoded();
		if (doDebug) {
			log.debug("cipher blksize: " + cipher.getBlockSize()
					+ ", symm key length: " + encKey.length);
		}
		if (cipher.getBlockSize() < encKey.length) {
			throw new WSSecurityException(
					WSSecurityException.FAILURE,
					"unsupportedKeyTransp",
					new Object[] { "public key algorithm too weak to encrypt symmetric key" });
		}
		byte[] encryptedKey = null;
		try {
			encryptedKey = cipher.doFinal(encKey);
		} catch (IllegalStateException e1) {
			throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC,
					null, null, e1);
		} catch (IllegalBlockSizeException e1) {
			throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC,
					null, null, e1);
		} catch (BadPaddingException e1) {
			throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC,
					null, null, e1);
		}
		Text keyText = WSSecurityUtil.createBase64EncodedTextNode(doc,
				encryptedKey);

		/*
		 * Now we need to setup the EncryptedKey header block 1) create a
		 * EncryptedKey element and set a wsu:Id for it 2) Generate ds:KeyInfo
		 * element, this wraps the wsse:SecurityTokenReference 3) Create and set
		 * up the SecurityTokenReference according to the keyIdentifer parameter
		 * 4) Create the CipherValue element structure and insert the encrypted
		 * session key 5) The last step sets up the reference list that pints to
		 * the encrypted data that was encrypted with this encrypted session key
		 * :-)
		 */
		xencEncryptedKey = createEnrcyptedKey(doc, keyEncAlgo);
		encKeyId = "EncKeyId-" + xencEncryptedKey.hashCode();
		String prefix = WSSecurityUtil.setNamespace(xencEncryptedKey,
				WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
		xencEncryptedKey.setAttributeNS(WSConstants.WSU_NS, prefix + ":Id",
				encKeyId);

		KeyInfo keyInfo = new KeyInfo(doc);

		SecurityTokenReference secToken = new SecurityTokenReference(doc);

		switch (keyIdentifierType) {
		case WSConstants.X509_KEY_IDENTIFIER:
			secToken.setKeyIdentifier(remoteCert);
			// build a key id class??
			break;

		case WSConstants.SKI_KEY_IDENTIFIER:
			secToken.setKeyIdentifierSKI(remoteCert, crypto);
			break;

		case WSConstants.THUMBPRINT_IDENTIFIER:
			secToken.setKeyIdentifierThumb(remoteCert);
			break;

		case WSConstants.ISSUER_SERIAL:
			XMLX509IssuerSerial data = new XMLX509IssuerSerial(doc, remoteCert);
			X509Data x509Data = new X509Data(doc);
			x509Data.add(data);
			secToken.setX509IssuerSerial(x509Data);
			break;

		case WSConstants.BST_DIRECT_REFERENCE:
			Reference ref = new Reference(doc);
			ref.setURI("#" + certUri);
			bstToken = new X509Security(doc);
			((X509Security) bstToken).setX509Certificate(remoteCert);
			bstToken.setID(certUri);
			ref.setValueType(bstToken.getValueType());
			secToken.setReference(ref);
			break;

		default:
			throw new WSSecurityException(WSSecurityException.FAILURE,
					"unsupportedKeyId");
		}
		keyInfo.addUnknownElement(secToken.getElement());
		WSSecurityUtil.appendChildElement(doc, xencEncryptedKey, keyInfo
				.getElement());

		Element xencCipherValue = createCipherValue(doc, xencEncryptedKey);
		xencCipherValue.appendChild(keyText);

		envelope = doc.getDocumentElement();
		envelope.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:"
				+ WSConstants.ENC_PREFIX, WSConstants.ENC_NS);

	}

	/**
	 * Prepends the Encrypt element to the elements already in the Security
	 * header.
	 * 
	 * The method can be called any time after <code>setupToken()</code>.
	 * This allows to insert the Signature element at any position in the
	 * Security header.
	 * 
	 * @param securityHeader
	 *            The securityHeader that holds the Signature element.
	 */
	public void prependEncryptElementToHeader(Element securityHeader) {
		WSSecurityUtil.prependChildElement(document, securityHeader,
				xencEncryptedKey, false);
	}

	/**
	 * Prepend the BinarySecurityToken to the elements already in the Security
	 * header.
	 * 
	 * The method can be called any time after <code>setupToken()</code>.
	 * This allows to insert the BST element at any position in the Security
	 * header.
	 * 
	 * @param securityHeader
	 *            The securityHeader that holds the BST element.
	 */
	public void prependBSTElementToHeader(Element securityHeader) {
		if (bstToken != null) {
			WSSecurityUtil.prependChildElement(document, securityHeader,
					bstToken.getElement(), false);
		}
		bstToken = null;
	}

	/**
	 * Builds the SOAP envelope with encrypted Body and adds encrypted key.
	 * 
	 * This is a convenience method and for backward compatibility. The method
	 * calls the single function methods in order to perform a <i>one shot
	 * encryption</i>. This method is compatible with the build method of the
	 * previous version with the exception of the additional WSSecHeader
	 * parameter.
	 * 
	 * @param doc
	 *            the SOAP envelope as <code>Document</code> with plaintext
	 *            Body
	 * @param crypto
	 *            an instance of the Crypto API to handle keystore and
	 *            Certificates
	 * @param secHeader
	 *            the security header element to hold the encrypted key element.
	 * @return the SOAP envelope with encrypted Body as <code>Document
	 *         </code>
	 * @throws WSSecurityException
	 */
	public Document build(Document doc, Crypto crypto, WSSecHeader secHeader)
			throws WSSecurityException {
		doDebug = log.isDebugEnabled();

		if (keyIdentifierType == WSConstants.EMBEDDED_KEYNAME
				|| keyIdentifierType == WSConstants.EMBED_SECURITY_TOKEN_REF) {
			return buildEmbedded(doc, crypto, secHeader);
		}

		if (doDebug) {
			log.debug("Beginning Encryption...");
		}
		Element securityHeader = secHeader.getSecurityHeader();

		setupToken(doc, crypto, securityHeader);

		SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(envelope);
		if (parts == null) {
			parts = new Vector();
			WSEncryptionPart encP = new WSEncryptionPart(soapConstants
					.getBodyQName().getLocalPart(), soapConstants
					.getEnvelopeURI(), "Content");
			parts.add(encP);
		}

		Element refs = encryptForInternalRef(null, parts);
		addRefElement(refs);

		prependEncryptElementToHeader(securityHeader);

		if (bstToken != null) {
			prependBSTElementToHeader(securityHeader);
		}

		log.debug("Encryption complete.");
		return doc;
	}

	public Element encryptForInternalRef(Element dataRef, Vector references)
			throws WSSecurityException {
		Vector encDataRefs = doEncryption(document, this.encryptionKey, parts);
		Element referenceList = dataRef;
		if (referenceList == null) {
			referenceList = document.createElementNS(WSConstants.ENC_NS,
					WSConstants.ENC_PREFIX + ":ReferenceList");
		}
		createDataRefList(document, referenceList, encDataRefs);
		return referenceList;
	}

	public Element encryptForExternalRef(Element dataRef, Vector references)
			throws WSSecurityException {

		KeyInfo keyInfo = new KeyInfo(document);
		SecurityTokenReference secToken = new SecurityTokenReference(document);
		Reference ref = new Reference(document);
		ref.setURI("#" + encKeyId);

		keyInfo.addUnknownElement(secToken.getElement());

		Vector encDataRefs = doEncryption(document, this.encryptionKey,
				keyInfo, parts);
		Element referenceList = dataRef;
		if (referenceList == null) {
			referenceList = document.createElementNS(WSConstants.ENC_NS,
					WSConstants.ENC_PREFIX + ":ReferenceList");
		}
		createDataRefList(document, referenceList, encDataRefs);
		return referenceList;
	}

	public void addRefElement(Element referenceList) {
		WSSecurityUtil.appendChildElement(document, xencEncryptedKey,
				referenceList);
	}

	private Vector doEncryption(Document doc, SecretKey secretKey,
			Vector references) throws WSSecurityException {
		return doEncryption(doc, secretKey, null, references);
	}

	private Vector doEncryption(Document doc, SecretKey secretKey,
			KeyInfo keyInfo, Vector references) throws WSSecurityException {

		XMLCipher xmlCipher = null;
		try {
			String provider = wssConfig.getJceProviderId();
			if (provider == null) {
				xmlCipher = XMLCipher.getInstance(symEncAlgo);
			} else {
				xmlCipher = XMLCipher.getProviderInstance(symEncAlgo, provider);
			}
		} catch (XMLEncryptionException e3) {
			throw new WSSecurityException(
					WSSecurityException.UNSUPPORTED_ALGORITHM, null, null, e3);
		}

		Vector encDataRefs = new Vector();

		for (int part = 0; part < references.size(); part++) {
			WSEncryptionPart encPart = (WSEncryptionPart) references.get(part);
			String elemName = encPart.getName();
			String nmSpace = encPart.getNamespace();
			String modifier = encPart.getEncModifier();
			/*
			 * Third step: get the data to encrypt.
			 */
			Element body = (Element) WSSecurityUtil.findElement(envelope,
					elemName, nmSpace);
			if (body == null) {
				throw new WSSecurityException(WSSecurityException.FAILURE,
						"noEncElement", new Object[] { "{" + nmSpace + "}"
								+ elemName });
			}

			boolean content = modifier.equals("Content") ? true : false;
			String xencEncryptedDataId = "EncDataId-" + body.hashCode();

			/*
			 * Forth step: encrypt data, and set neccessary attributes in
			 * xenc:EncryptedData
			 */
			try {
				xmlCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);
				EncryptedData encData = xmlCipher.getEncryptedData();
				encData.setId(xencEncryptedDataId);
				encData.setKeyInfo(keyInfo);
				xmlCipher.doFinal(doc, body, content);
			} catch (Exception e2) {
				throw new WSSecurityException(
						WSSecurityException.FAILED_ENC_DEC, null, null, e2);
			}
			encDataRefs.add(new String("#" + xencEncryptedDataId));
		}
		return encDataRefs;
	}

	private Document buildEmbedded(Document doc, Crypto crypto,
			WSSecHeader secHeader) throws WSSecurityException {
		doDebug = log.isDebugEnabled();

		if (doDebug) {
			log.debug("Beginning Encryption embedded...");
		}
		envelope = doc.getDocumentElement();
		envelope.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:"
				+ WSConstants.ENC_PREFIX, WSConstants.ENC_NS);

		/*
		 * Second step: generate a symmetric key from the specified key
		 * (password) for this alogrithm, and set the cipher into encryption
		 * mode.
		 */
		this.encryptionKey = this.symmetricKey;
		if (this.encryptionKey == null) {
			if (embeddedKey == null) {
				throw new WSSecurityException(WSSecurityException.FAILURE,
						"noKeySupplied");
			}
			this.encryptionKey = WSSecurityUtil.prepareSecretKey(symEncAlgo,
					embeddedKey);
		}

		KeyInfo keyInfo = null;
		if (this.keyIdentifierType == WSConstants.EMBEDDED_KEYNAME) {
			keyInfo = new KeyInfo(doc);
			keyInfo
					.addKeyName(embeddedKeyName == null ? user
							: embeddedKeyName);
		} else if (this.keyIdentifierType == WSConstants.EMBED_SECURITY_TOKEN_REF) {
			/*
			 * This means that we want to embed a <wsse:SecurityTokenReference>
			 * into keyInfo element. If we need this functionality, this.secRef
			 * MUST be set before calling the build(doc, crypto) method. So if
			 * secRef is null then throw an exception.
			 */
			if (this.securityTokenReference == null) {
				throw new WSSecurityException(
						WSSecurityException.SECURITY_TOKEN_UNAVAILABLE,
						"You must set keyInfo element, if the keyIdentifier "
								+ "== EMBED_SECURITY_TOKEN_REF");
			} else {
				keyInfo = new KeyInfo(doc);
				Element tmpE = securityTokenReference.getElement();
				tmpE.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:"
						+ tmpE.getPrefix(), tmpE.getNamespaceURI());
				keyInfo.addUnknownElement(securityTokenReference.getElement());
			}
		}

		SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(envelope);
		if (parts == null) {
			parts = new Vector();
			WSEncryptionPart encP = new WSEncryptionPart(soapConstants
					.getBodyQName().getLocalPart(), soapConstants
					.getEnvelopeURI(), "Content");
			parts.add(encP);
		}
		Vector encDataRefs = doEncryption(doc, this.encryptionKey, keyInfo,
				parts);

		/*
		 * At this point data is encrypted with the symmetric key and can be
		 * referenced via the above Id
		 */

		/*
		 * Now we need to setup the wsse:Security header block 1) get (or
		 * create) the wsse:Security header block 2) The last step sets up the
		 * reference list that pints to the encrypted data
		 */
		Element wsseSecurity = secHeader.getSecurityHeader();

		Element referenceList = doc.createElementNS(WSConstants.ENC_NS,
				WSConstants.ENC_PREFIX + ":ReferenceList");
		referenceList = createDataRefList(doc, referenceList, encDataRefs);
		WSSecurityUtil.prependChildElement(doc, wsseSecurity, referenceList,
				true);

		return doc;
	}

	private KeyGenerator getKeyGenerator() throws WSSecurityException {
		KeyGenerator keyGen = null;
		String id = wssConfig.getJceProviderId();
		try {
			/*
			 * Assume AES as default, so initialize it
			 */
			if (id == null) {
				keyGen = KeyGenerator.getInstance("AES");
			} else {
				keyGen = KeyGenerator.getInstance("AES", id);
			}
			if (symEncAlgo.equalsIgnoreCase(WSConstants.TRIPLE_DES)) {
				if (id == null) {
					keyGen = KeyGenerator.getInstance("DESede");
				} else {
					keyGen = KeyGenerator.getInstance("DESede", id);
				}
			} else if (symEncAlgo.equalsIgnoreCase(WSConstants.AES_128)) {
				keyGen.init(128);
			} else if (symEncAlgo.equalsIgnoreCase(WSConstants.AES_192)) {
				keyGen.init(192);
			} else if (symEncAlgo.equalsIgnoreCase(WSConstants.AES_256)) {
				keyGen.init(256);
			} else {
				return null;
			}
		} catch (NoSuchAlgorithmException e) {
			throw new WSSecurityException(
					WSSecurityException.UNSUPPORTED_ALGORITHM, null, null, e);
		} catch (NoSuchProviderException e) {
			throw new WSSecurityException(
					WSSecurityException.UNSUPPORTED_ALGORITHM, null, null, e);
		}
		return keyGen;
	}

	/**
	 * Create DOM subtree for <code>xenc:EncryptedKey</code>
	 * 
	 * @param doc
	 *            the SOAP enevelope parent document
	 * @param keyTransportAlgo
	 *            specifies which alogrithm to use to encrypt the symmetric key
	 * @return an <code>xenc:EncryptedKey</code> element
	 */
	public static Element createEnrcyptedKey(Document doc,
			String keyTransportAlgo) {
		Element encryptedKey = doc.createElementNS(WSConstants.ENC_NS,
				WSConstants.ENC_PREFIX + ":EncryptedKey");

		WSSecurityUtil.setNamespace(encryptedKey, WSConstants.ENC_NS,
				WSConstants.ENC_PREFIX);
		Element encryptionMethod = doc.createElementNS(WSConstants.ENC_NS,
				WSConstants.ENC_PREFIX + ":EncryptionMethod");
		encryptionMethod.setAttributeNS(null, "Algorithm", keyTransportAlgo);
		WSSecurityUtil.appendChildElement(doc, encryptedKey, encryptionMethod);
		return encryptedKey;
	}

	public static Element createCipherValue(Document doc, Element encryptedKey) {
		Element cipherData = doc.createElementNS(WSConstants.ENC_NS,
				WSConstants.ENC_PREFIX + ":CipherData");
		Element cipherValue = doc.createElementNS(WSConstants.ENC_NS,
				WSConstants.ENC_PREFIX + ":CipherValue");
		cipherData.appendChild(cipherValue);
		WSSecurityUtil.appendChildElement(doc, encryptedKey, cipherData);
		return cipherValue;
	}

	public static Element createDataRefList(Document doc,
			Element referenceList, Vector encDataRefs) {
		for (int i = 0; i < encDataRefs.size(); i++) {
			String dataReferenceUri = (String) encDataRefs.get(i);
			Element dataReference = doc.createElementNS(WSConstants.ENC_NS,
					WSConstants.ENC_PREFIX + ":DataReference");
			dataReference.setAttributeNS(null, "URI", dataReferenceUri);
			referenceList.appendChild(dataReference);
		}
		return referenceList;
	}

	/**
	 * Sets the parent node of the EncryptedKeyElement
	 * 
	 * @param element
	 */
	public void setParentNode(Element element) {
		parentNode = element;
	}

	/**
	 * @return TODO
	 */
	public SecretKey getSymmetricKey() {
		return symmetricKey;
	}

	/**
	 * Set the symmetric key to be used for encryption
	 * 
	 * @param key
	 */
	public void setSymmetricKey(SecretKey key) {
		this.symmetricKey = key;
	}

	/**
	 * Get the symmetric key used for encryption. This may be the same as the
	 * symmetric key field.
	 * 
	 * @return The symmetric key
	 */
	public SecretKey getEncryptionKey() {
		return this.encryptionKey;
	}

	/**
	 * @return TODO
	 */
	public SecurityTokenReference getSecurityTokenReference() {
		return securityTokenReference;
	}

	/**
	 * @param reference
	 */
	public void setSecurityTokenReference(SecurityTokenReference reference) {
		securityTokenReference = reference;
	}

}
