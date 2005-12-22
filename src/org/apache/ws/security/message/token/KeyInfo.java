package org.apache.ws.security.message.token;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import javax.crypto.SecretKey;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class KeyInfo {
	private static Log log = LogFactory.getLog(KeyInfo.class.getName());

	public static final QName TOKEN = new QName(WSConstants.SIG_NS, "KeyInfo");

	protected Element element = null;

	protected CallbackHandler callBack = null;

	protected Crypto crypto = null;

	private PrivateKey privateKey = null;

	private SecretKey secretKey = null;

	private SecurityTokenReference secRef = null;

	private boolean containsSecRef = true;
	
	private boolean containsKeyName = false;

	/**
	 * Constructor. Sets up the KeyInfo data structure from a DOM element.
	 * 
	 * @param elem
	 *            The KeyInfo DOM element
	 * @param cb
	 *            The callback handler to get the password to unlock a private
	 *            key. Maybe <code>null</code> if no password is required for
	 *            this instance of keyinfo
	 * @param c
	 *            An object implementing the Crypto interface to handle
	 *            certificates. Maybe <code>null</code> if no certificate is
	 *            required for this instance of keyinfo
	 * @throws WSSecurityException
	 */

	public KeyInfo(Element elem, CallbackHandler cb, Crypto c)
			throws WSSecurityException {
		if (elem == null) {
			throw new WSSecurityException(WSSecurityException.INVALID_SECURITY,
					"noKeyInfo");
		}
		this.element = elem;
		QName el = new QName(this.element.getNamespaceURI(), this.element
				.getLocalName());
		if (!el.equals(TOKEN)) {
			throw new WSSecurityException(WSSecurityException.FAILURE,
					"badElement", new Object[] { TOKEN, el });
		}
		crypto = c;
		callBack = cb;
		parseKeyInfo(elem);
	}

	private void parseKeyInfo(Element keyInfo) throws WSSecurityException {
		Element child;

		child = (Element) WSSecurityUtil.getDirectChild(keyInfo,
				"SecurityTokenReference", WSConstants.WSSE_NS);

		if (child == null) {
			containsSecRef = false;
			child = (Element) WSSecurityUtil.getDirectChild(keyInfo, "KeyName",
					WSConstants.SIG_NS);
			containsKeyName = true;
		}
		if (child == null) {
			containsKeyName = false;
			throw new WSSecurityException(WSSecurityException.INVALID_SECURITY,
					"noSecTokRef");
		}
		/*
		 * The securityTokenReference handles both the normal STR and the simple
		 * KeyName value
		 */
		secRef = new SecurityTokenReference(child);
	}

	public PrivateKey getPrivateKey() throws WSSecurityException {
		String alias;
		Document doc = element.getOwnerDocument();

		/*
		 * Well, at this point there are several ways to get the key. Try to
		 * handle all of them :-).
		 */
		alias = null;
		/*
		 * handle X509IssuerSerial here. First check if all elements are
		 * available, get the appropriate data, check if all data is available.
		 * If all is ok up to that point, look up the certificate alias
		 * according to issuer name and serial number. This method is
		 * recommended by OASIS WS-S specification, X509 profile
		 */
		if (secRef.containsX509Data() || secRef.containsX509IssuerSerial()) {
			alias = secRef.getX509IssuerSerialAlias(crypto);
			if (log.isDebugEnabled()) {
				log.debug("X509IssuerSerial alias: " + alias);
			}
		}
		/*
		 * If wsse:KeyIdentifier found, then the public key of the attached cert
		 * was used to encrypt the session (symmetric) key that encrypts the
		 * data. Extract the certificate using the BinarySecurity token (was
		 * enhanced to handle KeyIdentifier too). This method is _not_
		 * recommended by OASIS WS-S specification, X509 profile
		 */
		else if (secRef.containsKeyIdentifier()) {
			X509Certificate[] certs = secRef.getKeyIdentifier(crypto);
			if (certs == null || certs.length < 1 || certs[0] == null) {
				throw new WSSecurityException(WSSecurityException.FAILURE,
						"invalidX509Data",
						new Object[] { "for decryption (KeyId)" });
			}
			/*
			 * Here we have the certificate. Now find the alias for it. Needed
			 * to identify the private key associated with this certificate
			 */
			alias = crypto.getAliasForX509Cert(certs[0]);
			if (log.isDebugEnabled()) {
				log.debug("cert: " + certs[0]);
				log.debug("KeyIdentifier Alias: " + alias);
			}
		} else if (secRef.containsReference()) {
			Element bstElement = secRef.getTokenElement(doc, null);

			// at this point ... check token type: Binary
			QName el = new QName(bstElement.getNamespaceURI(), bstElement
					.getLocalName());
			if (el.equals(WSSecurityEngine.binaryToken)) {
				X509Security token = null;
				String value = bstElement
						.getAttribute(WSSecurityEngine.VALUE_TYPE);
				if (!X509Security.getType().equals(value)
						|| ((token = new X509Security(bstElement)) == null)) {
					throw new WSSecurityException(
							WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
							"unsupportedBinaryTokenType",
							new Object[] { "for decryption (BST)" });
				}
				X509Certificate cert = token.getX509Certificate(crypto);
				if (cert == null) {
					throw new WSSecurityException(WSSecurityException.FAILURE,
							"invalidX509Data",
							new Object[] { "for decryption" });
				}
				/*
				 * Here we have the certificate. Now find the alias for it.
				 * Needed to identify the private key associated with this
				 * certificate
				 */
				alias = crypto.getAliasForX509Cert(cert);
				if (log.isDebugEnabled()) {
					log.debug("BST Alias: " + alias);
				}
			} else {
				throw new WSSecurityException(
						WSSecurityException.INVALID_SECURITY,
						"unsupportedToken", null);
			}
			/*
			 * The following code is somewhat strange: the called crypto method gets
			 * the keyname and searches for a certificate with an issuer's name that is
			 * equal to this keyname. No serialnumber is used - IMHO this does
			 * not identifies a certificate. In addition neither the WSS4J encryption
			 * nor signature methods use this way to identify a certificate. Because of that
			 * the next lines of code are disabled.  
			 */
//		} else if (secRef.containsKeyName()) {
//			alias = crypto.getAliasForX509Cert(secRef.getKeyNameValue());
//			if (log.isDebugEnabled()) {
//				log.debug("KeyName alias: " + alias);
//			}
		} else {
			throw new WSSecurityException(WSSecurityException.FAILURE,
					"unsupportedKeyId");
		}
		return getPrivateKeyForName(alias, callBack, crypto);
	}

	static public PrivateKey getPrivateKeyForName(String name,
			CallbackHandler cb, Crypto crypto) throws WSSecurityException {

		WSPasswordCallback pwCb = new WSPasswordCallback(name,
				WSPasswordCallback.DECRYPT);
		Callback[] callbacks = new Callback[1];
		callbacks[0] = pwCb;
		try {
			cb.handle(callbacks);
		} catch (IOException e) {
			throw new WSSecurityException(WSSecurityException.FAILURE,
					"noPassword", new Object[] { name });
		} catch (UnsupportedCallbackException e) {
			throw new WSSecurityException(WSSecurityException.FAILURE,
					"noPassword", new Object[] { name });
		}
		String password = pwCb.getPassword();
		if (password == null) {
			throw new WSSecurityException(WSSecurityException.FAILURE,
					"noPassword", new Object[] { name });
		}

		try {
			return crypto.getPrivateKey(name, password);
		} catch (Exception e) {
			throw new WSSecurityException(WSSecurityException.FAILED_ENC_DEC,
					null, null, e);
		}

	}

}
