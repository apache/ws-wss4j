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

package org.apache.ws.axis.security;

import org.apache.axis.Constants;
import org.apache.ws.security.WSConstants;

import java.util.Hashtable;
import java.util.Map;


/**
 * @author Werner Dittmann (Werner.Dittmann@siemens.com)
 */
public class WSDoAllConstants {

	/**
	 * The action parameter in the WSDD configuration file. The
	 * handler uses tha value of this parameter to determine how
	 * to process the SOAP Envelope. For example:
	 * <pre>
		  &lt;handler type="java:org.apache.ws.axis.security.WSDoAllSender">
			&lt;parameter name="action" value="UsernameToken"/>
			...
	 * </pre>
	 * orders the handler to attach a <code>UsernameToken</code> to the SOAP
	 * enevelope. It is a blank speararted list of actions to perform.
	 * <p/>
	 * The application may set this parameter using the following method:
	 * <pre>
	 * call.setProperty(WSDoAllConstants.ACTION, WSDoAllConstants.USERNAME_TOKEN);
	 * </pre>
	 * However, the parameter in the WSDD deployment file overwrites the
	 * property setting (deployment setting overwrites application setting)
	 */
	public static final String ACTION = "action";

	/**
	 * Perform nothing. 
	 */
	public static final String NO_SECURITY = "NoSecurity";

	/**
	 * Perform a UsernameToken identifiaction only. 
	 */
	public static final String USERNAME_TOKEN = "UsernameToken";

	/**
	 * Perform a Signature only. 
	 * The signature specific parameters define how to sign, which keys
	 * to use, and so on
	 */
	public static final String SIGNATURE = "Signature";

	/**
	 * Perform Encryption only. 
	 * The encryption specific parameters define how to encrypt, which keys
	 * to use, and so on. 
	 * <p/>
	 * NOTE: the function encrypts the whole first child <code>Element</code> 
	 * of the SOAP body. Encryption does not yet support tag specific
	 * encryption.
	 */
	public static final String ENCRYPT = "Encrypt";

	/**
	 * Supress the serialization of the SOAP message.
	 * <p/>
	 * Usually the handler serializes the processed SOAP message into a string
	 * and sets it into the Axis message context as new current message. To
	 * supress this action, define this action. In this case the handler
	 * stores the processed SOAP message as <code>Document</code> in the
	 * Axis message context with the property name <code>SND_SECURITY</code>.
	 * <p/>
	 * A chained handler can retrieve the SOAP message and process it. The
	 * last handler in the chain must set the process SOAP message as
	 * current message in Axis message context.
	 * 
	 */
	public static final String NO_SERIALIZATION = "NoSerialization";

	/**
	 * This is an interal property name to support handler chaining.
	 * The Axis WSS4J handlers use this message context property to
	 * hand over the SOAP partially processed envelope document to
	 * the next WSS4J handler in the chain.
	 */
	public static final String SND_SECURITY = "SND_SECURTIY";
	// public static final String RCV_SECURITY = "RCV_SECURTIY";

	/**
	 * The actor name of the <code>wsse:Security</code> header.
	 * <p/>
	 * If this parameter is omitted, the actor name is not set. Please
	 * refer to {@link Constants#ATTR_ACTOR} and {@link Constants#ATTR_ROLE}
	 * about the parameter names. They are set to <code>"actor"</code>
	 * and <code>"role"</code> respectively.
	 * <p/>
	 * The value of the actor or role has to match the receiver's setting
	 * or may contain standard values.
	 * <p/>
	 * The application may set this parameter using the following method:
	 * <pre>
	 * call.setProperty(WSDoAllConstants.ACTOR, "ActorName");
	 * </pre>
	 * However, the parameter in the WSDD deployment file overwrites the
	 * property setting (deployment setting overwrites application setting).
	 * 
	 * @see Constants#URI_SOAP11_NEXT_ACTOR
	 * @see Constants#URI_SOAP12_NEXT_ROLE
	 */
	public static final String ACTOR = Constants.ATTR_ACTOR;

	/**
	 * The role name of the <code>wsse:Security</code> header.
	 * This is used for SOAP 1.2. Refer also to {@link #ACTOR}.
	 */
	public static final String ROLE = Constants.ATTR_ROLE;

	/**
	 * Sets the <code>mustUnderstand</code> flag.
	 * <p/>
	 * If the parameter has the value <code>1</code>
	 * or <code>true</code> the <code>mustUnderstand</code> is set.
	 * The values <code>0</code> or <code>false</code> supress the
	 * flag.
	 * <p/>
	 * The application may set this parameter using the following method:
	 * <pre>
	 * call.setProperty(WSDoAllConstants.MUST_UNDERSTAND, "false");
	 * </pre>
	 * However, the parameter in the WSDD deployment file overwrites the
	 * property setting (deployment setting overwrites application setting).
	 * <p/>
	 * The default setting is <code>true</code>
	 * <p/>
	 * Please refer to {@link Constants#ATTR_MUST_UNDERSTAND}
	 * about the parameter name (<code>"mustUnderstand"</code>).
	 */
	public static final String MUST_UNDERSTAND = Constants.ATTR_MUST_UNDERSTAND;

	/**
	 * The user's name. It is used differently by the WS Security functions.
	 * <ul>
	 * <li>The <i>UsernameToken</i> function sets this name in the 
	 * <code>UsernameToken</code>.
	 * </li> 
	 * <li>The <i>Signing</i> function uses this name as the alias name
	 * in the keystore to get user's certificate and private key to
	 * perform signing.
	 * </li>
	 * <li>The <i>encryption</i>
	 * functions uses this parameter as fallback if {@link #ENCRYPTION_USER}
	 * is not used. 
	 * </li>
	 * </ul>
	 * It is also possible to set the user's name and the according password
	 * via the call function, for example:
	 * <pre>
	 ...
	 call.setUsername("name");
	 call.setPassword("WSS4Java");
	 ...
	   </pre>
	 * The user parameter in the deployment descritor (WSDD) file overwrites
	 * the application's setting.
	 * </p>
	 * For an additional way to set the password refer to
	 * {@link #PW_CALLBACK_CLASS} and {@link #PW_CALLBACK_REF}.
	 * <p/>
	 * If the security functions uses the username from the message context, it
	 * clears the username from the message context
	 * after they copied it. This prevents sending of the username in the
	 * HTTP header.
	 * <p/>
	 * In this case the HTTP authentication mechansisms do <b>not</b> work
	 * anymore. User authentication shall be done via the username token or
	 * the certificate verification of the signature certificate.
	 */
	public static final String USER = "user";

	/**
	 * The Axis WSS4J handlers provide several ways to get the password required
	 * to construct a username token or to sign a message.
	 * <ul>
	 * <li> A class that implements a callback interface (see below). The
	 * 		handler loads this class and calls the callback method. This 
	 * 		class must have a public default constructor with not parameters.
	 * </li>
	 * <li> The application (or a preceeding handler) sets a reference to an 
	 * 		object that implements the callback interface
	 * </li>
	 * <li> The application sets the password directly using the 
	 * 		<code>setPassword</code> function of the <code>Call</code>.
	 * </ul> 
	 * The callback class or callback object must implement specific password 
	 * getter methods, for example reading a database or directory.
	 * <p/>
	 * The handler first checks if it can get a the password via a callback 
	 * class. If that fails it checks if it can get the password from the 
	 * object reference, if that also fails the handler tries the password 
	 * property.
	 * <p/>
	 * The following parameter defines a class that implements a callback 
	 * handler interface. The handler loads the class and calls the callback 
	 * handler method to get the password. The callback 
	 * class needs to implement the 
	 * {@link javax.security.auth.callback.CallbackHandler} interface.
	 * <p/>
	 * The callback function
	 * {@link javax.security.auth.callback.CallbackHandler#handle(Callback[])}
	 * gets an array of {@link org.apache.ws.security.WSPasswordCallback} 
	 * objects. Only the first entry of the array is used. This object
	 * contains the username/keyname as identifier. The callback handler must
	 * set the password or key associated with this identifier before it returns.
	 * <p/>
	 * The application may set this parameter using the following method:
	 * <pre>
	 * call.setProperty(WSDoAllConstants.PW_CALLBACK_CLASS, "PWCallbackClass");
	 * </pre>
	 * However, the parameter in the WSDD deployment file overwrites the
	 * property setting (deployment setting overwrites application setting).
	 * <p/>
	 * Refer also to comment in {@link #USER} about HTTP authentication 
	 * functions.
	 */
	public static final String PW_CALLBACK_CLASS = "passwordCallbackClass";

	/**
	 * An application may set an object reference to an object that implements
	 * the {@link javax.security.auth.callback.CallbackHandler} interface.
	 * Only the application can set this property using:
	 * <pre>
	 * call.setProperty(WSDoAllConstants.PW_CALLBACK_REF, anPWCallbackObject);
	 * </pre>
	 * Refer to {@link #PW_CALLBACK_CLASS} for further information about
	 * password callback handling and the priority of the different
	 * methods.
	 * <p/>
	 * Note: every handler that preceeds this handler in the chain can set
	 * this property too. This may be useful on the server side.
	 */
	public static final String PW_CALLBACK_REF = "passwordCallbackRef";

	/**
	 * The user's name for encryption.
	 * <p/>
	 * The encryption functions uses the public key of this user's certificate
	 * to encrypt the generated symmetric key.
	 * <p/>
	 * If this parameter is not set, then the encryption
	 * function falls back to the {@link #USER} parameter to get the
	 * certificate.
	 * <p/>
	 * If <b>only</b> encryption of the SOAP body data is requested,
	 * it is recommended to use this parameter to define the username.
	 * The application can then use the standard user and password 
	 * functions (see example at {@link #USER} to enable HTTP authentication
	 * functions.
	 * <p/>
	 * Encryption only does not authenticate a user / sender, therefore it
	 * does not need a password.
	 * <p/>
	 * Placing the username of the encryption certficate in the WSDD is not
	 * a security risk, because the public key of that certificate is used
	 * only.
	 * <p/>
	 * The application may set this parameter using the following method:
	 * <pre>
	 * call.setProperty(WSDoAllConstants.ENCYRPTION_USER, "encryptionuser");
	 * </pre>
	 * However, the parameter in the WSDD deployment file overwrites the
	 * property setting (deployment setting overwrites application setting).
	 */
	public static final String ENCRYPTION_USER = "encryptionUser";
	
	/**
	 * This parameter works in the same way as {@link #PW_CALLBACK_CLASS} but
	 * the Axis WSS4J handler uses it to get the key associated with a key name.
	 */
	public static final String ENC_CALLBACK_CLASS = "EmbeddedKeyCallbackClass";

	/**
	 * This parameter works in the same way as {@link #PW_CALLBACK_REF} but
	 * the Axis WSS4J handler uses it to get the key associated with a key name.
	 */
	public static final String ENC_CALLBACK_REF = "EmbeddedKeyCallbackRef";

	/**
	 * The name of the crypto propterty file to use for SOAP Signature.
	 * <p/>
	 * The classloader loads this file. Therefore it must be accessible
	 * via the classpath.
	 * <p/>
	 * To locate the implementation of the 
	 * {@link org.apache.ws.security.components.crypto.Crypto Crypto} 
	 * interface implementation the property file must contain the property
	 * <code>org.apache.ws.security.crypto.provider</code>. The value of
	 * this property is the classname of the implementation class.
	 * <p/>
	 * The following line defines the standard implementation:
	 * <pre>
	org.apache.ws.security.crypto.provider=org.apache.ws.security.components.crypto.Merlin
	 * </pre>
	 * The other contents of the property file depend on the implementation
	 * of the {@link org.apache.ws.security.components.crypto.Crypto Crypto}
	 * interface implementation. 
	 * <p/>
	 * The property file of the standard implementation 
	 * {@link org.apache.ws.security.components.crypto.Merlin} uses 
	 * the following properties:
	 * <pre>
	org.apache.ws.security.crypto.provider
	org.apache.ws.security.crypto.merlin.file
	org.apache.ws.security.crypto.merlin.keystore.type
	org.apache.ws.security.crypto.merlin.keystore.password
	org.apache.ws.security.crypto.merlin.keystore.pwcallback
	 * </pre>
	 * The entries are:
	 * <ul>
	 * <li> <code>org.apache.ws.security.crypto.provider</code> see 
	 * 	description above 
	 * </li>
	 * <li><code>org.apache.ws.security.crypto.merlin.file</code>
	 * The path to the keystore file. This file is <b>not</b> loaded with a
	 * classloader, thus this is either an absolute or relative path into the
	 * filesystem. A relative path is always relative to the current working
	 * directory. The default <code>Merlin</code> implementation uses the
	 * java <code>FileInputStream</code> to open the keystore.
	 * </li>
	 * <li><code>org.apache.ws.security.crypto.merlin.keystore.type</code>
	 * The keystore type, for example <code>JKS</code> for the Java key store.
	 * Other keystore type, such as <code>pkcs12</code> are also possible but depend
	 * on the actual <code>Crypto</code> implementation.
	 * </li>
	 * <li><code>org.apache.ws.security.crypto.merlin.keystore.password</code>
	 * The password to read the keystore. If this property is not set, then
	 * the <code>pwcallback</code>property must be defined.
	 * </li>
	 * <li><code>org.apache.ws.security.crypto.merlin.keystore.pwcallback
	 * </code>. Defines a class that implements the 
	 * {@link javax.security.auth.callback.CallbackHandler} interface.
	 * <p/>
	 * The callback function
	 * {@link javax.security.auth.callback.CallbackHandler#handle(Callback[])}
	 * of this class gets an array of 
	 * {@link org.apache.ws.security.WSPasswordCallback} objects. Only
	 * the first entry of the array is used.
	 * The object contains the the string "keystore" as identifier. 
	 * The callback handler must set the keystore's password before it returns.
	 * </li>
	 * </ul>
	 * The application may set this parameter using the following method:
	 * <pre>
	 * call.setProperty(WSDoAllConstants.SIG_PROP_FILE, "myCrypto.properties");
	 * </pre>
	 * However, the parameter in the WSDD deployment file overwrites the
	 * property setting (deployment setting overwrites application setting).
	 * <p/>
	 * If a property file is not set and a signature is requested,
	 * the handler throws an <code>AxisFault</code>.
	 */
	public static final String SIG_PROP_FILE = "signaturePropFile";

	/**
	 * The WSDoAllReceiver handler stores a result <code>Vector</code>
	 * in this property.
	 * <p/>
	 * The vector contains <code>WSDoAllReceiverResult</code> objects
	 * for each chained WSDoAllReceiver handler.
	 */
	public static final String RECV_RESULTS = "RECV_RESULTS";

	/**
	 * The name of the crypto propterty file to use for SOAP Decryption.
	 * <p/>
	 * Refer to documentation of {@link #SIG_PROP_FILE}.
	 * <p/>
	 * Refer to {@link #SIG_PROP_FILE} for a detail description
	 * about the format and how to use this property file.
	 * <p/>
	 * The application may set this parameter using the following method:
	 * <pre>
	 * call.setProperty(WSDoAllConstants.DEC_PROP_FILE, "myCrypto.properties");
	 * </pre>
	 * However, the parameter in the WSDD deployment file overwrites the
	 * property setting (deployment setting overwrites application setting).
	 * <p/>
	 * If this parameter is not used, but the signature crypto property 
	 * file is defined (combined Encryption/Signature action), then the
	 * encryption function uses that file. Otherwise the handler throws
	 * an <code>AxisFault</code>.
	 */
	public static final String DEC_PROP_FILE = "decryptionPropFile";

	/**
	 * Specific parameter for UsernameToken action to define the encoding
	 * of the passowrd.
	 * <p/>
	 * The parameter can be set to either {@link WSConstants#PASSWORD_DIGEST}
	 * or to {@link WSConstants#PASSWORD_TEXT}.
	 * <p/>
	 * The application may set this parameter using the following method:
	 * <pre>
	 * call.setProperty(WSDoAllConstants.PASSWORD_TYPE, WSConstants.PASSWORD_DIGEST);
	 * </pre>
	 * However, the parameter in the WSDD deployment file overwrites the
	 * property setting (deployment setting overwrites application setting).
	 * <p/>
	 * The default setting is PASSWORD_DIGEST.
	 */
	public static final String PASSWORD_TYPE = "passwordType";

	/**
	 * Parameter to generate additional elements in <code>UsernameToken</code>.
	 * <p/>
	 * The value of this parameter is a list of element names that are added
	 * to the UsernameToken. The names of the list a separated by spaces.
	 * <p/>
	 * The list may containe the names <code>nonce</code> and 
	 * <code>created</code> only. Use this option if the password type is
	 * <code>passwordText</code> and the handler shall add the <code>Nonce</code>
	 * and/or <code>Created</code> elements. 
	 * 
	 */
	public static final String ADD_UT_ELEMENTS = "addUTElements";

	/**
	 * Defines which key identifier type to use. The WS-Security specifications
	 * recommends to use the identifier type <code>IssuerSerial</code>. For
	 * possible signature key identifier types refer to
	 * {@link #keyIdentifier}. For signature <code>IssuerSerial</code>
	 * and <code>DirectReference</code> are valid only.
	 * <p/>
	 * The application may set this parameter using the following method:
	 * <pre>
	 * call.setProperty(WSDoAllConstants.SIG_KEY_ID, "DirectReference");
	 * </pre>
	 * However, the parameter in the WSDD deployment file overwrites the
	 * property setting (deployment setting overwrites application setting).
	 */
	public static final String SIG_KEY_ID = "signatureKeyIdentifier";

	/**
	 * Defines which signature algorithm to use. Currently this
	 * parameter is ignored - SHA1RSA is the only supported algorithm,
	 * will be enhanced soon.
	 * <p/>
	 * The application may set this parameter using the following method:
	 * <pre>
	 * call.setProperty(WSDoAllConstants.SIG_ALGO, "SHA1RSA");
	 * </pre>
	 * However, the parameter in the WSDD deployment file overwrites the
	 * property setting (deployment setting overwrites application setting).
	 */
	public static final String SIG_ALGO = "signatureAlgorithm";

	/**
	 * Parameter to define which parts of the request shall be signed.
	 * <p/>
	 * Refer to {@link #ENCRYPTION_PARTS} for a detailed description of
	 * the format of the value string.
	 * <p/>
	 * If this parameter is not specified the handler signs the SOAP Body
	 * by default. 
	 * <p/>
	 * The WS Security specifications define several formats to transfer the 
	 * signature tokens (certificates) or  references to these tokens.
	 * Thus, the plain element name <code>Token</code>
	 * signs the token and takes care of the different format. 
	 * <p/>
	 * To sign the SOAP body <b>and</b> the signature token the value of this
	 * parameter must contain:
	 * <pre>
	 * &lt;parameter name="signatureParts" 
	 *   value="{}{http://schemas.xmlsoap.org/soap/envelope/}Body; Token" /> 
	 * </pre>
	 * If there is no other element in the request with a local name of
	 * <code>Body</code> then the SOAP namespace identifier can be empty
	 * (<code>{}</code>).
	 */
	public static final String SIGNATURE_PARTS = "signatureParts";

	/**
	 * The name of the crypto propterty file to use for SOAP Encryption.
	 * <p/>
	 * Refer to documentation of {@link #SIG_PROP_FILE}.
	 * <p/>
	 * The application may set this parameter using the following method:
	 * <pre>
	 * call.setProperty(WSDoAllConstants.ENC_PROP_FILE, "myCrypto.properties");
	 * </pre>
	 * However, the parameter in the WSDD deployment file overwrites the
	 * property setting (deployment setting overwrites application setting).
	 * <p/>
	 * If this parameter is not used, but the signature crypto property 
	 * file is defined (combined Encryption/Signature action), then the
	 * encryption function uses signature property file. Otherwise the 
	 * handler throws an <code>AxisFault</code>.
	 */
	public static final String ENC_PROP_FILE = "encryptionPropFile";

	/**
	 * Defines which key identifier type to use. The WS-Security specifications
	 * recommends to use the identifier type <code>IssuerSerial</code>. For
	 * possible encryption key identifier types refer to
	 * {@link #keyIdentifier}. For encryption <code>IssuerSerial</code>
	 * and <code>X509KeyIdentifier</code> are valid only.
	 * <p/>
	 * The application may set this parameter using the following method:
	 * <pre>
	 * call.setProperty(WSDoAllConstants.ENC_KEY_ID, "X509KeyIdentifier");
	 * </pre>
	 * However, the parameter in the WSDD deployment file overwrites the
	 * property setting (deployment setting overwrites application setting).
	 */
	public static final String ENC_KEY_ID = "encryptionKeyIdentifier";

	/**
	 * Defines which symmetric encryption algorithm to use. WSS4J supports the
	 * following alorithms: {@link WSConstants#TRIPLE_DES},
	 * {@link WSConstants#AES_128}, {@link WSConstants#AES_256},
	 * and {@link WSConstants#AES_192}. Except for AES 192 all of these
	 * algorithms are required by the XML Encryption specification. 
	 * <p/>
	 * The application may set this parameter using the following method:
	 * <pre>
	 * call.setProperty(WSDoAllConstants.ENC_SYM_ALGO, "AES256");
	 * </pre>
	 * However, the parameter in the WSDD deployment file overwrites the
	 * property setting (deployment setting overwrites application setting).
	 */
	public static final String ENC_SYM_ALGO = "encryptionSymAlgorithm";

	/**
	 * Defines which algorithm to use to encrypt the generated symmetric key.
	 * Currently WSS4J supports {@link WSConstants#KEYTRANSPORT_RSA15} only.
	 * <p/>
	 * The application may set this parameter using the following method:
	 * <pre>
	 * call.setProperty(WSDoAllConstants.ENC_KEY_TRANSPORT, "RSA15");
	 * </pre>
	 * However, the parameter in the WSDD deployment file overwrites the
	 * property setting (deployment setting overwrites application setting).
	 */
	public static final String ENC_KEY_TRANSPORT =
		"encryptionKeyTransportAlgorithm";

	/**
	 * Parameter to define which parts of the request shall be encrypted.
	 * <p/>
	 * The value of this parameter is a list of semi-colon separated 
	 * element names that identify the elements to encrypt. An encryption mode
	 * specifier and a namespace identification, each inside a pair of curly 
	 * brackets, may preceed each element name.
	 * 
	 * The encryption mode specifier is either <code>{Content}</code> or
	 * <code>{Element}</code>. Please refer to the W3C XML Encryption 
	 * specification about the differences between Element and Content
	 * encryption. The encryption mode defaults to <code>Content</code>
	 * if it is omitted. Example of a list:
	 * <pre>
	 * &lt;parameter name="encryptionParts" 
	 *   value="{Content}{http://example.org/paymentv2}CreditCard; 
	 * 			{Element}{}UserName" />
	 * </pre>
	 * The the first entry of the list identifies the element 
	 * <code>CreditCard</code> in the namespace
	 * <code>http://example.org/paymentv2</code>, and will encrypt its content.
	 * Be aware that the element name, the namespace identifier, and the
	 * encryption modifier are case sensitive.
	 * <p/>
	 * The encryption modifier and the namespace identifier can be ommited.
	 * In this case the encryption mode defaults to <code>Content</code> and
	 * the namespace is set to the SOAP namespace.
	 * <p/>
	 * An empty encryption mode defaults to <code>Content</code>, an empty
	 * namespace identifier defaults to the SOAP namespace.
	 * The second line of the example defines <code>Element</code> as 
	 * encryption mode for an <code>UserName</code> element in the SOAP
	 * namespace.
	 * <p/>
	 * If no list is specified, the handler encrypts the SOAP Body in
	 * <code>Content</code> mode
	 */
	public static final String ENCRYPTION_PARTS = "encryptionParts";

	/**
	 * Define the parameter values to set the key identifier types. These are:
	 * <ul>
	 * <li><code>DirectReference</code> for {@link WSConstants#BST_DIRECT_REFERENCE}
	 * </li>
	 * <li><code>IssuerSerial</code> for {@link WSConstants#ISSUER_SERIAL}
	 * </li>
	 * <li><code>IssuerSerialDirect</code> for {@link WSConstants#ISSUER_SERIAL_DIRECT}
	 * </li>
	 * <li><code>X509KeyIdentifier</code> for {@link WSConstants#X509_KEY_IDENTIFIER}
	 * </li>
	 * <li><code>SKIKeyIdentifier</code> for {@link WSConstants#SKI_KEY_IDENTIFIER}
	 * </li>
	 * <li><code>SKIKeyIdentifierDirect</code> for {@link WSConstants#SKI_KEY_IDENTIFIER_DIRECT}
	 * </li>
	 * <li><code>EmbeddedKeyName</code> for {@link WSConstants#EMBEDDED_KEYNAME}
	 * </li>
	 * </ul
	 * See {@link #SIG_KEY_ID} {@link #ENC_KEY_ID}. 
	 */
	public static Map keyIdentifier = new Hashtable();

	static {
		keyIdentifier.put(
			"DirectReference",
			new Integer(WSConstants.BST_DIRECT_REFERENCE));
		keyIdentifier.put(
			"IssuerSerial",
			new Integer(WSConstants.ISSUER_SERIAL));
		keyIdentifier.put(
			"IssuerSerialDirect",
			new Integer(WSConstants.ISSUER_SERIAL_DIRECT));
		keyIdentifier.put(
			"X509KeyIdentifier",
			new Integer(WSConstants.X509_KEY_IDENTIFIER));
		keyIdentifier.put(
			"SKIKeyIdentifier",
			new Integer(WSConstants.SKI_KEY_IDENTIFIER));
		keyIdentifier.put(
			"EmbeddedKeyName",
			new Integer(WSConstants.EMBEDDED_KEYNAME));
		keyIdentifier.put(
			"SKIKeyIdentifierDirect",
			new Integer(WSConstants.SKI_KEY_IDENTIFIER_DIRECT));

	}

}
