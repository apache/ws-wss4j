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

package org.apache.ws.security.trust;

import java.lang.reflect.Constructor;
import java.net.URL;
import java.util.Properties;

import org.w3c.dom.Document;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.trust.verify.STVerifier;
import org.apache.ws.security.util.Loader;

/**
 * @author Ruchith
 * This is used in at the web service end to verfy trust of request
 * Three verifiers are used in verifying trust which represents the three key stpes performed by the STS
 * These three verifier classes and their properties can be specified in the trustEngine.properties file
 * The verifier classes will accept a Property object having the properties from the specified property file
 * The author of the verifier classes can decide how to carryout the verfication when the verify() is called
 */
public class TrustEngine {
	
	private Log log = LogFactory.getLog(TrustEngine.class.getName());
	
	/**
	 * Verifier class used to verify claims
	 */
	private final String CLAIM_VERIFIER_CLASS = "org.apache.ws.security.trust.ClaimVerifierClass";
	
	/**
	 * Verifier class used to verify signatures
	 */
	private final String SIGNATURE_VERIFIER_CLASS = "org.apache.ws.security.trust.SignatureVerifierClass";
	
	/**
	 * Verifier class used to verify the issuer
	 */
	private final String ISSUER_VERIFIER_CLASS = "org.apache.ws.security.trust.IssuerVerifierClass";
	
	/**
	 * Properties for the claims verifier
	 */
	private final String CLAIM_VERIFIER_PROPERTIES="org.apache.ws.security.trust.ClaimVerifierProperties";
	
	/**
	 * Properties for the signature verifier
	 */
	private final String SIGNATURE_VERIFIER_PROPERTIES="org.apache.ws.security.trust.SignatureVerifierProperties";
	
	/**
	 * Properties for the issuer verifier
	 */
	private final String ISSUER_VERIFIER_PROPERTIES="org.apache.ws.security.trust.IssuerVerifierProperties";
	
	/**
	 * Claim verifier
	 */
	private STVerifier claimVerifier;
	
	/**
	 * Signature verifier
	 */
	private STVerifier signatureVerifier;
	
	/**
	 * Issuer verifier
	 */
	private STVerifier issuerVerifier;
	
	/**
	 * Create a trust engine with config info in a Properties file
	 * @param propFileName Property file name
	 * @throws WSTrustException
	 */
	public TrustEngine(String propFileName) throws WSTrustException{
//		try {
//			Properties prop = getProperties(propFileName);
//			this.configureEngine(prop);
//		} catch (Exception e) {
//			throw new WSTrustException(e.getMessage(),e);
//		}		
	}
	
	/**
	 * Create a trust engine with the default properties file
	 * The default properties file used is trustEngine.properties
	 * @throws WSTrustException
	 */
	public TrustEngine() throws WSTrustException{
		try {
			Properties prop = getProperties("trustEngine.properties");
			this.configureEngine(prop);
		} catch (Exception e) {
			throw new WSTrustException(e.getMessage(),e);
		}
	}
	
	/**
	 * Configure the trust engine
	 * This is called from the constructor
	 * @param prop Config details for the TrustEngine
	 * @throws WSTrustException
	 */
	private void configureEngine(Properties prop) throws WSTrustException {
		Properties climProp,sigProp,issuerProp;
		climProp = getProperties(prop.getProperty(CLAIM_VERIFIER_PROPERTIES));
		sigProp = getProperties(prop.getProperty(SIGNATURE_VERIFIER_PROPERTIES));
		issuerProp = getProperties(prop.getProperty(ISSUER_VERIFIER_PROPERTIES));
		
		this.claimVerifier = loadClass(prop.getProperty(CLAIM_VERIFIER_CLASS),climProp);
		this.signatureVerifier = loadClass(prop.getProperty(SIGNATURE_VERIFIER_CLASS),sigProp);
		this.issuerVerifier = loadClass(prop.getProperty(ISSUER_VERIFIER_CLASS),issuerProp);
	}
	
	/**
	 * Verify trust for a given request
	 * @param doc The request message
	 * @return If all three verifiers verifies this will return true
	 * @throws WSTrustException
	 */
	public boolean verifyTrust(Document doc) throws WSTrustException{
		if( this.claimVerifier.verify(doc) && this.signatureVerifier.verify(doc)&& this.issuerVerifier.verify(doc))
			return true;
		else
			return false; 
	}
	
	/**
	 * STOLEN FROM  org.apache.ws.security.components.crypto.CryptoFactory :-)
	 * Gets the properties for SessionMonitor
	 * The functions loads the property file via 
	 * {@link Loader.getResource(String)}, thus the property file
	 * should be accesible via the classpath 
	 * 
	 * @param propFilename the properties file to load
	 * @return a <code>Properties</code> object loaded from the filename
	 */
	private Properties getProperties(String propFilename) {
		Properties properties = new Properties();
		try {
			URL url = Loader.getResource(propFilename);
			properties.load(url.openStream());
			log.debug("SessionMonitor.properties found");
		} catch (Exception e) {
			log.debug(
				"Cannot find SessionMonitor property file: " + propFilename);
			throw new RuntimeException(
				"SessionMonitor: Cannot load properties: " + propFilename);
		}
		return properties;
	}
	
	/**
	 * Load the verifier class with the given properties
	 * @param className Name of the Verifier class
	 * @param properties Properties of the 
	 * @return
	 * @throws WSTrustException
	 */
	private STVerifier loadClass(String className,Properties properties) throws WSTrustException{
		STVerifier verifier = null;
		Class verfierClass = null;
		try {
			verfierClass = Class.forName(className);
			Class[] classes = new Class[]{Properties.class};
			Constructor c = verfierClass.getConstructor(classes);
			verifier = (STVerifier) c.newInstance(new Object[]{properties});
		} catch (ClassNotFoundException e) {
			throw new RuntimeException(className + " Not Found");
		} catch (Exception e) {
			throw new WSTrustException(e.getMessage(),e);
		}
		return verifier;
	}
}
