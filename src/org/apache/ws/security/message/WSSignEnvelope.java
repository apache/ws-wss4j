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
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSDocInfoStore;
import org.apache.ws.security.transform.STRTransform;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.PKIPathSecurity;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.Transform;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.cert.X509Certificate;
import java.util.Vector;

/**
 * Signs a SOAP envelope according to WS Specification, X509 profile, and
 * adds the signature data.
 * 
 * @author Davanum Srinivas (dims@yahoo.com)
 * @author Werner Dittmann (Werner.Dittman@siemens.com)
 */
public class WSSignEnvelope extends WSBaseMessage {
    private static Log log = LogFactory.getLog(WSSignEnvelope.class.getName());
	private static Log tlog =
		LogFactory.getLog("org.apache.ws.security.TIME");

    
	protected boolean useSingleCert = true;

	static {
		Transform.init();
		try {
			Transform.register(STRTransform.implementedTransformURI,
				"org.apache.ws.security.transform.STRTransform");
		} catch (Exception ex) {
		};
	}

    /**
     * Constructor.
     */
    public WSSignEnvelope() {
    }

    /**
     * Constructor.
     * <p/>
     * 
     * @param actor The actor name of the <code>wsse:Security</code> 
     * 				header
     */
    public WSSignEnvelope(String actor) {
        super(actor);
    }

    /**
     * Constructor.
     * <p/>
     * 
     * @param actor The actor name of the <code>wsse:Security</code> header
     * @param mu    Set <code>mustUnderstand</code> to true or false
     */
    public WSSignEnvelope(String actor, boolean mu) {
        super(actor, mu);
    }


	/**
	 * set the single cert flag.
	 * <p/>
	 * 
	 * @param useSingleCert 
	 */
	public void setUseSingleCertificate(boolean useSingleCert) {
		this.useSingleCert = useSingleCert;
	}

	/**
	 * Get the single cert flag.
	 * <p/>
	 * 
	 * @return 
	 */
	public boolean isUseSingleCertificate() {
		return this.useSingleCert;
	}

    /**
     * Builds a signed soap envelope.
     * <p/>
     * The method first gets an appropriate security header. According to
     * the defined parameters for certificate handling the signature elements
     * are constructed and inserted into the <code>wsse:Signature</code>
     *  
     * @param doc    	The unsigned SOAP envelope as <code>Document</code>
     * @param crypto 	An instance of the Crypto API to handle keystore and certificates
     * @return 			A signed SOAP envelope as <code>Document</code>
     * @throws Exception 
     */
    public Document build(Document doc, Crypto crypto) throws Exception {
    	doDebug = log.isDebugEnabled();
    	
		long t0=0, t1=0, t2=0, t3=0, t4=0;
		if( tlog.isDebugEnabled() ) {
			t0=System.currentTimeMillis();
		}
		if (doDebug) {
			log.debug("Beginning signing...");
		} 

		/*
		 * Gather some info about the document to process and store
		 * it for retrival
		 */
		WSDocInfo wsDocInfo = new WSDocInfo(doc.hashCode());
		wsDocInfo.setCrypto(crypto);
		
		Element envelope = doc.getDocumentElement();
		SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(envelope);			
		
        Element securityHeader = insertSecurityHeader(doc, true);

        // Set the id of the elements to be used as digest source
		// String id = setBodyID(doc);
        XMLSignature sig = null;
        sig = new XMLSignature(doc, null, XMLSignature.ALGO_ID_SIGNATURE_RSA,
                Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        /*
         * If we don't generate a new Transforms for each addDocument
         * here, then only the last Transforms is put into the
         * according ds:Reference element, i.e. the first ds:Reference
         * does not contain a Transforms element. Thus the verification
         * fails (somehow)
         */

        KeyInfo info = sig.getKeyInfo();
		String keyInfoUri = "id-" + info.hashCode();
		info.setId(keyInfoUri);

        X509Certificate[] certs = crypto.getCertificates(user);
        if (certs == null || certs.length <= 0) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidX509Data", new Object[]{"for Signature"});
        }
		if( tlog.isDebugEnabled() ) {
			t1=System.currentTimeMillis();
		}

		if (parts == null) {
			parts = new Vector();
			WSEncryptionPart encP =
				new WSEncryptionPart(
					soapConstants.getBodyQName().getLocalPart(),
					soapConstants.getEnvelopeURI(),
					"Content");
			parts.add(encP);
		}

		String certUri = "id-" + certs[0].hashCode();
		
		Transforms transforms = null;
		
		for (int part = 0; part < parts.size(); part++) {
			WSEncryptionPart encPart = (WSEncryptionPart)parts.get(part);
			String elemName = encPart.getName();
			String nmSpace = encPart.getNamespace();

		/*
	 	 * Set up the elements to sign. 
	 	 * There are two resevered element names: "Token" and "STRTransform"
	 	 * "Token": Setup the Signature to either sign the information that 
	 	 * 			points to the security token or the token itself. If 
	 	 * 			its a direct reference sign the token, otherwise sign
	 	 * 			the KeyInfo Element.
	 	 * "STRTransform": Setup the ds:Reference to use STR Transform
	 	 * 
	 	 */			
			if (elemName.equals("Token")) {
				transforms = new Transforms(doc);
				transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
				if (keyIdentifierType == WSConstants.BST_DIRECT_REFERENCE) {
					sig.addDocument("#" + certUri, transforms);
				}
				else {
					sig.addDocument("#" + keyInfoUri, transforms);
				}
			}
			else if (elemName.equals("STRTransform")) {
				Element ctx = createSTRParameter(doc);	// This element shall conatin the arg to STR
				transforms = new Transforms(doc);
				transforms.addTransform(STRTransform.implementedTransformURI, ctx);
				sig.addDocument("#" + keyInfoUri, transforms);
			}
			else {
				Element body = (Element) WSSecurityUtil.findElement(envelope, elemName, nmSpace);
				if (body == null) {
					throw new WSSecurityException(
						WSSecurityException.FAILURE,
						"noEncElement",
						new Object[] { nmSpace, elemName });
				}
				transforms = new Transforms(doc);
				transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
				sig.addDocument("#" + setWsuId(body), transforms);
			}
		}
 
        sig.addResourceResolver(EnvelopeIdResolver.getInstance());
        
        WSSecurityUtil.prependChildElement(doc, securityHeader, sig.getElement(), false);
        SecurityTokenReference secRef = new SecurityTokenReference(doc);
		if (tlog.isDebugEnabled() ) {
			t2=System.currentTimeMillis();
		}
		switch (keyIdentifierType) {
			case WSConstants.BST_DIRECT_REFERENCE :
				Reference ref = new Reference(doc);
				ref.setURI("#" + certUri);
				secRef.setReference(ref);
				BinarySecurity bstToken = null;
				if (!useSingleCert) {
					bstToken = new PKIPathSecurity(doc);
					((PKIPathSecurity) bstToken).setX509Certificates(
						certs,
						true);
				} else {
					bstToken = new X509Security(doc);
					((X509Security) bstToken).setX509Certificate(certs[0]);
				}
				bstToken.setID(certUri);
				WSSecurityUtil.prependChildElement(
					doc,
					securityHeader,
					bstToken.getElement(),
					false);
				wsDocInfo.setBst(bstToken.getElement());
				break;
			case WSConstants.ISSUER_SERIAL_DIRECT : {
				X509Security x509token = new X509Security(doc);
				x509token.setX509Certificate(certs[0]);
				x509token.setID(certUri);
				WSSecurityUtil.prependChildElement(
					doc,
					securityHeader,
					x509token.getElement(),
					false);
				wsDocInfo.setBst(x509token.getElement());
				// fall thru
			}
			case WSConstants.ISSUER_SERIAL :
				XMLX509IssuerSerial data =
					new XMLX509IssuerSerial(
						doc,
						certs[0].getIssuerDN().getName(),
						certs[0].getSerialNumber());
				secRef.setX509IssuerSerial(data);
				break;
			case WSConstants.X509_KEY_IDENTIFIER :
				secRef.setKeyIdentifier(certs[0]);
				break;
			case WSConstants.SKI_KEY_IDENTIFIER_DIRECT : {
				X509Security x509token = new X509Security(doc);
				x509token.setX509Certificate(certs[0]);
				x509token.setID(certUri);
				WSSecurityUtil.prependChildElement(
					doc,
					securityHeader,
					x509token.getElement(),
					false);
				wsDocInfo.setBst(x509token.getElement());
				// fall thru
			}
			case WSConstants.SKI_KEY_IDENTIFIER :
				secRef.setKeyIdentifierSKI(certs[0], crypto);
				break;
			default :
				throw new WSSecurityException(
					WSSecurityException.FAILURE,
					"unsupportedKeyId");
		}
		if (tlog.isDebugEnabled() ) {
			t3=System.currentTimeMillis();
		}
        info.addUnknownElement(secRef.getElement());
        
		WSDocInfoStore.store(wsDocInfo);
		try {
			sig.sign(crypto.getPrivateKey(user, password));
		}
		catch (Exception ex) {
			throw ex;
		}
		finally {
			WSDocInfoStore.delete(wsDocInfo); 
		}
		if (tlog.isDebugEnabled() ) {
			t4=System.currentTimeMillis();
			tlog.debug("SignEnvelope: cre-Sig= " + (t1-t0) +
			" set transform= " + (t2-t1) +
			" sec-ref= " + (t3-t2) +
			" signature= " + (t4-t3));
		}
        if (doDebug) {
        	log.debug("Signing complete.");
        } 
        return (doc);
    }
    
    private Element createSTRParameter(Document doc) {
		Element transformParam =
			doc.createElementNS(
				WSConstants.WSSE_NS,
				WSConstants.WSSE_PREFIX + ":TransformationParameters");

		WSSecurityUtil.setNamespace(
			transformParam,
			WSConstants.WSSE_NS,
			WSConstants.WSSE_PREFIX);

		Element canonElem =
			doc.createElementNS(
				WSConstants.SIG_NS,
				WSConstants.SIG_PREFIX + ":CanonicalizationMethod");

		WSSecurityUtil.setNamespace(
			canonElem,
			WSConstants.SIG_NS,
			WSConstants.SIG_PREFIX);
			
		canonElem.setAttributeNS(null, "Algorithm", Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		transformParam.appendChild(canonElem);
		return transformParam;
    }
}
