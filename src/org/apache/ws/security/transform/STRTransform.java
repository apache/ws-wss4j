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

package org.apache.ws.security.transform;

import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSDocInfoStore;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.util.WSSecurityUtil;


import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.transforms.TransformSpi;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.Base64;
import org.apache.xpath.XPathAPI;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import java.security.cert.X509Certificate;

import org.xml.sax.SAXException;
import org.w3c.dom.Node;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.Document;
import org.w3c.dom.Text;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/**
 * Class STRTransform
 *
 * @author Werner Dittmann (Werner.Dittmann@siemens.com)
 * @version 1.0
 */
public class STRTransform extends TransformSpi {

	/** Field implementedTransformURI */
	public static final String implementedTransformURI =
		"http://www.docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#STRTransform";


	private static Log log = LogFactory.getLog(STRTransform.class.getName());
	private static boolean doDebug = false;
	
	private WSDocInfo wsDocInfo = null;

	public boolean wantsOctetStream() {
		return false;
	}
	public boolean wantsNodeSet() {
		return true;
	}
	public boolean returnsOctetStream() {
		return true;
	}
	public boolean returnsNodeSet() {
		return false;
	}

	/**
	 * Method engineGetURI
	 *
	 *
	 */
	protected String engineGetURI() {
		return STRTransform.implementedTransformURI;
	}

	/**
	 * Method enginePerformTransform
	 *
	 * @param input
	 *
	 * @throws CanonicalizationException
	 * @throws InvalidCanonicalizerException
	 */
	protected XMLSignatureInput enginePerformTransform(XMLSignatureInput input)
		throws IOException, CanonicalizationException, InvalidCanonicalizerException {

		doDebug = log.isDebugEnabled();

		if (doDebug) {
			log.debug("Beginning STRTransform..." + input.toString());
		}

		try {

			/*
			 * Get the main document, that is the complete SOAP request document
			 */
			Document thisDoc = this._transformObject.getDocument();
			int docHash = thisDoc.hashCode();
			if (doDebug) {
				log.debug("doc: " + thisDoc.toString() + ", " + docHash);
			}
			
			/*
			 * Her we get some information about the document that is being processed,
			 * in partucular the crypto implementation, and already detected BST that
			 * may be used later during dereferencing. 
			 */
			wsDocInfo = WSDocInfoStore.lookup(docHash);
			if (wsDocInfo == null) {
				throw (new CanonicalizationException("no WSDocInfo found"));
			}

			/*
			 * According to the OASIS WS Specification 
			 * "Web Services Security: SOAP Message Security 1.0"
			 * Monday, 19 January 2004, chapter 8.3 describes that
			 * the input node set must be processed bythe c14n that 
			 * is specified in the argument element of the STRTransform 
			 * element.
			 * 
			 * First step: Get the required c14n argument. After that, get 
			 * the c14n, feed the node set into c14n and get back the byte[].
			 * The byte[] contains the XML doc part to be 
			 * signed or verified. Then reparse the byte[] to get the DOM.
			 */

			String canonAlgo = null;
			if (this
				._transformObject
				.length(WSConstants.WSSE_NS, "TransformationParameters")
				== 1) {
				Element tmpE =
					this._transformObject.getChildElementLocalName(
						0,
						WSConstants.WSSE_NS,
						"TransformationParameters");
				Element canonElem =
					(Element) WSSecurityUtil.getDirectChild(
						tmpE,
						"CanonicalizationMethod",
						WSConstants.SIG_NS);
				canonAlgo = canonElem.getAttribute("Algorithm");
				if (doDebug) {
					log.debug("CanonAlgo: " + canonAlgo);
				}
			}
			Canonicalizer canon = Canonicalizer.getInstance(canonAlgo);
			byte buf[] = canon.canonicalizeXPathNodeSet(input.getNodeSet());

			ByteArrayOutputStream bos = new ByteArrayOutputStream(buf.length);
			bos.write(buf, 0, buf.length);

			if (doDebug) {
				log.debug("canon bos: " + bos.toString());
			}

			DocumentBuilderFactory dfactory =
				DocumentBuilderFactory.newInstance();
			dfactory.setValidating(false);
			dfactory.setNamespaceAware(true);

			DocumentBuilder db = dfactory.newDocumentBuilder();

			Document doc =
				db.parse(new ByteArrayInputStream(bos.toByteArray()));

			/*
			 * Second step: find the STR element inside the resulting XML doc,
			 * check if STR contains some reference to an security token. 
			 */

			NodeList nodeList =
				doc.getElementsByTagNameNS(
					WSConstants.WSSE_NS,
					"SecurityTokenReference");

			int length = nodeList.getLength();

			Element str = null;
			/*
			 * loop over all STR elements
			 */
			for (int i = 0; i < length; i++) {
				Element tmpEl = (Element) nodeList.item(i);
				if (doDebug) {
					log.debug("STR: " + tmpEl.toString());
				}
				/*
				 * Third and forht step are performed by derefenceSTR()
				 */

				str = dereferenceSTR(thisDoc, (Element) tmpEl);
				/*
				 * Keep in mind: the returned element belong to "thisDoc", thus
				 * import it to "doc" before replacing it.
				 */

				/*
				 * Fifth step: replace the STR with the above created/copied BST, feed
				 * this result in the specified c14n method and return this to
				 * the caller.
				 * 
				 */
				str = (Element) doc.importNode(str, true);
				Node parent = tmpEl.getParentNode();
				parent.replaceChild(str, tmpEl);
			}
			/*
			 * Convert resulting STR result doc into NodeList, then c14n
			 */
			XMLUtils.circumventBug2650(doc); // This is needed

			nodeList =
				XPathAPI.selectNodeList(
					doc.getDocumentElement(),
					Canonicalizer.XPATH_C14N_WITH_COMMENTS_SINGLE_NODE);

			buf =
				canon.canonicalizeXPathNodeSet(
					XMLUtils.convertNodelistToSet(nodeList));

			if (doDebug) {
				bos = new ByteArrayOutputStream(buf.length);
				bos.write(buf, 0, buf.length);
				log.debug("result bos: " + bos.toString());
			}
			return new XMLSignatureInput(buf);

		} catch (IOException ex) {
			throw new CanonicalizationException("empty", ex);
		} catch (ParserConfigurationException ex) {
			throw new CanonicalizationException("empty", ex);
		} catch (XMLSecurityException ex) {
			throw new CanonicalizationException("empty", ex);
		} catch (SAXException ex) {
			throw new CanonicalizationException("empty", ex);
		} catch (TransformerException ex) {
			throw new CanonicalizationException("empty", ex);
		} catch (Exception ex) {
			throw new CanonicalizationException("empty", ex);
		}
	}

	private Element dereferenceSTR(Document doc, Element secRefE)
		throws Exception {

		/*
		 * Third step: locate the security token referenced by the STR
		 * element. Either the Token is contained in the document as a 
		 * BinarySecurityToken or stored in some key storage. The WSDocInfo
		 * contains the implementation of the key storage to use. To locate
		 * a BST inside a document check if a BST was already found and the 
		 * element stored in WSDocInfo.
		 * 
		 * As per OASIS WS specification this shall be a X509SubjectKeyIdentifier
		 * (SKI) that points to a security token.
		 * (are other reference types also possible/allowed?)
		 * 
		 *
		 * Forth step: after security token was located, prepare it. Either
		 * return BinarySecurityToken or wrap the located token
		 * in a newly created BST element as specified in WS Specification.
		 * 
		 * Note: every element (also newly created elements) belong to the
		 * document defined by the doc parameter. This is the main SOAP document
		 * (thisDoc) and _not_ the document part that is to be signed/verified. Thus
		 * the caller must import the returned element into the document 
		 * part that is signed/verified.
		 * 
		 */
		SecurityTokenReference secRef = null;
		Element tokElement = null;
		
		secRef = new SecurityTokenReference(secRefE);
		
		/*
		 * First case: direct reference, according to chap 7.2 of OASIS
		 * WS specification (main document)
		 */
		if (secRef.containsReference()) {
			if (doDebug) {
				log.debug("STR: Reference");
			}
			tokElement = secRef.getTokenElement(secRef, doc);
			if (tokElement == null) {
				throw new CanonicalizationException("empty");
			}
		} 
		/*
		 * second case: IssuerSerial, first try to get embedded 
		 * certificate, if that fails, lookup in keystore, wrap
		 * in BST according to specification
		 */
		else if (secRef.containsX509IssuerSerial()) {
			if (doDebug) {
				log.debug("STR: IssuerSerial");
			}
			X509Security x509token = secRef.getEmbeddedTokenFromIS(doc, wsDocInfo.getCrypto());
			if (x509token != null) {
				tokElement = x509token.getElement();
			}
			else {
				X509Certificate[] certs = secRef.getX509IssuerSerial(wsDocInfo.getCrypto());
				if (certs == null || certs.length == 0 || certs[0] == null) {
					throw new CanonicalizationException("empty");
				}
				tokElement = createBST(doc, certs[0], secRefE);
			}	
		}
		/*
		 * third case: KeyIdentifier, must be SKI, first try to get embedded 
		 * certificate, if that fails, lookup in keystore, wrap
		 * in BST according to specification. No other KeyIdentifier
		 * type handled here - just SKI
		 */
		else if (secRef.containsKeyIdentifier()) {
			if (doDebug) {
				log.debug("STR: KeyIdentifier");
			}
			X509Security x509token = secRef.getEmbeddedTokenFromSKI(doc, wsDocInfo.getCrypto());
			if (x509token != null) {
				tokElement = x509token.getElement();
			}
			else {
				X509Certificate[] certs = secRef.getKeyIdentifier(wsDocInfo.getCrypto());
				if (certs == null || certs.length == 0 || certs[0] == null) {
					throw new CanonicalizationException("empty");
				}
				tokElement = createBST(doc, certs[0], secRefE);
			}
		}
		return (Element) tokElement;
	}
	
	private Element createBST(
		Document doc,
		X509Certificate cert,
		Element secRefE)
		throws Exception {
		byte data[] = cert.getEncoded();
		String prefix = WSSecurityUtil.getPrefix(WSConstants.WSSE_NS, secRefE);
		Element elem =
			doc.createElementNS(
				WSConstants.WSSE_NS,
				prefix + ":BinarySecurityToken");
		WSSecurityUtil.setNamespace(elem, WSConstants.WSSE_NS, prefix);

		elem.setAttributeNS(null, "ValueType", X509Security.TYPE);
		Text certText = doc.createTextNode(Base64.encode(data));
		// Text certText = doc.createTextNode(data);
		elem.appendChild(certText);
		return elem;
	}
}
