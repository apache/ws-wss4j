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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSDocInfoStore;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.TransformSpi;
import org.apache.xml.security.utils.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;


/**
 * Class STRTransform
 *
 * @author Werner Dittmann (Werner.Dittmann@siemens.com)
 * @version 1.0
 */
public class STRTransform extends TransformSpi {

	/** Field implementedTransformURI */
	public static final String implementedTransformURI =
		"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform";


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
			if (this._transformObject.length(WSConstants.WSSE_NS,
                    "TransformationParameters") == 1) {
                Element tmpE = this._transformObject.getChildElementLocalName(
                        0, WSConstants.WSSE_NS, "TransformationParameters");
                Element canonElem = (Element) WSSecurityUtil.getDirectChild(
                        tmpE, "CanonicalizationMethod", WSConstants.SIG_NS);
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

            DocumentBuilderFactory dfactory = DocumentBuilderFactory
                    .newInstance();
            dfactory.setValidating(false);
            dfactory.setNamespaceAware(true);

            DocumentBuilder db = dfactory.newDocumentBuilder();

            Document doc = db
                    .parse(new ByteArrayInputStream(bos.toByteArray()));

			/*
			 * Second step: find the STR element inside the resulting XML doc,
			 * check if STR contains some reference to an security token. 
			 */

			NodeList nodeList =
				doc.getElementsByTagNameNS(
					WSConstants.WSSE_NS,
					"SecurityTokenReference");

			Element str = null;
			Element tmpEl = (Element) nodeList.item(0);
			if (doDebug) {
				log.debug("STR: " + tmpEl.toString());
			}
			/*
			 * Third and forht step are performed by derefenceSTR()
			 */
			SecurityTokenReference secRef = new SecurityTokenReference(tmpEl);

			str = dereferenceSTR(thisDoc, secRef);
			/*
			 * Keep in mind: the returned element belong to "thisDoc", thus
			 * import it to "doc" before replacing it.
			 *
			 * Fifth step: replace the STR with the above created/copied BST, feed
			 * this result in the specified c14n method and return this to
			 * the caller.
			 * 
			 */
			str = (Element) doc.importNode(str, true);

			Node parent = tmpEl.getParentNode(); // point to document node
//			parent.replaceChild(str, tmpEl); // replace STR with new node
//

            /*
             * Alert: Hacks ahead  
             * 
             * TODO: Rework theses hacks after c14n was updated.
             */

            /*
             * HACK 1:
             * Create a top level fake element with a defined default namespace
             * setting (urn:X). Replace the STR node with this fake element that
             * is now the top level element. Append our result element to the
             * fake element, then call c14n. This forces the c14n to insert
             * xmlns="" if necessary. However, before we handover the result we
             * have to remove the fake element. See string buffer operation
             * below.
             */
			Element tmpEl1 = doc.createElement("temp");
			tmpEl1.setAttributeNS(WSConstants.XMLNS_NS, "xmlns", "urn:X");
			parent.replaceChild(tmpEl1, tmpEl); // replace STR with new node

			tmpEl1.appendChild(str);
			// End of HACK 1
            
			// XMLUtils.circumventBug2650(doc); // No longer needed???
			
			/*
			 * C14n with specified algorithm. According to WSS Specification.
			 */
			buf = canon.canonicalizeSubtree(doc, "#default");

			// If the problem with c14n method is solved then just do:
            
			/* return new XMLSignatureInput(buf); */
			
            /*
             * HACK 2
             */
			bos = new ByteArrayOutputStream(buf.length);
			bos.write(buf, 0, buf.length);

			if (doDebug) {
				log.debug("after c14n: " + bos.toString());
			}

			/*
             * Here we delete the previously inserted fake element from the
             * serialized XML.
			 */
			StringBuffer bf = new StringBuffer(bos.toString());
			String bf1 = bf.substring("<temp xmlns=\"urn:X\">".length(),bf.length()-"</temp>".length());

			if (doDebug) {
				log.debug("last result: ");
				log.debug(bf1.toString());
			}
			return new XMLSignatureInput(bf1.getBytes());
            // End of HACK 2

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

	private Element dereferenceSTR(Document doc, SecurityTokenReference secRef)
		throws Exception {

		/*
		 * Third step: locate the security token referenced by the STR
		 * element. Either the Token is contained in the document as a 
		 * BinarySecurityToken or stored in some key storage. 
		 *
		 * Forth step: after security token was located, prepare it. If its
		 * reference via a direct reference, i.e. a relative URI that references
		 * the BST directly in the message then just return that element.
		 * Otherwise wrap the located token in a newly created BST element 
		 * as described in WSS Specification.
		 * 
		 * Note: every element (also newly created elements) belong to the
		 * document defined by the doc parameter. This is the main SOAP document
		 * (thisDoc) and _not_ the document part that is to be signed/verified. Thus
		 * the caller must import the returned element into the document 
		 * part that is signed/verified.
		 * 
		 */
		 Element tokElement = null;
		
		/*
		 * First case: direct reference, according to chap 7.2 of OASIS
		 * WS specification (main document). Only in this case return
		 * a true reference to the BST. Copying is done by the caller.
		 */
		if (secRef.containsReference()) {
			if (doDebug) {
				log.debug("STR: Reference");
			}
			tokElement = secRef.getTokenElement(doc, wsDocInfo);
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
			X509Certificate cert = null;
			X509Security x509token = null;
			// Disable check for embedded, always get from store (comment from Merlin,
			// Betrust)
			// x509token = secRef.getEmbeddedTokenFromIS(doc, wsDocInfo.getCrypto());
			if (x509token != null) {
				cert = x509token.getX509Certificate(wsDocInfo.getCrypto());
			}
			else {
				X509Certificate[] certs = secRef.getX509IssuerSerial(wsDocInfo.getCrypto());
				if (certs == null || certs.length == 0 || certs[0] == null) {
					throw new CanonicalizationException("empty");
				}
				cert = certs[0];
			}	
			tokElement = createBST(doc, cert, secRef.getElement());
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
			X509Certificate cert = null;
			X509Security x509token = null;
			// Disable check for embedded, always get from store (comment from Merlin,
			// Betrust)
			// x509token = secRef.getEmbeddedTokenFromSKI(doc, wsDocInfo.getCrypto());
			if (x509token != null) {
				cert = x509token.getX509Certificate(wsDocInfo.getCrypto());
			}
			else {
				X509Certificate[] certs = secRef.getKeyIdentifier(wsDocInfo.getCrypto());
				if (certs == null || certs.length == 0 || certs[0] == null) {
					throw new CanonicalizationException("empty");
				}
				cert = certs[0];
			}
			tokElement = createBST(doc, cert, secRef.getElement());
		}
		return (Element) tokElement;
	}
	
	private Element createBST(
		Document doc,
		X509Certificate cert,
		Element secRefE)
		throws Exception {
		byte data[] = cert.getEncoded();
		String prefix = WSSecurityUtil.getPrefixNS(WSConstants.WSSE_NS, secRefE);
		Element elem =
			doc.createElementNS(
				WSConstants.WSSE_NS,
				prefix + ":BinarySecurityToken");
		WSSecurityUtil.setNamespace(elem, WSConstants.WSSE_NS, prefix);
		elem.setAttributeNS(WSConstants.XMLNS_NS, "xmlns", "");
		elem.setAttributeNS(null, "ValueType", X509Security.TYPE);
		Text certText = doc.createTextNode(Base64.encode(data, 0));  // no line wrap
		elem.appendChild(certText);
		return elem;
	}
}
