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

package org.apache.ws.security.trust.message.token;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.trust.WSTrustException;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.utils.QName;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * 
 * @author Dimuthu Leelarathne. (muthulee@yahoo.com)
 */
public class Entropy {
	private static Log log =
			LogFactory.getLog(Entropy.class.getName());

	public static final String ENTROPY = "Entropy";
	public static final QName TOKEN = new QName(TrustConstants.WST_NS,ENTROPY);
	public static final String BINARY_SECURITY = "BinarySecret";
	
	protected WSSConfig wssConfig = WSSConfig.getDefaultWSConfig();

	protected Element element = null;
   
	/**
	 * Constructor.
	 * <p/>
	 *
	 * @param wssConfig
	 * @param elem
	 * @throws WSSecurityException
	 */
	public Entropy(Element elem) throws WSTrustException {
		
				   this.element = elem;
						   QName el = new QName(this.element.getNamespaceURI(),
								   this.element.getLocalName());
						   if (!el.equals(TOKEN)) {
							   throw new WSTrustException();
						   }
	}

	/**
	 * Constructor.
	 * <p/>
	 *
	 * @param wssConfig
	 * @param doc
	 */
	public Entropy(Document doc) {
		this.element =
				doc.createElementNS(TrustConstants.WST_NS,
						TrustConstants.WST_PREFIX+":"+ENTROPY);
	}

	/*
	 * Here the methods that handle the direct reference inside
	 * a SecurityTokenReference
	 */

	/**
	 * set the BinarySecret.
	 * <p/>
	 *
	 * @param secret
	 */
	public void setBinarySecret(BinarySecret secret) {
			this.element.appendChild(secret.getElement());
	}

	/**
	 * 
	 * @return
	 * @throws WSTrustException
	 */
	public BinarySecret getBinarySecret() throws WSTrustException {
		Element elem = getFirstElement();
		return new BinarySecret(elem);
	}
	 
	/**
	 * get the first child element.
	 *
	 * @return the first <code>Element</code> child node
	 */
	public Element getFirstElement() {
		for (Node currentChild = this.element.getFirstChild();
			 currentChild != null;
			 currentChild = currentChild.getNextSibling()) {
			if (currentChild instanceof Element) {
				return (Element) currentChild;
			}
		}
		return null;
	}

	/**
	 * get the dom element.
	 * <p/>
	 *
	 * @return
	 */
	public Element getElement() {
		return this.element;
	}

	/**
	 * set the id.
	 * <p/>
	 *
	 * @param id
	 */
	public void setID(String id) {
		String prefix =
				WSSecurityUtil.setNamespace(this.element,
						wssConfig.getWsuNS(),
						WSConstants.WSU_PREFIX);
		this.element.setAttributeNS(wssConfig.getWsuNS(), prefix + ":Id", id);
	}

	/**
	 * return the string representation.
	 * <p/>
	 *
	 * @return
	 */
	public String toString() {
		return DOM2Writer.nodeToString((Node) this.element);
	}
}
