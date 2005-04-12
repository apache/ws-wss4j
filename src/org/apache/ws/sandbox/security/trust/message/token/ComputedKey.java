/*
 * Created on Sep 4, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package org.apache.ws.security.trust.message.token;


import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.trust.WSTrustException;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.xml.utils.QName;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * @author Dimuthu Leelarathne. (muthulee@yahoo.com)
 *
 * To change the template for this generated type comment go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
public class ComputedKey {
	 
	public static final String PSHA1 = "http://schemas.xmlsoap.org/ws/2005/02/security/trust/CK/PSHA1"; 

	
	 public static final QName TOKEN = new QName(TrustConstants.WST_NS, "ComputedKey");
    
	 protected Element element = null;
    
	 
	 /**
	  * Constructor.
	  * <p/>
	  *
	  * @param wssConfig
	  * @param elem
	  */
	 public ComputedKey(Element elem)
		 throws WSTrustException {
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
	 public ComputedKey(Document doc) {
		 this.element = doc.createElementNS(TrustConstants.WST_NS,
		 "wst:ComputedKey");
	 }

	 /**
	  * Sets the text node
	  *
	  * @param val
	  */
	 public void setComputedKeyValue(String val) {
		 this.element.appendChild(
			 element.getOwnerDocument().createTextNode(val));
	 }

	 /**
	 * return the value of the text node
			*
			* @return
			*/
	 public String getComputedKeyValue() {
		 String val = "";
		 if (this.element.getFirstChild().getNodeType() != Node.TEXT_NODE) {
			 return null;
		 }
		 val = this.element.getFirstChild().getNodeValue();
		 return val;
	 }

	 /**
		 * get the element
		 *
		 * @return
		 */
	 public Element getElement() {
		 return this.element;
	 }

	 /**
		 * set the element
		 *
		 * @param element
		 */
	 public void setElement(Element element) {
		 this.element = element;
	 }

	 public String toString() {
		 return DOM2Writer.nodeToString((Node) this.element);
	 }
	

}
