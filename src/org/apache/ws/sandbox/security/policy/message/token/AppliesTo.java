/*
 * Created on Jul 9, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package org.apache.ws.security.policy.message.token;
import javax.xml.namespace.QName;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;
/**
 * @author Malinda Kaushalye
 *
 */
public class AppliesTo {
	
	public static final QName TOKEN = new QName(TrustConstants.WSP_NS, TrustConstants.APPLIESTO_LN,TrustConstants.WSP_PREFIX);
	Element element=null;

/**
 * Constructor for AppliesTo
 * @param elem
 * @throws WSSecurityException
 */
	public AppliesTo(Element elem) throws WSSecurityException {	
		this.element = elem;
		 QName el = new QName(this.element.getNamespaceURI(), this.element.getLocalName());
		 if (!el.equals(TOKEN)) {
			 throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badTokenType", new Object[]{el});
		 }

	}
	/**
	 * Constructor for AppliesTo
	 * @param doc
	 */
	public AppliesTo(Document doc) {
		this.element = doc.createElementNS(TOKEN.getNamespaceURI(), TOKEN.getPrefix()+":"+TOKEN.getLocalPart());
		WSSecurityUtil.setNamespace(this.element, TOKEN.getNamespaceURI(), TOKEN.getPrefix());
		this.element.appendChild(doc.createTextNode(""));
	}
	public Text getFirstNode() {
		Node node = this.element.getFirstChild();
		return ((node != null) && node instanceof Text) ? (Text) node : null;
	}
	
	public String getValue(){
		String val="";
		if(this.element.getFirstChild().getNodeType()!=Node.TEXT_NODE){
			return null;
		}
		val=this.element.getFirstChild().getNodeValue();		
		return val;	
	}
	public void setValue(String val){	
		this.element.appendChild(element.getOwnerDocument().createTextNode(val));
	}
	/**
	 * @return
	 */
	public Element getElement() {
		return element;
	}
	
	/**
	 * @param element
	 */
	public void setElement(Element element) {
		this.element = element;
	}
	
	public String toString() {
	  return DOM2Writer.nodeToString((Node)this.element);
	}
	
	public void setAnyElement(Element elem) {
		this.element.appendChild(elem);
	}
}
