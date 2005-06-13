package org.apache.ws.security.trust.message.token;

import javax.xml.namespace.QName;

import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.trust.WSTrustException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public class Created extends ValueElement {

	public static final QName TOKEN = new QName(TrustConstants.WSU_NS, TrustConstants.CREATED_LN, TrustConstants.WSU_PREFIX);
	
	/**
	 * @param doc
	 */
	public Created(Document doc) {
		super(doc);
	}

	/**
	 * @param elem
	 * @throws WSTrustException
	 */
	public Created(Element elem) throws WSTrustException {
		super(elem);
	}

	/* (non-Javadoc)
	 * @see org.apache.ws.security.trust.message.token.AbstractToken#getToken()
	 */
	protected QName getToken() {
		return TOKEN;
	}

}
