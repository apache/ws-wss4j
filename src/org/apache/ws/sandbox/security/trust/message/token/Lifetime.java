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

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.TimeZone;

import javax.xml.namespace.QName;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;


/**
 * @author Malinda Kaushalye
 * Lifetime token
 */

public class LifeTime  {

 public Element element;
 public Element created;
 public Element expires;
 public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.LIFE_TIME_LN,TrustConstants.WST_PREFIX);




//new
	
  /**
   * Constructor for LifeTime
   * @param doc
   * @param created
   * @param expires
   */
	public LifeTime(Document doc,String created,String expires) {
		this.element = doc.createElementNS(TOKEN.getNamespaceURI(),"wst:"+TOKEN.getLocalPart());
		this.created = doc.createElementNS(TrustConstants.WST_NS,"wst:"+TrustConstants.CREATED_LN);
		this.expires = doc.createElementNS(TrustConstants.WST_NS,"wst:"+TrustConstants.EXPIRES_LN);	
		
		this.created.appendChild(doc.createTextNode(created));	
		this.expires.appendChild(doc.createTextNode(expires)); 	
		this.element.appendChild(this.created);
		this.element.appendChild(this.expires);
	}
	/**
	 * Constructor for LifeTime
	 * Check for created and epires elements
	 * @param elem
	 * @throws WSSecurityException
	 */
	//new
	public LifeTime(Element elem) throws WSSecurityException {
		this.element = elem;
		QName el =
			new QName(
				this.element.getNamespaceURI(),
				this.element.getLocalName());
		if (!el.equals(TOKEN)) {
			throw new WSSecurityException(
				WSSecurityException.INVALID_SECURITY_TOKEN,
				"badTokenType00",
				new Object[] { el });
		}
		
		this.created =
					(Element) WSSecurityUtil.getDirectChild(
						elem,
						TrustConstants.CREATED_LN,
						TrustConstants.WST_NS);
		this.expires =
					(Element) WSSecurityUtil.getDirectChild(
						elem,
						TrustConstants.EXPIRES_LN,
						TrustConstants.WST_NS);
		
	}
	/**
	 * Constructor for LifeTime
	 * @param doc
	 * @param duration in minutes
	 */
	//new
	
	public LifeTime(Document doc, int duration){
		
		SimpleDateFormat sdtf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
		sdtf.setTimeZone(TimeZone.getTimeZone("GMT"));
		Calendar rightNow = Calendar.getInstance();
		Calendar expires= Calendar.getInstance();
		this.element = doc.createElementNS(TOKEN.getNamespaceURI(),"wst:"+TOKEN.getLocalPart());
		WSSecurityUtil.setNamespace(this.element,TOKEN.getNamespaceURI(),TrustConstants.WST_PREFIX);
		this.created = doc.createElementNS(TrustConstants.WST_NS,"wst:"+TrustConstants.CREATED_LN);
		WSSecurityUtil.setNamespace(this.created,TOKEN.getNamespaceURI(),TrustConstants.WST_PREFIX);
		this.expires = doc.createElementNS(TrustConstants.WST_NS,"wst:"+TrustConstants.EXPIRES_LN);
		WSSecurityUtil.setNamespace(this.expires,TOKEN.getNamespaceURI(),TrustConstants.WST_PREFIX);
		this.created.appendChild(doc.createTextNode(sdtf.format(rightNow.getTime())));

		long exp=rightNow.getTimeInMillis()+duration*1000*60;
		expires.setTimeInMillis(exp);	
	
		
	
	
		this.expires.appendChild(doc.createTextNode(sdtf.format(expires.getTime()))); 	
		this.element.appendChild(this.created);
		this.element.appendChild(this.expires);
		
	}
	
	/**
	 * 
	 * @param duration in minutes
	 */
//	old
//	public LifeTime(int duration) {
//		this.ltt=new LifetimeType();
//		SimpleDateFormat sdtf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
//		sdtf.setTimeZone(TimeZone.getTimeZone("GMT"));
//		Calendar rightNow = Calendar.getInstance();
//		Calendar expires= Calendar.getInstance();
//		ltt.setCreated(new AttributedDateTime(sdtf.format(rightNow.getTime())));
//		long exp=rightNow.getTimeInMillis()+duration*1000*60;
//		expires.setTimeInMillis(exp);		
//		ltt.setExpires(new AttributedDateTime(sdtf.format(expires.getTime())));		
//	}
////	old
//	public String getCreated(){
//		return this.ltt.getCreated().getValue();
//	}
////	old
//	public String getExpires(){
//		return this.ltt.getExpires().getValue();
//	}
//	
////	old
//	public void setCreated(String created){
//		this.ltt.setCreated(new AttributedDateTime(created));
//	}
////	old
//	public void setExpires(String expires){
//		this.ltt.setExpires(new AttributedDateTime(expires));			
//	}
////	old
//	public Element getLifeTimeElement(Document doc){
//		Element elemLT = doc.createElementNS(LifetimeType.getTypeDesc().getXmlType().getNamespaceURI(),"wst:"+TrustConstants.LIFE_TIME_LN);
//		Element elemCrt = doc.createElementNS(LifetimeType.getTypeDesc().getXmlType().getNamespaceURI(),"wst:"+TrustConstants.CREATED_LN);
//		Element elemExp = doc.createElementNS(LifetimeType.getTypeDesc().getXmlType().getNamespaceURI(),"wst:"+TrustConstants.EXPIRES_LN);
//		elemCrt.appendChild(doc.createTextNode(this.getCreated()));		
//		elemExp.appendChild(doc.createTextNode(this.getExpires())); 	
//		elemLT.appendChild(elemCrt);
//		elemLT.appendChild(elemExp);
//		return elemLT;
//	}


	/**
	 * @return
	 */
	public Element getCreated() {
		return created;
	}
	
	/**
	 * @return
	 */
	public Element getElement() {
		return element;
	}
	
	/**
	 * @return
	 */
	public Element getExpires() {
		return expires;
	}
	
	/**
	 * @param element
	 */
	public void setCreated(Element element) {
		created = element;
	}

	/**
	 * @param element
	 */
	public void setElement(Element element) {
		this.element = element;
	}
	
	/**
	 * @param element
	 */
	public void setExpires(Element element) {
		expires = element;
	}

}
