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



package org.apache.ws.security.conversation.message.token;


/**
 * @author Dimuthu Leelarathne
 * @version 1.0
 */

import org.apache.axis.components.logger.LogFactory;
import org.apache.commons.logging.Log;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import javax.xml.soap.*;
import org.apache.ws.security.trust.TrustConstants;

public class RequestSecurityToken {

	private static Log log =
				LogFactory.getLog(RequestSecurityTokenResponse.class.getName());

		private Element element = null;
		
	public static final QName TOKEN =
			new QName(
				TrustConstants.WST_NS,
				TrustConstants.REQUEST_SECURITY_TOKEN_LN,
				TrustConstants.WST_PREFIX);


  public RequestSecurityToken(Element elem) throws WSSecurityException{
  	//TODO :: Support only for SCT - for now
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

  }


  public Element getElement() {
	  return element;
  }
  public void setElement(Element element) {
	  this.element = element;
  }

  public String toString() {
	  return DOM2Writer.nodeToString((Node) this.element);
  }
  public void addToken(Element childToken) {
	  this.element.appendChild(childToken);
  }

  public void removeToken(Element childToken) {
	  this.element.removeChild(childToken);
  }
//  
//  //TODO @context - added by kau
//   public void setContext(String context){
//	   this.element.setAttribute("Context", context);
//   }
//	
//   public String getContext(){
//	   return this.element.getAttribute("Context");
//   }



}