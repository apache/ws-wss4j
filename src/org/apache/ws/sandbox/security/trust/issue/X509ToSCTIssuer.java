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
package org.apache.ws.security.trust.issue;

import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.conversation.message.token.RequestSecurityTokenResponse;
import org.apache.ws.security.conversation.message.token.RequestedProofToken;
import org.apache.ws.security.conversation.message.token.RequestedSecurityToken;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.trust.STSUtil;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.trust.WSTrustException;
import org.apache.ws.security.trust.message.token.BaseToken;
import org.apache.ws.security.trust.message.token.LifeTime;
import org.apache.ws.security.trust.message.token.RequestType;
import org.apache.ws.security.trust.message.token.TokenType;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
/**
 * @author Malinda Kaushalye
 *
 * Issue SCTs based on X509 certificates.
 * Developers have to override the method getSecuritContextToken()
 * @see org.apache.ws.security.trust.STIssuer#issue(org.w3c.dom.Document, org.w3c.dom.Document)
 */
public abstract class X509ToSCTIssuer implements STIssuer {
	X509Security x509;
	int lifeTime = 2*60;//default in minutes
	Crypto crypto;
	protected String alias="";
	
	/**
	 * 
	 */
	public X509ToSCTIssuer() {
		super();
		
	}

	/* (non-Javadoc)
	 * @see org.apache.ws.security.trust.STIssuer#issue(org.w3c.dom.Document, org.w3c.dom.Document)
	 */
	public Document issue(Document req, Document res) throws Exception {
	
		
		Element elemTokenType=(Element)WSSecurityUtil.findElement(req,TokenType.TOKEN.getLocalPart(),TokenType.TOKEN.getNamespaceURI());
		TokenType tokenType=new TokenType(elemTokenType);
		
		Element elemRequestType=(Element)WSSecurityUtil.findElement(req,RequestType.TOKEN.getLocalPart(),RequestType.TOKEN.getNamespaceURI());
		RequestType requestType=new RequestType(elemRequestType);
		
		Element elemBase=(Element)WSSecurityUtil.findElement(req,BaseToken.TOKEN.getLocalPart(),BaseToken.TOKEN.getNamespaceURI());
		BaseToken base=new BaseToken(elemBase);		
		
		BinarySecurity binarySecurity=STSUtil.findBinarySecurityToken(req);
		//x509=new X509Security(binarySecurity.getElement());
		Element sct=this.getSecuritContextToken(res,x509);		
		
		/////////////////////////////////////////////////////////////////////////////
		//Now we build the response
		RequestSecurityTokenResponse requestSecurityTokenResponse=new RequestSecurityTokenResponse(res);
		
		RequestedSecurityToken requestedSecurityToken=new RequestedSecurityToken(res);
		//Token Type
		TokenType tokenTypeRes=new TokenType(res);
		tokenTypeRes.setValue(tokenType.getValue());
		//Request Type
		RequestType requestTypeRes=new RequestType(res);
		requestTypeRes.setValue(requestType.getValue());

		//It is RECOMMENDED that the issuer return this element with issued tokens so the 
		//requestor knows the actual validity period without having to parse the
		//returned token.
		LifeTime lt=new LifeTime(res,this.getLifeTime());
		Element elemLifeTime = lt.getElement();

		//append to req'ed token				
//		requestedSecurityToken.addToken(tokenTypeRes.getElement());
//		requestedSecurityToken.addToken(requestTypeRes.getElement());
		requestedSecurityToken.addToken(sct);
		

		RequestedProofToken requestedProofToken=new RequestedProofToken(res);
		if(!this.alias.equals("")){
			requestedProofToken.build(res, this.crypto, this.alias, requestedProofToken.getElement());
		}		
		
	//	append to response
		requestSecurityTokenResponse.addToken(tokenTypeRes.getElement());
		requestSecurityTokenResponse.addToken(requestTypeRes.getElement());
		requestSecurityTokenResponse.addToken(elemLifeTime);	
			
		requestSecurityTokenResponse.addToken(requestedSecurityToken.getElement());
		requestSecurityTokenResponse.addToken(requestedProofToken.getElement());
		requestSecurityTokenResponse.setContext(TrustConstants.ISSUE_SECURITY_TOKEN);
		
		
		
		//append to the body
		Element elemEnv=res.getDocumentElement();
		SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(elemEnv);
		Element elemBody=WSSecurityUtil.findBodyElement(elemEnv.getOwnerDocument(),soapConstants);	
		
		//Option1: Use the exisiting response element
		//Element cld1=(Element)elemBody.getFirstChild().appendChild(requestedSecurityToken.getElement());


		//Option2:remove old and create new response element 
		Element cld0=(Element)elemBody.removeChild((Element)elemBody.getFirstChild());
		Element cld1=(Element)elemBody.appendChild(requestSecurityTokenResponse.getElement());
		
		
		return res;
	}
	/**
	 * Override this method to generate the SCT. 
	 * Application developers can verify the requester
	 * according to their own mechanism (e.g. Searching a database) 
	 * The whole request is handed over to the end user to make the process more flexible.
	 */
	public abstract Element getSecuritContextToken(Document doc,X509Security x509Sec)throws WSTrustException;

	/**
	 * @return  Duration in minutes
	 */
	public int getLifeTime() {
		return lifeTime;
	}

	/**
	 * @return
	 */
	public X509Security getX509() {
		return x509;
	}

	/**
	 * 
	 * @param time Duration in minutes
	 */
	public void setLifeTime(int time) {
		lifeTime = time;
	}

	/**
	 * @return
	 */
	public Crypto getCrypto() {
		return crypto;
	}

	/**
	 * @param crypto
	 */
	public void setCrypto(Crypto crypto) {
		this.crypto = crypto;
	}

	/**
	 * @return
	 */
	public String getAlias() {
		return alias;
	}

	/**
	 * @param string
	 */
	public void setAlias(String string) {
		alias = string;
	}

}
