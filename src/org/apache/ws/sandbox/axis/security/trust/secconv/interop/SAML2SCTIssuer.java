package org.apache.ws.axis.security.trust.secconv.interop;

import org.apache.axis.message.addressing.Address;
import org.apache.axis.message.addressing.AttributedURI;
import org.apache.axis.message.addressing.EndpointReference;
import org.apache.axis.utils.DOM2Writer;

import org.apache.ws.security.SOAPConstants;
import org
    .apache
    .ws
    .security
    .conversation
    .message
    .token
    .RequestSecurityTokenResponse;
import org.apache.ws.security.conversation.message.token.RequestedProofToken;
import org.apache.ws.security.conversation.message.token.RequestedSecurityToken;
import org.apache.ws.security.conversation.message.token.SecurityContextToken;
import org.apache.ws.security.policy.message.token.AppliesTo;
import org.apache.ws.security.trust.message.token.BinarySecret;
import org.apache.ws.security.trust.message.token.LifeTime;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

/**
 * @author Dimuthu (muthulee@yahoo.com)
 * 
 * To change the template for this generated type comment go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
public class SAML2SCTIssuer {

    /* Retriev the SAML token.
     * Validate the signature. - already done.......
     * Create the SCT and send it on the way.
     */

    private String uuidOfSCT = null;
    private byte[] sharedKey = null;
    private String samlUUID = null;
    public Document issue(Document req, Document res) throws Exception {

        //	retrive the SAML token. Get the uuid

        Element samEle =
            (Element) WSSecurityUtil.findElement(
                req,
                "Assertion",
                "urn:oasis:names:tc:SAML:1.0:assertion");
        samlUUID = samEle.getAttribute("AssertionID");

        // from the message context - get the current message context figure out the
        //Put key identifire in da Derived Key Tokens  

        //Create the epr
		Element elemAppliesTo = (Element)WSSecurityUtil.findElement(req,AppliesTo.TOKEN.getLocalPart(),AppliesTo.TOKEN.getNamespaceURI()); 
		//Element elemEpr = (Element)elemAppliesTo.getFirstChild();
	
        Element elemEpr = null;
        NodeList list = elemAppliesTo.getChildNodes();
        for (int i = 0; i < list.getLength(); i++) {
            if (list.item(i).getNodeType() == Node.ELEMENT_NODE) {
                elemEpr = (Element) list.item(i);
                break;
            }

        }
        
        /*
         * Below lines doesn't work. I don't know why ??? Oho I am Clueless..... 
         *
         * EndpointReference epr = new EndpointReference(elemEpr);
         * 
         * appliesToRes.setAnyElement(new EndpointReference(epr.toDOM(req)).toDOM(res));
		 * 
		 * So I am Parsing DOM - the Ugly way.
	     */
        
        
		Element AddressElement = null;
		NodeList listAdd = elemEpr.getChildNodes();
		for (int i = 0; i < listAdd.getLength(); i++) {
			if (listAdd.item(i).getNodeType() == Node.ELEMENT_NODE) {
				AddressElement = (Element) listAdd.item(i);
				break;
			}
		}
		System.out.println(DOM2Writer.nodeToString((Node) AddressElement, true));
		System.out.println(((Text)AddressElement.getFirstChild()).getNodeValue());
		  
        //Create the AppliesTo for the response message
		AppliesTo appliesToRes = new AppliesTo(res);
		String addValue = ((Text)AddressElement.getFirstChild()).getNodeValue();
		EndpointReference eprNew = new EndpointReference(new AttributedURI(addValue));
		appliesToRes.setAnyElement(eprNew.toDOM(res));
        
		//	Create the Lifetime element for the response message
		LifeTime lt = new LifeTime(res, 12 * 60);

        
        //create Requested Security Token with a SCT
        RequestedSecurityToken reqtedSecTok = new RequestedSecurityToken(res);
        SecurityContextToken sct = new SecurityContextToken(res);
        this.uuidOfSCT = sct.getIdentifier();
		LifeTime lt2 = new LifeTime(res, 12 * 60);
        sct.setElement(lt2.getElement());
        reqtedSecTok.addToken(sct.getElement());

        //Requested Proof Token
        RequestedProofToken reqProofTok = new RequestedProofToken(res);
        BinarySecret binSecret = new BinarySecret(res);
        binSecret.setTypeAttribute(BinarySecret.SYMMETRIC_KEY);
        //TODO::
        binSecret.setBinarySecretValue("0987654321123456");
        this.sharedKey = "0987654321123456".getBytes();
        reqProofTok.addToken(binSecret.getElement());

        //Crete the response
        RequestSecurityTokenResponse rSTR =
            new RequestSecurityTokenResponse(res);

        //Add tokens into the respose message
        rSTR.addToken(lt.getElement());
        rSTR.addToken(appliesToRes.getElement());
        rSTR.addToken(reqtedSecTok.getElement());
        rSTR.addToken(reqProofTok.getElement());

        //append to the body
        Element elemEnv = res.getDocumentElement();
        SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(elemEnv);
        Element elemBody =
            WSSecurityUtil.findBodyElement(
                elemEnv.getOwnerDocument(),
                soapConstants);

        //elemBody.removeChild((Element)elemBody.getFirstChild()); - There's no token now
        elemBody.appendChild(rSTR.getElement());

        return res;
    }

    /**
     * @return
     */
    public byte[] getSharedKey() {
        return sharedKey;
    }

    /**
     * @return
     */
    public String getUuidOfSCT() {
        return uuidOfSCT;
    }

    /**
     * @param bs
     */
    public void setSharedKey(byte[] bs) {
        sharedKey = bs;
    }

    /**
     * @param string
     */
    public void setUuidOfSCT(String string) {
        uuidOfSCT = string;
    }

    /**
     * @return
     */
    public String getSamlUUID() {
        return samlUUID;
    }

}

//<soap:Envelope 
//  xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'
//  xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
//  xmlns:wst='http://schemas.xmlsoap.org/ws/2004/04/trust' 
//  xmlns:wsc='http://schemas.xmlsoap.org/ws/2004/04/sc'
//  xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd ' 
//  xmlns:wsa='http://schemas.xmlsoap.org/ws/2004/03/addressing' 
//  xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' >
// <soap:Header>
//  <wsa:RelatesTo wsu:Id='relates' RelationshipType='wsa:Reply' >
//  uuid:16f6c35b-182f-407f-bfb4-48542b1fee22
//  </wsa:RelatesTo>
//  <wsa:MessageID wsu:Id='msgid' >
//  uuid:923a53e5-4e0d-4a0f-96d2-3d10340dfec5
//  </wsa:MessageID>
//  <wsa:To wsu:Id='to' >
//  http://schemas.xmlsoap.org/ws/2004/03/addressing/role/anonymous  
//  </wsa:To>
//  <wsa:Action wsu:Id='action' >
//   http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/SCT
//  </wsa:Action>
//  <wsse:Security>
//   <wsu:Timestamp wsu:Id='timestamp' >
//	<wsu:Created>2004-04-15T18:18:34Z</wsu:Created>
//	<wsu:Expires>2004-04-15T18:23:34Z</wsu:Expires>
//   </wsu:Timestamp>
//
//   <wsc:DerivedKeyToken wsu:Id='Sx4' >
//	 <wsse:SecurityTokenReference>
//	  <wsse:KeyIdentifier 
// ValueType='http://www.docs.oasis-open.org/wss/2004/XX/oasis-2004XX-wss-saml-token-profile-1.0#SAMLAssertionID' >
//	  uuid:8f8a6868-cb87-4d90-8f5d-f6efdb6a83f4  
//	  </wsse:KeyIdentifier>
//	 </wsse:SecurityTokenReference>
//	 <wsc:Length>16</wsc:Length>
//	 <wsc:Nonce>2+UyKPxHjDh0Yt2FKd/vCA==</wsc:Nonce>
//   </wsc:DerivedKeyToken>
//
//   <xenc:ReferenceList     
//  xmlns:xenc='http://www.w3.org/2001/04/xmlenc#' >
//	<xenc:DataReference URI='#BodyContent' />
//	<xenc:DataReference URI='#SignatureElement' />
//   </xenc:ReferenceList>
//
//   <wsc:DerivedKeyToken wsu:Id='Sx3' >
//	  <wsse:SecurityTokenReference>
//	   <wsse:KeyIdentifier 
// ValueType='http://www.docs.oasis-open.org/wss/2004/XX/oasis-2004XX-wss-saml-token-profile-1.0#SAMLAssertionID' >
//	  uuid:8f8a6868-cb87-4d90-8f5d-f6efdb6a83f4  
//	  </wsse:KeyIdentifier>
//	 </wsse:SecurityTokenReference>
//	<wsc:Length>16</wsc:Length>
//	 <wsc:Nonce>63FFKtJcFMqODvHIuB9T8g==</wsc:Nonce>
//   </wsc:DerivedKeyToken>
//
//  
//	 The Encrypted form of the Signature element 
//		  over the message body, 
//		  relates
//	      msgid
//		  to
//	      action
//        timestamps using Sx3 is 
//		  shown in comments
//
//<!-- BEGIN: Signature element encrypted with Sx4 -->
//  <xenc:EncryptedData Id='SignatureElement' 
//  xmlns:xenc='http://www.w3.org/2001/04/xmlenc#' 
//  Type='http://www.w3.org/2001/03/xmlenc#Element' >
//   <xenc:EncryptionMethod
//  Algorithm='http://www.w3.org/2001/04/xmlenc#aes128-cbc' />
//   <xenc:CipherData>
//	<xenc:CipherValue>
//	   ...
//	</xenc:CipherValue>  
//   </xenc:CipherData>
//  </xenc:EncryptedData>
//  <!-- END: Signature element encrypted with Sx4 -->
//
//
//  </wsse:Security>
// </soap:Header>
//
// <soap:Body wsu:Id='Body'>
//
//  <!-- The unencrypted form of the following is 
//
//  <wst:RequestSecurityTokenResponse>
//   <wsp:AppliesTo  
//	 xmlns:wsp="http://schemas.xmlsoap.org/ws/2002/12/policy" >
//	<wsa:EndpointReference>
//	 <wsa:Address>http://fabrikam.com/service</wsa:Address>
//	</wsa:EndpointReference>
//   </wsp:AppliesTo>
//   <wst:Lifetime>
//	<wsu:Created>2004-04-04T14:42:06Z</wsu:Created>
//	<wsu:Expires>2004-04-05T02:42:06Z</wsu:Expires>
//   </wst:Lifetime>
//   <wst:RequestedSecurityToken>
//	<wsc:SecurityContextToken>
//	 <wsc:Identifier>uuid:b40816ed-0ff9-4293-9740-fe1253786069</wsc:Identifier> 
//	 <wsu:Created>2004-04-04T14:42:06Z</wsu:Created> 
//	 <wsu:Expires>2004-04-05T02:42:06Z</wsu:Expires> 
//	</wsc:SecurityContextToken>
//   </wst:RequestedSecurityToken>
//   <wst:RequestedProofToken>
//	<wst:BinarySecret Type='http://schemas.xmlsoap.org/ws/2004/04/security/trust/SymmetricKey' >
//	xpXWK2lWolprtuhPq/Ttjg==
//	</wst:BinarySecret>
//   </wst:RequestedProofToken>
//  </wst:RequestSecurityTokenResponse>
//
//  -->
//
//  <!-- BEGIN: Message body encrypted with Sx4 -->
//  <xenc:EncryptedData Id='BodyContent' 
//  xmlns:xenc='http://www.w3.org/2001/04/xmlenc#' 
//  Type='http://www.w3.org/2001/03/xmlenc#Element' >
//   <xenc:EncryptionMethod
//  Algorithm='http://www.w3.org/2001/04/xmlenc#aes128-cbc' />
//   <xenc:CipherData>
//	<xenc:CipherValue>
//K7ywZyhoZzG0uOg20aXztLqnM1xaHBx3e92OMSjioqv9ZIhF0o0CRAGdfaH9
//r9EcgTjqLObP8A6gOOtK2jYJ0hY8OGwdreEtpe5avJ96ecsMcq/v+HXFLnR5
//pZmht2rLk6uKwXdk/tRXvIf3dDNvJb8g    
//	</xenc:CipherValue>  
//   </xenc:CipherData>
//  </xenc:EncryptedData>
//  <!-- END: Message body encrypted with Sx4 -->
//
// </soap:Body>
//</soap:Envelope>
