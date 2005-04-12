/*
 * Created on Aug 29, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package org.apache.ws.axis.security.trust.secconv.interop;

import java.io.ByteArrayOutputStream;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.axis.AxisFault;
import org.apache.axis.message.addressing.EndpointReference;
import org.apache.axis.utils.DOM2Writer;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.conversation.ConversationUtil;
import org.apache.ws.security.conversation.message.token.RequestSecurityTokenResponse;
import org.apache.ws.security.conversation.message.token.RequestedProofToken;
import org.apache.ws.security.conversation.message.token.RequestedSecurityToken;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.policy.message.token.AppliesTo;
import org.apache.ws.security.saml.SAMLIssuer;
import org.apache.ws.security.saml.SAMLIssuerFactory;
import org.apache.ws.security.trust.issue.STIssuer;
import org.apache.ws.security.trust.message.token.BinarySecret;
import org.apache.ws.security.trust.message.token.ComputedKey;
import org.apache.ws.security.trust.message.token.Entropy;
import org.apache.ws.security.trust.message.token.LifeTime;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.utils.XMLUtils;
import org.opensaml.SAMLAssertion;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * @author Ruchith
 */

public class UNT2SAMLIssuer implements STIssuer{
	
	private boolean doDebug = false;

	public Document issue(Document req, Document res) throws Exception{
		try {

			//First gethold of the username

			//This didn't work
			//Element elemUnt = (Element)WSSecurityUtil.findElement(req,WSConstants.USERNAME_TOKEN_LN,WSConstants.WSSE_LN);

			/*
			 * --------Alternative method--------
			 * Get hold of the SecurityHeader
			 * Get all the child elements and find the UsernamToken
			 * Getting the element list by LN OR LN and NS didn't work :-?
			 */			

			Element elemHeader = WSSecurityUtil.findWsseSecurityHeaderBlock(WSSConfig.getDefaultWSConfig(),res,req.getDocumentElement(),false);
			
			NodeList tempList = elemHeader.getChildNodes();

			Element elemUnt = null;
			
			for(int i = 0; i < tempList.getLength(); i++) {
				Node n = tempList.item(i);
				if(n.getNodeType() == Element.ELEMENT_NODE)
					if(n.getLocalName().equals(WSConstants.USERNAME_TOKEN_LN))
						elemUnt = (Element)n;
			}
			
			UsernameToken unt = new UsernameToken(WSSConfig.getDefaultWSConfig(),elemUnt);
			
			if(doDebug) {
				System.out.println("Node count : " + tempList.getLength());
				System.out.println("Username token: " + DOM2Writer.nodeToString(elemUnt,true));
				System.out.println("Username: " + unt.getName());
				System.out.println("Password: " + unt.getPassword());
			}
			

			Element elemAppliesTo = (Element)WSSecurityUtil.findElement(req,AppliesTo.TOKEN.getLocalPart(),AppliesTo.TOKEN.getNamespaceURI()); 
			Element elemEpr = (Element)elemAppliesTo.getFirstChild();
			EndpointReference epr = new EndpointReference(elemEpr);


			//Create the Lifetime element for the response message
			LifeTime lt = new LifeTime(res,12*60);
			Element elemLifeTime = lt.getElement();

			//Create the AppliesTo for the response message
			AppliesTo appliesToRes = new AppliesTo(res);
			appliesToRes.setAnyElement(new EndpointReference(epr.toDOM(req)).toDOM(res));

			//Get the requester nonce value
			Element elemEntropy = (Element)WSSecurityUtil.findElement(req,Entropy.TOKEN.getLocalPart(),Entropy.TOKEN.getNamespaceURI());
			Element elemBinSecret = (Element) elemEntropy.getFirstChild();
			BinarySecret binSecretReq = new BinarySecret(elemBinSecret);
			String nonceReq =  binSecretReq.getBinarySecretValue();
			
			//Response entropy
			Entropy entropyRes = new Entropy(res);
			BinarySecret binSecretRes = new BinarySecret(res);
			String nonceRes = ConversationUtil.generateNonce(128);
			binSecretRes.setBinarySecretValue(nonceRes);
			entropyRes.setBinarySecret(binSecretRes);
			
			//Requested Proof Token
			RequestedProofToken requestedProofTokenRes = new RequestedProofToken(res);
			ComputedKey computedKeyRes = new ComputedKey(res);
			computedKeyRes.setComputedKeyValue(ComputedKey.PSHA1);
			requestedProofTokenRes.addToken(computedKeyRes.getElement());
			
			
			//Crete the response
				RequestSecurityTokenResponse requestSecurityTokenResponse = new RequestSecurityTokenResponse(res);

			RequestedSecurityToken requestedSecurityToken = new RequestedSecurityToken(res);
			
			byte[] sx = this.generateSymmetricFromEntropy(nonceReq,nonceRes);

			requestedSecurityToken.addToken(getSignedSAMLToken(res,epr.getAddress().toString(),sx,this.getEmailFromUserName(unt.getName())));

			
			//Add tokens into the respose message
			requestSecurityTokenResponse.addToken(elemLifeTime);
			requestSecurityTokenResponse.addToken(appliesToRes.getElement());
			requestSecurityTokenResponse.addToken(requestedSecurityToken.getElement());
			requestSecurityTokenResponse.addToken(requestedProofTokenRes.getElement());
			requestSecurityTokenResponse.addToken(entropyRes.getElement());

			//append to the body
			Element elemEnv=res.getDocumentElement();
			SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(elemEnv);
			Element elemBody=WSSecurityUtil.findBodyElement(elemEnv.getOwnerDocument(),soapConstants);	

			//elemBody.removeChild((Element)elemBody.getFirstChild()); - There's no token now
			elemBody.appendChild(requestSecurityTokenResponse.getElement());
            
//			ByteArrayOutputStream osReq = new ByteArrayOutputStream();
//		  XMLUtils.outputDOM(res.getDocumentElement(), osReq, true);
//           System.out.println(osReq);              
            return res;
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}
	

    private Element getSignedSAMLToken(Document doc,String epr, byte[] sx, String username)
            throws Exception {
        
    	
        Crypto crypto = CryptoFactory.getInstance("interop_STS_crypto.properties"); //Load the sig crypto
        
        String samlPropFile = "interop_saml_STS.properties";
        SAMLIssuer saml = SAMLIssuerFactory.getInstance(samlPropFile);
        
        saml.setUserCrypto(crypto);
        saml.setInstanceDoc(doc);
        saml.setUsername(username);
        ((InteropSAMLIssuerImpl)saml).setEpr(epr);
        ((InteropSAMLIssuerImpl)saml).setSx(sx);
        
        SAMLAssertion assertion = saml.newAssertion();
        
        if (assertion == null) {
            throw new AxisFault("Issuer: Signed SAML: no SAML token received");
        }
        
        Element assertionAsDom = (Element)assertion.toDOM(doc);
        return assertionAsDom;
        
    }
    
	private byte[] generateSymmetricFromEntropy(String requesterNonce, String responderNonce) throws Exception {
		return P_hash(requesterNonce.getBytes(),responderNonce.getBytes(),16);
	}
	
    /**
     * Stolen from WSUsernameToken  :-)
     *
     * @param secret
     * @param seed
     * @param mac
     * @param required
     * @return
     * @throws java.lang.Exception
     */
    private byte[] P_hash(byte[] secret, byte[] seed, int required) throws Exception {
    	
    	Mac mac = Mac.getInstance("HmacSHA1");
        byte[] out = new byte[required];
        int offset = 0, tocpy;
        byte[] A, tmp;
        A = seed;
        while (required > 0) {
            SecretKeySpec key = new SecretKeySpec(secret, "HMACSHA1");
            mac.init(key);
            mac.update(A);
            A = mac.doFinal();
            mac.reset();
            mac.init(key);
            mac.update(A);
            mac.update(seed);
            tmp = mac.doFinal();
            tocpy = min(required, tmp.length);
            System.arraycopy(tmp, 0, out, offset, tocpy);
            offset += tocpy;
            required -= tocpy;
        }
        return out;
    }

    private int min(int a, int b) {
        return (a > b) ? b : a;
    }
    
	private String getEmailFromUserName(String username) throws AxisFault {
		if(username.equals("Alice")) {
			return "alice@fabrikam.com";
		} else if(username.equals("Bob")) {
			return "bob@fabrikam.com";
		} else if(username.equals("Charlie")) {
			return "charlie@fabrikam.com";
		} else if(username.equals("Dawn")) {
			return "dawn@fabrikam.com";
		} else if(username.equals("Evan")) {
			return "evan@fabrikam.com";
		} else if(username.equals("Fred")) {
			return "fred@fabrikam.com";
		} else if(username.equals("Graham")) {
			return "graham@fabrikam.com";
		} else if(username.equals("Hayley")) {
			return "hayley@fabrikam.com";
		} else if(username.equals("Imogen")) {
			return "imogen@fabrikam.com";
		} else {
			throw new AxisFault("Invalid user: This should be checked at the WSDoAllReceiver");
		}
		
	}
}