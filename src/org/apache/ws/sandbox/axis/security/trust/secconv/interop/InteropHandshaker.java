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
package org.apache.ws.axis.security.trust.secconv.interop;

import java.io.ByteArrayOutputStream;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Properties;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.axis.utils.DOM2Writer;
//import org.apache.axis.utils.XMLUtils;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.ConversationConstants;
import org.apache.ws.security.conversation.ConversationUtil;
import org.apache.ws.security.conversation.DerivedKeyCallbackHandler;
import org.apache.ws.security.conversation.message.info.SecurityContextInfo;
import org
    .apache
    .ws
    .security
    .conversation
    .message
    .token
    .RequestSecurityTokenResponse;
import org.apache.ws.security.conversation.message.token.RequestedSecurityToken;
import org.apache.ws.security.conversation.message.token.SecurityContextToken;
import org.apache.ws.security.trust.RSTR_Parser;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.trust.WSTrustException;
import org.apache.ws.security.util.Loader;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.XMLUtils;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * @author Muthulee
 *
 * To change the template for this generated type comment go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
public class InteropHandshaker {

    private DerivedKeyCallbackHandler dkcb = null;

    private String uuid = null;
    
    Hashtable options = null;

    public void handshake(Hashtable opt) {
     
     this.loadProperties("interop_Data.properties");
        
     String serviceViaTCPMon = (String)this.options.get("serviceViaTCPMon");//"http://localhost:9080/axis/services/EchoInterop";
	 String ipViaTCMPMon= (String)this.options.get("ipViaTCMPMon");//"http://127.0.0.1:9080/axis/services/SecurityTokenService2";       
     String realIPAddress = (String)this.options.get("realIPAddress");//"http://127.0.0.1:9080/axis/services/SecurityTokenService2";
	 String realServiceAddress = (String)this.options.get("realServiceAddress");//"http://127.0.0.1:9080/axis/services/EchoInterop";
     
     System.out.println(serviceViaTCPMon);
	 System.out.println(ipViaTCMPMon);
	 System.out.println(realIPAddress);
	 System.out.println(realServiceAddress);
	 
	    try {
            UNT2SAMLRequester initReq = new UNT2SAMLRequester();
            initReq.setRealIPAddressReal(realIPAddress);
            initReq.setRealServiceAddress(realServiceAddress);
            initReq.setIpViaTCMPMon(ipViaTCMPMon);
            
            initReq.peformRST(opt);
            RSTR_Parser parser = null; // initReq.getParser();

            parser = initReq.getParser();

            //read the saml assertions
            Element samlEle =
                (Element) WSSecurityUtil.getDirectChild(
                    parser.getReqtedTok().getElement(),
                    "Assertion",
                    "urn:oasis:names:tc:SAML:1.0:assertion");
            
			SAMLAssertion saml = new SAMLAssertion(samlEle);
						
            /* 
             * The most important line in the code. 
             * If removed we get an error !!!!!
             * Wired without this system.out things don't work
             */  
            System.out.println(DOM2Writer.nodeToString((Node) samlEle, true));

            /*
             * Now we have got the SAML token from the STS.
             * So we can call the web service using the SAML token.
             * 
             * We have to sign and encrypt the message using derived keys.
             * DerivedKeys are derived using the requestor and response nonces.
             * 
             */
            
			System.out.println("Second request....");

			SAML2SCTRequester secondReq = new SAML2SCTRequester();
			secondReq.setRealServiceAddress(realServiceAddress);
			secondReq.setServiceViaTCMPMon(serviceViaTCPMon);
			secondReq.setRealIPAddressReal(realIPAddress);
            
			secondReq.setSaml(saml);
			secondReq.peformRST(opt);
			//generate the key
                         
            String key1 = initReq.getRequestNonce();
            String key2 = parser.getBinSecret().getBinarySecretValue();
            byte[] key = InteropUtil.generateSymmetricFromEntropy(key1, key2);               
            
            DerivedKeyCallbackHandler dkcbHandler;
            String tempUUID;
            SecurityContextInfo sctInfo;

//            KeyGenerator keyGen =
//                KeyGenerator.getInstance("2.16.840.1.101.3.4.1.2");
//            SecretKey symmetricKey = keyGen.generateKey();
//
//            System.out.println("" + symmetricKey.getEncoded().length);
            tempUUID = saml.getId();
            sctInfo =
                new SecurityContextInfo(
                    tempUUID,
                    //"1234567890123456".getBytes(),
                    key,
                    1);
            // new SecurityContextInfo(tempUUID, symmetricKey.getEncoded(), 1);
            dkcbHandler = new DerivedKeyCallbackHandler();

            dkcbHandler.addSecurtiyContext(tempUUID, sctInfo);

            secondReq.createSecurityHeader(dkcbHandler, tempUUID);

		    //process the response.
            Document resSCTdoc = secondReq.getDocRes();
            RSTR_Parser sec_Pars = new RSTR_Parser();
           
//            ByteArrayOutputStream os = new ByteArrayOutputStream();
//            XMLUtils.outputDOM(resSCTdoc, os, true);
//            System.out.println(
//                "**************Response*********\n" + os.toString());

            Element rstrEle =
                (Element) resSCTdoc
                    .getElementsByTagNameNS(
                        TrustConstants.WST_NS,
                        "RequestSecurityTokenResponse")
                    .item(0);
            sec_Pars.processRSTR(new RequestSecurityTokenResponse(rstrEle));

            RequestedSecurityToken secondTok = sec_Pars.getReqtedTok();
            Element sctEle =
                (Element) (secondTok
                    .getElement()
                    .getElementsByTagNameNS(
                        ConversationConstants.WSC_NS,
                        "SecurityContextToken")
                    .item(0));
            SecurityContextToken sct = new SecurityContextToken(sctEle);

            String stringKey = sec_Pars.getBinSecret().getBinarySecretValue();

            byte[] keyByte = stringKey.getBytes();

            SecurityContextInfo info = new SecurityContextInfo(sct, keyByte, 1);
            System.out.println("UUID is ::: :-)"+uuid);
            this.uuid = sct.getIdentifier();
            this.dkcb = new DerivedKeyCallbackHandler();
            this.dkcb.addSecurtiyContext(this.uuid, info);

        } catch (WSSecurityException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (SAMLException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        } catch (WSTrustException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        } catch (NoSuchAlgorithmException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        }catch(Exception e){
			e.printStackTrace();
        }
    } //handshake

    /**
     * @return
     */
    public DerivedKeyCallbackHandler getDkcb() {
        return dkcb;
    }

    /**
     * @param handler
     */
    public void setDkcb(DerivedKeyCallbackHandler handler) {
        dkcb = handler;
    }

    /**
     * @return
     */
    public String getUuid() {
        return uuid;
    }
    
	private void loadProperties(String propFilename) {
			Properties properties = new Properties();
			try {
				URL url = Loader.getResource(propFilename);
				properties.load(url.openStream());
			} catch (Exception e) {
				throw new RuntimeException("Cannot load properties: " + propFilename);
			}
			this.options = new Hashtable();
			Enumeration enum = properties.keys();
			while(enum.hasMoreElements()) {
				String key = (String)enum.nextElement();
				this.options.put(key,properties.getProperty(key));
			}
		}

}
