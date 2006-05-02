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

package org.apache.ws.sandbox.security.trust;

import org.apache.ws.sandbox.security.policy.message.token.AppliesTo;
import org.apache.ws.sandbox.security.trust.message.token.BinarySecret;
import org.apache.ws.sandbox.security.trust.message.token.ComputedKey;
import org.apache.ws.sandbox.security.trust.message.token.Entropy;
import org.apache.ws.sandbox.security.trust.message.token.RequestSecurityTokenResponse;
import org.apache.ws.sandbox.security.trust.message.token.RequestedProofToken;
import org.apache.ws.sandbox.security.trust.message.token.RequestedSecurityToken;
import org.apache.ws.sandbox.security.trust2.Lifetime;
import org.apache.ws.security.WSSecurityException;
import org.apache.xml.utils.QName;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * This class' functionality will be included in the RequestSecurityTokenResponse class itself :-)
 * When a  RequestSecurityTokenResponse instance is created with a corresponding 
 * DOM Element it will parse that element and populate its properties
 * 
 * @author Dimuthu Leelarathne. (muthulee@yahoo.com)
 * 
 * This parses the RequestSecurityTokenResponse. This will be extremely useful for 
 * requestor classes.
 * 
 */
public class RSTRParser {

    private Element element = null;
	private AppliesTo appto = null;
	private Lifetime lifeTime = null;
	private RequestedSecurityToken reqtedTok = null;
	private RequestedProofToken proofTok = null;
	private Entropy entropy = null;
	private ComputedKey ckey = null;
	private BinarySecret binSecret = null;
	
    private static final QName APPLIES_TO =
        new QName(TrustConstants.WSP_NS, "AppliesTo");
    private static final QName LIFE_TIME =
        new QName(TrustConstants.WST_NS, "Lifetime");
    private static final QName REQUESTED_ST =
        new QName(TrustConstants.WST_NS, "RequestedSecurityToken");
    private static final QName PROOF_TOKEN =
        new QName(TrustConstants.WST_NS, "RequestedProofToken");
    private static final QName ENTROPY =
        new QName(TrustConstants.WST_NS, "Entropy");
    private static final QName COMPUTED_KEY =
        new QName(TrustConstants.WST_NS, "ComputedKey");
    private static final QName BIN_SECRET = 
		new QName(TrustConstants.WST_NS, "BinarySecret");
		
    public void processRSTR(RequestSecurityTokenResponse rstr)
        throws WSTrustException, WSSecurityException {
//        element = rstr.getElement();
//
//        NodeList list = element.getChildNodes();
//        int len = list.getLength();
//        Node nod;
//        Element elem;
//        for (int i = 0; i < len; i++) {
//            nod = list.item(i);
//            if (nod.getNodeType() != Node.ELEMENT_NODE)
//                continue;
//            elem = (Element) nod;
//
//            QName el = new QName(elem.getNamespaceURI(), elem.getLocalName());
//
//            if (el.equals(APPLIES_TO)) {
//                appto = new AppliesTo(elem);
//            } else if (el.equals(LIFE_TIME)) {
//                //TODO: Fix the problem
//                //lifeTime = new Lifetime(elem);
//            } else if (el.equals(REQUESTED_ST)) {
//                reqtedTok = new RequestedSecurityToken(elem);
//                System.out.println("Found reqtedToken....");
//            } else if (el.equals(PROOF_TOKEN)) {
//                proofTok = new RequestedProofToken(elem);
//                this.handleProofToken();
//            } else if (el.equals(ENTROPY)) {
//                entropy = new Entropy(elem);
//				handleEntropy();
//            } else {
//                //TODO :: Do something :-0
//            }
//
//        } //end of for loop
    }

    private void handleProofToken()
        throws WSTrustException, WSSecurityException {

        NodeList list = this.proofTok.getElement().getChildNodes();

        int len = list.getLength();
        Node nod;
        Element elem;
        for (int i = 0; i < len; i++) {
            nod = list.item(i);
            if (nod.getNodeType() != Node.ELEMENT_NODE)
                continue;
            elem = (Element) nod;

            QName el = new QName(elem.getNamespaceURI(), elem.getLocalName());

            if (el.equals(COMPUTED_KEY)) {
                ckey = new ComputedKey(elem);
                //TODO: proofTok.s
                Node val = elem.getChildNodes().item(0);
                if (val.getNodeType() == Node.TEXT_NODE) {
                    ckey.setValue(val.getNodeValue());
                } else {
                    throw new WSTrustException("Parser Exception");
                }
            } else if (el.equals(BinarySecret.TOKEN)) {
				this.binSecret = new BinarySecret(elem);
				Node val = elem.getChildNodes().item(0);
				if (val.getNodeType() == Node.TEXT_NODE) {
					binSecret.setValue(val.getNodeValue());
				} else {
				throw new WSTrustException("Parser Exception");
				}
                
            }else{
//				TODO :: Do something :-0
            }

        } //for

    } //handleProof

    private void handleEntropy() throws WSTrustException, WSSecurityException{
    	
//        NodeList list = this.entropy.getElement().getChildNodes();
//
//        int len = list.getLength();
//        Node nod;
//        Element elem;
//        for (int i = 0; i < len; i++) {
//            nod = list.item(i);
//            if (nod.getNodeType() != Node.ELEMENT_NODE)
//                continue;
//            elem = (Element) nod;
//
//            QName el = new QName(elem.getNamespaceURI(), elem.getLocalName());
//
//            if (el.equals(BinarySecret.TOKEN)) {
//                this.binSecret = new BinarySecret(elem);
//                entropy.setBinarySecret(binSecret);
//                Node val = elem.getChildNodes().item(0);
//                if (val.getNodeType() == Node.TEXT_NODE) {
//                    binSecret.setBinarySecretValue(val.getNodeValue());
//                } else {
//                    throw new WSTrustException("Parser Exception");
//                }
//            } else {
//                //TODO :: Do something :-0
//            }
//
//        } //for

    } //handleEntropy
    

    /**
     * @return
     */
    public AppliesTo getAppto() {
        return appto;
    }

    /**
     * @return
     */
    public BinarySecret getBinSecret() {
        return binSecret;
    }

    /**
     * @return
     */
    public ComputedKey getCkey() {
        return ckey;
    }

    /**
     * @return
     */
    public Entropy getEntropy() {
        return entropy;
    }

    /**
     * @return
     */
    public Lifetime getLifeTime() {
        return lifeTime;
    }

    /**
     * @return
     */
    public RequestedProofToken getProofTok() {
        return proofTok;
    }

    /**
     * @return
     */
    public RequestedSecurityToken getReqtedTok() {
        return reqtedTok;
    }

    
    /**
     * @param to
     */
    public void setAppto(AppliesTo to) {
        appto = to;
    }

    /**
     * @param secret
     */
    public void setBinSecret(BinarySecret secret) {
        binSecret = secret;
    }

    /**
     * @param key
     */
    public void setCkey(ComputedKey key) {
        ckey = key;
    }

    /**
     * @param entropy
     */
    public void setEntropy(Entropy entropy) {
        this.entropy = entropy;
    }

    /**
     * @param lifetime
     */
    public void setLifeTime(Lifetime lifetime) {
        lifeTime = lifetime;
    }

    /**
     * @param token
     */
    public void setProofTok(RequestedProofToken token) {
        proofTok = token;
    }

    /**
     * @param token
     */
    public void setReqtedTok(RequestedSecurityToken token) {
        reqtedTok = token;
    }

}
