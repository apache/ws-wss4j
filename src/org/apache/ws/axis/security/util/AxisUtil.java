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

package org.apache.ws.axis.security.util;

import org.apache.axis.AxisFault;
import org.apache.ws.axis.security.WSDoAllConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.util.StringUtil;
import org.apache.xml.security.c14n.Canonicalizer;
import org.w3c.dom.Document;

import javax.xml.soap.MessageFactory;
import javax.xml.soap.Name;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.dom.DOMSource;
import java.io.ByteArrayInputStream;
import java.util.Iterator;
import java.util.Vector;

/**
 * Axis Utility methods.
 * <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public class AxisUtil {

    /**
     * Convert a DOM Document into a soap message.
     * <p/>
     * 
     * @param doc 
     * @return 
     * @throws Exception 
     */
    public static SOAPMessage toSOAPMessage(Document doc) throws Exception {
        Canonicalizer c14n =
            Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS);
        byte[] canonicalMessage = c14n.canonicalizeSubtree(doc);
        ByteArrayInputStream in = new ByteArrayInputStream(canonicalMessage);
        MessageFactory factory = MessageFactory.newInstance();
        return factory.createMessage(null, in);
    }

    /**
     * Update soap message.
     * <p/>
     * 
     * @param doc     
     * @param message 
     * @return 
     * @throws Exception 
     */
    public static SOAPMessage updateSOAPMessage(
        Document doc,
        SOAPMessage message)
        throws Exception {
        DOMSource domSource = new DOMSource(doc);
        message.getSOAPPart().setContent(domSource);
        return message;
    }

    /**
     * Returns first WS-Security header for a given actor.
     * Only one WS-Security header is allowed for an actor.
     * <p/>
     * 
     * @param env   
     * @param actor 
     * @return 
     * @throws SOAPException 
     *
    public static SOAPHeaderElement getSecurityHeader(
        SOAPEnvelope env,
        String actor)
        throws SOAPException {
        SOAPHeader header = env.getHeader();
        if (header == null) {
            return null;
        }
        Iterator headerElements = header.examineHeaderElements(actor);
        while (headerElements.hasNext()) {
            SOAPHeaderElement he = (SOAPHeaderElement) headerElements.next();
            Name nm = he.getElementName();

            // find ws-security header
            if (nm.getLocalName().equalsIgnoreCase(WSConstants.WSSE_LN)
                && nm.getURI().equalsIgnoreCase(WSConstants.WSSE_NS)) {
                return he;
            }
        }
        return null;
    }*/

    static public int decodeAction(String action, Vector actions)
        throws AxisFault {

        int doAction = 0;

        if (action == null) {
            return doAction;
        }
        String single[] = StringUtil.split(action,' ');
        for (int i = 0; i < single.length; i++) {
            if (single[i].equals(WSDoAllConstants.NO_SECURITY)) {
                doAction = WSConstants.NO_SECURITY;
                return doAction;
            } else if (single[i].equals(WSDoAllConstants.USERNAME_TOKEN)) {
                doAction |= WSConstants.UT;
                actions.add(new Integer(WSConstants.UT));
            } else if (single[i].equals(WSDoAllConstants.SIGNATURE)) {
                doAction |= WSConstants.SIGN;
                actions.add(new Integer(WSConstants.SIGN));
            } else if (single[i].equals(WSDoAllConstants.ENCRYPT)) {
                doAction |= WSConstants.ENCR;
                actions.add(new Integer(WSConstants.ENCR));
            } else if (single[i].equals(WSDoAllConstants.SAML_TOKEN_UNSIGNED)) {
                doAction |= WSConstants.ST_UNSIGNED;
                actions.add(new Integer(WSConstants.ST_UNSIGNED));
            } else if (single[i].equals(WSDoAllConstants.SAML_TOKEN_SIGNED)) {
                doAction |= WSConstants.ST_SIGNED;
                actions.add(new Integer(WSConstants.ST_SIGNED));
            } else if (single[i].equals(WSDoAllConstants.TIMESTAMP)) {
                doAction |= WSConstants.TS;
                actions.add(new Integer(WSConstants.TS));
            } else if (single[i].equals(WSDoAllConstants.NO_SERIALIZATION)) {
                doAction |= WSConstants.NO_SERIALIZE;
                actions.add(new Integer(WSConstants.NO_SERIALIZE));
            } else {
                throw new AxisFault("WSDoAllSender: Unknown action defined" + single[i]);
            }
        }
        return doAction;
    }

}
