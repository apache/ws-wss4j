/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.ws.security.message;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSecurityException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;

/**
 * XML-Security resolver that is used for resolving same-document URIs like URI="#id".
 * It is designed to work only with SOAPEnvelopes.
 * <p/>
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public class EnvelopeIdResolver extends ResourceResolverSpi {
    private static Log log =
            LogFactory.getLog(EnvelopeIdResolver.class.getName());
    
    private boolean doDebug = false;
    
    private WSDocInfo wsDocInfo;
    
    /**
     * @param docInfo The WSDocInfo object to be used for resolving elements
     */
    public void setWsDocInfo(WSDocInfo docInfo) {
        wsDocInfo = docInfo;
    }
    
    /**
     * This is the workhorse method used to resolve resources.
     * <p/>
     *
     * @param uri
     * @param BaseURI
     * @return TODO
     * @throws ResourceResolverException
     */
    public XMLSignatureInput engineResolve(Attr uri, String BaseURI)
            throws ResourceResolverException {

        doDebug = log.isDebugEnabled();

        String uriNodeValue = uri.getNodeValue();
        if (doDebug) {
            log.debug("enter engineResolve, look for: " + uriNodeValue);
        }

        //
        // First check to see if the element that we require is stored in as a 
        // protection element in WSDocInfo
        //
        String id = uriNodeValue.substring(1);
        Element selectedElem = null;
        if (wsDocInfo != null) {
            selectedElem = wsDocInfo.getProtectionElement(id);
        }
        //
        // Next check to see if the element that we require is a previously processed 
        // Security Token that is stored in WSDocInfo.
        //
        if (selectedElem == null && wsDocInfo != null) {
            selectedElem = wsDocInfo.getTokenElement(id);
        }
        
        if (selectedElem == null && (id != null || "".equals(id))) {
            CallbackLookup callbackLookup = null;
            if (wsDocInfo != null) {
                callbackLookup = wsDocInfo.getCallbackLookup();
            }
            if (callbackLookup == null) {
                callbackLookup = new DOMCallbackLookup(uri.getOwnerDocument());
            }
            try {
                selectedElem = callbackLookup.getElement(id, true);
            } catch (WSSecurityException ex) {
                throw new ResourceResolverException(
                    ex.getMessage(), new Object[]{"Id: " + id + " not found"},
                    uri, BaseURI
                );
            }
            if (selectedElem == null) {
                throw new ResourceResolverException("generic.EmptyMessage",
                        new Object[]{"Id: " + id + " not found"},
                        uri,
                        BaseURI);
            }
        }

        XMLSignatureInput result = new XMLSignatureInput(selectedElem);
        result.setMIMEType("text/xml");
        if (doDebug) {
            log.debug("exit engineResolve, result: " + result);
        }
        return result;
    }
    
    /**
     * This method helps the ResourceResolver to decide whether a
     * ResourceResolverSpi is able to perform the requested action.
     * <p/>
     *
     * @param uri
     * @param BaseURI
     * @return TODO
     */
    public boolean engineCanResolve(Attr uri, String BaseURI) {
        if (uri == null) {
            return false;
        }
        String uriNodeValue = uri.getNodeValue();
        return uriNodeValue.startsWith("#");
    }
    
}
