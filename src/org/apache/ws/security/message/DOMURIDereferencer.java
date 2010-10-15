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

import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.apache.ws.security.WSDocInfo;
import org.apache.xml.security.utils.IdResolver;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.signature.XMLSignatureInput;

import org.jcp.xml.dsig.internal.dom.DOMSubTreeData;

import javax.xml.crypto.Data;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dom.DOMURIReference;

/**
 * DOM-based implementation of URIDereferencer.
 */
public class DOMURIDereferencer implements URIDereferencer {
    
    private WSDocInfo wsDocInfo;
    
    /**
     * @param docInfo The WSDocInfo object to be used for resolving elements
     */
    public void setWsDocInfo(WSDocInfo docInfo) {
        wsDocInfo = docInfo;
    }

    public Data dereference(URIReference uriRef, XMLCryptoContext context)
        throws URIReferenceException {

        if (uriRef == null) {
            throw new NullPointerException("uriRef cannot be null");
        }
        if (context == null) {
            throw new NullPointerException("context cannot be null");
        }

        DOMURIReference domRef = (DOMURIReference) uriRef;
        Attr uriAttr = (Attr) domRef.getHere();
        String uri = uriRef.getURI();
        DOMCryptoContext dcc = (DOMCryptoContext) context;

        // Check if same-document URI and register ID
        if (uri != null && uri.length() != 0 && uri.charAt(0) == '#') {
            String id = uri.substring(1);

            if (id.startsWith("xpointer(id(")) {
                int i1 = id.indexOf('\'');
                int i2 = id.indexOf('\'', i1+1);
                id = id.substring(i1+1, i2);
            }

            // this is a bit of a hack to check for registered 
            // IDRefs and manually register them with Apache's IdResolver 
            // map which includes builtin schema knowledge of DSig/Enc IDs
            Node referencedElem = dcc.getElementById(id);
            if (referencedElem != null) {
                IdResolver.registerElementById((Element) referencedElem, id);
            }
        } 

        try {
            String baseURI = context.getBaseURI();
            //
            // Try to resolve the element directly using the EnvelopeIdResolver first
            //
            XMLSignatureInput in = null;
            EnvelopeIdResolver envelopeResolver = 
                (EnvelopeIdResolver)EnvelopeIdResolver.getInstance();
            if (envelopeResolver.engineCanResolve(uriAttr, baseURI)) {
                envelopeResolver.setWsDocInfo(wsDocInfo);
                in = envelopeResolver.engineResolve(uriAttr, baseURI);
            } else {
                ResourceResolver resolver = 
                    ResourceResolver.getInstance(uriAttr, baseURI);
                in = resolver.resolve(uriAttr, baseURI);
            }
            
            return new DOMSubTreeData(in.getSubNode(), in.isExcludeComments());
        } catch (Exception e) {
            throw new URIReferenceException(e);
        }
    }
}
