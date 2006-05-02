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

package org.apache.ws.sandbox.security.trust2.serialization;

import org.apache.axis.encoding.DeserializationContext;
import org.apache.axis.encoding.DeserializerImpl;
import org.apache.ws.sandbox.security.trust2.RequestSecurityToken;
import org.apache.ws.sandbox.security.trust2.TrustConstants;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import javax.xml.namespace.QName;

/**
 * @author ddelvecc
 *         <p/>
 *         For deserializing RequestSecurityToken objects/elements.
 */
public class RSTDeserializer extends DeserializerImpl {
    public static final QName myTypeQName = TrustConstants.REQUEST_NAME;

    private RequestSecurityToken tokenRequest;

    public RSTDeserializer() {
    }

    public void onStartElement(String namespace, String localName, String prefix, Attributes attributes, DeserializationContext context)
            throws SAXException {

        try {
            tokenRequest = new RequestSecurityToken(context.getCurElement().getAsDOM(), context.getEnvelope().getAsDocument());
            value = tokenRequest;
        } catch (Exception e) {
            throw new SAXException("Exception while processing RequestSecurityToken startElement: " + e.getMessage());
        }
    }
}
