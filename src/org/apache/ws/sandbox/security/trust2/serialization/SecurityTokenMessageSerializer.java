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

import org.apache.ws.sandbox.security.trust2.SecurityTokenMessage;
import org.apache.ws.sandbox.security.trust2.TrustConstants;
import org.apache.ws.sandbox.security.trust2.exception.TrustException;
import org.apache.axis.Constants;
import org.apache.axis.encoding.SerializationContext;
import org.apache.axis.encoding.Serializer;
import org.apache.axis.wsdl.fromJava.Types;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.Attributes;
import org.xml.sax.helpers.AttributesImpl;

import javax.xml.namespace.QName;
import java.io.IOException;

/**
 * @author ddelvecc
 *         <p/>
 *         For serializing any SecurityTokenMessage objects into their XML representation.
 */
public abstract class SecurityTokenMessageSerializer implements Serializer {

    /**
     * Serialize an element named name, with the indicated attributes
     * and value.
     *
     * @param name       is the element name
     * @param attributes are the attributes...serialize is free to add more.
     * @param value      is the value
     * @param context    is the SerializationContext
     */
    public void serialize(QName name, Attributes attributes, Object value, SerializationContext context) throws IOException {
        if (!(value instanceof SecurityTokenMessage))
            throw new IOException("Can't serialize a " + value.getClass().getName() + " with a SecurityTokenMessageSerializer.");

        context.setPretty(false);

        SecurityTokenMessage tokenRequest = (SecurityTokenMessage) value;
        try {

            Element element = tokenRequest.getElement();
            if (name.equals(new QName(element.getNamespaceURI(), element.getLocalName()))) {
                AttributesImpl attrs = null;
                if (attributes != null)
                    attrs = new AttributesImpl(attributes);
                else
                    attrs = new AttributesImpl();
                Attr ctxt = element.getAttributeNodeNS(TrustConstants.WST_NS, TrustConstants.CONTEXT_ATTR);
                if (ctxt != null)
                    attrs.addAttribute(ctxt.getNamespaceURI(), ctxt.getLocalName(), ctxt.getName(), "CDATA", ctxt.getValue());

                context.startElement(name, attrs);
                NodeList children = element.getChildNodes();
                if (children != null) {
                    for (int i = 0; i < children.getLength(); i++)
                        context.writeDOMElement((Element) children.item(i));
                }
            } else {
                context.startElement(name, attributes);
                context.writeDOMElement(element);
            }

            context.endElement();
        } catch (TrustException e) {
            throw new IOException("TrustException during SecurityTokenMessage serialization: " + e.getMessage());
        } catch (Exception e) {
            throw new IOException("Exception during SecurityTokenMessage serialization: " + e.getMessage());
        }
    }

    public Element writeSchema(Class javaType, Types types) throws Exception {
        return null;
    }

    public String getMechanismType() {
        return Constants.AXIS_SAX;
    }

}
