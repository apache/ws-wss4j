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

package org.apache.ws.security.trust2.serialization;

import org.apache.ws.security.trust2.RequestSecurityTokenResponse;
import org.apache.axis.encoding.SerializationContext;
import org.xml.sax.Attributes;

import javax.xml.namespace.QName;
import java.io.IOException;

/**
 * @author ddelvecc
 *         <p/>
 *         For serializing RequestSecurityTokenResponse objects into their XML representation.
 */
public class RSTResponseSerializer extends SecurityTokenMessageSerializer {

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
        if (!(value instanceof RequestSecurityTokenResponse))
            throw new IOException("Can't serialize a " + value.getClass().getName() + " with a RSTResponseSerializer.");

        super.serialize(name, attributes, value, context);
    }
}
