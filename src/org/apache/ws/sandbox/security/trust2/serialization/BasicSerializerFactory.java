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

import org.apache.axis.Constants;
import org.apache.axis.encoding.DeserializerFactory;
import org.apache.axis.encoding.SerializerFactory;

import javax.xml.rpc.encoding.Deserializer;
import javax.xml.rpc.encoding.Serializer;
import java.util.Iterator;
import java.util.Vector;

/**
 * @author ddelvecc
 *         <p/>
 *         An abstract base class for creating Axis-SAX serializers.
 */
public abstract class BasicSerializerFactory implements SerializerFactory, DeserializerFactory {
    private Vector mechanisms;

    public Iterator getSupportedMechanismTypes() {
        if (mechanisms == null) {
            mechanisms = new Vector();
            mechanisms.add(Constants.AXIS_SAX);
        }
        return mechanisms.iterator();
    }

    public Serializer getSerializerAs(String arg0) {
        return null;
    }

    public Deserializer getDeserializerAs(String arg0) {
        return null;
    }
}
