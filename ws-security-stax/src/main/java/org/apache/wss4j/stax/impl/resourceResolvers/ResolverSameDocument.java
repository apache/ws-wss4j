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
package org.apache.wss4j.stax.impl.resourceResolvers;

import org.apache.xml.security.stax.ext.ResourceResolver;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.wss4j.stax.ext.WSSConstants;

import javax.xml.stream.events.Attribute;

public class ResolverSameDocument extends org.apache.xml.security.stax.impl.resourceResolvers.ResolverSameDocument {

    public ResolverSameDocument() {
        super();
    }

    public ResolverSameDocument(String uri) {
        super(uri);
    }

    @Override
    public ResourceResolver newInstance(String uri, String baseURI) {
        return new ResolverSameDocument(uri);
    }

    @Override
    public boolean matches(XMLSecStartElement xmlSecStartElement) {
        Attribute attribute = xmlSecStartElement.getAttributeByName(WSSConstants.ATT_WSU_ID);
        if (attribute != null && attribute.getValue().equals(getId())) {
            return true;
        }

        attribute = xmlSecStartElement.getAttributeByName(WSSConstants.ATT_NULL_ASSERTION_ID);
        if (attribute != null && attribute.getValue().equals(getId())) {
            return true;
        }

        attribute = xmlSecStartElement.getAttributeByName(WSSConstants.ATT_NULL_ID);
        if (attribute != null && attribute.getValue().equals(getId())) {
            return true;
        }
        return super.matches(xmlSecStartElement);
    }
}
