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
package org.apache.ws.secpolicy.builders;

import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SP13Constants;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.SPUtils;
import org.apache.ws.secpolicy.model.Attachments;
import org.apache.ws.secpolicy.model.EncryptedParts;
import org.apache.ws.secpolicy.model.Header;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class EncryptedPartsBuilder extends SignedPartsBuilder {

    public Assertion build(Element element, AssertionBuilderFactory factory) throws IllegalArgumentException {

        final SPConstants.SPVersion spVersion = SPConstants.SPVersion.getSPVersion(element.getNamespaceURI());
        boolean body = SPUtils.hasChildElementWithName(element, spVersion.getSPConstants().getBody());
        final List<Header> headers = getHeaders(element, true, spVersion);
        final Attachments attachments = getAttachments(element, spVersion);
        body |= !SPUtils.hasChildElements(element);

        EncryptedParts encryptedParts = new EncryptedParts(spVersion, body, attachments, headers);
        encryptedParts.setOptional(SPUtils.isOptional(element));
        encryptedParts.setIgnorable(SPUtils.isIgnorable(element));
        return encryptedParts;
    }

    public QName[] getKnownElements() {
        return new QName[]{SP13Constants.ENCRYPTED_PARTS, SP11Constants.ENCRYPTED_PARTS};
    }
}
