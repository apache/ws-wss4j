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
package org.apache.wss4j.policy.builders;

import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.wss4j.policy.SP11Constants;
import org.apache.wss4j.policy.SP13Constants;
import org.apache.wss4j.policy.SPConstants;
import org.apache.wss4j.policy.SPUtils;
import org.apache.wss4j.policy.model.Attachments;
import org.apache.wss4j.policy.model.Header;
import org.apache.wss4j.policy.model.SignedParts;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.util.List;

public class SignedPartsBuilder extends RequiredPartsBuilder {

    @Override
    public Assertion build(Element element, AssertionBuilderFactory factory) throws IllegalArgumentException {

        final SPConstants.SPVersion spVersion = SPConstants.SPVersion.getSPVersion(element.getNamespaceURI());
        boolean body = SPUtils.hasChildElementWithName(element, spVersion.getSPConstants().getBody());
        final List<Header> headers = getHeaders(element, true, spVersion);
        final Attachments attachments = getAttachments(element, spVersion);
        final boolean signAllHeaders = !SPUtils.hasChildElements(element);
        body |= signAllHeaders;
        SignedParts signedParts = new SignedParts(spVersion, body, attachments, headers, signAllHeaders);
        signedParts.setOptional(SPUtils.isOptional(element));
        signedParts.setIgnorable(SPUtils.isIgnorable(element));

        return signedParts;
    }

    protected Attachments getAttachments(Element element, SPConstants.SPVersion spVersion) {
        Element child = SPUtils.getFirstChildElement(element);
        while (child != null) {
            if (spVersion.getSPConstants().getAttachments().getLocalPart().equals(child.getLocalName())
                    && spVersion.getSPConstants().getAttachments().getNamespaceURI().equals(child.getNamespaceURI())) {
                boolean contentSignatureTransform =
                    SPUtils.hasChildElementWithName(child, spVersion.getSPConstants().getContentSignatureTransform());
                QName completeSigTransform =
                    spVersion.getSPConstants().getAttachmentCompleteSignatureTransform();
                boolean attachmentCompleteSignatureTransform =
                    SPUtils.hasChildElementWithName(child, completeSigTransform);
                return new Attachments(spVersion, contentSignatureTransform, attachmentCompleteSignatureTransform);
            }
            child = SPUtils.getNextSiblingElement(child);
        }
        return null;
    }

    @Override
    public QName[] getKnownElements() {
        return new QName[]{SP13Constants.SIGNED_PARTS, SP11Constants.SIGNED_PARTS};
    }
}
