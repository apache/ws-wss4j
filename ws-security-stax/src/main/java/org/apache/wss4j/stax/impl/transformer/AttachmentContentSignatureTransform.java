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
package org.apache.wss4j.stax.impl.transformer;

import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.util.CRLFOutputStream;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.transformer.TransformIdentity;
import org.apache.xml.security.stax.impl.transformer.canonicalizer.Canonicalizer20010315_ExclOmitCommentsTransformer;

import javax.xml.stream.XMLStreamException;

import java.io.InputStream;
import java.util.Map;

public class AttachmentContentSignatureTransform extends TransformIdentity {

    public static final String ATTACHMENT = "attachment";

    private Attachment attachment;

    @Override
    public XMLSecurityConstants.TransformMethod getPreferredTransformMethod(XMLSecurityConstants.TransformMethod forInput) {
        switch (forInput) {
            case XMLSecEvent:
                return XMLSecurityConstants.TransformMethod.InputStream;
            case InputStream:
                return XMLSecurityConstants.TransformMethod.InputStream;
            default:
                throw new IllegalArgumentException("Unsupported class " + forInput.name());
        }
    }

    @Override
    public void setProperties(Map<String, Object> properties) throws XMLSecurityException {
        this.attachment = (Attachment) properties.get(ATTACHMENT);
    }

    protected Attachment getAttachment() {
        return attachment;
    }

    /*
             * http://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-SwAProfile-v1.1.1-os.html
             * 5.2 Referencing Attachments
             * This profile assumes, since it is not defined in RFC 2396 Section 4.2, that
             * all cid: references are not same-document references and that therefore, under
             * XMLDSIG, dereferencing a cid: URI always yields an octet stream as input to the
             * transform chain [RFC2396], [XMLDSIG].
             */
    @Override
    public void transform(XMLSecEvent xmlSecEvent) throws XMLStreamException {
        throw new UnsupportedOperationException("transform(XMLSecEvent) not allowed");
    }

    @Override
    public void transform(InputStream inputStream) throws XMLStreamException {
        String mimeType = getAttachment().getMimeType();
        String lowerCaseMimeType = null;
        if (mimeType != null) {
            lowerCaseMimeType = mimeType.toLowerCase();
        }

        if (lowerCaseMimeType != null
            && (lowerCaseMimeType.startsWith("text/xml")
                || lowerCaseMimeType.startsWith("application/xml")
                || lowerCaseMimeType.matches("(application|image)/.*\\+xml.*"))) {
            /* 5.4.2:
             * Content of an XML Content-Type MUST be XML canonicalized using
             * Exclusive XML Canonicalization without comments,as specified by
             * the URI http://www.w3.org/2001/10/xml-exc-c14n# [Excl-Canon].
             * The reason for requiring Exclusive Canonicalization is that many
             * implementations will support Exclusive Canonicalization for other
             * XML Signature purposes, since this form of canonicalization
             * supports context changes. The InclusiveNamespace PrefixList
             * attribute SHOULD be empty or not present.
             */
            Canonicalizer20010315_ExclOmitCommentsTransformer canon =
                    new Canonicalizer20010315_ExclOmitCommentsTransformer();
            try {
                canon.setOutputStream(getOutputStream());
            } catch (XMLSecurityException e) {
                throw new XMLStreamException(e);
            }
            canon.transform(inputStream);

        } else if (lowerCaseMimeType != null && lowerCaseMimeType.startsWith("text/")) {
            CRLFOutputStream crlfOutputStream = new CRLFOutputStream(getOutputStream());
            try {
                setOutputStream(crlfOutputStream);
            } catch (XMLSecurityException e) {
                throw new XMLStreamException(e);
            }
            super.transform(inputStream);
        } else {
            super.transform(inputStream);
        }
    }
}
