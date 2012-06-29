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
package org.swssf.wss.impl.processor.output;

import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSSecurityProperties;
import org.swssf.wss.ext.WSSUtils;
import org.swssf.wss.ext.WSSecurityContext;
import org.swssf.wss.securityEvent.SignatureValueSecurityEvent;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.SecurityToken;
import org.apache.xml.security.stax.ext.XMLSecurityException;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.impl.SignaturePartDef;
import org.apache.xml.security.stax.impl.algorithms.SignatureAlgorithm;
import org.apache.xml.security.stax.impl.processor.output.AbstractSignatureEndingOutputProcessor;
import org.apache.xml.security.stax.impl.util.IDGenerator;

import javax.xml.stream.XMLStreamException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * @author $Author: coheigea $
 * @version $Revision: 1354898 $ $Date: 2012-06-28 11:19:02 +0100 (Thu, 28 Jun 2012) $
 */
public class WSSSignatureEndingOutputProcessor extends AbstractSignatureEndingOutputProcessor {

    private SignedInfoProcessor signedInfoProcessor = null;

    public WSSSignatureEndingOutputProcessor(WSSSignatureOutputProcessor signatureOutputProcessor) throws XMLSecurityException {
        super(signatureOutputProcessor);
        this.addAfterProcessor(WSSSignatureOutputProcessor.class.getName());
        this.addAfterProcessor(UsernameTokenOutputProcessor.class.getName());
    }

    @Override
    public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        setAppendAfterThisTokenId(outputProcessorChain.getSecurityContext().<String>get(WSSConstants.PROP_APPEND_SIGNATURE_ON_THIS_ID));
        OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
        WSSUtils.flushBufferAndCallbackAfterTokenID(subOutputProcessorChain, this, getXmlSecEventBuffer());
        //call final on the rest of the chain
        subOutputProcessorChain.doFinal();
        //this processor is now finished and we can remove it now
        subOutputProcessorChain.removeProcessor(this);
    }

    @Override
    protected SignedInfoProcessor newSignedInfoProcessor(SignatureAlgorithm signatureAlgorithm, OutputProcessorChain outputProcessorChain) throws XMLSecurityException {
        this.signedInfoProcessor = new SignedInfoProcessor(signatureAlgorithm);
        this.signedInfoProcessor.setXMLSecurityProperties(getSecurityProperties());
        this.signedInfoProcessor.setAction(getAction());
        this.signedInfoProcessor.addAfterProcessor(WSSSignatureEndingOutputProcessor.class.getName());
        this.signedInfoProcessor.init(outputProcessorChain);
        return this.signedInfoProcessor;
    }

    @Override
    public void processHeaderEvent(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        super.processHeaderEvent(outputProcessorChain);

        SignatureValueSecurityEvent signatureValueSecurityEvent = new SignatureValueSecurityEvent();
        signatureValueSecurityEvent.setSignatureValue(this.signedInfoProcessor.getSignatureValue());
        ((WSSecurityContext) outputProcessorChain.getSecurityContext()).registerSecurityEvent(signatureValueSecurityEvent);
    }

    @Override
    protected void createKeyInfoStructureForSignature(
            OutputProcessorChain outputProcessorChain,
            SecurityToken securityToken,
            boolean useSingleCertificate)
            throws XMLStreamException, XMLSecurityException {

        WSSConstants.KeyIdentifierType keyIdentifierType = ((WSSSecurityProperties) getSecurityProperties()).getSignatureKeyIdentifierType();

        X509Certificate[] x509Certificates = securityToken.getX509Certificates();

        if (keyIdentifierType == WSSConstants.KeyIdentifierType.KEY_VALUE) {
            WSSUtils.createKeyValueTokenStructure(this, outputProcessorChain, x509Certificates);
        } else {
            List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(2);
            attributes.add(createAttribute(WSSConstants.ATT_wsu_Id, IDGenerator.generateID(null)));
            if (keyIdentifierType == WSSConstants.KeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE && !useSingleCertificate) {
                attributes.add(createAttribute(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_X509PKIPathv1));
            } else if (WSSConstants.Saml10Token.equals(securityToken.getTokenType())
                    || WSSConstants.Saml11Token.equals(securityToken.getTokenType())) {
                attributes.add(createAttribute(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_SAML11_TOKEN_PROFILE_TYPE));
            } else if (WSSConstants.Saml20Token.equals(securityToken.getTokenType())) {
                attributes.add(createAttribute(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_SAML20_TOKEN_PROFILE_TYPE));
            }
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference, false, attributes);

            String tokenId = securityToken.getId();

            if (keyIdentifierType == WSSConstants.KeyIdentifierType.ISSUER_SERIAL) {
                createX509IssuerSerialStructure(outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType == WSSConstants.KeyIdentifierType.SKI_KEY_IDENTIFIER) {
                WSSUtils.createX509SubjectKeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType == WSSConstants.KeyIdentifierType.X509_KEY_IDENTIFIER) {
                WSSUtils.createX509KeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType == WSSConstants.KeyIdentifierType.THUMBPRINT_IDENTIFIER) {
                WSSUtils.createThumbprintKeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType == WSSConstants.KeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE) {
                String valueType;
                if (useSingleCertificate) {
                    valueType = WSSConstants.NS_X509_V3_TYPE;
                } else {
                    valueType = WSSConstants.NS_X509PKIPathv1;
                }
                WSSUtils.createBSTReferenceStructure(this, outputProcessorChain, tokenId, valueType);
            } else if (keyIdentifierType == WSSConstants.KeyIdentifierType.EMBEDDED_KEYIDENTIFIER_REF) {
                WSSUtils.createEmbeddedKeyIdentifierStructure(this, outputProcessorChain, securityToken.getTokenType(), tokenId);
            } else if (keyIdentifierType == WSSConstants.KeyIdentifierType.USERNAMETOKEN_REFERENCE) {
                WSSUtils.createUsernameTokenReferenceStructure(this, outputProcessorChain, tokenId);
            } else {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, "unsupportedSecurityToken", keyIdentifierType.name());
            }
            createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference);
        }
    }

    protected void createTransformsStructureForSignature(OutputProcessorChain subOutputProcessorChain, SignaturePartDef signaturePartDef) throws XMLStreamException, XMLSecurityException {
        if (signaturePartDef.getTransformAlgo() != null) {
            List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(1);
            attributes.add(createAttribute(WSSConstants.ATT_NULL_Algorithm, signaturePartDef.getTransformAlgo()));
            createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_Transform, false, attributes);
            createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_TransformationParameters, false, null);
            attributes = new ArrayList<XMLSecAttribute>(1);
            attributes.add(createAttribute(WSSConstants.ATT_NULL_Algorithm, signaturePartDef.getC14nAlgo()));
            createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_CanonicalizationMethod, false, attributes);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_CanonicalizationMethod);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_TransformationParameters);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_Transform);
        } else {
            List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(1);
            attributes.add(createAttribute(WSSConstants.ATT_NULL_Algorithm, signaturePartDef.getC14nAlgo()));
            createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_Transform, false, attributes);
            createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_Transform);
        }
    }
}
