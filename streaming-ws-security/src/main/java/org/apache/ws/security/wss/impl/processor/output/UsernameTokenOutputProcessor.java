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
package org.apache.ws.security.wss.impl.processor.output;

import org.apache.commons.codec.binary.Base64;
import org.apache.ws.security.wss.ext.*;
import org.apache.ws.security.wss.impl.securityToken.UsernameSecurityToken;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.util.IDGenerator;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.GregorianCalendar;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class UsernameTokenOutputProcessor extends AbstractOutputProcessor {

    public UsernameTokenOutputProcessor() throws XMLSecurityException {
        super();
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

        try {
            WSPasswordCallback pwCb = new WSPasswordCallback(((WSSSecurityProperties) getSecurityProperties()).getTokenUser(), WSPasswordCallback.Usage.USERNAME_TOKEN);
            WSSUtils.doPasswordCallback(getSecurityProperties().getCallbackHandler(), pwCb);
            String password = pwCb.getPassword();
            WSSConstants.UsernameTokenPasswordType usernameTokenPasswordType = ((WSSSecurityProperties) getSecurityProperties()).getUsernameTokenPasswordType();

            if (password == null && usernameTokenPasswordType != null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }

            byte[] nonceValue = new byte[16];
            WSSConstants.secureRandom.nextBytes(nonceValue);

            XMLGregorianCalendar created = WSSConstants.datatypeFactory.newXMLGregorianCalendar(new GregorianCalendar());

            final String wsuId = IDGenerator.generateID(null);

            final OutputProcessor outputProcessor = this;

            final UsernameSecurityToken usernameSecurityToken =
                    new UsernameSecurityToken(
                            ((WSSSecurityProperties) getSecurityProperties()).getTokenUser(),
                            password,
                            created != null ? created.toXMLFormat() : null,
                            nonceValue,
                            null,
                            null,
                            wsuId
                    );
            usernameSecurityToken.setProcessor(outputProcessor);

            SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

                @Override
                public SecurityToken getSecurityToken() throws WSSecurityException {
                    return usernameSecurityToken;
                }

                @Override
                public String getId() {
                    return wsuId;
                }
            };
            if (getAction() == WSSConstants.USERNAMETOKEN_SIGNED) {
                outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(wsuId, securityTokenProvider);
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, wsuId);
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_APPEND_SIGNATURE_ON_THIS_ID, wsuId);
            }
            final FinalUsernameTokenOutputProcessor finalUsernameTokenOutputProcessor = new FinalUsernameTokenOutputProcessor(wsuId, nonceValue, password, created);
            finalUsernameTokenOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
            finalUsernameTokenOutputProcessor.setAction(getAction());
            finalUsernameTokenOutputProcessor.init(outputProcessorChain);

        } finally {
            outputProcessorChain.removeProcessor(this);
        }
        outputProcessorChain.processEvent(xmlSecEvent);
    }

    class FinalUsernameTokenOutputProcessor extends AbstractOutputProcessor {

        private String wsuId = null;
        private byte[] nonceValue = null;
        private String password = null;
        private XMLGregorianCalendar created = null;

        FinalUsernameTokenOutputProcessor(String wsuId, byte[] nonceValue, String password, XMLGregorianCalendar created)
                throws XMLSecurityException {
            super();
            this.addAfterProcessor(UsernameTokenOutputProcessor.class.getName());
            this.addAfterProcessor(UsernameTokenOutputProcessor.class.getName());
            this.wsuId = wsuId;
            this.nonceValue = nonceValue;
            this.password = password;
            this.created = created;
        }

        @Override
        public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
            outputProcessorChain.processEvent(xmlSecEvent);
            if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT) {
                XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();
                if (xmlSecStartElement.getName().equals(WSSConstants.TAG_wsse_Security)
                        && WSSUtils.isInSecurityHeader(xmlSecStartElement, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                    List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(1);
                    attributes.add(createAttribute(WSSConstants.ATT_wsu_Id, this.wsuId));
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_UsernameToken, false, attributes);
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_Username, false, null);
                    createCharactersAndOutputAsEvent(subOutputProcessorChain, ((WSSSecurityProperties) getSecurityProperties()).getTokenUser());
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_Username);
                    if (((WSSSecurityProperties) getSecurityProperties()).getUsernameTokenPasswordType() != WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE) {
                        attributes = new ArrayList<XMLSecAttribute>(1);
                        attributes.add(createAttribute(WSSConstants.ATT_NULL_Type,
                                ((WSSSecurityProperties) getSecurityProperties()).getUsernameTokenPasswordType() == WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST
                                        ? WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST.getNamespace()
                                        : WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT.getNamespace()));
                        createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_Password, false, attributes);
                        createCharactersAndOutputAsEvent(subOutputProcessorChain,
                                ((WSSSecurityProperties) getSecurityProperties()).getUsernameTokenPasswordType() == WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST
                                        ? WSSUtils.doPasswordDigest(this.nonceValue, this.created.toXMLFormat(), this.password)
                                        : this.password);
                        createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_Password);
                    }

                    if (((WSSSecurityProperties) getSecurityProperties()).getUsernameTokenPasswordType() == WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST
                            || Arrays.binarySearch(getSecurityProperties().getOutAction(), WSSConstants.USERNAMETOKEN_SIGNED) >= 0) {
                        attributes = new ArrayList<XMLSecAttribute>(1);
                        attributes.add(createAttribute(WSSConstants.ATT_NULL_EncodingType, WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING));
                        createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_Nonce, false, attributes);


                        createCharactersAndOutputAsEvent(subOutputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(this.nonceValue));
                        createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_Nonce);
                        createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsu_Created, false, null);

                        createCharactersAndOutputAsEvent(subOutputProcessorChain, this.created.toXMLFormat());
                        createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsu_Created);
                    }
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_wsse_UsernameToken);

                    outputProcessorChain.removeProcessor(this);
                }
            }
        }
    }
}
