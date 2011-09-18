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
package org.swssf.impl.processor.output;

import org.apache.commons.codec.binary.Base64;
import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.swssf.impl.securityToken.UsernameSecurityToken;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.*;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class UsernameTokenOutputProcessor extends AbstractOutputProcessor {

    public UsernameTokenOutputProcessor(SecurityProperties securityProperties, Constants.Action action) throws WSSecurityException {
        super(securityProperties, action);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {

        try {
            WSPasswordCallback pwCb = new WSPasswordCallback(getSecurityProperties().getTokenUser(), WSPasswordCallback.Usage.USERNAME_TOKEN);
            Utils.doPasswordCallback(getSecurityProperties().getCallbackHandler(), pwCb);
            String password = pwCb.getPassword();
            Constants.UsernameTokenPasswordType usernameTokenPasswordType = getSecurityProperties().getUsernameTokenPasswordType();

            if (password == null && usernameTokenPasswordType != null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }

            byte[] nonceValue = new byte[16];
            Constants.secureRandom.nextBytes(nonceValue);

            DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
            XMLGregorianCalendar created = datatypeFactory.newXMLGregorianCalendar(new GregorianCalendar());

            final String wsuId = "UsernameToken-" + UUID.randomUUID().toString();

            final OutputProcessor outputProcessor = this;

            final UsernameSecurityToken usernameSecurityToken =
                    new UsernameSecurityToken(
                            getSecurityProperties().getTokenUser(),
                            password,
                            created != null ? created.toXMLFormat() : null,
                            nonceValue,
                            null,
                            null,
                            outputProcessorChain.getSecurityContext(),
                            wsuId,
                            outputProcessor
                    );

            SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {
                public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {
                    return usernameSecurityToken;
                }

                public String getId() {
                    return wsuId;
                }
            };
            if (getAction() == Constants.Action.USERNAMETOKEN_SIGNED) {
                outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(wsuId, securityTokenProvider);
                outputProcessorChain.getSecurityContext().put(Constants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, wsuId);
                outputProcessorChain.getSecurityContext().put(Constants.PROP_APPEND_SIGNATURE_ON_THIS_ID, wsuId);
            }
            outputProcessorChain.addProcessor(new FinalUsernameTokenOutputProcessor(getSecurityProperties(), getAction(), wsuId, nonceValue, password, created));

        } catch (DatatypeConfigurationException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        } finally {
            outputProcessorChain.removeProcessor(this);
        }
        outputProcessorChain.processEvent(xmlEvent);
    }

    class FinalUsernameTokenOutputProcessor extends AbstractOutputProcessor {

        private String wsuId = null;
        private byte[] nonceValue = null;
        private String password = null;
        private XMLGregorianCalendar created = null;

        FinalUsernameTokenOutputProcessor(SecurityProperties securityProperties, Constants.Action action, String wsuId,
                                          byte[] nonceValue, String password, XMLGregorianCalendar created)
                throws WSSecurityException {
            super(securityProperties, action);
            this.getAfterProcessors().add(UsernameTokenOutputProcessor.class.getName());
            this.getAfterProcessors().add(UsernameTokenOutputProcessor.class.getName());
            this.wsuId = wsuId;
            this.nonceValue = nonceValue;
            this.password = password;
            this.created = created;
        }

        @Override
        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
            outputProcessorChain.processEvent(xmlEvent);
            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                if (outputProcessorChain.getDocumentContext().isInSecurityHeader() && startElement.getName().equals(Constants.TAG_wsse_Security)) {
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                    Map<QName, String> attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_wsu_Id, this.wsuId);
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_UsernameToken, attributes);
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Username, null);
                    createCharactersAndOutputAsEvent(subOutputProcessorChain, getSecurityProperties().getTokenUser());
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Username);
                    if (getSecurityProperties().getUsernameTokenPasswordType() != Constants.UsernameTokenPasswordType.PASSWORD_NONE) {
                        attributes = new HashMap<QName, String>();
                        attributes.put(Constants.ATT_NULL_Type,
                                getSecurityProperties().getUsernameTokenPasswordType() == Constants.UsernameTokenPasswordType.PASSWORD_DIGEST
                                        ? Constants.UsernameTokenPasswordType.PASSWORD_DIGEST.getNamespace()
                                        : Constants.UsernameTokenPasswordType.PASSWORD_TEXT.getNamespace());
                        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Password, attributes);
                        createCharactersAndOutputAsEvent(subOutputProcessorChain,
                                getSecurityProperties().getUsernameTokenPasswordType() == Constants.UsernameTokenPasswordType.PASSWORD_DIGEST
                                        ? Utils.doPasswordDigest(this.nonceValue, this.created.toXMLFormat(), this.password)
                                        : this.password);
                        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Password);
                    }

                    if (getSecurityProperties().getUsernameTokenPasswordType() == Constants.UsernameTokenPasswordType.PASSWORD_DIGEST
                            || Arrays.binarySearch(getSecurityProperties().getOutAction(), Constants.Action.USERNAMETOKEN_SIGNED) >= 0) {
                        attributes = new HashMap<QName, String>();
                        attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
                        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Nonce, attributes);


                        createCharactersAndOutputAsEvent(subOutputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(this.nonceValue));
                        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Nonce);
                        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsu_Created, null);

                        createCharactersAndOutputAsEvent(subOutputProcessorChain, this.created.toXMLFormat());
                        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsu_Created);
                    }
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_UsernameToken);

                    outputProcessorChain.removeProcessor(this);
                }
            }
        }
    }
}
