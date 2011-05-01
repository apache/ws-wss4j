/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.impl.processor.output;

import org.apache.commons.codec.binary.Base64;
import org.swssf.ext.*;
import org.swssf.securityEvent.InitiatorSignatureTokenSecurityEvent;
import org.swssf.securityEvent.SecurityEvent;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class SignatureConfirmationOutputProcessor extends AbstractOutputProcessor {

    public SignatureConfirmationOutputProcessor(SecurityProperties securityProperties) throws WSSecurityException {
        super(securityProperties);
        getBeforeProcessors().add(SignatureOutputProcessor.class.getName());
        getBeforeProcessors().add(EncryptOutputProcessor.class.getName());
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        outputProcessorChain.processEvent(xmlEvent);

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();
            if (startElement.getName().equals(Constants.TAG_wsse_Security)) {
                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                boolean aSignatureFound = false;

                List<SecurityEvent> requestSecurityEvents = outputProcessorChain.getSecurityContext().getAsList(SecurityEvent.class);
                for (int i = 0; i < requestSecurityEvents.size(); i++) {
                    SecurityEvent securityEvent = requestSecurityEvents.get(i);
                    if (securityEvent.getSecurityEventType() == SecurityEvent.Event.InitiatorSignatureToken) {
                        aSignatureFound = true;
                        InitiatorSignatureTokenSecurityEvent initiatorSignatureTokenSecurityEvent = (InitiatorSignatureTokenSecurityEvent) securityEvent;

                        Map<QName, String> attributes = new HashMap<QName, String>();
                        attributes.put(Constants.ATT_wsu_Id, "SigConf-" + UUID.randomUUID().toString());
                        attributes.put(Constants.ATT_NULL_Value, new Base64(76, new byte[]{'\n'}).encodeToString(initiatorSignatureTokenSecurityEvent.getSignatureValue()));
                        createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse11_SignatureConfirmation, attributes);
                        createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse11_SignatureConfirmation);
                    }
                }

                if (!aSignatureFound) {
                    Map<QName, String> attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_wsu_Id, "SigConf-" + UUID.randomUUID().toString());
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse11_SignatureConfirmation, attributes);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse11_SignatureConfirmation);
                }

                outputProcessorChain.removeProcessor(this);
            }
        }
    }
}
