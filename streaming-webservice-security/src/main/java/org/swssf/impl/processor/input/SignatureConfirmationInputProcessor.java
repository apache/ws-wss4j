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
package org.swssf.impl.processor.input;

import org.oasis_open.docs.wss.oasis_wss_wssecurity_secext_1_1.SignatureConfirmationType;
import org.swssf.ext.*;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.securityEvent.SignatureValueSecurityEvent;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.XMLEvent;
import java.util.Arrays;
import java.util.List;

/**
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public class SignatureConfirmationInputProcessor extends AbstractInputProcessor {

    public SignatureConfirmationInputProcessor(SecurityProperties securityProperties) {
        super(securityProperties);
    }

    @Override
    public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
        XMLEvent xmlEvent = inputProcessorChain.processHeaderEvent();
        if (xmlEvent.isEndElement()) {
            EndElement endElement = xmlEvent.asEndElement();
            if (endElement.getName().equals(Constants.TAG_wsse_Security)) {
                inputProcessorChain.removeProcessor(this);

                List<SignatureValueSecurityEvent> signatureValueSecurityEventList = inputProcessorChain.getSecurityContext().getAsList(SecurityEvent.class);
                List<SignatureConfirmationType> signatureConfirmationTypeList = inputProcessorChain.getSecurityContext().getAsList(SignatureConfirmationType.class);

                //when no signature was sent, we expect an empty SignatureConfirmation in the response
                if (signatureValueSecurityEventList == null || signatureValueSecurityEventList.size() == 0) {
                    if (signatureConfirmationTypeList == null || signatureConfirmationTypeList.size() != 1) {
                        throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
                    } else if (signatureConfirmationTypeList.get(0).getValue() != null) {
                        throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
                    }
                }

                if (signatureConfirmationTypeList == null) {
                    throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
                }

                for (int i = 0; i < signatureValueSecurityEventList.size(); i++) {
                    SignatureValueSecurityEvent signatureValueSecurityEvent = signatureValueSecurityEventList.get(i);
                    byte[] signatureValue = signatureValueSecurityEvent.getSignatureValue();

                    boolean found = false;

                    for (int j = 0; j < signatureConfirmationTypeList.size(); j++) {
                        SignatureConfirmationType signatureConfirmationType = signatureConfirmationTypeList.get(j);
                        byte[] sigConfValue = signatureConfirmationType.getValue();
                        if (Arrays.equals(signatureValue, sigConfValue)) {
                            found = true;
                        }
                    }

                    if (!found) {
                        throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
                    }
                }
            }
        }
        return xmlEvent;
    }

    @Override
    public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
        //should never be called
        return null;
    }
}
