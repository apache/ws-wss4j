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
package ch.gigerstyle.xmlsec.impl.processor.input;

import ch.gigerstyle.xmlsec.crypto.Crypto;
import ch.gigerstyle.xmlsec.ext.*;
import ch.gigerstyle.xmlsec.impl.SecurityTokenFactory;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.BinarySecurityTokenType;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

/**
 * Prozessor for the BinarySecurityToken XML Structure
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class BinarySecurityTokenInputProcessor extends AbstractInputProcessor implements SecurityTokenProvider {

    private BinarySecurityTokenType currentBinarySecurityTokenType;

    public BinarySecurityTokenInputProcessor(SecurityProperties securityProperties, StartElement startElement) {
        super(securityProperties);
        currentBinarySecurityTokenType = new BinarySecurityTokenType(startElement);
    }

    @Override
    public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        XMLEvent xmlEvent = inputProcessorChain.processHeaderEvent();

        //parse the BinarySecurityToken XML Structure
        //this is ugly and will be replaced with a better implementation
        boolean isFinishedcurrentBinarySecurityToken = false;

        if (currentBinarySecurityTokenType != null) {
            try {
                isFinishedcurrentBinarySecurityToken = currentBinarySecurityTokenType.parseXMLEvent(xmlEvent);
                if (isFinishedcurrentBinarySecurityToken) {
                    currentBinarySecurityTokenType.validate();
                }
            } catch (ParseException e) {
                throw new XMLSecurityException(e);
            }
        }

        //register the SecurityToken when finished parsing
        if (currentBinarySecurityTokenType != null && isFinishedcurrentBinarySecurityToken) {
            try {
                if (currentBinarySecurityTokenType.getId() != null) {
                    inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(currentBinarySecurityTokenType.getId(), this);
                }
            } finally {
                inputProcessorChain.removeProcessor(this);
            }
        }

        return xmlEvent;
    }

    @Override
    public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        //this method should not be called (processor will be removed after processing header
        return null;
    }

    public SecurityToken getSecurityToken(Crypto crypto) throws XMLSecurityException {
        return SecurityTokenFactory.newInstance().getSecurityToken(currentBinarySecurityTokenType, crypto, getSecurityProperties().getCallbackHandler());
    }
}
