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

import org.swssf.ext.*;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

/**
 * Processor to build the Security Header structure
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class SecurityHeaderOutputProcessor extends AbstractOutputProcessor {

    public SecurityHeaderOutputProcessor(SecurityProperties securityProperties) throws WSSecurityException {
        super(securityProperties);
        setPhase(Constants.Phase.PREPROCESSING);
    }

    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {

        boolean eventHandled = false;
        int level = outputProcessorChain.getDocumentContext().getDocumentLevel();

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            String soapMessageVersion = outputProcessorChain.getDocumentContext().getSOAPMessageVersionNamespace();
            if (level == 1 && soapMessageVersion == null) {
                throw new WSSecurityException("Root Element must be " + Constants.TAG_soap11_Envelope +
                        " or " + Constants.TAG_soap12_Envelope + " but was " + startElement.getName());
            } else if (level == 2
                    && startElement.getName().getLocalPart().equals(Constants.TAG_soap_Header_LocalName)
                    && startElement.getName().getNamespaceURI().equals(soapMessageVersion)) {
                //output current soap-header event
                outputProcessorChain.processEvent(xmlEvent);

                //create subchain and output securityHeader
                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Security, null);
                createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Security);

                //remove this processor. its no longer needed.
                outputProcessorChain.removeProcessor(this);

                eventHandled = true;
            } else if (level == 2
                    && startElement.getName().getLocalPart().equals(Constants.TAG_soap_Body_LocalName)
                    && startElement.getName().getNamespaceURI().equals(soapMessageVersion)) {
                //hmm it seems we don't have a soap header in the current document
                //so output one and add securityHeader

                //create subchain and output soap-header and securityHeader
                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                createStartElementAndOutputAsEvent(subOutputProcessorChain,
                        new QName(soapMessageVersion, Constants.TAG_soap_Header_LocalName, Constants.PREFIX_SOAPENV), null);
                createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Security, null);
                createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsse_Security);
                createEndElementAndOutputAsEvent(subOutputProcessorChain,
                        new QName(soapMessageVersion, Constants.TAG_soap_Header_LocalName, Constants.PREFIX_SOAPENV));

                //output current soap-header event
                outputProcessorChain.processEvent(xmlEvent);

                //remove this processor. its no longer needed.
                outputProcessorChain.removeProcessor(this);

                eventHandled = true;
            }
        }

        if (!eventHandled) {
            outputProcessorChain.processEvent(xmlEvent);
        }
    }
}
