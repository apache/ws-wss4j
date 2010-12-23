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
package ch.gigerstyle.xmlsec.impl.processor.output;

import ch.gigerstyle.xmlsec.ext.*;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.Calendar;
import java.util.GregorianCalendar;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class TimestampOutputProcessor extends AbstractOutputProcessor {

    public TimestampOutputProcessor(SecurityProperties securityProperties) throws XMLSecurityException {
        super(securityProperties);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        outputProcessorChain.processEvent(xmlEvent);

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();
            if (startElement.getName().equals(Constants.TAG_wsse_Security)) {
                try {
                    DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
                    XMLGregorianCalendar created = datatypeFactory.newXMLGregorianCalendar(new GregorianCalendar());

                    GregorianCalendar expiresCalendar = new GregorianCalendar();
                    expiresCalendar.add(Calendar.SECOND, getSecurityProperties().getTimestampTTL());
                    XMLGregorianCalendar expires = datatypeFactory.newXMLGregorianCalendar(expiresCalendar);

                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                    //wsu:id will be added when signing...todo must there always be a wsu:id?
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsu_Timestamp, null);
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsu_Created, null);
                    createCharactersAndOutputAsEvent(subOutputProcessorChain, created.toXMLFormat());
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsu_Created);
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsu_Expires, null);
                    createCharactersAndOutputAsEvent(subOutputProcessorChain, expires.toXMLFormat());
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsu_Expires);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_wsu_Timestamp);
                } catch (DatatypeConfigurationException e) {
                    throw new XMLSecurityException(e);
                }

                outputProcessorChain.removeProcessor(this);

                /*
                <wsu:Timestamp wsu:Id="Timestamp-1247751600"
                    xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                        <wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                            2009-08-31T05:37:57.391Z
                        </wsu:Created>
                        <wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                            2009-08-31T05:52:57.391Z
                        </wsu:Expires>
                    </wsu:Timestamp>
                 */
            }
        }
    }
}
