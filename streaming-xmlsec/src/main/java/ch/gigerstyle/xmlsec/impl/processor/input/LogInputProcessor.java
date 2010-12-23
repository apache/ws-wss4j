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

import ch.gigerstyle.xmlsec.ext.*;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.io.StringWriter;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class LogInputProcessor extends AbstractInputProcessor {

    public LogInputProcessor(SecurityProperties securityProperties) {
        super(securityProperties);
        setPhase(Constants.Phase.POSTPROCESSING);
        this.getAfterProcessors().add(SecurityHeaderInputProcessor.class.getName());
    }

    @Override
    public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        return inputProcessorChain.processHeaderEvent();
    }

    @Override
    public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        XMLEvent xmlEvent = inputProcessorChain.processEvent();
        StringWriter stringWriter = new StringWriter();
        xmlEvent.writeAsEncodedUnicode(stringWriter);
        logger.trace(stringWriter.toString());
        return xmlEvent;
    }
}
