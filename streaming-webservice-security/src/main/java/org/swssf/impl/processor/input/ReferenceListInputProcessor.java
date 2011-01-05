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

import org.swssf.ext.*;
import org.w3._2001._04.xmlenc_.ReferenceList;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

/**
 * Prozessor for the ReferenceList XML Structure 
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class ReferenceListInputProcessor extends AbstractInputProcessor {

    private ReferenceList currentReferenceList;

    public ReferenceListInputProcessor(SecurityProperties securityProperties, StartElement startElement) {
        super(securityProperties);
        currentReferenceList = new ReferenceList(startElement);
    }

    @Override
    public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
        XMLEvent xmlEvent = inputProcessorChain.processHeaderEvent();

        //parse the ReferenceList XML Structure
        //this is ugly and will be replaced with a better implementation
        boolean isFinishedcurrentReferenceList = false;

        if (currentReferenceList != null) {
            try {
                isFinishedcurrentReferenceList = currentReferenceList.parseXMLEvent(xmlEvent);
                if (isFinishedcurrentReferenceList) {
                    currentReferenceList.validate();
                }
            } catch (ParseException e) {
                throw new WSSecurityException(e);
            }
        }

        if (currentReferenceList != null && isFinishedcurrentReferenceList) {
            try {
                //instantiate a new DecryptInputProcessor and add it to the chain
                inputProcessorChain.addProcessor(new DecryptInputProcessor(currentReferenceList, getSecurityProperties()));
            } finally {
                inputProcessorChain.removeProcessor(this);
                currentReferenceList = null;
                isFinishedcurrentReferenceList = false;
            }
        }
        return xmlEvent;
    }

    @Override
    public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
        //this method should not be called (processor will be removed after processing header
        return null;
    }
}
