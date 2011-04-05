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

import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.Deque;

/**
 * Processor for the SignatureConfirmation XML Structure
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class SignatureConfirmationInputHandler extends AbstractInputSecurityHeaderHandler {

    public SignatureConfirmationInputHandler(InputProcessorChain inputProcessorChain, final SecurityProperties securityProperties, Deque<XMLEvent> eventQueue, Integer index) throws WSSecurityException {

        final SignatureConfirmationType signatureConfirmationType = (SignatureConfirmationType) parseStructure(eventQueue, index);
        inputProcessorChain.getSecurityContext().putAsList(SignatureConfirmationType.class, signatureConfirmationType);
    }

    @Override
    protected Parseable getParseable(StartElement startElement) {
        return new SignatureConfirmationType(startElement);
    }
}
