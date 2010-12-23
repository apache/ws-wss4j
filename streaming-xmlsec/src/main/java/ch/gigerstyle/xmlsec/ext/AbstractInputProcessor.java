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
package ch.gigerstyle.xmlsec.ext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.util.HashSet;
import java.util.Set;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class AbstractInputProcessor implements InputProcessor {

    protected final transient Log logger = LogFactory.getLog(this.getClass());

    private SecurityProperties securityProperties;

    private Constants.Phase phase = Constants.Phase.PROCESSING;
    private Set<String> beforeProcessors = new HashSet<String>();
    private Set<String> afterProcessors = new HashSet<String>();

    public AbstractInputProcessor(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    public Constants.Phase getPhase() {
        return phase;
    }

    public void setPhase(Constants.Phase phase) {
        this.phase = phase;
    }

    public Set<String> getBeforeProcessors() {
        return beforeProcessors;
    }

    public Set<String> getAfterProcessors() {
        return afterProcessors;
    }

    public abstract XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException;

    public abstract XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException;

    public void doFinal(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        inputProcessorChain.doFinal();
    }

    public SecurityProperties getSecurityProperties() {
        return securityProperties;
    }
}
