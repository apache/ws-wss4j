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
package org.swssf.impl.transformer.canonicalizer;

import org.swssf.ext.ComparableAttribute;
import org.swssf.ext.ComparableNamespace;
import org.swssf.ext.XMLEventNS;

import javax.xml.stream.events.StartElement;
import java.util.List;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class Canonicalizer20010315_OmitCommentsTransformer extends CanonicalizerBase {

    public Canonicalizer20010315_OmitCommentsTransformer(String inclusiveNamespaces) {
        super(inclusiveNamespaces, false);
    }

    @Override
    @SuppressWarnings("unchecked")
    protected List<ComparableNamespace>[] getInitialNamespaces(XMLEventNS xmlEventNS) {
        return xmlEventNS.getNamespaceList();
    }

    @Override
    @SuppressWarnings("unchecked")
    protected List<ComparableAttribute>[] getInitialAttributes(XMLEventNS xmlEventNS) {
        return xmlEventNS.getAttributeList();
    }

    @Override
    protected boolean namespaceIsVisibleUtilized(StartElement startElement, ComparableNamespace comparableNamespace) {
        return true;
    }
}
