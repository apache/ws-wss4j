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
package ch.gigerstyle.xmlsec.test.utils;

import org.apache.cxf.staxutils.AbstractDOMStreamReader;
import org.apache.cxf.staxutils.W3CDOMStreamReader;
import org.w3c.dom.Document;

import javax.xml.stream.XMLInputFactory;
import java.lang.reflect.Field;
import java.util.Map;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class CustomW3CDOMStreamReader extends W3CDOMStreamReader {

    public CustomW3CDOMStreamReader(Document doc) {
        super(doc);
        try {
            Field field = AbstractDOMStreamReader.class.getDeclaredField("properties");
            field.setAccessible(true);
            Map properties = (Map) field.get(this);
            properties.put(XMLInputFactory.IS_NAMESPACE_AWARE, true);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
