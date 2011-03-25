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
package org.swssf.test;

import org.swssf.config.Init;
import org.swssf.ext.WSSecurityException;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.File;
import java.net.URL;

/**
 *
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public class UncategorizedTest {

    @Test
    public void testConfigurationLoadFromUrl() throws Exception {
        URL url = this.getClass().getClassLoader().getResource("testdata/plain-soap.xml");
        try {
            Init.init(url);
            Assert.fail();
        } catch (WSSecurityException e) {
            Assert.assertEquals(e.getMessage(), "javax.xml.bind.UnmarshalException\n" +
                    " - with linked exception:\n" +
                    "[org.xml.sax.SAXParseException: cvc-elt.1: Cannot find the declaration of element 'env:Envelope'.]");
        }
    }
}
