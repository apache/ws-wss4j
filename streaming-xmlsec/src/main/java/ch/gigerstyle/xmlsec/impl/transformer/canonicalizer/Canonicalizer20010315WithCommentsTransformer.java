package ch.gigerstyle.xmlsec.impl.transformer.canonicalizer;

/**
 * User: giger
 * Date: May 14, 2010
 * Time: 3:47:06 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class Canonicalizer20010315WithCommentsTransformer extends Canonicalizer20010315Transformer {

    public Canonicalizer20010315WithCommentsTransformer(String inclusiveNamespaces) {
        super(inclusiveNamespaces, true, false);
    }
}