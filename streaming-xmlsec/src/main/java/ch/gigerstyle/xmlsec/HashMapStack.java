package ch.gigerstyle.xmlsec;

import java.util.*;

/**
 * User: giger
 * Date: Apr 21, 2010
 * Time: 7:04:27 PM
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
public class HashMapStack {

    List<Map> level = new ArrayList<Map>();
    int curLevel = -1;

    public void push() {
        if (curLevel < 0) {
            level.add(new TreeMap());
        } else {
            level.add(new TreeMap(level.get(curLevel)));
        }
        curLevel++;
    }

    public void pop() {
        level.remove(curLevel);
        curLevel--;
    }

    public void put(Object key, Object value) {
        level.get(curLevel).put(key, value);
    }

    public Object get(Object key) {
        return level.get(curLevel).get(key);
    }
}