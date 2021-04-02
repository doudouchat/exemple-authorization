package com.exemple.authorization.integration.common;

import java.io.Serializable;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;

import javax.naming.Context;
import javax.naming.Name;
import javax.naming.RefAddr;
import javax.naming.Reference;
import javax.naming.spi.ObjectFactory;

/*
 * Ce code est récupéré depuis la dépendance 
 * <dependency>
 * <groupId>org.glassfish.main.resources</groupId>
 * <artifactId>resources-connector</artifactId>
 * <version>4.0</version>
 * </dependency>
 * Pour permettre à Cargo d'interpréter les valeurs primitives dans les resources du context
 */
public class PrimitivesAndStringFactory implements Serializable, ObjectFactory {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws Exception {
        Reference ref = (Reference) obj;

        Enumeration<RefAddr> refAddrs = ref.getAll();
        String type = null;
        String value = null;
        while (refAddrs.hasMoreElements()) {
            RefAddr addr = refAddrs.nextElement();
            String propName = addr.getType();

            type = ref.getClassName();

            if ("value".equalsIgnoreCase(propName)) {
                value = (String) addr.getContent();
            }
        }

        if (type != null && value != null) {
            type = type.toUpperCase(Locale.getDefault());
            if (type.endsWith("INT") || type.endsWith("INTEGER")) {
                return Integer.valueOf(value);
            } else if (type.endsWith("LONG")) {
                return Long.valueOf(value);
            } else if (type.endsWith("DOUBLE")) {
                return Double.valueOf(value);
            } else if (type.endsWith("FLOAT")) {
                return Float.valueOf(value);
            } else if (type.endsWith("CHAR") || type.endsWith("CHARACTER")) {
                return value.charAt(0);
            } else if (type.endsWith("SHORT")) {
                return Short.valueOf(value);
            } else if (type.endsWith("BYTE")) {
                return Byte.valueOf(value);
            } else if (type.endsWith("BOOLEAN")) {
                return Boolean.valueOf(value);
            } else if (type.endsWith("STRING")) {
                return value;
            } else {
                throw new IllegalArgumentException("unknown type [" + type + "] ");
            }
        } else if (type == null) {
            throw new IllegalArgumentException("type cannot be null");
        } else {
            throw new IllegalAccessException("value cannot be null");
        }
    }
}
