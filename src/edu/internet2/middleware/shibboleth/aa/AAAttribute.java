/* 
 * The Shibboleth License, Version 1. 
 * Copyright (c) 2002 
 * University Corporation for Advanced Internet Development, Inc. 
 * All rights reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this 
 * list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution, if any, must include 
 * the following acknowledgment: "This product includes software developed by 
 * the University Corporation for Advanced Internet Development 
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement 
 * may appear in the software itself, if and wherever such third-party 
 * acknowledgments normally appear.
 * 
 * Neither the name of Shibboleth nor the names of its contributors, nor 
 * Internet2, nor the University Corporation for Advanced Internet Development, 
 * Inc., nor UCAID may be used to endorse or promote products derived from this 
 * software without specific prior written permission. For written permission, 
 * please contact shibboleth@shibboleth.org
 * 
 * Products derived from this software may not be called Shibboleth, Internet2, 
 * UCAID, or the University Corporation for Advanced Internet Development, nor 
 * may Shibboleth appear in their name, without prior written permission of the 
 * University Corporation for Advanced Internet Development.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK 
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY 
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
package edu.internet2.middleware.shibboleth.aa;


import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.opensaml.QName;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLException;
import org.opensaml.XML;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import edu.internet2.middleware.shibboleth.aa.arp.ArpAttribute;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.ValueHandler;
import edu.internet2.middleware.shibboleth.aa.attrresolv.provider.ValueHandlerException;
import edu.internet2.middleware.shibboleth.common.Constants;

/**
 * An attribute for which the Shibboleth Attribute Authority has been asked
 * to provide an assertion.
 * 
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public class AAAttribute extends SAMLAttribute implements ResolverAttribute, ArpAttribute {

	private static Logger log = Logger.getLogger(AAAttribute.class.getName());
	private boolean resolved = false;
	private static long defaultLifetime = 1800000;
	private ValueHandler valueHandler = new StringValueHandler();

	public AAAttribute(String name) throws SAMLException {
		super(
			name,
			Constants.SHIB_ATTRIBUTE_NAMESPACE_URI,
			new QName("shibNameSpace", "shibLocalName"),
			defaultLifetime,
			null);
	}

	public AAAttribute(String name, Object[] values) throws SAMLException {
		this(name);
		setValues(values);
	}

	public boolean hasValues() {
		if (values.isEmpty()) {
			return false;
		}
		return true;
	}

	public Iterator getValues() {
		return valueHandler.getValues(values);
	}

	public void setValues(Object[] values) {
		if (!this.values.isEmpty()) {
			this.values.clear();
		}
		this.values.addAll(Arrays.asList(values));
	}

	/**
	* @see java.lang.Object#hashCode()
	*/
	public int hashCode() {
		int code = 0;
		if (values != null) {
			Iterator iterator = values.iterator();
			while (iterator.hasNext()) {
				code += iterator.next().hashCode();
			}
		}
		return name.hashCode() + code;
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.ArpAttribute#resolved()
	 */
	public boolean resolved() {
		return resolved;
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.ArpAttribute#setResolved()
	 */
	public void setResolved() {
		resolved = true;
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.ArpAttribute#resolveFromCached(edu.internet2.middleware.shibboleth.aa.attrresolv.ArpAttribute)
	 */
	public void resolveFromCached(ResolverAttribute attribute) {
		resolved = true;
		setLifetime(attribute.getLifetime());

		if (!this.values.isEmpty()) {
			this.values.clear();
		}
		for (Iterator iterator = attribute.getValues(); iterator.hasNext();) {
			values.add(iterator.next());
		}

		registerValueHandler(attribute.getRegisteredValueHandler());
	}

	public void setLifetime(long lifetime) {
		this.lifetime = lifetime;

	}

	public void addValue(Object value) {
		values.add(value);
	}

	/**
	 * @see org.opensaml.SAMLObject#toDOM(org.w3c.dom.Document)
	 */
	public Node toDOM(Document doc) {

		Element attributeElement = doc.createElementNS(XML.SAML_NS, "Attribute");
		attributeElement.setAttributeNS(null, "AttributeName", name);
		attributeElement.setAttributeNS(null, "AttributeNamespace", namespace);

		for (int i = 0; i < values.size(); i++) {

			attributeElement.setAttributeNS(XML.XMLNS_NS, "xmlns:typens", type.getNamespaceURI());

			Element valueElement = doc.createElementNS(XML.SAML_NS, "AttributeValue");
			valueElement.setAttributeNS(XML.XSI_NS, "xsi:type", "typens:" + type.getLocalName());

			try {
				valueHandler.toDOM(valueElement, values.get(i), doc);
				attributeElement.appendChild(valueElement);

			} catch (ValueHandlerException e) {
				log.error("Value Handler unable to convert value to DOM Node: " + e);
			}
		}
		return attributeElement;
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.ArpAttribute#registerValueHandler(edu.internet2.middleware.shibboleth.aa.attrresolv.provider.ValueHandler)
	 */
	public void registerValueHandler(ValueHandler handler) {
		valueHandler = handler;
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.ArpAttribute#getRegisteredValueHandler()
	 */
	public ValueHandler getRegisteredValueHandler() {
		return valueHandler;
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	public boolean equals(Object object) {

		if (!(object instanceof AAAttribute)) {
			return false;
		}
		if (lifetime != ((AAAttribute) object).lifetime) {
			return false;
		}
		if (name != ((AAAttribute) object).name) {
			return false;
		}
		if (!valueHandler.getClass().getName().equals(((AAAttribute) object).valueHandler.getClass().getName())) {
			return false;
		}
		return values.equals(((AAAttribute) object).values);
	}

}

/**
 *  Default <code>ValueHandler</code> implementation.  Expects all values to be String objects.
 *
 * @author Walter Hoehn (wassa@columbia.edu)
 */
class StringValueHandler implements ValueHandler {

	public void toDOM(Element valueElement, Object value, Document document) {
		valueElement.appendChild(document.createTextNode(value.toString()));
	}

	public Iterator getValues(Collection internalValues) {
		return internalValues.iterator();
	}

}

