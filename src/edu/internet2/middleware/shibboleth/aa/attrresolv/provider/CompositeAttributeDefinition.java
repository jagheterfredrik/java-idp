/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution, if any, must include the following acknowledgment: "This product includes software
 * developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu>Internet2 Project.
 * Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor
 * the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please contact
 * shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the
 * University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name, without prior
 * written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS PROVIDED BY THE
 * COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE
 * DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO
 * EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC.
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Contributed by SunGard SCT.
 */

package edu.internet2.middleware.shibboleth.aa.attrresolv.provider;

import java.security.Principal;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.StringTokenizer;

import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute;

/**
 * The CompositeAttributeDefinition allows composing a single attribute from multiple attributes. It is particularly
 * useful when values from several columns of a DataBase must be 'concatenated' to form a single composite attribute. To
 * ensure that the results are same for a given set of source values, multi-valued source attributes must be ordered and
 * each must have the same number of values. This is true for the attribute values read using the JDBCDataConnector, but
 * not true with attributes read using the JNDIDirectoryDataConnector or the LDAPDirectoryDataConnector. Hence,
 * CompositeAttributeDefinition is only currently meaningful for attributes read from an RDB using the
 * JDBCDataConnector. The specification of this attribute definition is simple. You specify which source attributes to
 * compose and the format for composing them using the notation of java.text.MessageFormat. The format defaults to a
 * space separated concatenation of all source attributes. One use case is in the construction of a labeledURI attribute
 * from two attributes, the 'URL' and the 'URL_Title' that may appear as two columns in a DataBase. As per the
 * definition of labeledURI, it is essentially a 'space' separated concatenation of URL followed by the title. Since URL
 * itself should not contain any spaces (assuming it is properly encoded, converting spaces to +), where the URL ends
 * and the title begins is unambiguous. The specification fpr such a composite attribute is simply: format="{0} {1}"
 * orderedSourceNames="URL, URL_Title" The format definition in the above example is optional, since that is infact the
 * default if not specified. Another example of usage of this attribute is as follows: format="{0} ({1})"
 * orderedSourceNames="Group_Name, Group_Title" Notice that in this example, we are composing the name of a Group and
 * the descriptive title of the group in parenthesis using the format to create a single attribute from two attributes.
 * 
 * @author <a href="mailto:vgoenka@sungardsct.com">Vishal Goenka </a>
 */

public class CompositeAttributeDefinition extends SimpleBaseAttributeDefinition implements AttributeDefinitionPlugIn {

	private static Logger log = Logger.getLogger(CompositeAttributeDefinition.class.getName());

	// The formatter used to compose from all Source Attributes
	private MessageFormat sourceFormat;

	// Names of source attributes to compose the target from, in ordered list
	private String[] sourceNames;

	// Names of source attributes in a Set for convenience of checking membership
	private Set sourceNamesSet;

	// Number of values that each source attribute has (must be same for all attributes)
	private int valueCount = -1;

	public CompositeAttributeDefinition(Element e) throws ResolutionPlugInException {

		super(e);

		try {
			// Since there are more than one source objects in an ordered list, one sourceName doesn't make sense. In
			// this
			// respect, it differs from other attribute definition
			if (e.hasAttribute("sourceName"))
				throw new ResolutionPlugInException(
						"sourceName is not an allowed attribute for CompositeAttributeDefinition (" + getId() + ")");

			String orderedSourceNames = e.getAttribute("orderedSourceNames");
			if ((orderedSourceNames == null) || ("".equals(orderedSourceNames)))
				throw new ResolutionPlugInException(
						"orderedSourceNames is a required attribute for CompositeAttributeDefinition (" + getId() + ")");

			// We assume space or comma as separators
			StringTokenizer st = new StringTokenizer(orderedSourceNames, " ,");
			ArrayList sourceNamesList = new ArrayList();
			while (st.hasMoreTokens()) {
				String token = st.nextToken().trim();
				if (token.length() > 0) sourceNamesList.add(token);
			}
			sourceNamesSet = new HashSet();
			sourceNamesSet.addAll(sourceNamesList);
			sourceNames = (String[]) sourceNamesList.toArray(new String[0]);

			String format = e.getAttribute("format");
			// default format is essentially all ordered attribute values separated by a space
			if ((format == null) || ("".equals(format))) {
				StringBuffer defaultFormat = new StringBuffer();
				for (int i = 0; i < sourceNames.length; i++) {
					defaultFormat.append("{").append(i).append("}");
					if (i < sourceNames.length - 1) defaultFormat.append(" ");
				}
				format = defaultFormat.toString();
			}
			sourceFormat = new MessageFormat(format);
		} catch (ResolutionPlugInException ex) {
			// To ensure that exceptions thrown in the constructor are logged!
			log.error(ex.getMessage());
			throw ex;
		} catch (RuntimeException ex) {
			// To ensure that exceptions thrown in the constructor are logged!
			log.error(ex.getMessage());
			throw ex;
		}
	}

	/**
	 * Get ordered attribute values for all source attributes from the dependent data connectors. The values of all
	 * multi-valued attribute MUST be ordered and MUST be of same size or else the results can be unpredictable.
	 */
	private void addAttributesFromConnectors(Dependencies depends, Attributes sourceAttrs)
			throws ResolutionPlugInException {

		Iterator connectorDependIt = connectorDependencyIds.iterator();
		while (connectorDependIt.hasNext()) {
			Attributes attrs = depends.getConnectorResolution((String) connectorDependIt.next());
			if (attrs != null) {
				for (int i = 0; i < sourceNames.length; i++) {
					Attribute attr = attrs.get(sourceNames[i]);
					if (attr != null) {
						int size = attr.size();
						if (!attr.isOrdered() && (size > 1)) { throw new ResolutionPlugInException(
								"Multi-valued attribute (" + attr.getID()
										+ ") MUST be ordered for CompositeAttributeDefinition (" + getId() + ")"); }
						if (valueCount == -1) {
							valueCount = size; // initialize valueCount
						} else if (valueCount != size) { throw new ResolutionPlugInException("Multi-valued attribute ("
								+ attr.getID() + ") has different number of values (" + size
								+ ") than other attribute(s) that have (" + valueCount + ") values. "
								+ "All attributes must have same number of values for CompositeAttributeDefinition ("
								+ getId() + ")"); }
						if (sourceAttrs.put(attr) != null) { throw new ResolutionPlugInException("Attribute ("
								+ attr.getID() + ") occured more than once in the dependency chain for (" + getId()
								+ ") and I don't know which one to pick"); }
					}
				}
			}
		}
	}

	/**
	 * Get ordered attribute values for all source attributes from the dependent attributes. The values of all
	 * multi-valued attribute MUST be ordered and MUST be of same size or else the results can be unpredictable.
	 */
	private void addAttributesFromAttributeDependencies(Dependencies depends, Attributes sourceAttrs)
			throws ResolutionPlugInException {

		Iterator attrDependIt = attributeDependencyIds.iterator();
		while (attrDependIt.hasNext()) {
			ResolverAttribute attribute = depends.getAttributeResolution((String) attrDependIt.next());
			if (attribute != null) {
				if (sourceNamesSet.contains(attribute.getName())) {
					BasicAttribute attr = new BasicAttribute(attribute.getName(), true);
					int size = 0;
					for (Iterator iterator = attribute.getValues(); iterator.hasNext();) {
						attr.add(size++, iterator.next());
					}
					if (valueCount == -1) {
						valueCount = size; // initialize valueCount
					} else if (valueCount != size) { throw new ResolutionPlugInException("Multi-valued attribute ("
							+ attr.getID() + ") has different number of values (" + size
							+ ") than other attribute(s) that have (" + valueCount + ") values. "
							+ "All attributes must have same number of values for CompositeAttributeDefinition ("
							+ getId() + ")"); }
					if (sourceAttrs.put(attr) != null) { throw new ResolutionPlugInException("Attribute ("
							+ attr.getID() + ") occured more than once in the dependency chain for (" + getId()
							+ ") and I don't know which one to pick"); }
				} else {
					log
							.warn("Attribute Dependency ("
									+ attribute.getName()
									+ ") is not listed in the orderedSourceNames attribute for the CustomAttributeDefinition for ("
									+ getId() + ")");
				}
			}
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn#resolve(
	 *      edu.internet2.middleware.shibboleth.aa.attrresolv.ArpAttribute, java.security.Principal, java.lang.String,
	 *      edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies)
	 */
	public void resolve(ResolverAttribute attribute, Principal principal, String requester, Dependencies depends)
			throws ResolutionPlugInException {

		// Collect attribute values from dependencies
		BasicAttributes attributes = new BasicAttributes();
		addAttributesFromConnectors(depends, attributes);
		addAttributesFromAttributeDependencies(depends, attributes);

		// If we got this far, all attributes are ordered and have 'valueCount' number of values
		for (int i = 0; i < valueCount; i++) {
			// put values in an array so we can use the formatter for creating the composite value
			Object[] values = new Object[sourceNames.length];
			try {
				for (int j = 0; j < sourceNames.length; j++) {
					Attribute attr = attributes.get(sourceNames[j]);
					if (attr == null)
						throw new ResolutionPlugInException("No value found for attribute (" + sourceNames[j]
								+ ") during resolution of (" + getId() + ")");
					// get the ordered (i'th) value of the attribute
					values[j] = attr.get(i);
				}
				attribute.addValue(sourceFormat.format(values));
			} catch (ResolutionPlugInException e) {
				// Simply rethrow ...
				throw e;
			} catch (Exception e) {
				StringBuffer err = new StringBuffer();
				err.append("Error creating composite attribute [");
				if (values != null) {
					for (int ii = 0; ii < values.length; ii++) {
						if (values[ii] != null) err.append(values[ii].toString()).append(", ");
						else err.append("null ");
					}
				} else err.append(" null ");
				err.append("] using format ").append(sourceFormat.toPattern()).append(" for (").append(getId()).append(
						"): ").append(e.getMessage());
				log.error(err.toString());
				throw new ResolutionPlugInException(err.toString());
			}
		}
		if (lifeTime != -1) {
			attribute.setLifetime(lifeTime);
		}

		if (valueHandler != null) {
			attribute.registerValueHandler(valueHandler);
		}
		attribute.setResolved();
	}

}
