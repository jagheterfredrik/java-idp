/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.idp.config.profile;

import javax.xml.namespace.QName;

import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.idp.profile.saml2.AuthenticationRequestBrowserPost;

/**
 * Spring bean definition parser for {@link AuthenticationRequestBrowserPost} profile handlers.
 */
public class SAML2SSOProfileHandlerBeanDefinitionParser extends AbstractSAML2ProfileHandlerBeanDefinitionParser {

    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(IdPProfileHandlerNamespaceHandler.NAMESPACE, "SAML2SSO");

    /** {@inheritDoc} */
    protected Class getBeanClass(Element arg0) {
        return AuthenticationRequestBrowserPost.class;
    }

    /** {@inheritDoc} */
    protected void doParse(Element config, BeanDefinitionBuilder builder) {
        super.doParse(config, builder);

        builder.addPropertyReference("authenticationManager", config.getAttributeNS(null, "authenticationManagerId"));
    }
}