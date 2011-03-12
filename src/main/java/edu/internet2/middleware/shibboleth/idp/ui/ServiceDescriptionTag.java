/*
 * Copyright 2011 University Corporation for Advanced Internet Development, Inc.
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

package edu.internet2.middleware.shibboleth.idp.ui;

import java.io.IOException;
import java.util.List;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.JspWriter;
import javax.servlet.jsp.tagext.BodyContent;

import org.opensaml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml2.metadata.LocalizedString;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.ServiceDescription;
import org.opensaml.samlext.saml2mdui.Description;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Display the description from the &lt;mdui:UIInfo&gt;.
 * 
 */
public class ServiceDescriptionTag extends ServiceTagSupport {
    
    /** required by checkstyle. */
    private static final long serialVersionUID = -2000941439055969537L;
    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(ServiceDescriptionTag.class);

    /** 
     * look at &lt;Uiinfo&gt; if there and if so look for appropriate description.
     * @return null or an appropriate description
     */
    private String getDescriptionFromUIInfo() {
        String lang = getBrowserLanguage();

        if (getSPUIInfo() != null && getSPUIInfo().getDescriptions() != null) {
            for (Description desc:getSPUIInfo().getDescriptions()) {
                if (log.isDebugEnabled()){
                    log.debug("Found description in UIInfo, language=" + desc.getXMLLang());
                }
                if (desc.getXMLLang().equals(lang)) {
                    //
                    // Found it
                    //
                    if (log.isDebugEnabled()){
                        log.debug("returning description from UIInfo " + desc.getName().getLocalString());
                    }
                    return desc.getName().getLocalString();
                }
            }
            if (log.isDebugEnabled()){
                log.debug("No valid description in UIInfo");
            }            
        }
        return null;
    }
    
    /**
     * look for an &ltAttributeConsumeService&gt and if its there look for an appropriate description.
     * @return null or an appropriate description
     */
    private String getDescriptionFromAttributeConsumingService() {
        String lang = getBrowserLanguage();
        List<RoleDescriptor> roles;
        AttributeConsumingService acs = null;

        roles = getSPEntityDescriptor().getRoleDescriptors(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        if (!roles.isEmpty()) {
            SPSSODescriptor spssod = (SPSSODescriptor) roles.get(0);
            acs = spssod.getDefaultAttributeConsumingService();
        }
        if (acs != null) {
            for (ServiceDescription desc:acs.getDescriptions()) {
                LocalizedString localDescription = desc.getDescription();
                if (log.isDebugEnabled()){
                    log.debug("Found name in AttributeConsumingService, language=" + localDescription.getLanguage());
                }
                if (localDescription.getLanguage().equals(lang)) {
                    if (log.isDebugEnabled()){
                        log.debug("returning name from AttributeConsumingService " + 
                                desc.getDescription().getLocalString());
                    }
                    return localDescription.getLocalString();
                }
            }
            if (log.isDebugEnabled()){
                log.debug("No description in AttributeConsumingService");
            }            
        }        
        return null;
    }

    @Override
    public int doEndTag() throws JspException {
       
        String result;
        //
        // UIInfoirst
        //
        result = getDescriptionFromUIInfo();
        
        if (result == null) {
            //
            // Then AttributeCOnsumingService
            //
            result = getDescriptionFromAttributeConsumingService();
        }

        try {
            if (null == result) {
                BodyContent bc = getBodyContent();
                if (null != bc) {
                    JspWriter ew= bc.getEnclosingWriter();
                    if (ew != null) {
                        bc.writeOut(ew);
                    }
                }
            } else {
                pageContext.getOut().print(result);
            }
        } catch (IOException e) {
            log.warn("Error generating Description");
            throw new JspException("EndTag", e);
        }
        return super.doEndTag();
    }
}
