/*
 * Copyright 2009 University Corporation for Advanced Internet Development, Inc.
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

package edu.internet2.middleware.shibboleth.idp;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.joda.time.chrono.ISOChronology;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.opensaml.xml.util.DatatypeHelper;

import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolver;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfigurationManager;

/** A servlet for displaying the status of the IdP. */
public class StatusServlet extends HttpServlet {

    /** Formatter used when print date/times. */
    private DateTimeFormatter dateFormat;

    /** Time the IdP started up. */
    private DateTime startTime;

    /** Attribute resolver used by the IdP. */
    private AttributeResolver<?> attributeResolver;

    /** Relying party configuration manager used by the IdP. */
    private RelyingPartyConfigurationManager rpConfigManager;

    /** {@inheritDoc} */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        dateFormat = ISODateTimeFormat.dateTimeNoMillis();

        startTime = new DateTime(ISOChronology.getInstanceUTC());

        String attributeResolverId = config.getInitParameter("attributeResolverId");
        if (DatatypeHelper.isEmpty(attributeResolverId)) {
            attributeResolverId = "shibboleth.AttributeResolver";
        }
        attributeResolver = (AttributeResolver<?>) getServletContext().getAttribute(attributeResolverId);

        String rpConfigManagerId = config.getInitParameter("rpConfigManagerId");
        if (DatatypeHelper.isEmpty(rpConfigManagerId)) {
            rpConfigManagerId = "shibboleth.RelyingPartyConfigurationManager";
        }
        rpConfigManager = (RelyingPartyConfigurationManager) getServletContext().getAttribute(rpConfigManagerId);
    }

    /** {@inheritDoc} */
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        PrintWriter output = resp.getWriter();

        printOperatingEnvironmentInformation(output);
        output.println();
        printIdPInformation(output);
        output.println();
        printRelyingPartyConfigurationsInformation(output, req.getParameter("relyingParty"));

        output.flush();
    }

    /**
     * Prints out information about the operating environment. This includes the operating system name, version and
     * architecture, the JDK version, available CPU cores, memory currently used by the JVM process, the maximum amount
     * of memory that may be used by the JVM, and the current time in UTC.
     * 
     * @param out output writer to which information will be written
     */
    protected void printOperatingEnvironmentInformation(PrintWriter out) {
        Runtime runtime = Runtime.getRuntime();

        out.println("### Operating Environment Information");
        out.println("operating_system: " + System.getProperty("os.name"));
        out.println("operating_system_version: " + System.getProperty("os.version"));
        out.println("operating_system_architecture: " + System.getProperty("os.arch"));
        out.println("jdk_version: " + System.getProperty("java.version"));
        out.println("available_cores: " + runtime.availableProcessors());
        out.println("used_memory: " + runtime.totalMemory() / 1048576 + "MB");
        out.println("maximum_memory: " + runtime.maxMemory() / 1048576 + "MB");
        out.println("current_time: " + new DateTime(ISOChronology.getInstanceUTC()).toString(dateFormat));
    }

    /**
     * Prints out general IdP information. This includes IdP version, start up time, and whether the attribute resolver
     * is currently operational.
     * 
     * @param out output writer to which information will be written
     */
    protected void printIdPInformation(PrintWriter out) {
        Package pkg = Version.class.getPackage();

        out.println("### Identity Provider Information");
        out.println("idp_version: " + pkg.getImplementationVersion());
        out.println("idp_start_time: " + startTime.toString(dateFormat));
        try {
            attributeResolver.validate();
            out.println("attribute_resolver_valid: " + Boolean.TRUE);
        } catch (AttributeResolutionException e) {
            out.println("attribute_resolver_valid: " + Boolean.FALSE);
        }
    }

    /**
     * Prints information about relying party configurations. If the given relying party is null then the configuration
     * for all relying parties is printed. If the relying party ID is not null then the relying party configurations for
     * that entity is printed.
     * 
     * @param out output writer to which information will be written
     * @param relyingPartyId entity ID of the relying party whose configuration should be printed
     */
    protected void printRelyingPartyConfigurationsInformation(PrintWriter out, String relyingPartyId) {
        out.println("### Relying Party Configurations");

        if (relyingPartyId == null) {
            for (RelyingPartyConfiguration config : rpConfigManager.getRelyingPartyConfigurations().values()) {
                printRelyingPartyConfigurationInformation(out, config);
                out.println();
            }
        } else {
            RelyingPartyConfiguration config = rpConfigManager.getRelyingPartyConfiguration(relyingPartyId);
            printRelyingPartyConfigurationInformation(out, config);
            out.println();
        }
    }

    /**
     * Prints out the information for a specific relying party configuration. This information includes the relying
     * party or relying party group ID, the entity ID of the IdP when it responds when using this configuration, the
     * default authentication method used for this config, and configured communication profiles.
     * 
     * @param out output writer to which information will be written
     * @param config the relying party configuration
     */
    protected void printRelyingPartyConfigurationInformation(PrintWriter out, RelyingPartyConfiguration config) {
        out.println("relying_party_id: " + config.getRelyingPartyId());
        out.println("idp_entity_id: " + config.getProviderId());

        if (config.getDefaultAuthenticationMethod() != null) {
            out.println("default_authentication_method: " + config.getDefaultAuthenticationMethod());
        } else {
            out.println("default_authentication_method: none");
        }

        for (String profileId : config.getProfileConfigurations().keySet()) {
            out.println("configured_communication_profile: " + profileId);
        }
    }
}