/*
 * Copyright (c) 2003 National Research Council of Canada
 *
 * Permission is hereby granted, free of charge, to any person 
 * obtaining a copy of this software and associated documentation 
 * files (the "Software"), to deal in the Software without 
 * restriction, including without limitation the rights to use, 
 * copy, modify, merge, publish, distribute, sublicense, and/or 
 * sell copies of the Software, and to permit persons to whom the 
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */

package edu.internet2.middleware.shibboleth.aa.attrresolv.provider;

import java.sql.ResultSet;

import javax.naming.directory.Attributes;

/*
 * Built at the Canada Institute for Scientific and Technical Information (CISTI 
 * <ahref="http://www.cisti-icist.nrc-cnrc.gc.ca/">http://www.cisti-icist.nrc-cnrc.gc.ca/</a>, 
 * the National Research Council Canada 
 * (NRC <a href="http://www.nrc-cnrc.gc.ca/">http://www.nrc-cnrc.gc.ca/</a>)
 * by David Dearman, COOP student from Dalhousie University,
 * under the direction of Glen Newton, Head research (IT)
 * <ahref="mailto:glen.newton@nrc-cnrc.gc.ca">glen.newton@nrc-cnrc.gc.ca</a>. 
 */

/**
 * Definition for the JDBC attribute extractor. 
 * 
 * @author David Dearman (dearman@cs.dal.ca)
 * @version 1.0 July 24, 2003
 *
 */

public interface JDBCAttributeExtractor {

	/**
	 * Method of extracting the attributes from the supplied result set.
	 *
	 * @param rs The result set from the query which contains the attributes
     * @param minResultSet The minimum number of rows that constitutes successful extraction
     * @param maxResultSet The maximum number of rows that constitutes successful extraction
	 * @return BasicAttributes as objects containing all the attributes
	 * @throws JDBCAttributeExtractorException If there is a complication in retrieving the attributes
	 */
	public Attributes extractAttributes(ResultSet rs, int minResultSet, int maxResultSet)
        throws JDBCAttributeExtractorException;
}
