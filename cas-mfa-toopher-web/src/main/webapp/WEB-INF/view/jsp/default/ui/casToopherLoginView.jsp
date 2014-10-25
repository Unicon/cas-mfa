<%--
    Licensed to Jasig under one or more contributor license
    agreements. See the NOTICE file distributed with this work
    for additional information regarding copyright ownership.
    Jasig licenses this file to you under the Apache License,
    Version 2.0 (the "License"); you may not use this file
    except in compliance with the License.  You may obtain a
    copy of the License at the following location:

      http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.

--%>
<jsp:directive.include file="includes/top.jsp" />

<link type="text/css" rel="stylesheet" href="<c:url value='/css/toopher-cas.css'/>" />
<script src="<c:url value='/js/jquery-1.11.0.min.js'/>" ></script>
<script src="<c:url value='/js/jquery.cookie.min.js'/>" ></script>
<script src="<c:url value='/js/toopher-web.js'/>" ></script>


<div id="msg" class="info">
  <h2><spring:message code="service.mfa.service.mfa.inprogress.header" /></h2>
  <h4><spring:message code="service.mfa.service.mfa.inprogress.message"
                    arguments="${service.authenticationMethod},${service}"
                    htmlEscape="true" /></h4>
</div>

<h1>${toopherIframeSrc}</h1>

<iframe id='toopher_iframe' toopher_req='${toopherIframeSrc}' toopher_postback='' framework_post_args='{"lt":"${loginTicket}","execution":"${flowExecutionKey}","_eventId":"toopher-api-response"}'></iframe>

<script>
    toopher.init('#toopher_iframe');
</script>


