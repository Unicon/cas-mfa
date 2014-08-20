<jsp:directive.include file="includes/top.jsp"/>
<script src="<c:url value='js/duo/Duo-Web-v1.bundled.min.js'/>"></script>
<script>
    Duo.init({
        'host': '${apiHost}',
        'sig_request': '${sigRequest}',
        'post_argument': 'signedDuoResponse'
    });
</script>

<form:form method="post" id="duo_form" cssClass="fm-v clearfix" commandName="${commandName}" htmlEscape="true">
    <input type="hidden" name="lt" value="${loginTicket}"/>
    <input type="hidden" name="execution" value="${flowExecutionKey}"/>
    <input type="hidden" name="_eventId" value="submit"/>

    <div class="box fl-panel" id="login">
        <iframe id="duo_iframe" width="100%" height="360" frameborder="0"></iframe>
    </div>
</form:form>

<jsp:directive.include file="includes/bottom.jsp"/>