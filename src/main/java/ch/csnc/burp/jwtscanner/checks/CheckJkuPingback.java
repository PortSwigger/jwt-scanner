package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import ch.csnc.burp.jwtscanner.Jwt;
import ch.csnc.burp.jwtscanner.JwtAuditIssues;
import ch.csnc.burp.jwtscanner.JwtScannerExtension;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class CheckJkuPingback extends Check {

    @Override
    protected Optional<AuditIssue> doPerform(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        var collaborator = JwtScannerExtension.api().collaborator().createClient();
        var jwt = Jwt.newBuilder(auditInsertionPoint.baseValue()).withHeader("jku", "http://%s".formatted(collaborator.generatePayload().toString())).build();
        var checkRequest = buildCheckRequest(baseRequestResponse, auditInsertionPoint, ByteArray.byteArray(jwt.encode()), "jku pingback");
        var checkRequestResponse = JwtScannerExtension.api().http().sendRequest(checkRequest);
        CompletableFuture
                .delayedExecutor(30, TimeUnit.SECONDS, JwtScannerExtension.executor())
                .execute(() -> {
                    // Check later whether there was any interaction with the collaborator.
                    // If so then create an issue.
                    if (!collaborator.getAllInteractions().isEmpty()) {
                        var markers = markersOf(baseRequestResponse, auditInsertionPoint);
                        var auditIssue = JwtAuditIssues.jkuPingback(jwt, AuditIssueConfidence.FIRM, baseRequestResponse.withRequestMarkers(markers), checkRequestResponse);
                        JwtScannerExtension.api().siteMap().add(auditIssue);
                    }
                });
        return Optional.empty();
    }

}
