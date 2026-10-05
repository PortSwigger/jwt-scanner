package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import ch.csnc.burp.jwtscanner.Jwt;
import ch.csnc.burp.jwtscanner.JwtAuditIssues;
import ch.csnc.burp.jwtscanner.JwtScannerExtension;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class CheckExpiredJwtAccepted extends Check {

    @Override
    protected Optional<AuditIssue> doPerform(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        var jwt = new Jwt(auditInsertionPoint.baseValue());
        if (jwt.isExpired()) {
            return perform(baseRequestResponse, auditInsertionPoint, "expired jwt", jwt, JwtAuditIssues::expiredAccepted);
        } else {
            // Schedule a recheck.
            jwt.getExp().ifPresent(exp -> {
                var now = System.currentTimeMillis() / 1000;
                var left = exp.longValue() - now;
                var runAt = left + 60;
                CompletableFuture
                        .delayedExecutor(runAt, TimeUnit.SECONDS, JwtScannerExtension.executor())
                        .execute(() -> new CheckExpiredJwtAccepted()
                                .perform(baseRequestResponse, auditInsertionPoint)
                                .ifPresent(JwtScannerExtension.api().siteMap()::add));
                JwtScannerExtension.logging().raiseInfoEvent("Checking whether an expired token is accepted in %d seconds".formatted(runAt));
            });
            return Optional.empty();
        }
    }

}
