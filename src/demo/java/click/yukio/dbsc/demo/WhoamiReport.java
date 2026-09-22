package click.yukio.dbsc.demo;

import click.yukio.dbsc.DbscService;
import click.yukio.dbsc.core.Session;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * The "why is my browser bound / not bound" report.
 *
 * <p>Three different things are easy to confuse, so the report keeps them apart:
 *
 * <ul>
 *   <li>{@code tier} — what the server enforces <em>right now</em>. This is the
 *       one that decides whether guarded routes open.</li>
 *   <li>{@code deviceKey} — whether the browser registered a hardware-backed key
 *       (Chromium 145+ on a platform with a TPM/Secure Enclave).</li>
 *   <li>{@code skippedReason} — why the browser declined, e.g. an unsupported
 *       platform or a profile without the hardware key facility. It arrives in
 *       the {@code Sec-Session-Skipped} header, and it is the difference between
 *       "broken" and "this browser will never support it".</li>
 * </ul>
 *
 * <p>{@code dbscSessionId} and {@code httpSessionId} are two independent
 * identifiers: the first is minted by the login route and identifies the DBSC
 * binding, the second belongs to the application's own session. They are shown
 * side by side precisely because they are <em>not</em> expected to match.
 */
record WhoamiReport(
        String httpSessionId,
        String dbscSessionId,
        String userId,
        String tier,
        boolean deviceKey,
        String skippedReason) {

    /** Builds the report for a request; never returns {@code null}. */
    static WhoamiReport of(DbscService dbsc, HttpServletRequest request) {
        HttpSession httpSession = request.getSession(false);
        String httpSessionId = httpSession == null ? null : httpSession.getId();

        Optional<Session> found = dbsc.sessionFor(request);
        if (found.isEmpty()) {
            return new WhoamiReport(
                    httpSessionId, null, null, "none", false, skippedReason(request));
        }

        Session session = found.get();
        return new WhoamiReport(
                httpSessionId,
                session.id(),
                session.userId(),
                dbsc.tierFor(session.id()).wireValue(),
                dbsc.hasDeviceKey(session.id()),
                skippedReason(request));
    }

    /** Convenience for the Thymeleaf templates, which read this as a map. */
    Map<String, Object> asMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("httpSessionId", httpSessionId);
        map.put("dbscSessionId", dbscSessionId);
        map.put("userId", userId);
        map.put("tier", tier);
        map.put("deviceKey", deviceKey);
        map.put("skippedReason", skippedReason);
        return map;
    }

    private static String skippedReason(HttpServletRequest request) {
        String skipped = request.getHeader("Sec-Session-Skipped");
        return skipped == null || skipped.isBlank() ? null : skipped;
    }
}
