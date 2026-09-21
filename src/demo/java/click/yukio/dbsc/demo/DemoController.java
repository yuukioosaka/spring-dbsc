package click.yukio.dbsc.demo;

import click.yukio.dbsc.DbscService;
import click.yukio.dbsc.core.Json;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The application endpoints the demo exercises: a plain one a stolen cookie can
 * still reach, and a guarded one it cannot.
 */
@RestController
@RequestMapping("/app")
class DemoController {

    private final DbscService dbsc;

    DemoController(DbscService dbsc) {
        this.dbsc = dbsc;
    }

    /**
     * Unguarded, and deliberately so. It answers as long as the login cookie is
     * valid — which is exactly the request a stolen cookie can replay. Compare it
     * with {@link #payment}: the difference between the two is the whole value of
     * DBSC.
     */
    @GetMapping(path = "/whoami", produces = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<String> whoami(HttpServletRequest request) {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON)
                .body(Json.write(WhoamiReport.of(dbsc, request).asMap()));
    }

    /**
     * Guarded by {@link DemoFormLoginConfig#paymentRoute()}. Reaching this method
     * means the request carried a fresh proof signed by the device key, over a
     * body hash matching the exact bytes posted.
     */
    @PostMapping(path = "/payment", produces = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<String> payment(@RequestBody(required = false) String rawBody) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "authorized");
        body.put("note", "the per-request proof verified against this session's bound key");
        body.put("receivedBody", rawBody);
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(Json.write(body));
    }
}
