package click.yukio.dbsc.storage;

import click.yukio.dbsc.core.DbscException;

import java.util.Map;
import java.util.Optional;

/**
 * Shared helpers for the storage adapters.
 */
final class StorageSupport {

    private StorageSupport() {
    }

    /**
     * Converts a stored JWK map into the immutable form {@code DeviceKey} expects,
     * or throws when the row is corrupt.
     *
     * <p>A missing JWK here is a corrupt row, not a protocol outcome: the caller
     * only reaches this after a row was found. It is deliberately not mapped to a
     * DBSC error code, because the client cannot fix it and the response should be
     * a 500 rather than a protocol 403 that suggests a bad key was presented.
     */
    static Map<String, Object> requireJwk(Map<String, Object> jwk, String sessionId) {
        if (jwk == null || jwk.isEmpty()) {
            throw new IllegalStateException(
                    "stored key for session " + sessionId + " has no JWK");
        }
        return jwk;
    }

    static <T> Optional<T> optional(T value) {
        return Optional.ofNullable(value);
    }
}
