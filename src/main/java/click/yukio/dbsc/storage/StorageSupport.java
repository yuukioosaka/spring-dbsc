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
     * Converts a stored JWK map into the immutable form {@code BoundKey} expects,
     * or throws when the row is corrupt.
     */
    static Map<String, Object> requireJwk(Map<String, Object> jwk, String sessionId) {
        if (jwk == null || jwk.isEmpty()) {
            throw new DbscException(
                    click.yukio.dbsc.core.DbscErrorCode.KEY_NOT_FOUND,
                    "stored bound key for session " + sessionId + " has no JWK");
        }
        return jwk;
    }

    static <T> Optional<T> optional(T value) {
        return Optional.ofNullable(value);
    }
}
