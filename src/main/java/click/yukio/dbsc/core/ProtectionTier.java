package click.yukio.dbsc.core;

/**
 * Binding strength of a session. Mirrors the toolkit's {@code ProtectionTier}.
 *
 * <ul>
 *   <li>{@code DBSC} - a native hardware-backed key is registered (02).</li>
 *   <li>{@code BOUND} - only a polyfill key is registered (03).</li>
 *   <li>{@code NONE} - nothing bound, or a refresh signature failed.</li>
 * </ul>
 */
public enum ProtectionTier {
    DBSC("dbsc"),
    BOUND("bound"),
    NONE("none");

    private final String wireValue;

    ProtectionTier(String wireValue) {
        this.wireValue = wireValue;
    }

    public String wireValue() {
        return wireValue;
    }

    public static ProtectionTier fromWire(String value) {
        if (value == null) {
            return NONE;
        }
        return switch (value) {
            case "dbsc" -> DBSC;
            case "bound" -> BOUND;
            default -> NONE;
        };
    }
}
