package click.yukio.dbsc.core;

/** Why a native registration was declined by the browser. Diagnostic only. */
public enum SkippedReason {
    UNREACHABLE("unreachable"),
    SERVER_ERROR("server_error"),
    QUOTA_EXCEEDED("quota_exceeded");

    private final String wireValue;

    SkippedReason(String wireValue) {
        this.wireValue = wireValue;
    }

    public String wireValue() {
        return wireValue;
    }

    /**
     * @return the matching reason, or {@code null} when the token is unrecognized
     *         (unrecognized tokens MUST be ignored, not rejected).
     */
    public static SkippedReason fromWire(String token) {
        if (token == null) {
            return null;
        }
        return switch (token) {
            case "unreachable" -> UNREACHABLE;
            case "server_error" -> SERVER_ERROR;
            case "quota_exceeded" -> QUOTA_EXCEEDED;
            default -> null;
        };
    }
}
