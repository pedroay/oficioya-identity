package eci.edu.dosw.identity.exception;

public class OtpRateLimitException extends IdentityException {

    public OtpRateLimitException() {
        super("Superaste el limite de solicitudes de codigo. Intenta mas tarde.");
    }

    public OtpRateLimitException(String message) {
        super(message);
    }
}