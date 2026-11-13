package eci.edu.dosw.identity.exception;

public class InvalidOtpException extends IdentityException {

    public InvalidOtpException() {
        super("El codigo es invalido o ha expirado.");
    }

    public InvalidOtpException(String message) {
        super(message);
    }
}
