package eci.edu.dosw.identity.exception;

/** Base de los errores de negocio del modulo Identity. */
public abstract class IdentityException extends RuntimeException {

    protected IdentityException(String message) {
        super(message);
    }
}
