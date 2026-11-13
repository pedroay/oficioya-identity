package eci.edu.dosw.identity.exception;

public class UserNotFoundException extends IdentityException {

    public UserNotFoundException() {
        super("Usuario no encontrado.");
    }

    public UserNotFoundException(String message) {
        super(message);
    }
}
