package eci.edu.dosw.identity.exception;

public class InvalidCredentialsException extends IdentityException {

    public InvalidCredentialsException() {
        super("Usuario o contraseña incorrectos, por favor rectifique sus credenciales.");
    }

    public InvalidCredentialsException(String message) {
        super(message);
    }
}