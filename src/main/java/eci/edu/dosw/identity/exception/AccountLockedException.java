package eci.edu.dosw.identity.exception;

public class AccountLockedException extends IdentityException {

    public AccountLockedException() {
        super("La cuenta esta bloqueada temporalmente por intentos fallidos.");
    }

    public AccountLockedException(String message) {
        super(message);
    }
}