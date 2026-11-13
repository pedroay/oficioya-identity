package eci.edu.dosw.identity.service;

import eci.edu.dosw.identity.exception.InvalidOtpException;
import eci.edu.dosw.identity.exception.UserNotFoundException;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * Restablece la contraseña tras verificar un OTP. Valida primero la nueva contraseña
 * para no consumir el código si la contraseña no cumple la política.
 */
@Service
public class PasswordRecoveryService {

    private final CredentialService credentialService;
    private final OtpService otpService;

    public PasswordRecoveryService(CredentialService credentialService, OtpService otpService) {
        this.credentialService = credentialService;
        this.otpService = otpService;
    }

    public void reset(UUID userId, String code, String newPassword) {
        try {
            credentialService.validateNewPassword(userId, newPassword);
        } catch (UserNotFoundException e) {
            throw new InvalidOtpException();
        }
        otpService.verifyAndConsume(userId, code);
        credentialService.resetPassword(userId, newPassword);
    }
}