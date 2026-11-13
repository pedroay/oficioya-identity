package eci.edu.dosw.identity.controller;

import eci.edu.dosw.identity.dto.InternalDtos.AuthenticateRequest;
import eci.edu.dosw.identity.dto.InternalDtos.ChangePasswordRequest;
import eci.edu.dosw.identity.dto.InternalDtos.CreateCredentialRequest;
import eci.edu.dosw.identity.dto.InternalDtos.OtpResponse;
import eci.edu.dosw.identity.dto.InternalDtos.ResetPasswordRequest;
import eci.edu.dosw.identity.dto.InternalDtos.TokenResponse;
import eci.edu.dosw.identity.dto.InternalDtos.ValidatePasswordRequest;
import eci.edu.dosw.identity.service.CredentialService;
import eci.edu.dosw.identity.service.JwtProvider;
import eci.edu.dosw.identity.service.OtpService;
import eci.edu.dosw.identity.service.PasswordPolicyService;
import eci.edu.dosw.identity.service.PasswordRecoveryService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * API interna de Identity: solo la consume el orquestador (rol SERVICE).
 * Identity solo autentica; no conoce perfiles de usuario ni envía notificaciones.
 */
@Tag(name = "Identity interno", description = "Credenciales, autenticación y OTP (uso exclusivo del orquestador)")
@RestController
@RequestMapping("/internal/v1")
public class InternalIdentityController {

    private final CredentialService credentialService;
    private final OtpService otpService;
    private final PasswordPolicyService passwordPolicy;
    private final PasswordRecoveryService recoveryService;
    private final JwtProvider jwtProvider;

    public InternalIdentityController(CredentialService credentialService,
            OtpService otpService,
            PasswordPolicyService passwordPolicy,
            PasswordRecoveryService recoveryService,
            JwtProvider jwtProvider) {
        this.credentialService = credentialService;
        this.otpService = otpService;
        this.passwordPolicy = passwordPolicy;
        this.recoveryService = recoveryService;
        this.jwtProvider = jwtProvider;
    }

    @PostMapping("/credentials/validate-password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void validatePassword(@Valid @RequestBody ValidatePasswordRequest request) {
        passwordPolicy.validate(request.password());
    }

    @PostMapping("/credentials")
    @ResponseStatus(HttpStatus.CREATED)
    public void createCredential(@Valid @RequestBody CreateCredentialRequest request) {
        credentialService.create(request.userId(), request.email(), request.password());
    }

    @DeleteMapping("/credentials/{userId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteCredential(@PathVariable UUID userId) {
        credentialService.delete(userId);
    }

    @PostMapping("/auth/login")
    public TokenResponse login(@Valid @RequestBody AuthenticateRequest request) {
        credentialService.authenticate(request.userId(), request.password());
        String token = jwtProvider.generateToken(request.userId(), request.roles());
        return new TokenResponse(token, jwtProvider.getExpirationSeconds());
    }

    @PutMapping("/credentials/{userId}/password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void changePassword(@PathVariable UUID userId,
            @Valid @RequestBody ChangePasswordRequest request) {
        credentialService.changePassword(userId, request.currentPassword(), request.newPassword());
    }

    @PostMapping("/credentials/{userId}/otp")
    public OtpResponse generateOtp(@PathVariable UUID userId) {
        return new OtpResponse(otpService.generate(userId), OtpService.VALID_MINUTES);
    }

    @PostMapping("/credentials/{userId}/password/reset")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void resetPassword(@PathVariable UUID userId,
            @Valid @RequestBody ResetPasswordRequest request) {
        recoveryService.reset(userId, request.code(), request.newPassword());
    }
}