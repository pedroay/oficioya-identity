package eci.edu.dosw.identity.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.List;
import java.util.UUID;

/**
 * Contratos (request/response) de la API interna de Identity,
 * usada únicamente por el orquestador.
 */
public final class InternalDtos {

    private InternalDtos() {
    }

    public record ValidatePasswordRequest(@NotBlank String password) {
    }

    public record CreateCredentialRequest(
            @NotNull UUID userId,
            @NotBlank @Email String email,
            @NotBlank String password) {
    }

    public record AuthenticateRequest(
            @NotNull UUID userId,
            @NotBlank String password,
            List<String> roles) {
    }

    public record TokenResponse(String token, long expiresIn) {
    }

    public record ChangePasswordRequest(
            @NotBlank String currentPassword,
            @NotBlank String newPassword) {
    }

    public record OtpResponse(String code, int validMinutes) {
    }

    public record ResetPasswordRequest(
            @NotBlank String code,
            @NotBlank String newPassword) {
    }
}