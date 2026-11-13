package eci.edu.dosw.identity.controller;

import eci.edu.dosw.identity.repository.CredentialRepository;
import eci.edu.dosw.identity.service.JwtProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class InternalIdentityControllerTest {

    private static final UUID USER_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final String CLAVE = "Segura#Clave2026";
    private static final String VALIDATE = "/internal/v1/credentials/validate-password";

    @Autowired
    private MockMvc mvc;
    @Autowired
    private JwtProvider jwtProvider;
    @Autowired
    private CredentialRepository credentialRepository;

    @BeforeEach
    @AfterEach
    void limpiar() {
        credentialRepository.deleteAll();
    }

    private String servicio() {
        return "Bearer " + jwtProvider.generateServiceToken();
    }

    private String json(String password) {
        return "{\"password\":\"" + password + "\"}";
    }

    @Test
    void sinTokenResponde401() throws Exception {
        mvc.perform(post(VALIDATE).contentType(MediaType.APPLICATION_JSON).content(json(CLAVE)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tokenDeUsuarioResponde401() throws Exception {
        String tokenUsuario = "Bearer " + jwtProvider.generateToken(USER_ID, List.of("ADMIN"));
        mvc.perform(post(VALIDATE).header(HttpHeaders.AUTHORIZATION, tokenUsuario)
                .contentType(MediaType.APPLICATION_JSON).content(json(CLAVE)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tokenBasuraResponde401() throws Exception {
        mvc.perform(post(VALIDATE).header(HttpHeaders.AUTHORIZATION, "Bearer no.es.un.jwt")
                .contentType(MediaType.APPLICATION_JSON).content(json(CLAVE)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void contrasenaDebilResponde400() throws Exception {
        mvc.perform(post(VALIDATE).header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON).content(json("123")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void contrasenaFuerteResponde204() throws Exception {
        mvc.perform(post(VALIDATE).header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON).content(json(CLAVE)))
                .andExpect(status().isNoContent());
    }

    @Test
    void rutaNoInternaSeDeniegaAunConTokenDeServicio() throws Exception {
        mvc.perform(get("/api/v1/auth/login").header(HttpHeaders.AUTHORIZATION, servicio()))
                .andExpect(status().isForbidden());
    }

    @Test
    void crearCredencialYAutenticar() throws Exception {
        mvc.perform(post("/internal/v1/credentials").header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"" + USER_ID + "\",\"email\":\"carlos@oficioya.com\",\"password\":\"" + CLAVE + "\"}"))
                .andExpect(status().isCreated());

        mvc.perform(post("/internal/v1/auth/login").header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"" + USER_ID + "\",\"password\":\"" + CLAVE + "\",\"roles\":[\"CONTRATANTE\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.expiresIn").isNumber());
    }

    @Test
    void loginConClaveIncorrectaResponde401() throws Exception {
        mvc.perform(post("/internal/v1/credentials").header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"" + USER_ID + "\",\"email\":\"carlos@oficioya.com\",\"password\":\"" + CLAVE + "\"}"))
                .andExpect(status().isCreated());

        mvc.perform(post("/internal/v1/auth/login").header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"" + USER_ID + "\",\"password\":\"Otra#Clave9999\",\"roles\":[\"CONTRATANTE\"]}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void elTokenDeUsuarioNuncaLlevaRolServicio() throws Exception {
        mvc.perform(post("/internal/v1/credentials").header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"" + USER_ID + "\",\"email\":\"carlos@oficioya.com\",\"password\":\"" + CLAVE + "\"}"))
                .andExpect(status().isCreated());

        String cuerpo = mvc.perform(post("/internal/v1/auth/login").header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"" + USER_ID + "\",\"password\":\"" + CLAVE + "\",\"roles\":[\"SERVICE\",\"CONTRATANTE\"]}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String token = cuerpo.replaceAll(".*\"token\":\"([^\"]+)\".*", "$1");
        List<String> roles = jwtProvider.getRolesFromToken(token);
        assertTrue(roles.contains("CONTRATANTE"));
        assertFalse(roles.contains("SERVICE"));
    }
}