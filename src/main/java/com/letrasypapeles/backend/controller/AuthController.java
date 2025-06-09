package com.letrasypapeles.backend.controller;

import com.letrasypapeles.backend.dto.LoginRequest;
import com.letrasypapeles.backend.dto.LoginResponse;
import com.letrasypapeles.backend.dto.RegisterRequest;
import com.letrasypapeles.backend.entity.Cliente;
import com.letrasypapeles.backend.service.ClienteService;
import com.letrasypapeles.backend.security.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final ClienteService clienteService;

    public AuthController(AuthenticationManager authenticationManager, JwtUtil jwtUtil, ClienteService clienteService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.clienteService = clienteService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> autenticarUsuario(@RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtil.generateJwtToken(authentication);

        return ResponseEntity.ok(new LoginResponse(jwt));
    }

    @PostMapping("/register")
    public ResponseEntity<?> registrarUsuario(@RequestBody RegisterRequest registroRequest) {
        try {
            Cliente cliente = new Cliente();
            cliente.setNombre(registroRequest.getNombre());
            cliente.setApellido(registroRequest.getApellido());
            cliente.setEmail(registroRequest.getEmail());
            cliente.setContraseña(registroRequest.getPassword());
    
            Cliente registrado = clienteService.registrarCliente(cliente);
            return ResponseEntity.ok(registrado);
        } catch (Exception e) {
            return ResponseEntity
                    .status(500)
                    .body("Error al registrar usuario: " + e.getMessage());
        }
    }
    
}