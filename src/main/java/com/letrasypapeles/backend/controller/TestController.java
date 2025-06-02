package com.letrasypapeles.backend.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
@CrossOrigin(origins = "*", maxAge = 3600)
public class TestController {

    @GetMapping("/all")
    public String allAccess() {
        return "Contenido público";
    }

    @GetMapping("/cliente")
    @PreAuthorize("hasAuthority('CLIENTE') or hasAuthority('EMPLEADO') or hasAuthority('GERENTE')")
    public String clienteAccess() {
        return "Contenido para clientes";
    }

    @GetMapping("/empleado")
    @PreAuthorize("hasAuthority('EMPLEADO') or hasAuthority('GERENTE')")
    public String empleadoAccess() {
        return "Contenido para empleados";
    }

    @GetMapping("/gerente")
    @PreAuthorize("hasAuthority('GERENTE')")
    public String gerenteAccess() {
        return "Contenido para gerentes";
    }
}
