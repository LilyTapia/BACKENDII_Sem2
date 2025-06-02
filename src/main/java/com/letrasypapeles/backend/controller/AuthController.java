package com.letrasypapeles.backend.controller;

import com.letrasypapeles.backend.dto.JwtResponse;
import com.letrasypapeles.backend.dto.LoginRequest;
import com.letrasypapeles.backend.dto.RegisterRequest;
import com.letrasypapeles.backend.entity.Cliente;
import com.letrasypapeles.backend.entity.Role;
import com.letrasypapeles.backend.repository.ClienteRepository;
import com.letrasypapeles.backend.repository.RoleRepository;
import com.letrasypapeles.backend.security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails; // No se utiliza
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private ClienteRepository clienteRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @PersistenceContext
    private EntityManager entityManager;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        // Autenticar usuario
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
        
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtil.generateJwtToken(authentication);
        
        // Cargar el cliente con sus roles directamente desde el repositorio
        Cliente cliente = clienteRepository.findByEmail(loginRequest.getEmail())
                .orElseThrow(() -> new RuntimeException("Error: Usuario no encontrado."));
        
        // Verificar los roles del cliente
        Set<Role> rolesSet = cliente.getRoles();
        System.out.println("Cliente encontrado: " + cliente.getEmail());
        System.out.println("Roles encontrados en el objeto Cliente: " + (rolesSet != null ? rolesSet.size() : 0));
        
        if (rolesSet == null || rolesSet.isEmpty()) {
            System.out.println("No se encontraron roles en el objeto Cliente, intentando cargar desde la base de datos");
            // Consultar directamente en la base de datos para los roles
            String sql = "SELECT r.nombre FROM roles r JOIN clientes_roles cr ON r.nombre = cr.role_nombre WHERE cr.cliente_id = " + cliente.getId();
            
            try {
                @SuppressWarnings("unchecked")
                List<String> roleNames = entityManager.createNativeQuery(sql).getResultList();
                
                if (!roleNames.isEmpty()) {
                    System.out.println("Roles encontrados en la base de datos: " + roleNames);
                    // Crear un nuevo conjunto de roles si es necesario
                    if (rolesSet == null) {
                        rolesSet = new HashSet<>();
                        cliente.setRoles(rolesSet);
                    }
                    
                    // Agregar los roles encontrados al cliente
                    for (String roleName : roleNames) {
                        Role role = roleRepository.findByNombre(roleName)
                                .orElseThrow(() -> new RuntimeException("Error: Rol " + roleName + " no encontrado."));
                        cliente.addRole(role);
                    }
                    
                    // Guardar el cliente con los roles actualizados
                    clienteRepository.save(cliente);
                    System.out.println("Cliente actualizado con roles: " + cliente.getRoles());
                }
            } catch (Exception e) {
                System.err.println("Error al cargar roles desde la base de datos: " + e.getMessage());
            }
        }
        
        // Extraer los nombres de los roles para la respuesta JWT
        List<String> roleNames = cliente.getRoles().stream()
                .map(Role::getNombre)
                .collect(Collectors.toList());
        
        System.out.println("Roles incluidos en la respuesta JWT: " + roleNames);

        return ResponseEntity.ok(new JwtResponse(jwt, cliente.getEmail(), roleNames));
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RegisterRequest registerRequest) {
        if (clienteRepository.existsByEmail(registerRequest.getEmail())) {
            return ResponseEntity.badRequest().body("Error: Email ya está en uso!");
        }

        // Crear nuevo cliente
        Cliente cliente = new Cliente();
        cliente.setNombre(registerRequest.getNombre());
        cliente.setEmail(registerRequest.getEmail());
        cliente.setContraseña(passwordEncoder.encode(registerRequest.getPassword()));
        cliente.setPuntosFidelidad(0);
        
        // Asignar roles o rol por defecto
        System.out.println("Roles recibidos en la solicitud: " + registerRequest.getRoles());
        
        // Siempre asignar rol CLIENTE por defecto
        Role clienteRole = roleRepository.findByNombre("CLIENTE")
            .orElseThrow(() -> new RuntimeException("Error: Rol CLIENTE no encontrado."));
        System.out.println("Rol CLIENTE encontrado en la base de datos: " + clienteRole);
        cliente.addRole(clienteRole);
        
        // Asignar roles adicionales si se especificaron
        if (registerRequest.getRoles() != null && !registerRequest.getRoles().isEmpty()) {
            registerRequest.getRoles().forEach(roleName -> {
                if (!roleName.equals("CLIENTE")) { // Evitar duplicar CLIENTE
                    Role role = roleRepository.findByNombre(roleName)
                        .orElseThrow(() -> new RuntimeException("Error: Rol " + roleName + " no encontrado."));
                    cliente.addRole(role);
                }
            });
        }
        
        System.out.println("Roles asignados antes de guardar: " + cliente.getRoles());
        clienteRepository.save(cliente);
        System.out.println("Roles guardados después de persistir: " + cliente.getRoles());
        
        Cliente clienteVerificado = clienteRepository.findByEmail(cliente.getEmail()).orElse(null);
        if (clienteVerificado != null) {
            System.out.println("Cliente guardado con ID: " + clienteVerificado.getId());
            System.out.println("Roles guardados: " + clienteVerificado.getRoles().stream()
                    .map(Role::getNombre)
                    .collect(Collectors.joining(", ")));
        }

        // Preparar respuesta
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Usuario registrado exitosamente!");
        response.put("usuario", cliente.getEmail());
        response.put("roles", cliente.getRoles().stream().map(Role::getNombre).collect(Collectors.toList()));

        return ResponseEntity.ok(response);
    }
}
