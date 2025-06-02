Endpoints disponibles en la aplicación


El proyecto posee los siguientes endpoints configurados:

Endpoints públicos (sin autenticación)
POST /api/auth/login - Para iniciar sesión
POST /api/auth/register - Para registrar nuevos usuarios
GET /api/test/all - Contenido público
/h2-console/** - Consola de la base de datos H2
Endpoints protegidos (requieren autenticación)
GET /api/test/cliente - Requiere rol CLIENTE, EMPLEADO, o GERENTE
GET /api/test/empleado - Requiere rol EMPLEADO o GERENTE
GET /api/test/gerente - Requiere rol GERENTE
/api/admin/** - Requiere rol GERENTE
/api/empleado/** - Requiere rol GERENTE o EMPLEADO
Cómo probar los endpoints protegidos
Para probar los endpoints protegidos, se necesita:

Registrar un usuario usando /api/auth/register

Si no se especifican roles, automáticamente se asigna el rol "CLIENTE" por defecto.
Los roles válidos son:
"CLIENTE" (por defecto)
"EMPLEADO"
"GERENTE"
El sistema verifica si el email ya está en uso antes de permitir el registro.
Ejemplo de JSON para registro

Para registrar un nuevo usuario, enviar una solicitud POST a /api/auth/register con un cuerpo JSON como este:


{
  "nombre": "Nicolas herrera",
  "email": "nicohv@email.com",
  "password": "pass123",
  "roles": ["CLIENTE"]  // Opcional, por defecto es "CLIENTE"
}

Para un usuario con rol de empleado:

{
  "nombre": "Lily Tapia",
  "email": "lilytu@email.com",
  "password": "ron123",
  "roles": ["EMPLEADO"]
}

Para un usuario con múltiples roles:

{
  "nombre": "Colomba Herrera",
  "email": "colombaht@email.com",
  "password": "colomba123",
  "roles": ["EMPLEADO", "GERENTE"]
}

Iniciar sesión con ese usuario usando /api/auth/login para obtener un token JWT

Copiar el token y pegar en los endpoints protegidos usando el encabezado Authorization: Bearer {tu_token}
