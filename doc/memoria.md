# Sistema de autenticación de doble factor basado en criptografía de curva elíptica

## Palabras clave
Criptografía, Sistemas operativos, C, PAM, Autenticación, MQTT, Seguridad, Criptogagría de Curva Elíptica, ECDSA, HPC, 

## Resumen
La criptografía de curva elíptica está popularizándose debido a la robustez que ofrece con un reducido número de bits frente a otros algoritmos como
puede ser RSA que requieren un mayor número de bits para un nivel de seguridad equivalente.
El objetivo de este proyecto es implementar los mecanismos de autenticación de doble factor a nivel de sistema operativo y aplicación para un sistema
basado en un token con criptografía elíptica.

## Abstract


## Agradecimientos


## Índice general


## Índice de ilustraciones


1. Introduccion

1.1 Motivación

1.2 Objetivos

1.3 Estructura del trabajo


2. Estado del arte
yubikey, google auth, sso, 

3. Análisis del problema

4.1 Seguridad en la autenticación
sistemas actuales de autenticacion, prblema ssh 


4.2 Propuesta de solución
alternativa ecc combinado con un token electronico, flexible e independiente, ventajas modulo pam (usable en multiples servicios)

4.2.1 Aplicación de IoT en seguridad
SP32

4.2.2 MQTT

4.2.3 Criptografía de Curva Elíptica

4.2.4 Módulo PAM

4.2.5 Análisis de herramientas
herramientas usadas

4. Diseño de solución
Este apartado describe las fases en las que se desarrolla el sistema:

5.2 Fase de establecimiento de canales seguros

5.1 Fase de identificacion

5.3 Fase de autenticacion

2 imagenes: estructura de cajas e imagen draw.io
link repositorio

5. Análsis de serguridad
5.1 MITM
5.2 Confidencialidad
5.3 Integridad

5. Presupuesto
hardware y software
horas de desarrollo
diagrama de gantt

6. Conclusión

7. trabajos futuro
- ip (estricto, relajado)
- pruebas masivas
- escalado mqtt
- selinux 
- acl list

8. Bibliografía 

9. acronimos

