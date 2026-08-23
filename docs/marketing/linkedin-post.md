# Post para LinkedIn — Patch Genius

## Versión principal

---

Wazuh te dice **qué** está sin parchear.

No te dice qué parchear **primero**.

Si tenés Wazuh corriendo, ya conocés la pantalla: miles de CVEs, ordenados por
nada en particular. Un CVSS 9.8 que nadie explotó nunca al lado de un 7.8 que
está en campañas de ransomware ahora mismo. ¿Por dónde arrancás un lunes a la
mañana?

Armé **Patch Genius** para responder eso. Es open source (MIT), corre con
`docker compose up`, y lee tu propio Wazuh.

**Qué hace distinto**

→ **Prioriza como un analista, no por CVSS.** CISA KEV primero (explotación
confirmada en el mundo real), EPSS después (probabilidad a 30 días), y un score
ponderado para ordenar. Un CVE en KEV sube aunque su CVSS sea mediocre: alguien
ya lo está usando.

→ **Separa Linux de Windows.** Un hallazgo a nivel sistema operativo se cierra
con un KB acumulativo, no con `apt upgrade`. Y un solo build de Windows Server
puede acumular miles de CVEs: si van en el mismo ranking que los paquetes, tapan
todo lo demás.

→ **Los "sin triar" no desaparecen.** Wazuh reporta severidad `-` para los CVEs
que NVD todavía no puntuó. No son de severidad baja: son *desconocidos*, y uno
nuevo puede terminar siendo crítico. Tienen su propio bucket.

→ **Seguimiento por CVE y por agente.** El mismo CVE puede estar resuelto en un
servidor y pendiente en otro. Responsable, estado y fecha objetivo a ese nivel.

**Dos cosas que aprendí construyéndolo**

El índice de vulnerabilidades de Wazuh contiene **solo lo activo**: cuando
parcheás, el registro se borra. No hay campo de estado ni historial. Así que
"resuelto" y "reabierto" se derivan comparando cada lectura con la anterior.

Y hay una trampa peor: Wazuh **reescribe `vulnerability.detected_at`** cada vez
que reindexa un registro. Un SLA de parcheo construido sobre ese campo se
reinicia solo y **nunca vence**. Te muestra todo en verde para siempre. Patch
Genius guarda su propia fecha de primera detección.

**Lo demás**

Autenticación en todas las rutas (la pantalla es el inventario de lo que no está
parcheado en máquinas vivas), credenciales cifradas en reposo, interfaz en
español o inglés, y sin build step: cloná y levantá, sin Node ni CDN, que en
redes aisladas importa.

Está en desarrollo activo — las integraciones con SMTP, Jira, Slack y Teams ya
se configuran y se prueban desde la app, pero los disparadores automáticos están
en camino.

Si usás Wazuh y el parcheo te viene ganando, probalo y decime qué le falta:

🔗 github.com/safernandez666/patch-genius

Un producto de Zebra Security.

#Wazuh #Ciberseguridad #SOC #VulnerabilityManagement #PatchManagement #OpenSource #BlueTeam #CISAKEV #EPSS #DevSecOps

---

## Versión corta (si querés algo más liviano)

---

Wazuh te dice qué está sin parchear. No te dice qué parchear primero.

Hice **Patch Genius** para eso: lee tu Wazuh y ordena los CVEs como lo haría un
analista — CISA KEV primero (explotación confirmada), EPSS después, y un score
ponderado.

Tres cosas que me importaban:

• **Linux y Windows no se parchean igual.** Un CVE de sistema operativo se cierra
con un KB, no con `apt`. Van separados.

• **El SLA tiene que vencer de verdad.** Wazuh reescribe `detected_at` cuando
reindexa, así que un SLA basado en ese campo se reinicia solo y muestra todo en
verde para siempre. Patch Genius guarda su propia fecha.

• **Los CVEs sin puntaje de NVD no son "bajos"**, son desconocidos. Tienen su
propio bucket en vez de perderse al fondo.

Open source (MIT), `docker compose up`, y en desarrollo activo.

🔗 github.com/safernandez666/patch-genius

#Wazuh #Ciberseguridad #SOC #VulnerabilityManagement #OpenSource #BlueTeam

---

## Notas para publicar

- **Imagen sugerida**: `docs/img/dashboard.png` (el panel con las cuatro tarjetas
  de prioridad) o `docs/img/arquitectura.png` si querés algo más técnico.
  LinkedIn recorta a 1200×627 en el preview del link — subir la imagen aparte
  rinde más que dejar que tome la del repo.
- **Las primeras dos líneas** son lo único que se ve antes del "ver más". Están
  escritas para funcionar solas.
- **Sin promesas de más**: el post dice explícitamente que los disparadores
  automáticos de notificación todavía no están. Si los terminamos antes de que
  publiques, avisame y actualizo ese párrafo.
