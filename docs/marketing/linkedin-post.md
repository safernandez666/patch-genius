# Post para LinkedIn — Patch Genius

Todos los números que aparecen abajo salen de una instalación real corriendo
contra un Wazuh 4.14.6 con agentes Linux y Windows. Están verificados contra la
API antes de escribirlos.

---

## Versión principal

---

Wazuh te dice **qué** está sin parchear.

No te dice qué parchear **primero**.

Si tenés Wazuh corriendo ya conocés la pantalla: miles de CVEs ordenados por nada
en particular. Un CVSS 9.8 que nadie explotó nunca al lado de un 7.8 que está en
campañas de ransomware ahora mismo. ¿Por dónde arrancás un lunes a la mañana?

Armé **Patch Genius** para responder eso. Open source (MIT), `docker compose up`,
y lee tu propio Wazuh.

En la instalación con la que lo desarrollé: **2.515 CVEs** en 5 servidores. De
esos, **86 están en CISA KEV** —explotación confirmada en el mundo real— y **16
tienen campaña de ransomware conocida**. Ese es el número por el que empezás. No
por los 1.622 de severidad alta.

**Qué hace**

→ **Prioriza como un analista.** CISA KEV primero, EPSS después (probabilidad de
explotación a 30 días), y un score ponderado para ordenar. Un CVE en KEV sube
aunque su CVSS sea mediocre: alguien ya lo está usando.

→ **Separa Linux de Windows.** Un hallazgo de sistema operativo se cierra con un
KB acumulativo, no con `apt upgrade`. Y no es un detalle: en esa instalación
**2.089 de los 2.515 CVEs son de un solo build de Windows Server**. En el mismo
ranking que los paquetes, tapan absolutamente todo lo demás.

→ **Resumen con IA.** Un brief diario que dice qué priorizar esta semana, con qué
servidores y qué paquetes. Funciona con Claude, OpenAI o un modelo local — y esa
última opción existe porque el brief se arma con el estado real del parque,
hostnames incluidos. Con un modelo local no sale nada de tu red.

→ **Seguimiento por CVE y por agente.** El mismo CVE puede estar resuelto en un
servidor y pendiente en otro. Responsable, estado y fecha objetivo a ese nivel.

**Dos cosas que aprendí construyéndolo**

El índice de vulnerabilidades de Wazuh contiene **solo lo activo**: cuando
parcheás, el registro se borra. No hay campo de estado ni historial. Así que
"resuelto" se deriva comparando cada lectura con la anterior. En la última
corrida eso detectó **501 pares (CVE, servidor) cerrados en un día** que de otra
forma simplemente habrían desaparecido de la pantalla sin dejar rastro.

Y una trampa peor: Wazuh **reescribe `vulnerability.detected_at`** cada vez que
reindexa un registro. Un SLA de parcheo construido sobre ese campo se reinicia
solo y **nunca vence**. Te muestra todo en verde para siempre. Patch Genius
guarda su propia fecha de primera detección.

**Lo demás**

Autenticación en todas las rutas —la pantalla es el inventario de lo que no está
parcheado en máquinas vivas—, credenciales cifradas en reposo, interfaz en
español o inglés, y sin build step: cloná y levantá, sin Node ni CDN, que en
redes aisladas importa.

Está en desarrollo activo. Las integraciones con SMTP, Jira, Slack y Teams ya se
configuran y se prueban desde la app; los disparadores automáticos vienen ahora.

Si usás Wazuh y el parcheo te viene ganando, probalo y decime qué le falta:

🔗 github.com/safernandez666/patch-genius

Un producto de Zebra Security.

#Wazuh #Ciberseguridad #SOC #VulnerabilityManagement #PatchManagement #OpenSource #BlueTeam #CISAKEV #EPSS #DevSecOps

---

## Versión corta

---

Wazuh te dice qué está sin parchear. No te dice qué parchear primero.

Hice **Patch Genius** para eso: lee tu Wazuh y ordena los CVEs como lo haría un
analista — CISA KEV primero, EPSS después, y un score ponderado.

En la instalación donde lo desarrollé: 2.515 CVEs, de los cuales **86 en CISA KEV
y 16 con ransomware conocido**. Ese es el número por el que empezás.

Tres cosas que me importaban:

• **Linux y Windows no se parchean igual.** 2.089 de esos CVEs son de un solo
build de Windows Server: si comparten ranking con los paquetes, tapan todo.

• **El SLA tiene que vencer de verdad.** Wazuh reescribe `detected_at` al
reindexar, así que un SLA sobre ese campo se reinicia solo y muestra todo en
verde para siempre. Patch Genius guarda su propia fecha.

• **Un resumen con IA** que dice qué priorizar, con Claude, OpenAI o un modelo
local — porque el brief lleva hostnames y no todo el mundo puede mandarlos afuera.

Open source (MIT), `docker compose up`.

🔗 github.com/safernandez666/patch-genius

#Wazuh #Ciberseguridad #SOC #VulnerabilityManagement #OpenSource #BlueTeam

---

## Versión técnica (para un público más de ingeniería)

---

Wazuh 4.8 movió los datos de vulnerabilidades de la API del manager al Indexer.
Construí una herramienta encima de ese índice y me encontré con tres cosas que no
esperaba:

**1. El índice solo tiene lo activo.** Cuando parcheás, Wazuh borra el registro.
No hay campo de estado, no hay historial. "Resuelto" y "reabierto" hay que
derivarlos comparando cada lectura con la anterior.

**2. Hay que leerlo con un point-in-time.** Como el scanner borra filas mientras
paginás, un cursor sin congelar se saltea registros — y esos registros salteados
se reportan después como "resueltos". Un falso negativo de parcheo.

**3. `vulnerability.detected_at` se reescribe.** Cada vez que Wazuh reindexa un
registro, esa fecha se actualiza. Un SLA construido sobre ese campo se reinicia
solo y nunca vence: muestra todo en verde para siempre. Hay que guardar fecha
propia.

Bonus: el centinela de "sin puntaje" no es `null` ni `0`, es `-1.0` con severidad
`-`. Sin filtrarlo, esos CVEs entran al ranking como CVSS cero real.

Todo eso está resuelto en **Patch Genius**: prioriza con CISA KEV y EPSS, separa
CVEs de sistema operativo de los de paquete, lleva el ciclo de vida por (CVE,
agente), y escribe un brief diario con IA — Claude, OpenAI o local.

MIT, `docker compose up`, sin build step.

🔗 github.com/safernandez666/patch-genius

#Wazuh #OpenSearch #DevSecOps #VulnerabilityManagement #OpenSource

---

## Notas para publicar

- **Imagen**: `docs/img/dashboard.png` (las cuatro tarjetas de prioridad) para la
  versión principal o la corta; `docs/img/arquitectura.png` para la técnica.
  Subila aparte en vez de dejar que LinkedIn tome la del repo — el preview del
  link recorta a 1200×627.
- **Las primeras dos líneas** son lo único visible antes del "ver más". Están
  escritas para funcionar solas.
- **Los números cambian.** Salen de una instalación viva: cuando la escribí eran
  2.515 CVEs / 86 KEV / 16 ransomware / 501 resueltas. Verificalos antes de
  publicar o sacá las cifras.
- **Lo que el post NO promete**: alertas automáticas por Slack/Teams/mail ni
  creación de tickets en Jira. Eso todavía no dispara solo, y el post lo dice.
