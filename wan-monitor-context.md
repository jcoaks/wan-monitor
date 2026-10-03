# wan-monitor — contexto para continuar en otro chat

Repo: `github.com/jcoaks/wan-monitor` (proyecto separado de `starr-server`).

## Qué hace

Script Python (`wan_monitor.py`) que corre en un contenedor Docker 24/7 y manda alertas a un canal de Telegram dedicado ("Internet Casa", bot propio, distinto al de `starr-server`). Dos funciones independientes:

1. **Monitor de WAN**: hace poll al API local del router (login + consulta de estado de interfaces) y avisa cuando una WAN cae o vuelve.
2. **Sensor de corte de luz**: hace ping a uno o más dispositivos sin batería de respaldo (a diferencia del router/host, que sí están en UPS) — si dejan de responder, asume que se fue la luz en la casa.

## Dónde vive

- **Despliegue real**: Docker en **PLEXSERVER**, el laptop Windows siempre encendido que también corre Plex + `starr-server`.
- **Copia sincronizada**: en el Mac (`robles-juan-local`), en `~/projects/wan-monitor` — copia del repo para desarrollo, no es donde corre el contenedor real.
- `.gitignore` excluye **todo** `.env*` (incluyendo `.env.example`), así que el `.env.example` del repo no queda versionado — es solo referencia local.

## Comandos de Telegram

`/pausa [minutos]` (default 5, máx 60), `/reanudar`, `/estado` — sirven para pausar el chequeo del router mientras entras tú mismo al panel web (el router del momento, ER605, solo permite una sesión admin a la vez y te saca si el bot está consultando al mismo tiempo).

## Variables de entorno relevantes (`.env`)

Router: `ROUTER_SCHEME`, `ROUTER_HOST` (default `192.168.0.1`), `ROUTER_USERNAME`, `ROUTER_PASSWORD`
Polling: `POLL_INTERVAL_SECONDS` (default 20), `UNREACHABLE_ALERT_AFTER` (default 3)
Telegram: `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`
Comandos: `COMMAND_CHECK_INTERVAL_SECONDS`, `DEFAULT_PAUSE_MINUTES`, `MAX_PAUSE_MINUTES`
Sensor de luz: `POWER_SENTINEL_IP`, `POWER_SENTINEL_LABEL`, `POWER_SENTINEL_MAC`, `PING_TIMEOUT_SECONDS`

Sentinel #1 (nevera): IP `192.168.0.175`.

## Cambio reciente (hecho en la copia del Mac, 2026-10-02 — NO deployado aún)

Se agregó soporte para un **segundo sentinel** de corte de luz, porque la nevera a veces se desconecta del WiFi por su cuenta y el bot lo confundía con un corte de luz real.

- Nuevas env vars: `POWER_SENTINEL2_IP`, `POWER_SENTINEL2_LABEL`, `POWER_SENTINEL2_MAC`.
- Sentinel #2 elegido: un smart plug con IP fija `192.168.0.176`, MAC `34-60-F9-37-CE-EC`.
- **Lógica nueva**: si solo hay 1 sentinel configurado, comportamiento idéntico a antes. Si hay 2, el aviso de "se fue la luz" **solo se dispara cuando AMBOS dejan de responder al mismo tiempo** — un solo dispositivo cayéndose (ej. la nevera por WiFi) queda en el log pero no manda alerta a Telegram. "Volvió la luz" se dispara en cuanto al menos uno de los dos vuelve a responder.
- Edición hecha directo en `wan_monitor.py` vía el bridge al Mac (`~/projects/wan-monitor`), **sin commitear todavía** (quedó pendiente confirmar con Juan si se commitea).
- También se actualizó `.env.example` como referencia (no versionado, ver arriba).

### Pendiente para activar el cambio

1. Decidir si se commitea/pushea el cambio en `wan_monitor.py`.
2. Llevar el código actualizado a PLEXSERVER (`git pull` si clona del mismo repo, o copiarlo manual).
3. Agregar al `.env` real de PLEXSERVER:
   ```
   POWER_SENTINEL2_IP=192.168.0.176
   POWER_SENTINEL2_LABEL=el smart plug
   POWER_SENTINEL2_MAC=34-60-F9-37-CE-EC
   ```
4. Reconstruir el contenedor: `docker compose up -d --build`.
5. Confirmar que `POWER_SENTINEL_IP` (nevera) esté efectivamente seteado en el `.env` de PLEXSERVER — el `.env` local del Mac no lo tenía, parece ser solo una copia de desarrollo incompleta.

## Importante: el router está cambiando

El monitor de WAN (`client.get_wan_status()`) habla con el API del **TP-Link Omada ER605** actual (login + LuCI). Juan está migrando ese router a un **MikroTik hEX RB750Gr3** con RouterOS — un proyecto en curso, en paralelo, que todavía no ha terminado (sigue resolviendo temas de PCC/load-balancing en ese router nuevo). Cuando el MikroTik reemplace por completo al ER605, **la parte de "monitor de WAN" de `wan_monitor.py` va a dejar de funcionar** porque habla el protocolo/API específico del ER605 — habrá que reescribir esa parte para consultar el estado de las WANs vía la API de RouterOS en su lugar. El sensor de corte de luz (ping a dispositivos) no depende del router y seguiría funcionando igual.
