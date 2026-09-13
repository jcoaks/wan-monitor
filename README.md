# wan-monitor

Monitorea el estado real de las 3 WAN del TP-Link Omada ER605 (consultando
directamente su API interna, no haciendo ping desde afuera) y avisa por
Telegram cuando una se cae o vuelve. También puede avisar cuando se va y
vuelve la luz de la casa, usando un dispositivo sin batería (la nevera)
como sensor.

Proyecto totalmente independiente de `starr-server`: bot de Telegram propio,
canal propio, contenedor propio.

## Cómo funciona

El ER605 no expone su estado de WAN por SNMP ni nada estándar: hay que
loguearse en su panel web local (LuCI) igual que lo hace el navegador. Tres
cosas nada obvias que hicieron falta para replicar el login (documentadas
también como comentarios en el código):

1. El password nunca se manda en claro: primero hay que pedirle al mismo
   endpoint de login la clave pública RSA (n, e), y cifrar el password con
   el esquema propio del router (relleno con ceros, no PKCS#1 estándar).
2. Los endpoints de login exigen headers `Referer`/`Origin` como protección
   CSRF — sin ellos el router responde un 404 genérico como si la ruta no
   existiera.
3. El valor que se cifra **no es el password solo**: el widget de login le
   agrega `"_" + uptime_del_router` (segundos desde que arrancó el router,
   consultado justo antes de loguearse) como protección anti-replay. Sin
   este sufijo el login falla con `error_code: 700` aunque el password sea
   correcto.

Todo ese flujo (pedir la clave pública, pedir el uptime, cifrar, loguearse,
y luego consultar `/admin/online?form=online`) está reimplementado en
`wan_monitor.py`, sin dependencias externas de criptografía (usa el `pow()`
nativo de Python para la exponenciación modular).

El router sirve el panel solo por HTTP en este modelo/firmware (HTTPS en el
puerto 443 da 404) — por eso `ROUTER_SCHEME=http` por defecto en `.env.example`.
El password sigue viajando cifrado con RSA dentro del payload aunque el
transporte sea HTTP, y de todas formas es tráfico solo dentro de la LAN.

Cada `POLL_INTERVAL_SECONDS` segundos consulta el estado de WAN1, WAN/LAN2 y
WAN/LAN3, y manda un mensaje a Telegram solo cuando **cambia** el estado de
alguna (no en cada poll). También avisa si deja de poder contactar al router.

## Setup

1. Crea un bot nuevo con [@BotFather](https://t.me/BotFather) (dedicado a
   esto, no el de starr-server) y guarda el token.
2. Crea un canal de Telegram (puede ser privado), agrega el bot como
   administrador, y usa su `@username` como `TELEGRAM_CHAT_ID` (más simple
   que buscar el chat_id numérico).
3. Copia `.env.example` a `.env` y completa:
   - `ROUTER_PASSWORD` con el password de admin del router
   - `TELEGRAM_BOT_TOKEN` y `TELEGRAM_CHAT_ID`
   - (opcional) `POWER_SENTINEL_IP` con la IP reservada de un dispositivo sin
     batería (ver sección de abajo) para detectar cortes de luz
4. Levanta el contenedor:

   ```bash
   docker compose up -d --build
   ```

5. Revisa los logs:

   ```bash
   docker compose logs -f
   ```

Al iniciar manda un mensaje con el estado actual de las 3 WAN, y desde ahí
solo avisa ante cambios.

## Sensor de luz (opcional)

Si el laptop donde corre el contenedor está en UPS pero otro dispositivo de
la casa no (por ejemplo la nevera), ese dispositivo dejando de responder al
ping es una buena señal de que se fue la luz — a diferencia de un simple
problema de WiFi, ya que el router también suele estar en el UPS.

Configúralo con `POWER_SENTINEL_IP` (la IP reservada por DHCP del
dispositivo) y opcionalmente `POWER_SENTINEL_LABEL` (el nombre que aparece
en los mensajes) y `POWER_SENTINEL_MAC` (solo informativo, para tus propios
registros). Si `POWER_SENTINEL_IP` queda vacío, este chequeo se desactiva
por completo.

Al iniciar manda un mensaje con el estado actual ("con luz" / "sin
responder"), y desde ahí solo avisa cuando cambia:

- 🔌 Se fue la luz (el dispositivo dejó de responder)
- 💡 Volvió la luz (el dispositivo responde de nuevo)

## Notas

- `ROUTER_SCHEME=https` usa el certificado autofirmado del router
  (`verify=False` en el script) — es tráfico dentro de tu LAN, no sale a
  internet.
- Si el router se reinicia, la clave RSA pública puede regenerarse; el
  script la vuelve a pedir en cada login, así que no hay que tocar nada.
- Si el `stok`/sesión expira, el script reintenta logueándose de nuevo
  automáticamente.
