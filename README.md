# wan-monitor

Monitorea el estado real de las 3 WAN del TP-Link Omada ER605 (consultando
directamente su API interna, no haciendo ping desde afuera) y avisa por
Telegram cuando una se cae o vuelve.

Proyecto totalmente independiente de `starr-server`: bot de Telegram propio,
canal propio, contenedor propio.

## Cómo funciona

El ER605 no expone su estado de WAN por SNMP ni nada estándar: hay que
loguearse en su panel web local (LuCI) igual que lo hace el navegador,
incluyendo el cifrado RSA del password que hace `encrypt.js` en el login.
Ese flujo completo (pedir la clave pública, cifrar el password, loguearse,
y luego consultar `/admin/online?form=online`) está reimplementado en
`wan_monitor.py`, sin dependencias externas de criptografía (usa el `pow()`
nativo de Python para la exponenciación modular).

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

## Notas

- `ROUTER_SCHEME=https` usa el certificado autofirmado del router
  (`verify=False` en el script) — es tráfico dentro de tu LAN, no sale a
  internet.
- Si el router se reinicia, la clave RSA pública puede regenerarse; el
  script la vuelve a pedir en cada login, así que no hay que tocar nada.
- Si el `stok`/sesión expira, el script reintenta logueándose de nuevo
  automáticamente.
