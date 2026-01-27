
//CONSTANTES
export const PROTOCOLS = ['TCP', 'UDP', 'ICMP'];
export const ACTIONS = ['ACCEPT', 'DROP'];
export const BAN_DURATION = 10000; // Duración del bloqueo IPS en ms
export const SERVER_MAC = "00:50:56:C0:00:08";

export const ATTACK_TYPES = {
    NONE: 'NONE',
    SQL_INJECTION: 'SQL_INJECTION',
    DDoS_UDP: 'DDoS_UDP',
    SYN_FLOOD: 'SYN_FLOOD'
};

//GENERADORES

export const generateMAC = () => {
    return "XX:XX:XX:XX:XX:XX".replace(/X/g, function () {
        return "0123456789ABCDEF".charAt(Math.floor(Math.random() * 16));
    });
};

export const generateRandomIP = (isAttack = false) => {
    if (isAttack) return `192.168.1.${Math.floor(Math.random() * 50) + 200}`;
    return `192.168.1.${Math.floor(Math.random() * 100) + 1}`;
};

// Conversión de datos a Bytes
const ipToBytes = (ip) => ip.split('.').map(Number);
const macToBytes = (mac) => mac.split(':').map(b => parseInt(b, 16));
const numToTwoBytes = (num) => [(num >> 8) & 0xFF, num & 0xFF];
const numToFourBytes = (num) => [
    (num >> 24) & 0xFF,
    (num >> 16) & 0xFF,
    (num >> 8) & 0xFF,
    num & 0xFF
];
const stringToBytes = (str) => {
    const bytes = [];
    for (let i = 0; i < str.length; i++) {
        bytes.push(str.charCodeAt(i));
    }
    return bytes;
};

// Serializador de Paquetes
const serializePacket = (packet) => {
    let bytes = [];

    bytes.push(...macToBytes(packet.destMAC));
    bytes.push(...macToBytes(packet.sourceMAC));
    bytes.push(0x08, 0x00);

    // Preparar Payload y Headers L4 para calcular longitud total IP
    const payloadBytes = packet.payload ? stringToBytes(packet.payload) : [];
    let l4HeaderBytes = [];
    let protocolNum = 6;

    // Construcción Header L4
    if (packet.protocol === 'TCP') {
        protocolNum = 6;
        // Source Port (2)
        l4HeaderBytes.push(...numToTwoBytes(parseInt(packet.srcPort)));
        // Dest Port (2)
        l4HeaderBytes.push(...numToTwoBytes(parseInt(packet.destPort)));
        // Seq Num (4)
        l4HeaderBytes.push(...numToFourBytes(packet.seq_num || 0));
        // Ack Num (4)
        l4HeaderBytes.push(...numToFourBytes(packet.ack_num || 0));

        let flagsVal = 0;
        if (packet.flags && packet.flags.includes('SYN')) flagsVal |= 0x02;
        if (packet.flags && packet.flags.includes('ACK')) flagsVal |= 0x10;
        if (packet.flags && packet.flags.includes('PSH')) flagsVal |= 0x08;
        if (packet.flags && packet.flags.includes('FIN')) flagsVal |= 0x01;
        if (packet.flags && packet.flags.includes('RST')) flagsVal |= 0x04;

        l4HeaderBytes.push(0x50, flagsVal);
        // Window Size (2)
        l4HeaderBytes.push(...numToTwoBytes(packet.window_size || 65535));
        // Checksum (2)
        l4HeaderBytes.push(0xAB, 0xCD);
        // Urgent Pointer (2)
        l4HeaderBytes.push(0x00, 0x00);

    } else if (packet.protocol === 'UDP') {
        protocolNum = 17;
        // Source Port (2)
        l4HeaderBytes.push(...numToTwoBytes(parseInt(packet.srcPort)));
        // Dest Port (2)
        l4HeaderBytes.push(...numToTwoBytes(parseInt(packet.destPort)));
        // Length (2) -> Header (8) + Payload
        const udpLen = 8 + payloadBytes.length;
        l4HeaderBytes.push(...numToTwoBytes(udpLen));
        // Checksum (2)
        l4HeaderBytes.push(0xAB, 0xCD);

    } else if (packet.protocol === 'ICMP') {
        protocolNum = 1;
        // Type (1) Echo Request = 8, Reply = 0
        l4HeaderBytes.push(0x08);
        // Code (1)
        l4HeaderBytes.push(0x00);
        // Checksum (2)
        l4HeaderBytes.push(0xF1, 0x22);
        // Identifier (2)
        l4HeaderBytes.push(0x00, 0x01);
        // Sequence (2)
        l4HeaderBytes.push(0x00, 0x01);
    }

    //CAPA 3: IPv4 (20 Bytes)
    const ipHeaderLen = 20;
    const totalLength = ipHeaderLen + l4HeaderBytes.length + payloadBytes.length;

    bytes.push(0x45);
    bytes.push(0x00);
    bytes.push(...numToTwoBytes(totalLength));
    bytes.push(...numToTwoBytes(packet.id_ip || 0));
    bytes.push(0x40, 0x00);
    bytes.push(packet.ttl);
    bytes.push(protocolNum);
    bytes.push(0x00, 0x00);
    bytes.push(...ipToBytes(packet.sourceIP));
    bytes.push(...ipToBytes(packet.destIP));

    // Añadir L4 y Payload
    bytes.push(...l4HeaderBytes);
    bytes.push(...payloadBytes);

    return bytes;
};

export const generateHexDump = (packet) => {
    const rawBytes = serializePacket(packet);
    const lines = [];
    let currentLineHex = "";
    let currentLineAscii = "";

    // Iterar bytes y formatear
    for (let i = 0; i < rawBytes.length; i++) {
        const byte = rawBytes[i];

        // Hex
        currentLineHex += byte.toString(16).padStart(2, '0').toUpperCase() + " ";

        // Ascii
        const char = (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : ".";
        currentLineAscii += char;

        // Salto de línea cada 16 bytes o al final
        if ((i + 1) % 16 === 0 || i === rawBytes.length - 1) {
            // Padding si es la última línea incompleta
            if (i === rawBytes.length - 1) {
                const remaining = 16 - ((i + 1) % 16);
                if (remaining < 16) {
                    currentLineHex += "   ".repeat(remaining);
                }
            }

            // Offset
            const offset = (Math.floor(i / 16) * 16).toString(16).padStart(4, '0').toUpperCase();

            lines.push(`${offset}   ${currentLineHex.trim()}   ${currentLineAscii}`);

            currentLineHex = "";
            currentLineAscii = "";
        }
    }
    return lines;
};

// Generador de Paquetes
export const generatePacket = (activeConnections = [], currentAttackMode = ATTACK_TYPES.NONE) => {
    const commonProps = {
        id: Date.now() + Math.random(),
        timestamp: new Date().toLocaleTimeString(),
        destIP: '10.0.0.5',
        destMAC: SERVER_MAC,
        ttl: 64,
        id_ip: Math.floor(Math.random() * 65535),
        seq_num: Math.floor(Math.random() * 4294967295),
        ack_num: Math.floor(Math.random() * 4294967295),
        window_size: 65535,
        checksum: Math.floor(Math.random() * 65535).toString(16).toUpperCase()
    };

    if (currentAttackMode === ATTACK_TYPES.SQL_INJECTION && Math.random() < 0.3) {
        return {
            ...commonProps,
            sourceIP: generateRandomIP(true),
            sourceMAC: generateMAC(),
            protocol: 'TCP',
            srcPort: Math.floor(Math.random() * 60000) + 1024,
            destPort: 80,
            isAttackSignature: true,
            flags: 'PSH, ACK',
            payload: "SELECT * FROM users WHERE id='1' OR '1'='1'",
            attackType: 'SQL Injection'
        };
    }

    if (currentAttackMode === ATTACK_TYPES.DDoS_UDP && Math.random() < 0.9) {
        // Reducimos el payload para que no sea excesivo en el hex dump
        const junkData = "X".repeat(Math.floor(Math.random() * 20) + 10);
        return {
            ...commonProps,
            sourceIP: generateRandomIP(true),
            sourceMAC: generateMAC(),
            protocol: 'UDP',
            srcPort: Math.floor(Math.random() * 60000) + 1024,
            destPort: 53,
            isAttackSignature: true,
            flags: '',
            payload: junkData,
            attackType: 'UDP Flood'
        };
    }

    if (currentAttackMode === ATTACK_TYPES.SYN_FLOOD && Math.random() < 0.8) {
        return {
            ...commonProps,
            sourceIP: generateRandomIP(true),
            sourceMAC: generateMAC(),
            protocol: 'TCP',
            srcPort: Math.floor(Math.random() * 60000) + 1024,
            destPort: 443,
            isAttackSignature: true,
            flags: 'SYN',
            payload: '',
            attackType: 'SYN Flood',
            window_size: 1024
        };
    }

    const isResponse = activeConnections.length > 0 && Math.random() < 0.3;
    if (isResponse) {
        const conn = activeConnections[Math.floor(Math.random() * activeConnections.length)];
        return {
            ...commonProps,
            id: Date.now() + Math.random(),
            timestamp: new Date().toLocaleTimeString(),
            sourceIP: conn.destIP,
            sourceMAC: SERVER_MAC,
            destIP: conn.sourceIP,
            destMAC: conn.sourceMAC || generateMAC(),
            protocol: conn.protocol,
            srcPort: conn.destPort,
            destPort: conn.srcPort,
            isAttackSignature: false,
            flags: 'ACK',
            isReturnTraffic: true,
            payload: 'HTTP/1.1 200 OK',
            ttl: 128
        };
    }

    const isAttack = Math.random() < 0.1;
    const protocol = PROTOCOLS[Math.floor(Math.random() * PROTOCOLS.length)];
    const commonPorts = [80, 443, 22, 21, 53, 8080];
    const port = isAttack ? 22 : commonPorts[Math.floor(Math.random() * commonPorts.length)];

    return {
        ...commonProps,
        sourceIP: generateRandomIP(isAttack),
        sourceMAC: generateMAC(),
        protocol: protocol,
        srcPort: Math.floor(Math.random() * 60000) + 1024,
        destPort: port,
        isAttackSignature: isAttack,
        flags: protocol === 'TCP' ? 'SYN' : '',
        isReturnTraffic: false,
        payload: isAttack ? 'SSH-2.0-OpenSSH_8.2p1' : (protocol === 'HTTP' ? 'GET /index.html HTTP/1.1' : ''),
        attackType: isAttack ? 'Port Scan' : ''
    };
};

//DATOS DEL TUTORIAL
export const TUTORIAL_STEPS = [
    {
        id: 0,
        title: "Bootcamp de Ciberseguridad",
        content: "Aprenderás a proteger un servidor desde cero. El entrenamiento incluye: Reglas básicas, Stateful Inspection y defensa contra ataques de Inyección SQL usando DPI.",
        actionCheck: () => true,
        tab: 'dashboard'
    },
    {
        id: 1,
        title: "1. La Regla de Oro",
        content: "En seguridad, lo que no está permitido está prohibido. Ve a la pestaña 'Reglas' y cambia la Política por Defecto a DROP para cerrar todo acceso.",
        actionCheck: (state) => state.defaultPolicy === 'DROP' && state.activeTab === 'rules',
        tab: 'rules',
        hint: "Busca los botones arriba a la derecha en la pestaña Reglas."
    },
    {
        id: 2,
        title: "2. Abrir Servicio Web",
        content: "El servidor necesita servir páginas web. Añade una regla para aceptar tráfico TCP en el puerto 80 (HTTP).",
        actionCheck: (state) => state.rules.some(r => r.port == '80' && r.protocol === 'TCP' && r.action === 'ACCEPT'),
        tab: 'rules',
        hint: "Usa el formulario inferior. Puerto: 80, Protocolo: TCP, Acción: ACCEPT."
    },
    {
        id: 3,
        title: "3. Memoria de Conexión (Stateful)",
        content: "El firewall está bloqueando las respuestas del servidor porque no 'recuerda' las peticiones. Activa el 'Modo Stateful' en la barra superior para permitir respuestas automáticamente.",
        actionCheck: (state) => state.isStateful === true,
        tab: 'dashboard',
        hint: "Busca el interruptor 'Modo Stateful' en la barra superior azul oscura."
    },
    {
        id: 4,
        title: "4. Simular un Ciberataque",
        content: "Es hora de probar las defensas. Ve a la pestaña 'Simulador' y activa el ataque 'SQL Injection'.",
        actionCheck: (state) => state.activeTab === 'simulate' && state.attackMode === 'SQL_INJECTION',
        tab: 'simulate',
        hint: "Haz clic en el panel rojo 'SQL Injection Attack'."
    },
    {
        id: 5,
        title: "5. Análisis Forense (Inspección)",
        content: "El ataque está pasando porque el puerto 80 está abierto. Ve a 'Logs', busca una fila roja (SQL Injection) y haz DOBLE CLIC para inspeccionar el paquete.",
        actionCheck: (state) => state.activeTab === 'logs' && state.selectedPacket && state.selectedPacket.attackType === 'SQL Injection',
        tab: 'logs',
        hint: "Doble clic en cualquier fila de la tabla de logs que tenga texto rojo."
    },
    {
        id: 6,
        title: "6. Defensa Profunda (DPI)",
        content: "¿ Has visto el comando 'SELECT' en el inspector? Eso es una inyección. Crea una regla nueva que bloquee el contenido 'SELECT' para bloquear este patrón.",
        actionCheck: (state) => state.rules.some(r => r.content.toUpperCase().includes('SELECT') && r.action === 'DROP'),
        tab: 'rules',
        hint: "Usa el campo 'Contenido (DPI)' en el formulario de reglas."
    },
    {
        id: 7,
        title: "7. Examen Final: Gestión de Crisis",
        content: "¡Emergencia! Un ataque masivo de tipo 'DDoS UDP' está ocurriendo. Tu misión: 1) Activa el ataque DDoS UDP. 2) Permite acceso SSH de emergencia (TCP 22) para admins. 3) Bloquea explícitamente el puerto DNS (UDP 53). 4) Audita (abre) un paquete UDP bloqueado en el Inspector para confirmar.",
        actionCheck: (state) => {
            const isAttacking = state.attackMode === 'DDoS_UDP';
            const hasSSH = state.rules.some(r => r.port.toString().trim() === '22' && r.protocol === 'TCP' && r.action === 'ACCEPT');
            const hasBlockUDP = state.rules.some(r => r.port.toString().trim() === '53' && r.protocol === 'UDP' && r.action === 'DROP');
            const validAudit = state.selectedPacket &&
                state.selectedPacket.attackType === 'UDP Flood' &&
                state.selectedPacket.action === 'DROP';

            return isAttacking && hasSSH && hasBlockUDP && validAudit;
        },
        tab: 'logs',
        hint: "Activa el ataque DDoS UDP, crea reglas para TCP/22 (ACCEPT) y UDP/53 (DROP). Finalmente, ve a logs y abre un paquete 'UDP Flood' rojo."
    },
    {
        id: 8,
        title: "¡BIEN HECHO!",
        content: "¡Felicidades! Has completado el entrenamiento. Ya estás preparado para investigar el simulador por tu cuenta.",
        actionCheck: () => true,
        tab: 'dashboard'
    }
];